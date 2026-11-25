use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use scrutinycheck::collect::{self, ReadOutcome, ScannedDevice, Smartctl};
use scrutinycheck::report::{self, AsleepReport, DeviceReport, ErrorReport};
use scrutinycheck::rules::{self, Policy, Status};

/// Disk health verdict from smartctl, using Scrutiny's rules.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Devices to check (e.g. /dev/sda, /dev/nvme0). Default: every device listed by `smartctl --scan`.
    devices: Vec<String>,

    /// Evaluate saved `smartctl -x --json` outputs instead of live devices.
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Device type passed to smartctl (-d), e.g. sat, nvme.
    #[arg(short = 'd', long = "device-type")]
    device_type: Option<String>,

    /// JSON output.
    #[arg(long)]
    json: bool,

    /// Show details (serial, power-on hours, temperature).
    #[arg(short, long)]
    verbose: bool,

    /// Strict mode: the verdict is the worst alert (warning = WARNING, manufacturer
    /// threshold failing now = FAILED, missing data = UNKNOWN).
    /// Default: Scrutiny's exact verdict (see README).
    #[arg(long)]
    strict: bool,

    /// Also read drives in standby, even if that wakes them up. By default a hard
    /// drive in STANDBY/SLEEP is skipped so it does not spin up.
    #[arg(long)]
    wake: bool,

    /// Path to the smartctl executable.
    #[arg(long, value_name = "PATH")]
    smartctl: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Entry {
    Ok(DeviceReport),
    Asleep(AsleepReport),
    Err(ErrorReport),
}

/// Exit codes: 0 all pass, 1 usage/runtime error, 2 a device could not be read
/// or is unknown, 3 warning, 4 failure. A drive skipped because it is asleep is
/// not an error and does not change the code.
fn exit_code(worst: Option<Status>, had_error: bool) -> u8 {
    match worst {
        Some(Status::Fail) => 4,
        Some(Status::Warning) => 3,
        _ if had_error => 2,
        Some(Status::Unknown) => 2,
        _ => 0,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    let mut entries = Vec::new();
    let policy = if cli.strict { Policy::Strict } else { Policy::Scrutiny };

    if !cli.files.is_empty() {
        for path in &cli.files {
            let label = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            entries.push(match collect::load_file(path) {
                Ok(dev) => Entry::Ok(DeviceReport::new(label, &dev, rules::evaluate_with(&dev, policy))),
                Err(e) => Entry::Err(ErrorReport { device: label, error: format!("{e:#}") }),
            });
        }
    } else {
        let smartctl = Smartctl::new(cli.smartctl.clone());
        let targets: Vec<ScannedDevice> = if cli.devices.is_empty() {
            smartctl.scan()?
        } else {
            cli.devices
                .iter()
                .map(|n| ScannedDevice { name: n.clone(), dev_type: cli.device_type.clone() })
                .collect()
        };
        if targets.is_empty() {
            anyhow::bail!("no device found by smartctl (missing administrator/root rights?)");
        }
        for t in &targets {
            entries.push(match smartctl.read_device(t, cli.wake) {
                Ok(ReadOutcome::Data(dev)) => {
                    let label = dev.device_name().unwrap_or(&t.name).to_string();
                    Entry::Ok(DeviceReport::new(label, &dev, rules::evaluate_with(&dev, policy)))
                }
                Ok(ReadOutcome::Asleep { mode }) => Entry::Asleep(AsleepReport::new(t.name.clone(), mode)),
                Err(e) => Entry::Err(ErrorReport { device: t.name.clone(), error: format!("{e:#}") }),
            });
        }
    }

    let worst = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Ok(r) => Some(r.evaluation.status),
            Entry::Asleep(_) | Entry::Err(_) => None,
        })
        .max();
    let had_error = entries.iter().any(|e| matches!(e, Entry::Err(_)));

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for e in &entries {
            match e {
                Entry::Ok(r) => print!("{}", report::render_text(r, cli.verbose)),
                Entry::Asleep(a) => print!("{}", report::render_asleep_text(a)),
                Entry::Err(e) => print!("{}", report::render_error_text(e)),
            }
        }
    }
    Ok(exit_code(worst, had_error))
}
