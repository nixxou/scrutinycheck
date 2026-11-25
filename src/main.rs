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

    /// Test harness: read one smartctl JSON document per stdin line and write one
    /// compact result per line (both policies), flushed after each line.
    #[arg(long, hide = true)]
    batch: bool,
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

#[derive(Serialize)]
struct BatchFinding<'a> {
    attribute: &'a str,
    source: rules::Source,
    status: Status,
}

#[derive(Serialize, Default)]
struct BatchResult<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strict_status: Option<Status>,
    findings: Vec<BatchFinding<'a>>,
}

/// `--batch`: the differential fuzzer keeps this process running and streams
/// documents through it. A panic is reported as an error line (it is a bug to
/// find), not a crash.
fn run_batch() -> anyhow::Result<u8> {
    use std::io::{BufRead, Write};
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let mut line = String::new();
    let mut input = stdin.lock();
    std::panic::set_hook(Box::new(|_| {}));
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(0);
        }
        let text = line.clone();
        let outcome = std::panic::catch_unwind(move || -> String {
            let dev: scrutinycheck::model::SmartctlOutput = match serde_json::from_str(&text) {
                Ok(d) => d,
                Err(e) => {
                    let r = BatchResult { error: Some(format!("json: {e}")), ..Default::default() };
                    return serde_json::to_string(&r).unwrap();
                }
            };
            let default = rules::evaluate_with(&dev, Policy::Scrutiny);
            let strict = rules::evaluate_with(&dev, Policy::Strict);
            let r = BatchResult {
                error: None,
                status: Some(default.status),
                strict_status: Some(strict.status),
                findings: default
                    .findings
                    .iter()
                    .map(|f| BatchFinding { attribute: &f.attribute, source: f.source, status: f.status })
                    .collect(),
            };
            serde_json::to_string(&r).unwrap()
        });
        let json = match outcome {
            Ok(j) => j,
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                serde_json::to_string(&BatchResult { error: Some(format!("panic: {msg}")), ..Default::default() })?
            }
        };
        writeln!(out, "{json}")?;
        out.flush()?;
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    if cli.batch {
        return run_batch();
    }
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
