use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use scrutinycheck::collect::{self, ScannedDevice, Smartctl};
use scrutinycheck::report::{self, DeviceReport, ErrorReport};
use scrutinycheck::rules::{self, Policy, Status};

/// Évalue la santé des disques à partir de smartctl, avec les règles de Scrutiny.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Disques à analyser (ex. /dev/sda, /dev/nvme0). Par défaut : tous ceux trouvés par `smartctl --scan`.
    devices: Vec<String>,

    /// Analyser des sorties `smartctl -x --json` enregistrées au lieu des disques.
    #[arg(short = 'f', long = "file", value_name = "FICHIER")]
    files: Vec<PathBuf>,

    /// Type de périphérique transmis à smartctl (-d), ex. sat, nvme.
    #[arg(short = 'd', long = "device-type")]
    device_type: Option<String>,

    /// Sortie JSON.
    #[arg(long)]
    json: bool,

    /// Afficher les détails (série, heures, température).
    #[arg(short, long)]
    verbose: bool,

    /// Mode strict : le verdict est la pire alerte (avertissement = ATTENTION, seuil
    /// constructeur franchi maintenant = DÉFAILLANT, données absentes = INCONNU).
    /// Par défaut : verdict exact de Scrutiny (voir README).
    #[arg(long)]
    strict: bool,

    /// Chemin de l'exécutable smartctl.
    #[arg(long, value_name = "CHEMIN")]
    smartctl: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Entry {
    Ok(DeviceReport),
    Err(ErrorReport),
}

/// Exit codes: 0 all pass, 1 usage/runtime error, 2 a device could not be read
/// or is unknown, 3 warning, 4 failure.
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
            eprintln!("erreur : {e:#}");
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
            anyhow::bail!("aucun disque trouvé par smartctl (droits administrateur/root ?)");
        }
        for t in &targets {
            entries.push(match smartctl.read_device(t) {
                Ok(dev) => {
                    let label = dev.device_name().unwrap_or(&t.name).to_string();
                    Entry::Ok(DeviceReport::new(label, &dev, rules::evaluate_with(&dev, policy)))
                }
                Err(e) => Entry::Err(ErrorReport { device: t.name.clone(), error: format!("{e:#}") }),
            });
        }
    }

    let worst = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Ok(r) => Some(r.evaluation.status),
            Entry::Err(_) => None,
        })
        .max();
    let had_error = entries.iter().any(|e| matches!(e, Entry::Err(_)));

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for e in &entries {
            match e {
                Entry::Ok(r) => print!("{}", report::render_text(r, cli.verbose)),
                Entry::Err(e) => print!("{}", report::render_error_text(e)),
            }
        }
    }
    Ok(exit_code(worst, had_error))
}
