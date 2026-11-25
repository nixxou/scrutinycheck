//! Device discovery and data collection through `smartctl --json`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::model::SmartctlOutput;

/// smartctl exit status bits (see `man smartctl`, "EXIT STATUS").
/// Bits 0-1 mean the command could not run or open the device; the
/// higher bits report disk health and still come with usable JSON.
const EXIT_FATAL_MASK: i32 = 0b0000_0011;

#[derive(Debug, Clone)]
pub struct ScannedDevice {
    pub name: String,
    pub dev_type: Option<String>,
}

#[derive(Deserialize)]
struct ScanOutput {
    #[serde(default)]
    devices: Vec<ScanEntry>,
}

#[derive(Deserialize)]
struct ScanEntry {
    name: String,
    #[serde(default, rename = "type")]
    dev_type: Option<String>,
}

pub struct Smartctl {
    pub bin: String,
}

impl Smartctl {
    pub fn new(bin: Option<String>) -> Self {
        Self {
            bin: bin.unwrap_or_else(|| "smartctl".to_string()),
        }
    }

    fn run(&self, args: &[&str]) -> Result<(i32, Vec<u8>)> {
        let out = Command::new(&self.bin).args(args).output().with_context(|| {
            format!(
                "impossible de lancer `{}` : smartmontools est-il installé et dans le PATH ?",
                self.bin
            )
        })?;
        Ok((out.status.code().unwrap_or(-1), out.stdout))
    }

    /// `--scan-open` (rather than `--scan`) opens each device so the reported
    /// type is the real one: plain `--scan` reports SATA disks behind libata
    /// as "scsi", and passing `-d scsi` would hide their ATA attributes.
    pub fn scan(&self) -> Result<Vec<ScannedDevice>> {
        let (_, stdout) = self.run(&["--scan-open", "--json"])?;
        parse_scan(&stdout)
    }

    pub fn read_device(&self, dev: &ScannedDevice) -> Result<SmartctlOutput> {
        let mut args = vec!["-x", "--json"];
        if let Some(t) = dev.dev_type.as_deref() {
            args.extend(["-d", t]);
        }
        args.push(&dev.name);
        let (code, stdout) = self.run(&args)?;
        if stdout.is_empty() {
            bail!("{} : aucune sortie de smartctl (code {code})", dev.name);
        }
        let parsed: SmartctlOutput = serde_json::from_slice(&stdout)
            .with_context(|| format!("{} : JSON smartctl illisible", dev.name))?;
        if code >= 0 && code & EXIT_FATAL_MASK != 0 {
            let msg = parsed
                .smartctl
                .as_ref()
                .and_then(|m| m.messages.as_ref())
                .and_then(|m| m.first())
                .and_then(|m| m.string.clone())
                .unwrap_or_default();
            bail!("{} : smartctl a échoué (code {code}) {msg}", dev.name);
        }
        Ok(parsed)
    }
}

pub fn parse_scan(json: &[u8]) -> Result<Vec<ScannedDevice>> {
    let scan: ScanOutput = serde_json::from_slice(json).context("sortie de `smartctl --scan` illisible")?;
    Ok(scan
        .devices
        .into_iter()
        .map(|d| ScannedDevice {
            name: d.name,
            dev_type: d.dev_type,
        })
        .collect())
}

/// Load a saved `smartctl --json` output (for offline analysis and tests).
pub fn load_file(path: &Path) -> Result<SmartctlOutput> {
    let data = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("{} : JSON smartctl illisible", path.display()))
}
