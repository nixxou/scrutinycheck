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
                "cannot run `{}`: is smartmontools installed and on the PATH?",
                self.bin
            )
        })?;
        Ok((out.status.code().unwrap_or(-1), out.stdout))
    }

    /// Plain `--scan` only lists device nodes; it does not open them, so it
    /// cannot spin up a sleeping drive (`--scan-open` would). Its "scsi" type
    /// for SATA disks behind libata is dropped in `parse_scan`, letting
    /// smartctl's own autodetection pick SAT vs SCSI at read time.
    pub fn scan(&self) -> Result<Vec<ScannedDevice>> {
        let (_, stdout) = self.run(&["--scan", "--json"])?;
        parse_scan(&stdout)
    }

    /// Read one device. Unless `wake` is set, smartctl is given `-n standby`:
    /// it checks the power mode first (CHECK POWER MODE does not spin up a
    /// drive) and skips a drive in STANDBY or SLEEP instead of waking it.
    pub fn read_device(&self, dev: &ScannedDevice, wake: bool) -> Result<ReadOutcome> {
        let mut args = vec!["-x", "--json"];
        if !wake {
            args.extend(["-n", "standby"]);
        }
        if let Some(t) = dev.dev_type.as_deref() {
            args.extend(["-d", t]);
        }
        args.push(&dev.name);
        let (code, stdout) = self.run(&args)?;
        if let Some(mode) = low_power_skip(&stdout) {
            return Ok(ReadOutcome::Asleep { mode });
        }
        if stdout.is_empty() {
            bail!("{}: no output from smartctl (exit code {code})", dev.name);
        }
        let parsed: SmartctlOutput = serde_json::from_slice(&stdout)
            .with_context(|| format!("{}: unreadable smartctl JSON", dev.name))?;
        if code >= 0 && code & EXIT_FATAL_MASK != 0 {
            let msg = parsed
                .smartctl
                .as_ref()
                .and_then(|m| m.messages.as_ref())
                .and_then(|m| m.first())
                .and_then(|m| m.string.clone())
                .unwrap_or_default();
            bail!("{}: smartctl failed (exit code {code}) {msg}", dev.name);
        }
        Ok(ReadOutcome::Data(Box::new(parsed)))
    }
}

#[derive(Debug)]
pub enum ReadOutcome {
    Data(Box<SmartctlOutput>),
    /// smartctl skipped the drive because of `-n standby`; `mode` is the power
    /// mode it reported (e.g. "STANDBY", "SLEEP").
    Asleep { mode: String },
}

/// Detect smartctl's low-power skip. Like the Scrutiny collector (fix #911) we
/// match the message, not the exit status: the status is 2 by default (which
/// collides with "device open failed") and N with `-n standby,N`. The message
/// reads "Device is in STANDBY mode, exit(2)" in text output and appears in
/// `smartctl.messages` in JSON output.
pub fn low_power_skip(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    let start = text.find("Device is in ")? + "Device is in ".len();
    let rest = &text[start..];
    let end = rest.find(' ')?;
    let mode = &rest[..end];
    let tail = &rest[end..];
    if !mode.is_empty() && tail.starts_with(" mode, exit(") {
        Some(mode.to_string())
    } else {
        None
    }
}

pub fn parse_scan(json: &[u8]) -> Result<Vec<ScannedDevice>> {
    let scan: ScanOutput = serde_json::from_slice(json).context("unreadable `smartctl --scan` output")?;
    Ok(scan
        .devices
        .into_iter()
        .map(|d| ScannedDevice {
            name: d.name,
            // `--scan` labels SATA disks behind libata "scsi"; forcing `-d scsi`
            // would hide their ATA attributes. Let smartctl autodetect instead.
            dev_type: d.dev_type.filter(|t| t != "scsi"),
        })
        .collect())
}

/// Load a saved `smartctl --json` output (for offline analysis and tests).
pub fn load_file(path: &Path) -> Result<SmartctlOutput> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("{}: unreadable smartctl JSON", path.display()))
}
