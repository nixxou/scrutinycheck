//! Human and JSON rendering of evaluations.

use serde::Serialize;

use crate::model::SmartctlOutput;
use crate::rules::{Evaluation, Status};

#[derive(Debug, Serialize)]
pub struct DeviceReport {
    pub device: String,
    pub protocol: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub capacity_bytes: Option<u64>,
    pub kind: &'static str,
    pub power_on_hours: Option<i64>,
    pub temperature_c: Option<i64>,
    #[serde(flatten)]
    pub evaluation: Evaluation,
}

/// A drive smartctl skipped because it is in a low-power mode (`-n standby`).
#[derive(Debug, Serialize)]
pub struct AsleepReport {
    pub device: String,
    /// Always "asleep", so JSON consumers can tell it from a status.
    pub skipped: &'static str,
    pub power_mode: String,
}

impl AsleepReport {
    pub fn new(device: String, power_mode: String) -> Self {
        Self { device, skipped: "asleep", power_mode }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorReport {
    pub device: String,
    pub error: String,
}

impl DeviceReport {
    pub fn new(label: String, dev: &SmartctlOutput, evaluation: Evaluation) -> Self {
        let protocol = dev.protocol().map(str::to_string);
        let kind = match (protocol.as_deref(), dev.rotation_rate) {
            (Some("NVMe"), _) => "SSD NVMe",
            (_, Some(0)) => "SSD",
            (_, Some(_)) => "HDD",
            _ => "?",
        };
        Self {
            device: label,
            protocol,
            model: dev.model_name.clone(),
            serial: dev.serial_number.clone(),
            capacity_bytes: dev
                .user_capacity
                .as_ref()
                .and_then(|c| c.bytes)
                .and_then(|b| u64::try_from(b).ok()),
            kind,
            power_on_hours: dev
                .power_on_time
                .as_ref()
                .and_then(|p| p.hours)
                .or_else(|| dev.nvme_smart_health_information_log.as_ref().and_then(|n| n.power_on_hours)),
            temperature_c: dev.temperature.as_ref().and_then(|t| t.current),
            evaluation,
        }
    }
}

pub fn status_label(s: Status) -> &'static str {
    match s {
        Status::Pass => "OK",
        Status::Unknown => "UNKNOWN",
        Status::Warning => "WARNING",
        Status::Fail => "FAILED",
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if v >= 100.0 || i == 0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn render_text(r: &DeviceReport, verbose: bool) -> String {
    let mut out = String::new();
    let size = r.capacity_bytes.map(human_size).unwrap_or_default();
    // Under the default (Scrutiny) policy a drive can be OK and still carry
    // attribute findings (warnings, manufacturer threshold failing now):
    // say so on its line, the findings themselves are listed below.
    let alerts = r.evaluation.findings.len();
    let label = if r.evaluation.status == Status::Pass && alerts > 0 {
        format!("OK ({alerts} alert{})", if alerts > 1 { "s" } else { "" })
    } else {
        status_label(r.evaluation.status).to_string()
    };
    out.push_str(&format!(
        "{:<14} {:<16} {:<36} {:>8}  {}\n",
        r.device,
        label,
        r.model.as_deref().unwrap_or("?"),
        size,
        r.kind,
    ));
    if verbose {
        let mut meta = Vec::new();
        if let Some(s) = &r.serial {
            meta.push(format!("serial {s}"));
        }
        if let Some(h) = r.power_on_hours {
            meta.push(format!("{h} power-on hours"));
        }
        if let Some(t) = r.temperature_c {
            meta.push(format!("{t} °C"));
        }
        if !meta.is_empty() {
            out.push_str(&format!("   {}\n", meta.join(" · ")));
        }
    }
    for f in &r.evaluation.findings {
        let raw = f.raw_value.map(|v| format!(" raw={v}")).unwrap_or_default();
        let afr = f
            .annual_failure_rate
            .map(|a| format!(" (observed annual failure rate ≈ {:.1}%)", a * 100.0))
            .unwrap_or_default();
        out.push_str(&format!(
            "   └ [{}] {:>4} {}{raw}: {}{afr}\n",
            status_label(f.status),
            f.attribute,
            f.name,
            f.message,
        ));
    }
    out
}

pub fn render_asleep_text(a: &AsleepReport) -> String {
    format!(
        "{:<14} {:<16} drive in {}: not read so it is not woken up (--wake to force)\n",
        a.device, "ASLEEP", a.power_mode
    )
}

pub fn render_error_text(e: &ErrorReport) -> String {
    format!("{:<14} {:<16} {}\n", e.device, "ERROR", e.error)
}
