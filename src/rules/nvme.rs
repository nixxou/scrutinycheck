//! NVMe health log rules.
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `webapp/backend/pkg/thresholds/nvme_attribute_metadata.go`,
//! `webapp/backend/pkg/models/measurements/smart_nvme_attribute.go` and
//! `processNvmeSmartInfoWithOverrides` in `webapp/backend/pkg/models/measurements/smart.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! Each field of the health log is compared with a recommended threshold along its `Ideal`
//! direction. Only four fields have a threshold in the fork: `critical_warning` (0),
//! `available_spare` (the drive's own `available_spare_threshold`), `percentage_used` (100)
//! and `media_errors` (0). The others are recorded but never judged; that includes
//! `num_err_log_entries`, although its metadata marks it critical.

use super::{AttrStatus, Finding, Ideal, Source, recommended_threshold_status};
use crate::model::{NvmeHealthLog, SmartctlOutput};

#[derive(Debug, Clone, Copy)]
pub struct NvmeAttributeMetadata {
    pub id: &'static str,
    pub display_name: &'static str,
    pub ideal: Ideal,
    pub critical: bool,
}

const fn meta(
    id: &'static str,
    display_name: &'static str,
    ideal: Ideal,
    critical: bool,
) -> NvmeAttributeMetadata {
    NvmeAttributeMetadata {
        id,
        display_name,
        ideal,
        critical,
    }
}

/// The fork's `NmveMetadata` map, display names verbatim.
pub static NVME_METADATA: &[NvmeAttributeMetadata] = &[
    meta("critical_warning", "Critical Warning", Ideal::Low, true),
    meta("temperature", "Temperature", Ideal::Unspecified, false),
    meta("available_spare", "Available Spare", Ideal::High, true),
    meta("percentage_used", "Percentage Used", Ideal::Low, true),
    meta(
        "data_units_read",
        "Data Units Read",
        Ideal::Unspecified,
        false,
    ),
    meta(
        "data_units_written",
        "Data Units Written",
        Ideal::Unspecified,
        false,
    ),
    meta("host_reads", "Host Reads", Ideal::Unspecified, false),
    meta("host_writes", "Host Writes", Ideal::Unspecified, false),
    meta(
        "controller_busy_time",
        "Controller Busy Time",
        Ideal::Unspecified,
        false,
    ),
    meta("power_cycles", "Power Cycles", Ideal::Unspecified, false),
    meta(
        "power_on_hours",
        "Power on Hours",
        Ideal::Unspecified,
        false,
    ),
    meta(
        "unsafe_shutdowns",
        "Unsafe Shutdowns",
        Ideal::Unspecified,
        false,
    ),
    meta("media_errors", "Media Errors", Ideal::Low, true),
    meta(
        "num_err_log_entries",
        "Numb Err Log Entries",
        Ideal::Low,
        true,
    ),
    meta(
        "warning_temp_time",
        "Warning Temp Time",
        Ideal::Unspecified,
        false,
    ),
    meta(
        "critical_comp_time",
        "Critical CompTime",
        Ideal::Unspecified,
        false,
    ),
];

pub fn nvme_metadata(id: &str) -> Option<&'static NvmeAttributeMetadata> {
    NVME_METADATA.iter().find(|m| m.id == id)
}

/// `SmartNvmeAttribute.PopulateAttributeStatus`. `threshold` is `None` where the fork uses -1.
pub fn evaluate_attribute(id: &str, value: i64, threshold: Option<i64>) -> AttrStatus {
    match nvme_metadata(id) {
        Some(metadata) => recommended_threshold_status(metadata.ideal, value, threshold),
        None => AttrStatus::PASSED,
    }
}

/// The judged fields of the health log with their thresholds, as built by the fork's
/// `processNvmeSmartInfoWithOverrides`. Fields with no threshold cannot produce a finding
/// and are left out.
fn judged_attributes(log: &NvmeHealthLog) -> [(&'static str, Option<i64>, i64); 4] {
    [
        ("critical_warning", log.critical_warning, 0),
        // An absent threshold decodes to 0 in the fork.
        (
            "available_spare",
            log.available_spare,
            log.available_spare_threshold.unwrap_or(0),
        ),
        ("percentage_used", log.percentage_used, 100),
        ("media_errors", log.media_errors, 0),
    ]
}

/// Evaluate the health log. Returns false when the device reports none.
pub(super) fn evaluate(dev: &SmartctlOutput, findings: &mut Vec<Finding>) -> bool {
    let Some(log) = &dev.nvme_smart_health_information_log else {
        return false;
    };
    for (id, value, threshold) in judged_attributes(log) {
        // The fork reads an absent field as 0. That is harmless for the "low is ideal"
        // fields, but would fail `available_spare`; an absent field is skipped here.
        let Some(value) = value else { continue };
        let status = evaluate_attribute(id, value, Some(threshold));
        if status == AttrStatus::PASSED {
            continue;
        }
        findings.push(Finding {
            source: Source::Nvme,
            attribute: id.to_string(),
            name: nvme_metadata(id).map_or(id, |m| m.display_name).to_string(),
            raw_value: Some(value),
            status: status.to_status(),
            message: message(id, value, threshold),
            annual_failure_rate: None,
        });
    }
    true
}

fn message(id: &str, value: i64, threshold: i64) -> String {
    match id {
        "critical_warning" => format!(
            "controller critical warning ({})",
            critical_warning_causes(value)
        ),
        "available_spare" => {
            format!("available spare at {value}%, below the drive threshold ({threshold}%)")
        }
        "percentage_used" => format!("{value}% of rated endurance used"),
        "media_errors" => format!("{value} data integrity error(s)"),
        _ => format!("value {value} outside the recommended threshold ({threshold})"),
    }
}

/// Bits of the NVMe "Critical Warning" byte (NVMe base specification, SMART / Health
/// Information log). The fork only checks that the byte is non-zero; the decoding is there
/// to make the message useful.
fn critical_warning_causes(value: i64) -> String {
    const BITS: [(i64, &str); 6] = [
        (0x01, "spare below threshold"),
        (0x02, "temperature out of range"),
        (0x04, "reliability degraded"),
        (0x08, "media read-only"),
        (0x10, "volatile memory backup failed"),
        (0x20, "persistent memory read-only"),
    ];
    let causes: Vec<&str> = BITS
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, cause)| *cause)
        .collect();
    if causes.is_empty() {
        format!("code {value:#04x}")
    } else {
        causes.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::Status;
    use super::*;

    const FAILED: AttrStatus = AttrStatus::FAILED_SCRUTINY;

    fn run(log: serde_json::Value) -> Vec<Finding> {
        let dev: SmartctlOutput =
            serde_json::from_value(json!({"nvme_smart_health_information_log": log})).unwrap();
        let mut findings = Vec::new();
        assert!(evaluate(&dev, &mut findings));
        findings
    }

    fn healthy() -> serde_json::Value {
        json!({
            "critical_warning": 0, "temperature": 36, "available_spare": 100,
            "available_spare_threshold": 10, "percentage_used": 3, "media_errors": 0,
            "num_err_log_entries": 0, "unsafe_shutdowns": 12
        })
    }

    #[test]
    fn metadata_matches_the_fork() {
        assert_eq!(NVME_METADATA.len(), 16);
        let critical: Vec<&str> = NVME_METADATA
            .iter()
            .filter(|m| m.critical)
            .map(|m| m.id)
            .collect();
        assert_eq!(
            critical,
            [
                "critical_warning",
                "available_spare",
                "percentage_used",
                "media_errors",
                "num_err_log_entries"
            ]
        );
        assert_eq!(nvme_metadata("available_spare").unwrap().ideal, Ideal::High);
        assert!(nvme_metadata("nope").is_none());
    }

    #[test]
    fn attribute_thresholds() {
        assert_eq!(evaluate_attribute("media_errors", 1, Some(0)), FAILED);
        assert_eq!(
            evaluate_attribute("media_errors", 0, Some(0)),
            AttrStatus::PASSED
        );
        assert_eq!(evaluate_attribute("critical_warning", 4, Some(0)), FAILED);
        // "high is ideal": failing strictly below the threshold
        assert_eq!(evaluate_attribute("available_spare", 9, Some(10)), FAILED);
        assert_eq!(
            evaluate_attribute("available_spare", 10, Some(10)),
            AttrStatus::PASSED
        );
        // endurance: 100 % used is still a pass, 101 % is not
        assert_eq!(
            evaluate_attribute("percentage_used", 100, Some(100)),
            AttrStatus::PASSED
        );
        assert_eq!(
            evaluate_attribute("percentage_used", 101, Some(100)),
            FAILED
        );
        // no threshold (-1 in the fork): never judged, even for a critical attribute
        assert_eq!(
            evaluate_attribute("num_err_log_entries", 5000, None),
            AttrStatus::PASSED
        );
        // no direction: never judged
        assert_eq!(
            evaluate_attribute("temperature", 99, Some(0)),
            AttrStatus::PASSED
        );
        assert_eq!(
            evaluate_attribute("unknown", 99, Some(0)),
            AttrStatus::PASSED
        );
    }

    #[test]
    fn healthy_log_has_no_finding() {
        assert!(run(healthy()).is_empty());
    }

    #[test]
    fn error_log_entries_alone_are_not_a_finding() {
        let mut log = healthy();
        log["num_err_log_entries"] = json!(1234);
        log["unsafe_shutdowns"] = json!(900);
        assert!(run(log).is_empty());
    }

    #[test]
    fn each_judged_field_produces_a_fail() {
        let mut log = healthy();
        log["critical_warning"] = json!(5);
        log["available_spare"] = json!(4);
        log["percentage_used"] = json!(117);
        log["media_errors"] = json!(2);
        let findings = run(log);
        let ids: Vec<&str> = findings.iter().map(|f| f.attribute.as_str()).collect();
        assert_eq!(
            ids,
            [
                "critical_warning",
                "available_spare",
                "percentage_used",
                "media_errors"
            ]
        );
        assert!(
            findings
                .iter()
                .all(|f| f.status == Status::Fail && f.source == Source::Nvme)
        );
        assert_eq!(findings[0].name, "Critical Warning");
        assert!(
            findings[0]
                .message
                .contains("spare below threshold, reliability degraded")
        );
        assert_eq!(findings[3].raw_value, Some(2));
    }

    #[test]
    fn absent_fields_are_skipped() {
        // only the spare threshold is present: nothing to compare it with
        assert!(run(json!({"available_spare_threshold": 10})).is_empty());
        // an absent threshold reads as 0, which no spare value can be below
        assert!(run(json!({"available_spare": 0})).is_empty());
    }

    #[test]
    fn unknown_critical_warning_bit_is_shown_as_a_code() {
        assert_eq!(critical_warning_causes(0x40), "code 0x40");
        assert_eq!(critical_warning_causes(0x08), "media read-only");
    }

    #[test]
    fn missing_log_is_not_usable_data() {
        let mut findings = Vec::new();
        assert!(!evaluate(&SmartctlOutput::default(), &mut findings));
    }
}
