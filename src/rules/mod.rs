//! Health evaluation rules. CONTRACT shared with the CLI (main.rs / report.rs):
//! keep the public types and `evaluate` signature stable; add fields only.
//!
//! The rules are a port of Scrutiny (<https://github.com/AnalogJ/scrutiny>), as maintained in
//! the Starosdev fork (<https://github.com/Starosdev/scrutiny>, `master` at commit `de9f016f0987`,
//! release 1.80.2), MIT licensed, Copyright (c) 2020 Jason Kulatunga. See
//! `THIRD_PARTY_NOTICES.md`.
//!
//! # Layers
//!
//! 1. Overall SMART self-assessment (`smart_status.passed`), [`Source::SmartOverall`].
//! 2. Per-protocol attribute rules, dispatched on `device.protocol` exactly like the fork's
//!    `FromCollectorSmartInfoWithOverrides`: [`ata`], [`nvme`] or [`scsi`].
//!
//! # Mapping of the fork's status bits to [`Status`]
//!
//! The fork stores a bit set per attribute (`pkg.AttributeStatus`) and a separate, binary
//! device status (`pkg.DeviceStatus`). This crate has one four-level scale:
//!
//! | Fork                                   | Raised by                                              | Here                                  |
//! | -------------------------------------- | ------------------------------------------------------ | ------------------------------------- |
//! | `AttributeStatusPassed` (0)            | nothing to report                                      | no finding ([`Status::Pass`])         |
//! | `AttributeStatusFailedSmart` (1)       | ATA `when_failed == "now"`                             | [`Status::Fail`], `Manufacturer`      |
//! | `AttributeStatusWarningScrutiny` (2)   | ATA `when_failed == "past"`; non-critical AFR >= 10 %  | [`Status::Warning`]                   |
//! | `AttributeStatusFailedScrutiny` (4)    | AFR cutoffs; NVMe / SCSI recommended thresholds        | [`Status::Fail`]                      |
//! | `AttributeStatusInvalidValue` (8)      | ATA device statistics only (not ported)                | would be [`Status::Unknown`]          |
//! | `DeviceStatusFailedSmart`              | `smart_status.passed == false`                         | [`Status::Fail`], `SmartOverall`      |
//! | `DeviceStatusFailedScrutiny`           | any attribute carrying `FailedScrutiny`                | follows from the attribute finding    |
//!
//! The verdict of [`evaluate`] is the worst finding. That is deliberately stricter than the
//! fork's device status in two places, because the fork's device status has no warning level
//! and does not look at the attribute-level `FailedSmart` bit:
//!
//! * a warning-only device is `Warning` here, while the fork keeps the device "passed" and
//!   only colours the attribute;
//! * an attribute failing its manufacturer threshold *now* is `Fail` here even when the drive
//!   still answers `smart_status.passed == true`.
//!
//! [`Status::Unknown`] is returned when there is no usable SMART data at all (no
//! `smart_status.passed` and no attribute data for the device's protocol). The fork would
//! report such a submission as a SMART failure, because a missing `smart_status` decodes to
//! `passed == false` in Go; a missing answer is treated here as "no answer", not as a failure.
//!
//! # Not ported (extension points)
//!
//! * Consumer drive profiles: the hook is [`ata::observed_thresholds_for`].
//! * History: the fork clears warnings on cumulative counters whose value did not move since
//!   the previous collection (`UseDeltaEvaluation`). A single run has no previous value, so
//!   such findings are reported the way the fork reports a first submission.
//!   [`is_cumulative_counter`] identifies them.
//! * Replacement-risk score, power-on-hours rollover detection, Seagate FARM, ATA device
//!   statistics, user overrides and the `failures.transient.ata` setting.

use serde::Serialize;

use crate::model::SmartctlOutput;

pub mod ata;
pub mod ata_thresholds;
pub mod nvme;
pub mod scsi;

/// Ordered from best to worst so `max()` gives the overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Unknown,
    Warning,
    Fail,
}

/// Which rule layer produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Overall SMART self-assessment (smart_status.passed).
    SmartOverall,
    /// Normalized value at or below the manufacturer threshold.
    Manufacturer,
    /// Backblaze-derived observed failure-rate buckets (from Scrutiny).
    Backblaze,
    /// NVMe health log rules.
    Nvme,
    /// SCSI/SAS rules.
    Scsi,
    /// The smartctl output carries nothing that can be evaluated.
    NoData,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub source: Source,
    /// Attribute key: ATA id as string ("5"), NVMe/SCSI field name.
    pub attribute: String,
    pub name: String,
    pub raw_value: Option<i64>,
    pub status: Status,
    pub message: String,
    /// Annual failure rate (fraction, 0.06 = 6 %) when the Backblaze layer applies.
    pub annual_failure_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evaluation {
    pub status: Status,
    /// Only non-passing findings, worst first.
    pub findings: Vec<Finding>,
    /// Scrutiny mode only: a duplicated ATA attribute failed Scrutiny's thresholds in an
    /// occurrence that a later one overwrote (see `ata::evaluate`). The fork still fails
    /// the device for it.
    #[serde(skip)]
    pub(crate) overwritten_failure: bool,
}

/// Which way an attribute degrades (`Ideal` in the fork's metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ideal {
    /// The fork declares no direction (`""`).
    Unspecified,
    /// Lower is healthier.
    Low,
    /// Higher is healthier.
    High,
}

/// Per-attribute status bit set, the fork's `pkg.AttributeStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttrStatus(u8);

impl AttrStatus {
    pub const PASSED: AttrStatus = AttrStatus(0);
    /// The drive itself reports the attribute as failing its manufacturer threshold.
    pub const FAILED_SMART: AttrStatus = AttrStatus(1);
    pub const WARNING_SCRUTINY: AttrStatus = AttrStatus(2);
    pub const FAILED_SCRUTINY: AttrStatus = AttrStatus(4);
    /// Value exceeds a reasonable maximum (ATA device statistics, not ported).
    pub const INVALID_VALUE: AttrStatus = AttrStatus(8);

    pub fn has(self, flag: AttrStatus) -> bool {
        self.0 & flag.0 != 0
    }

    pub fn set(&mut self, flag: AttrStatus) {
        self.0 |= flag.0;
    }

    /// Raw bit set, comparable with the values the fork stores.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Collapse the bit set onto the four-level scale (see the module documentation).
    pub fn to_status(self) -> Status {
        if self.has(Self::FAILED_SMART) || self.has(Self::FAILED_SCRUTINY) {
            Status::Fail
        } else if self.has(Self::WARNING_SCRUTINY) {
            Status::Warning
        } else if self.has(Self::INVALID_VALUE) {
            Status::Unknown
        } else {
            Status::Pass
        }
    }
}

/// Port of the fork's NVMe / SCSI `PopulateAttributeStatus`: an attribute fails when its value
/// is on the wrong side of the recommended threshold for its `Ideal` direction. `threshold` is
/// `None` where the fork passes `-1` ("record, never evaluate").
pub(crate) fn recommended_threshold_status(
    ideal: Ideal,
    value: i64,
    threshold: Option<i64>,
) -> AttrStatus {
    let mut status = AttrStatus::PASSED;
    if let Some(threshold) = threshold {
        let failing = match ideal {
            Ideal::Low => value > threshold,
            Ideal::High => value < threshold,
            Ideal::Unspecified => false,
        };
        if failing {
            status.set(AttrStatus::FAILED_SCRUTINY);
        }
    }
    status
}

/// True when the finding is about a cumulative counter that the fork evaluates by trend
/// (`UseDeltaEvaluation`): ATA 199 (UltraDMA CRC errors), the SCSI verify re-read counter and
/// the SAS PHY error counters. The fork clears such a finding once the counter stops moving;
/// a single run cannot, so the value may be the trace of an old, fixed incident (a cable).
/// A manufacturer failure is never trend-evaluated.
pub fn is_cumulative_counter(finding: &Finding) -> bool {
    match finding.source {
        Source::Backblaze => finding
            .attribute
            .parse::<i64>()
            .ok()
            .and_then(ata_thresholds::ata_metadata)
            .is_some_and(|m| m.use_delta_evaluation),
        Source::Scsi => {
            scsi::scsi_metadata_for(&finding.attribute).is_some_and(|m| m.use_delta_evaluation)
        }
        Source::SmartOverall | Source::Manufacturer | Source::Nvme | Source::NoData => false,
    }
}

pub(crate) const CUMULATIVE_HINT: &str = "; cumulative counter, may date from an old incident";

#[derive(Clone, Copy)]
enum Protocol {
    Ata,
    Nvme,
    Scsi,
}

/// The fork dispatches on `device.protocol` alone. When smartctl gave no protocol (a hand-made
/// or truncated file), fall back on the section that is present.
fn protocol_of(dev: &SmartctlOutput, exact: bool) -> Option<Protocol> {
    match dev.protocol() {
        Some("ATA") => Some(Protocol::Ata),
        Some("NVMe") => Some(Protocol::Nvme),
        Some("SCSI") => Some(Protocol::Scsi),
        Some(_) => None,
        // The fork evaluates nothing without a protocol.
        None if exact => None,
        None => {
            if dev.ata_smart_attributes.is_some() {
                Some(Protocol::Ata)
            } else if dev.nvme_smart_health_information_log.is_some() {
                Some(Protocol::Nvme)
            } else if dev.scsi_grown_defect_list.is_some() || dev.scsi_error_counter_log.is_some() {
                Some(Protocol::Scsi)
            } else {
                None
            }
        }
    }
}

fn no_data_finding(dev: &SmartctlOutput) -> Finding {
    let smartctl_error = dev
        .smartctl
        .as_ref()
        .and_then(|meta| meta.messages.as_ref())
        .and_then(|messages| {
            messages
                .iter()
                .find(|m| m.severity.as_deref() == Some("error"))
        })
        .and_then(|m| m.string.as_deref());
    let message = match smartctl_error {
        Some(error) => format!("no usable SMART data (smartctl: {error})"),
        None => "no usable SMART data".to_string(),
    };
    Finding {
        source: Source::NoData,
        attribute: "smart".to_string(),
        name: "SMART data".to_string(),
        raw_value: None,
        status: Status::Unknown,
        message,
        annual_failure_rate: None,
    }
}

/// How findings are folded into the device verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Policy {
    /// Exactly the fork's device status (`FromCollectorSmartInfoWithOverrides`): the device
    /// fails when `smart_status.passed` is not true (a missing field decodes to false in Go)
    /// or when an attribute carries `FailedScrutiny`; otherwise it passes. Warnings and the
    /// attribute-level `FailedSmart` bit (`when_failed == "now"`) are reported on their
    /// attribute but do not change the verdict.
    #[default]
    Scrutiny,
    /// The verdict is the worst finding: warnings make the device `Warning`, a manufacturer
    /// threshold failing now makes it `Fail`, and missing SMART data gives `Unknown` instead
    /// of a failure.
    Strict,
}

/// Evaluate one device's smartctl JSON with the given verdict policy. Findings are the same
/// under every policy, except that [`Policy::Scrutiny`] adds a `SmartOverall` finding when
/// `smart_status` is missing, to explain the failure it implies.
pub fn evaluate_with(dev: &SmartctlOutput, policy: Policy) -> Evaluation {
    let mut evaluation = evaluate_inner(dev, policy == Policy::Scrutiny);
    if policy == Policy::Strict {
        return evaluation;
    }
    let smart_status_missing = dev.smart_status.as_ref().and_then(|s| s.passed).is_none();
    if smart_status_missing {
        evaluation.findings.insert(
            0,
            Finding {
                source: Source::SmartOverall,
                attribute: "smart_status".to_string(),
                name: "SMART overall health".to_string(),
                raw_value: None,
                status: Status::Fail,
                message: "SMART overall health missing: counted as a failure (Scrutiny logic)".to_string(),
                annual_failure_rate: None,
            },
        );
    }
    let failed_scrutiny = evaluation.findings.iter().any(|f| {
        f.status == Status::Fail && matches!(f.source, Source::Backblaze | Source::Nvme | Source::Scsi)
    });
    let failed_smart = evaluation
        .findings
        .iter()
        .any(|f| f.source == Source::SmartOverall);
    evaluation.status = if failed_smart || failed_scrutiny || evaluation.overwritten_failure {
        Status::Fail
    } else {
        Status::Pass
    };
    evaluation
}

/// Evaluate one device's smartctl JSON; the verdict is the worst finding ([`Policy::Strict`]).
pub fn evaluate(dev: &SmartctlOutput) -> Evaluation {
    evaluate_inner(dev, false)
}

/// `exact` reproduces the fork's input handling bug for bug (used by [`Policy::Scrutiny`]):
/// attributes are evaluated only when `device.protocol` is exactly "ATA", "NVMe" or "SCSI",
/// and an absent NVMe health field counts as 0, as Go's zero values make it. Without
/// `exact` ([`Policy::Strict`]), the protocol is inferred from the sections present and an
/// absent NVMe field is skipped.
fn evaluate_inner(dev: &SmartctlOutput, exact: bool) -> Evaluation {
    let mut findings = Vec::new();
    let mut overwritten_failure = false;
    let mut usable = false;

    if let Some(passed) = dev.smart_status.as_ref().and_then(|s| s.passed) {
        usable = true;
        if !passed {
            findings.push(Finding {
                source: Source::SmartOverall,
                attribute: "smart_status".to_string(),
                name: "SMART overall health".to_string(),
                raw_value: None,
                status: Status::Fail,
                message: "the drive reports itself as failing".to_string(),
                annual_failure_rate: None,
            });
        }
    }

    usable |= match protocol_of(dev, exact) {
        Some(Protocol::Ata) => {
            let (usable, overwritten) = ata::evaluate(dev, &mut findings, exact);
            overwritten_failure = overwritten;
            usable
        }
        Some(Protocol::Nvme) => nvme::evaluate(dev, &mut findings, exact),
        Some(Protocol::Scsi) => scsi::evaluate(dev, &mut findings),
        None => false,
    };

    if !usable {
        findings.push(no_data_finding(dev));
    }

    // Stable: equal statuses keep the overall verdict first, then the drive's own order.
    findings.sort_by_key(|f| std::cmp::Reverse(f.status));
    let status = findings
        .iter()
        .map(|f| f.status)
        .max()
        .unwrap_or(Status::Pass);
    Evaluation { status, findings, overwritten_failure }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn run(value: serde_json::Value) -> Evaluation {
        evaluate(&serde_json::from_value(value).unwrap())
    }

    #[test]
    fn attr_status_bits_match_the_fork() {
        assert_eq!(AttrStatus::PASSED.bits(), 0);
        assert_eq!(AttrStatus::FAILED_SMART.bits(), 1);
        assert_eq!(AttrStatus::WARNING_SCRUTINY.bits(), 2);
        assert_eq!(AttrStatus::FAILED_SCRUTINY.bits(), 4);
        assert_eq!(AttrStatus::INVALID_VALUE.bits(), 8);
    }

    #[test]
    fn attr_status_collapses_to_the_worst_level() {
        assert_eq!(AttrStatus::PASSED.to_status(), Status::Pass);
        assert_eq!(AttrStatus::WARNING_SCRUTINY.to_status(), Status::Warning);
        assert_eq!(AttrStatus::FAILED_SMART.to_status(), Status::Fail);
        assert_eq!(AttrStatus::FAILED_SCRUTINY.to_status(), Status::Fail);
        assert_eq!(AttrStatus::INVALID_VALUE.to_status(), Status::Unknown);

        let mut both = AttrStatus::WARNING_SCRUTINY;
        both.set(AttrStatus::FAILED_SCRUTINY);
        assert_eq!(both.bits(), 6);
        assert_eq!(both.to_status(), Status::Fail);
    }

    #[test]
    fn recommended_threshold_follows_the_ideal_direction() {
        let failed = AttrStatus::FAILED_SCRUTINY;
        assert_eq!(recommended_threshold_status(Ideal::Low, 1, Some(0)), failed);
        assert_eq!(
            recommended_threshold_status(Ideal::Low, 0, Some(0)),
            AttrStatus::PASSED
        );
        assert_eq!(
            recommended_threshold_status(Ideal::High, 9, Some(10)),
            failed
        );
        assert_eq!(
            recommended_threshold_status(Ideal::High, 10, Some(10)),
            AttrStatus::PASSED
        );
        // no direction, or no threshold: recorded, never judged
        assert_eq!(
            recommended_threshold_status(Ideal::Unspecified, 99, Some(0)),
            AttrStatus::PASSED
        );
        assert_eq!(
            recommended_threshold_status(Ideal::Low, 99, None),
            AttrStatus::PASSED
        );
    }

    #[test]
    fn empty_output_is_unknown() {
        // an empty object, and a `smartctl --scan` listing, which is not about one device
        for value in [
            json!({}),
            json!({"devices": [{"name": "/dev/sda", "protocol": "SCSI"}]}),
        ] {
            let eval = run(value);
            assert_eq!(eval.status, Status::Unknown);
            assert_eq!(eval.findings.len(), 1);
            assert_eq!(eval.findings[0].source, Source::NoData);
            assert_eq!(eval.findings[0].status, Status::Unknown);
        }
    }

    #[test]
    fn unknown_carries_the_smartctl_error() {
        let eval = run(json!({"smartctl": {"exit_status": 2, "messages": [
            {"string": "Smartctl open device: /dev/sda failed", "severity": "error"}
        ]}}));
        assert_eq!(eval.status, Status::Unknown);
        assert!(eval.findings[0].message.contains("Smartctl open device"));
    }

    #[test]
    fn overall_failure_alone_is_a_fail() {
        let eval = run(json!({"device": {"protocol": "ATA"}, "smart_status": {"passed": false}}));
        assert_eq!(eval.status, Status::Fail);
        assert_eq!(eval.findings.len(), 1);
        assert_eq!(eval.findings[0].source, Source::SmartOverall);
    }

    #[test]
    fn overall_pass_without_attributes_is_a_pass() {
        let eval = run(json!({"device": {"protocol": "ATA"}, "smart_status": {"passed": true}}));
        assert_eq!(eval.status, Status::Pass);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn attributes_without_overall_status_are_still_evaluated() {
        let eval = run(json!({
            "device": {"protocol": "NVMe"},
            "nvme_smart_health_information_log": {"critical_warning": 0, "media_errors": 0}
        }));
        assert_eq!(eval.status, Status::Pass);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn worst_finding_comes_first_and_decides_the_verdict() {
        let eval = run(json!({
            "device": {"protocol": "ATA"},
            "rotation_rate": 7200,
            "smart_status": {"passed": true},
            "ata_smart_attributes": {"table": [
                {"id": 190, "value": 72, "worst": 37, "thresh": 40, "when_failed": "past", "raw": {"value": 28}},
                {"id": 199, "value": 200, "thresh": 0, "when_failed": "", "raw": {"value": 3}},
                {"id": 5, "value": 100, "thresh": 5, "when_failed": "", "raw": {"value": 40}}
            ]}
        }));
        assert_eq!(eval.status, Status::Fail);
        let order: Vec<(&str, Status)> = eval
            .findings
            .iter()
            .map(|f| (f.attribute.as_str(), f.status))
            .collect();
        assert_eq!(
            order,
            [
                ("5", Status::Fail),
                ("190", Status::Warning),
                ("199", Status::Warning)
            ]
        );
        assert!(!is_cumulative_counter(&eval.findings[0]));
        assert!(!is_cumulative_counter(&eval.findings[1]));
        assert!(is_cumulative_counter(&eval.findings[2]));
    }

    #[test]
    fn warnings_alone_give_a_warning_verdict() {
        let eval = run(json!({
            "device": {"protocol": "ATA"},
            "rotation_rate": 7200,
            "smart_status": {"passed": true},
            "ata_smart_attributes": {"table": [
                {"id": 190, "value": 72, "worst": 37, "thresh": 40, "when_failed": "past", "raw": {"value": 28}}
            ]}
        }));
        assert_eq!(eval.status, Status::Warning);
    }

    #[test]
    fn overall_failure_is_listed_before_attribute_failures() {
        let eval = run(json!({
            "device": {"protocol": "SCSI"},
            "smart_status": {"passed": false},
            "scsi_grown_defect_list": 12
        }));
        let sources: Vec<Source> = eval.findings.iter().map(|f| f.source).collect();
        assert_eq!(sources, [Source::SmartOverall, Source::Scsi]);
    }

    #[test]
    fn protocol_is_inferred_when_smartctl_gives_none() {
        let eval = run(json!({"nvme_smart_health_information_log": {"media_errors": 7}}));
        assert_eq!(eval.status, Status::Fail);
        assert_eq!(eval.findings[0].source, Source::Nvme);
    }

    #[test]
    fn sections_of_another_protocol_are_ignored() {
        // the fork dispatches on device.protocol alone
        let eval = run(json!({
            "device": {"protocol": "ATA"},
            "smart_status": {"passed": true},
            "nvme_smart_health_information_log": {"media_errors": 7}
        }));
        assert_eq!(eval.status, Status::Pass);
    }

    #[test]
    fn status_serializes_in_lowercase() {
        let eval = run(json!({"device": {"protocol": "ATA"}, "smart_status": {"passed": false}}));
        let value = serde_json::to_value(&eval).unwrap();
        assert_eq!(value["status"], "fail");
        assert_eq!(value["findings"][0]["source"], "smart_overall");
    }
}
