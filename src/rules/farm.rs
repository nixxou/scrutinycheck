//! Seagate FARM log evaluation (Field Accessible Reliability Metrics, `seagate_farm_log`).
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `webapp/backend/pkg/thresholds/farm_attribute_metadata.go`,
//! `webapp/backend/pkg/models/measurements/smart_farm_attribute.go`,
//! `buildFarmAttributeValues` / `processFarmDataWithOverrides` in
//! `webapp/backend/pkg/models/measurements/smart.go` and
//! `webapp/backend/pkg/models/collector/farm.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! The log is read only when `supported` is true, on an ATA device. Each page that is
//! present contributes a fixed set of `farm_` attributes (an absent counter is 0), judged
//! with the same rules as ATA device statistics ([`statistic_status`]). No FARM attribute
//! has a fixed threshold in the fork, so the layer can only raise:
//!
//! * `WarningScrutiny` on a non-zero critical error count (unrecoverable read / write
//!   errors, reallocated sectors, reallocation candidates, CRC errors);
//! * `InvalidValue` on an `Ideal::Low` attribute above 1,000,000.
//!
//! A `FailedScrutiny` would fail the device (there is no ignore list for FARM).
//!
//! Not ported: the fork's power-on-hours rollover detection, which compares `farm_poh`
//! with the SMART power-on hours across collections.

use super::devstat::{statistic_finding, statistic_status};
use super::devstat_thresholds::{DeviceStatisticMetadata, meta};
use super::{Finding, Ideal, Source};
use crate::model::{SeagateFarmLog, SmartctlOutput};

/// The fork's `FarmMetadata` map, display names verbatim.
pub static FARM_METADATA: &[DeviceStatisticMetadata] = &[
    // Page 1: Drive Information
    meta("farm_poh", "Power-On Hours (FARM)", Ideal::Unspecified, false, 0),
    meta("farm_spoh", "Spindle Power-On Hours", Ideal::Unspecified, false, 0),
    meta("farm_head_flight_hours", "Head Flight Hours", Ideal::Unspecified, false, 0),
    meta("farm_head_load_events", "Head Load Events", Ideal::Low, false, 0),
    meta("farm_power_cycle_count", "Power Cycle Count (FARM)", Ideal::Unspecified, false, 0),
    // Page 2: Workload Statistics
    meta("farm_total_read_commands", "Total Read Commands", Ideal::Unspecified, false, 0),
    meta("farm_total_write_commands", "Total Write Commands", Ideal::Unspecified, false, 0),
    meta("farm_logical_sectors_written", "Logical Sectors Written", Ideal::Unspecified, false, 0),
    meta("farm_logical_sectors_read", "Logical Sectors Read", Ideal::Unspecified, false, 0),
    // Page 3: Error Statistics
    meta("farm_unrecoverable_read_errors", "Unrecoverable Read Errors (FARM)", Ideal::Low, true, 0),
    meta("farm_unrecoverable_write_errors", "Unrecoverable Write Errors (FARM)", Ideal::Low, true, 0),
    meta("farm_reallocated_sectors", "Reallocated Sectors (FARM)", Ideal::Low, true, 0),
    meta("farm_reallocation_candidates", "Reallocation Candidates", Ideal::Low, true, 0),
    meta("farm_crc_errors", "CRC Errors (FARM)", Ideal::Low, true, 0),
    meta("farm_command_timeouts", "Command Timeouts", Ideal::Low, false, 0),
    // Page 4: Environment Statistics
    meta("farm_current_temperature", "Temperature (FARM)", Ideal::Low, false, 0),
    meta("farm_highest_temperature", "Highest Temperature", Ideal::Low, false, 0),
    meta("farm_lowest_temperature", "Lowest Temperature", Ideal::Unspecified, false, 0),
];

/// Metadata of a FARM attribute id, if Scrutiny knows it.
pub fn farm_metadata(id: &str) -> Option<&'static DeviceStatisticMetadata> {
    FARM_METADATA.iter().find(|m| m.id == id)
}

/// `buildFarmAttributeValues`: the attributes of the pages present in the log, by id.
/// An absent page contributes nothing.
pub fn farm_attribute_values(log: &SeagateFarmLog) -> Vec<(&'static str, i64)> {
    let mut values = Vec::new();
    if let Some(drive) = &log.page_1_drive_information {
        values.extend([
            ("farm_poh", drive.poh),
            ("farm_spoh", drive.spoh),
            ("farm_head_flight_hours", drive.head_flight_hours),
            ("farm_head_load_events", drive.head_load_events),
            ("farm_power_cycle_count", drive.power_cycle_count),
        ]);
    }
    if let Some(workload) = &log.page_2_workload_statistics {
        values.extend([
            ("farm_total_read_commands", workload.total_read_commands),
            ("farm_total_write_commands", workload.total_write_commands),
            ("farm_logical_sectors_written", workload.logical_sectors_written),
            ("farm_logical_sectors_read", workload.logical_sectors_read),
        ]);
    }
    if let Some(errors) = &log.page_3_error_statistics {
        values.extend([
            ("farm_unrecoverable_read_errors", errors.number_of_unrecoverable_read_errors),
            ("farm_unrecoverable_write_errors", errors.number_of_unrecoverable_write_errors),
            ("farm_reallocated_sectors", errors.number_of_reallocated_sectors),
            ("farm_reallocation_candidates", errors.number_of_reallocated_candidate_sectors),
            ("farm_crc_errors", errors.total_crc_errors),
            ("farm_command_timeouts", errors.command_time_out_count_total),
        ]);
    }
    if let Some(environment) = &log.page_4_environment_statistics {
        values.extend([
            ("farm_current_temperature", environment.curent_temp),
            ("farm_highest_temperature", environment.highest_temp),
            ("farm_lowest_temperature", environment.lowest_temp),
        ]);
    }
    values
}

/// Evaluate the FARM log. Returns false when it yields no attribute (no log, not
/// `supported`, or none of the evaluated pages).
pub(super) fn evaluate(dev: &SmartctlOutput, findings: &mut Vec<Finding>) -> bool {
    let Some(log) = dev.seagate_farm_log.as_ref().filter(|log| log.supported) else {
        return false;
    };
    let values = farm_attribute_values(log);
    for &(id, value) in &values {
        let Some(metadata) = farm_metadata(id) else {
            continue;
        };
        let status = statistic_status(Some(metadata), value);
        findings.extend(statistic_finding(Source::Farm, metadata, value, status));
    }
    !values.is_empty()
}

#[cfg(test)]
mod tests {
    //! Expected results from `TestFromCollectorSmartInfo_ATA_Farm` and
    //! `TestFromCollectorSmartInfo_ATA_Farm_NilSkipped` in the fork's
    //! `models/measurements/smart_test.go`; the status rules are those of
    //! `smart_ata_devstat_attribute_test.go` (same code in the fork).

    use serde_json::{Value, json};

    use super::*;
    use crate::rules::devstat_thresholds::MAX_REASONABLE_FAILURE_COUNT;
    use crate::rules::{AttrStatus, Evaluation, Policy, Status, evaluate_with};

    const PASSED: AttrStatus = AttrStatus::PASSED;
    const WARNING: AttrStatus = AttrStatus::WARNING_SCRUTINY;
    const INVALID: AttrStatus = AttrStatus::INVALID_VALUE;

    fn status(id: &str, value: i64) -> AttrStatus {
        statistic_status(farm_metadata(id), value)
    }

    /// The log of `TestFromCollectorSmartInfo_ATA_Farm`.
    fn healthy_log() -> Value {
        json!({
            "supported": true,
            "page_1_drive_information": {
                "poh": 2344, "spoh": 2322, "head_flight_hours": 516,
                "head_load_events": 4333, "power_cycle_count": 19
            },
            "page_2_workload_statistics": {
                "total_read_commands": 72695, "total_write_commands": 172682850,
                "logical_sectors_written": 115597072064_i64, "logical_sectors_read": 34761656
            },
            "page_3_error_statistics": {
                "number_of_unrecoverable_read_errors": 0,
                "number_of_unrecoverable_write_errors": 0,
                "number_of_reallocated_sectors": 0,
                "number_of_reallocated_candidate_sectors": 0,
                "total_crc_errors": 0,
                "command_time_out_count_total": 1
            },
            "page_4_environment_statistics": {"curent_temp": 35, "highest_temp": 43, "lowest_temp": 28}
        })
    }

    fn device(log: Value) -> SmartctlOutput {
        serde_json::from_value(json!({
            "device": {"protocol": "ATA"},
            "smart_status": {"passed": true},
            "seagate_farm_log": log
        }))
        .unwrap()
    }

    fn summary(evaluation: &Evaluation) -> Vec<(&str, Source, Status)> {
        evaluation
            .findings
            .iter()
            .map(|f| (f.attribute.as_str(), f.source, f.status))
            .collect()
    }

    #[test]
    fn table_matches_the_fork() {
        assert_eq!(FARM_METADATA.len(), 18);
        assert!(FARM_METADATA.iter().all(|m| m.id.starts_with("farm_")));
        assert!(FARM_METADATA.iter().all(|m| m.threshold == 0 && m.ideal != Ideal::High));
        let critical: Vec<_> = FARM_METADATA.iter().filter(|m| m.critical).map(|m| m.id).collect();
        assert_eq!(
            critical,
            [
                "farm_unrecoverable_read_errors",
                "farm_unrecoverable_write_errors",
                "farm_reallocated_sectors",
                "farm_reallocation_candidates",
                "farm_crc_errors"
            ]
        );
    }

    /// `TestFromCollectorSmartInfo_ATA_Farm`: 18 attributes, expected values, device passed.
    #[test]
    fn healthy_log_yields_the_18_attributes_and_no_finding() {
        let dev = device(healthy_log());
        let values = farm_attribute_values(dev.seagate_farm_log.as_ref().unwrap());
        let ids: Vec<_> = values.iter().map(|(id, _)| *id).collect();
        let expected: Vec<_> = FARM_METADATA.iter().map(|m| m.id).collect();
        assert_eq!(ids, expected);
        let value = |id: &str| values.iter().find(|(i, _)| *i == id).unwrap().1;
        assert_eq!(value("farm_poh"), 2344);
        assert_eq!(value("farm_current_temperature"), 35);
        assert_eq!(value("farm_reallocated_sectors"), 0);
        assert_eq!(value("farm_logical_sectors_written"), 115597072064);
        assert_eq!(value("farm_reallocation_candidates"), 0);
        assert_eq!(value("farm_command_timeouts"), 1);

        let evaluation = evaluate_with(&dev, Policy::Scrutiny);
        assert_eq!(evaluation.status, Status::Pass);
        assert!(evaluation.findings.is_empty());
    }

    /// `TestFromCollectorSmartInfo_ATA_Farm_NilSkipped`, and the `Supported` gate of
    /// `FromCollectorSmartInfoWithOverrides`.
    #[test]
    fn absent_or_unsupported_log_is_skipped() {
        let mut failing = healthy_log();
        failing["page_3_error_statistics"]["number_of_reallocated_sectors"] = json!(8);
        let mut unsupported = failing.clone();
        unsupported["supported"] = json!(false);
        let mut supported_null = failing.clone();
        supported_null["supported"] = json!(null);
        let mut supported_missing = failing.clone();
        supported_missing.as_object_mut().unwrap().remove("supported");
        for log in [json!(null), json!({}), unsupported, supported_null, supported_missing] {
            let mut findings = Vec::new();
            assert!(!evaluate(&device(log), &mut findings));
            assert!(findings.is_empty());
        }
        let mut findings = Vec::new();
        assert!(evaluate(&device(failing), &mut findings));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn critical_error_counts_warn_when_non_zero() {
        for id in [
            "farm_unrecoverable_read_errors",
            "farm_unrecoverable_write_errors",
            "farm_reallocated_sectors",
            "farm_reallocation_candidates",
            "farm_crc_errors",
        ] {
            assert_eq!(status(id, 0), PASSED, "{id}");
            assert_eq!(status(id, -1), PASSED, "{id}");
            assert_eq!(status(id, 1), WARNING, "{id}");
            assert_eq!(status(id, MAX_REASONABLE_FAILURE_COUNT), WARNING, "{id}");
            assert_eq!(status(id, MAX_REASONABLE_FAILURE_COUNT + 1), INVALID, "{id}");
        }
        // lower is better but not critical: recorded, only the sanity check applies
        for id in [
            "farm_head_load_events",
            "farm_command_timeouts",
            "farm_current_temperature",
            "farm_highest_temperature",
        ] {
            assert_eq!(status(id, 4333), PASSED, "{id}");
            assert_eq!(status(id, MAX_REASONABLE_FAILURE_COUNT + 1), INVALID, "{id}");
        }
        // no direction: never judged
        for id in ["farm_poh", "farm_logical_sectors_written", "farm_lowest_temperature"] {
            assert_eq!(status(id, i64::MAX), PASSED, "{id}");
        }
        assert_eq!(status("farm_unknown", 5), PASSED);
    }

    #[test]
    fn warnings_do_not_fail_the_device_in_scrutiny_mode() {
        let mut log = healthy_log();
        log["page_3_error_statistics"]["number_of_reallocated_sectors"] = json!(8);
        log["page_3_error_statistics"]["total_crc_errors"] = json!(2);
        log["page_1_drive_information"]["head_load_events"] = json!(1_000_001);
        let dev = device(log);

        let evaluation = evaluate_with(&dev, Policy::Scrutiny);
        assert_eq!(evaluation.status, Status::Pass);
        assert_eq!(
            summary(&evaluation),
            [
                ("farm_reallocated_sectors", Source::Farm, Status::Warning),
                ("farm_crc_errors", Source::Farm, Status::Warning),
                ("farm_head_load_events", Source::Farm, Status::Unknown),
            ]
        );
        assert_eq!(evaluation.findings[0].name, "Reallocated Sectors (FARM)");
        assert_eq!(evaluation.findings[0].raw_value, Some(8));

        let evaluation = evaluate_with(&dev, Policy::Strict);
        assert_eq!(evaluation.status, Status::Warning);
        assert_eq!(evaluation.findings.len(), 3);
    }

    #[test]
    fn an_invalid_value_alone_never_changes_the_verdict() {
        let mut log = healthy_log();
        log["page_4_environment_statistics"]["highest_temp"] = json!(9_999_999);
        let dev = device(log);
        for policy in [Policy::Scrutiny, Policy::Strict] {
            let evaluation = evaluate_with(&dev, policy);
            assert_eq!(evaluation.status, Status::Pass);
            assert_eq!(summary(&evaluation), [("farm_highest_temperature", Source::Farm, Status::Unknown)]);
        }
    }

    #[test]
    fn absent_pages_contribute_nothing_and_absent_counters_read_as_zero() {
        // an empty page object is a present page: all its counters are 0
        let dev = device(json!({"supported": true, "page_3_error_statistics": {}}));
        let values = farm_attribute_values(dev.seagate_farm_log.as_ref().unwrap());
        assert_eq!(values.len(), 6);
        assert!(values.iter().all(|&(_, value)| value == 0));

        // a null page is an absent page; null counters are 0
        let dev = device(json!({
            "supported": true,
            "page_1_drive_information": null,
            "page_3_error_statistics": {"number_of_reallocated_sectors": null, "total_crc_errors": 3}
        }));
        let mut findings = Vec::new();
        assert!(evaluate(&dev, &mut findings));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attribute, "farm_crc_errors");

        // supported, but none of the evaluated pages
        let dev = device(json!({"supported": true, "page_5_reliability_statistics": {"error_rate_worst": 1}}));
        let mut findings = Vec::new();
        assert!(!evaluate(&dev, &mut findings));
    }

    #[test]
    fn only_ata_devices_have_a_farm_log() {
        let mut log = healthy_log();
        log["page_3_error_statistics"]["total_crc_errors"] = json!(2);
        let mut dev = device(log);
        dev.device.as_mut().unwrap().protocol = Some("SCSI".to_string());
        let evaluation = evaluate_with(&dev, Policy::Scrutiny);
        assert!(evaluation.findings.iter().all(|f| f.source != Source::Farm));
    }

    /// `models/testdata/smart-ata-farm.json` (a real `smartctl -l farm` output).
    #[test]
    fn real_farm_fixture_is_read() {
        let text = include_str!("../../tests/fixtures/smart-ata-farm.json");
        let dev: SmartctlOutput = serde_json::from_str(text).unwrap();
        let log = dev.seagate_farm_log.as_ref().unwrap();
        assert!(log.supported);
        assert_eq!(farm_attribute_values(log).len(), 18);
        let mut findings = Vec::new();
        assert!(evaluate(&dev, &mut findings));
        assert!(findings.is_empty());
    }
}
