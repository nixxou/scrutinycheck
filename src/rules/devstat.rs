//! ATA Device Statistics evaluation (GP log 0x04, `ata_device_statistics`).
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `webapp/backend/pkg/models/measurements/smart_ata_devstat_attribute.go` and
//! `processAtaDeviceStatisticsWithOverrides` / `isDevstatIgnored` in
//! `webapp/backend/pkg/models/measurements/smart.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! Every statistic whose `flags.valid` is true becomes the attribute
//! `devstat_<page number>_<offset>`. Its raw value is judged as is (no transform), in this
//! order ([`statistic_status`], shared with the Seagate FARM layer):
//!
//! 1. no metadata for the id: recorded, never judged;
//! 2. an `Ideal::Low` statistic above [`MAX_REASONABLE_FAILURE_COUNT`] is corrupted data:
//!    `InvalidValue`, nothing else;
//! 3. with a fixed threshold (only `devstat_7_8`, percentage used, 100): `FailedScrutiny`
//!    when the value has reached it;
//! 4. without one, a critical `Ideal::Low` statistic above 0 is a `WarningScrutiny`.
//!
//! A statistic therefore carries at most one status bit. `FailedScrutiny` fails the device
//! unless the id is in the `failures.ignored.devstat` list (empty by default).
//!
//! The fork also falls back on a drive-reported threshold when the metadata has none; it
//! never fills that field from smartctl output, so the fallback is not ported.

use std::collections::HashMap;

use super::devstat_thresholds::{
    DeviceStatisticMetadata, MAX_REASONABLE_FAILURE_COUNT, devstat_metadata, is_devstat_ignored,
};
use super::{AttrStatus, Finding, Ideal, Source, Status};
use crate::model::SmartctlOutput;

/// The fork's attribute id of a statistic: `fmt.Sprintf("devstat_%d_%d", page, offset)`.
pub fn statistic_id(page_number: i64, offset: i64) -> String {
    format!("devstat_{page_number}_{offset}")
}

/// `PopulateAttributeStatus` of the fork's `SmartAtaDeviceStatAttribute` and
/// `SmartFarmAttribute` (the two are the same code over different metadata maps).
pub fn statistic_status(metadata: Option<&DeviceStatisticMetadata>, value: i64) -> AttrStatus {
    let mut status = AttrStatus::PASSED;
    let Some(metadata) = metadata else {
        return status;
    };

    // Some drives report corrupted or encoded values that must not be read literally.
    if metadata.ideal == Ideal::Low && value > MAX_REASONABLE_FAILURE_COUNT {
        status.set(AttrStatus::INVALID_VALUE);
        return status;
    }

    if metadata.threshold > 0 {
        let failing = match metadata.ideal {
            Ideal::Low => value >= metadata.threshold,
            Ideal::High => value <= metadata.threshold,
            Ideal::Unspecified => false,
        };
        if failing {
            status.set(AttrStatus::FAILED_SCRUTINY);
        }
    } else if metadata.critical && metadata.ideal == Ideal::Low && value > 0 {
        status.set(AttrStatus::WARNING_SCRUTINY);
    }
    status
}

/// Status of the statistic at `offset` of page `page_number`.
pub fn evaluate_statistic(page_number: i64, offset: i64, value: i64) -> AttrStatus {
    statistic_status(devstat_metadata(&statistic_id(page_number, offset)), value)
}

/// The finding for a judged statistic, `None` when it passed. Only a statistic with
/// metadata can carry a status, hence the non-optional `metadata`.
pub(super) fn statistic_finding(
    source: Source,
    metadata: &DeviceStatisticMetadata,
    value: i64,
    status: AttrStatus,
) -> Option<Finding> {
    let message = if status.has(AttrStatus::INVALID_VALUE) {
        format!("implausible value (above {MAX_REASONABLE_FAILURE_COUNT}), likely corrupted data: not judged")
    } else if status.has(AttrStatus::FAILED_SCRUTINY) {
        match metadata.ideal {
            Ideal::High => format!("value at or below the threshold {}", metadata.threshold),
            Ideal::Low | Ideal::Unspecified => format!("value has reached the threshold {}", metadata.threshold),
        }
    } else if status.has(AttrStatus::WARNING_SCRUTINY) {
        "non-zero error count on a critical statistic".to_string()
    } else {
        return None;
    };
    Some(Finding {
        source,
        attribute: metadata.id.to_string(),
        name: metadata.display_name.to_string(),
        raw_value: Some(value),
        status: status.to_status(),
        message,
        annual_failure_rate: None,
    })
}

/// True for the finding of an `InvalidValue` statistic: it is shown, but like in the fork it
/// never takes part in a device verdict.
pub(super) fn is_invalid_value_finding(finding: &Finding) -> bool {
    finding.status == Status::Unknown && matches!(finding.source, Source::Devstat | Source::Farm)
}

/// Evaluate the device statistics pages. Returns `(usable, overwritten_failure)`: whether
/// at least one valid statistic was read, and (in `exact` mode) whether a `FailedScrutiny`
/// was raised by an occurrence that a later one replaced.
///
/// The fork stores attributes in a map keyed by id. When a page number / offset pair comes
/// twice, in `exact` (Scrutiny) mode the last occurrence is the one reported, but a failure
/// of an earlier occurrence has already failed the device, as for ATA attributes (see
/// `ata::evaluate`). Otherwise every occurrence is reported.
pub(super) fn evaluate(dev: &SmartctlOutput, findings: &mut Vec<Finding>, exact: bool) -> (bool, bool) {
    let Some(statistics) = &dev.ata_device_statistics else {
        return (false, false);
    };
    let mut usable = false;
    let mut overwritten_failure = false;
    // exact mode: id -> slot in `reported`, in order of first occurrence
    let mut slots: HashMap<String, usize> = HashMap::new();
    let mut reported: Vec<Option<Finding>> = Vec::new();

    for page in &statistics.pages {
        for statistic in &page.table {
            if !statistic.flags.valid {
                continue;
            }
            usable = true;
            let id = statistic_id(page.number, statistic.offset);
            let metadata = devstat_metadata(&id);
            let status = statistic_status(metadata, statistic.value);
            let finding = metadata.and_then(|m| statistic_finding(Source::Devstat, m, statistic.value, status));
            if !exact {
                findings.extend(finding);
                continue;
            }
            match slots.get(&id) {
                Some(&slot) => {
                    let replaced = std::mem::replace(&mut reported[slot], finding);
                    overwritten_failure |=
                        replaced.is_some_and(|f| f.status == Status::Fail) && !is_devstat_ignored(&id);
                }
                None => {
                    slots.insert(id, reported.len());
                    reported.push(finding);
                }
            }
        }
    }
    findings.extend(reported.into_iter().flatten());
    (usable, overwritten_failure)
}

#[cfg(test)]
mod tests {
    //! Expected results from the fork's
    //! `models/measurements/smart_ata_devstat_attribute_test.go` and the
    //! `TestFromCollectorSmartInfo_ATA_DeviceStatistics*` tests of
    //! `models/measurements/smart_test.go`.

    use serde_json::json;

    use super::*;
    use crate::rules::{Evaluation, Policy, evaluate_with};

    const PASSED: AttrStatus = AttrStatus::PASSED;
    const WARNING: AttrStatus = AttrStatus::WARNING_SCRUTINY;
    const FAILED: AttrStatus = AttrStatus::FAILED_SCRUTINY;
    const INVALID: AttrStatus = AttrStatus::INVALID_VALUE;

    fn status(id: &str, value: i64) -> AttrStatus {
        statistic_status(devstat_metadata(id), value)
    }

    /// An ATA device, SMART passed, with the given `(page, offset, value, valid)` statistics.
    fn device(statistics: &[(i64, i64, i64, bool)]) -> SmartctlOutput {
        let pages: Vec<_> = statistics
            .iter()
            .map(|&(page, offset, value, valid)| {
                json!({"number": page, "table": [
                    {"offset": offset, "value": value, "flags": {"valid": valid}}
                ]})
            })
            .collect();
        serde_json::from_value(json!({
            "device": {"protocol": "ATA"},
            "smart_status": {"passed": true},
            "ata_device_statistics": {"pages": pages}
        }))
        .unwrap()
    }

    fn scrutiny(statistics: &[(i64, i64, i64, bool)]) -> Evaluation {
        evaluate_with(&device(statistics), Policy::Scrutiny)
    }

    fn strict(statistics: &[(i64, i64, i64, bool)]) -> Evaluation {
        evaluate_with(&device(statistics), Policy::Strict)
    }

    fn summary(evaluation: &Evaluation) -> Vec<(&str, Source, Status)> {
        evaluation
            .findings
            .iter()
            .map(|f| (f.attribute.as_str(), f.source, f.status))
            .collect()
    }

    #[test]
    fn id_is_page_then_offset() {
        assert_eq!(statistic_id(7, 8), "devstat_7_8");
        assert_eq!(statistic_id(255, 24), "devstat_255_24");
        // Go's %d on whatever the document holds
        assert_eq!(statistic_id(0, 0), "devstat_0_0");
        assert_eq!(statistic_id(-1, -8), "devstat_-1_-8");
    }

    /// `TestSmartAtaDeviceStatAttribute_PopulateAttributeStatus_BelowThreshold`,
    /// `_AtThreshold`, `_AboveThreshold`, `_MetadataThreshold` and `_Discussion239`.
    #[test]
    fn percentage_used_fails_from_100() {
        assert_eq!(status("devstat_7_8", 19), PASSED);
        assert_eq!(status("devstat_7_8", 99), PASSED);
        assert_eq!(status("devstat_7_8", 100), FAILED);
        assert_eq!(status("devstat_7_8", 118), FAILED);
        assert_eq!(status("devstat_7_8", 150), FAILED);
        // a threshold replaces the non-zero warning of critical statistics
        assert_eq!(status("devstat_7_8", 1), PASSED);
        assert_eq!(status("devstat_7_8", 0), PASSED);
        assert_eq!(status("devstat_7_8", -1), PASSED);
        assert_eq!(evaluate_statistic(7, 8, 100), FAILED);
    }

    /// `TestSmartAtaDeviceStatAttribute_PopulateAttributeStatus_UnknownAttribute`.
    #[test]
    fn unknown_statistic_is_never_judged() {
        assert_eq!(status("devstat_99_99", 42), PASSED);
        assert_eq!(status("devstat_99_99", i64::MAX), PASSED);
        assert_eq!(evaluate_statistic(99, 99, i64::MAX), PASSED);
    }

    /// `..._InvalidValue_TooHigh`, `_InvalidValue_AtBoundary`, `_ValidHighValue` and
    /// `_InvalidValue_NonCritical`.
    #[test]
    fn implausible_values_are_invalid_not_failed() {
        assert_eq!(status("devstat_7_8", 420_000_000_000), INVALID);
        assert_eq!(status("devstat_7_8", MAX_REASONABLE_FAILURE_COUNT + 1), INVALID);
        // exactly at the limit: still judged, and failing its threshold
        assert_eq!(status("devstat_7_8", MAX_REASONABLE_FAILURE_COUNT), FAILED);
        // non-critical statistics too, as long as lower is better
        assert_eq!(status("devstat_5_88", 999_999_999_999), INVALID);
        assert_eq!(status("devstat_5_88", MAX_REASONABLE_FAILURE_COUNT), PASSED);
        assert_eq!(status("devstat_4_8", MAX_REASONABLE_FAILURE_COUNT), WARNING);
        assert_eq!(status("devstat_4_8", MAX_REASONABLE_FAILURE_COUNT + 1), INVALID);
        // no direction: any value goes (logical sectors read is routinely in the billions)
        assert_eq!(status("devstat_1_40", 999_999_999_999), PASSED);
        assert_eq!(INVALID.bits(), 8);
    }

    /// `..._ErrorCount_NonZero` (discussion #215), `_ErrorCount_Zero`,
    /// `_ReallocatedSectors_NonZero` and `_MechanicalFailures_Zero`.
    #[test]
    fn critical_error_counts_warn_when_non_zero() {
        assert_eq!(status("devstat_4_8", 452), WARNING);
        assert_eq!(status("devstat_4_8", 0), PASSED);
        assert_eq!(status("devstat_3_32", 5), WARNING);
        assert_eq!(status("devstat_3_48", 0), PASSED);
        assert_eq!(status("devstat_3_48", 1), WARNING);
        assert_eq!(status("devstat_3_56", 1), WARNING);
        assert_eq!(status("devstat_4_24", 1), WARNING);
        assert_eq!(status("devstat_4_24", -1), PASSED);
        // non-critical counters are recorded only
        assert_eq!(status("devstat_4_16", 452), PASSED);
        assert_eq!(status("devstat_6_24", 452), PASSED);
        assert_eq!(status("devstat_3_64", 452), PASSED);
    }

    #[test]
    fn every_statistic_carries_at_most_one_bit() {
        use crate::rules::devstat_thresholds::ATA_DEVICE_STATS_METADATA;
        for metadata in ATA_DEVICE_STATS_METADATA {
            for value in [i64::MIN, -1, 0, 1, 99, 100, 101, 1_000_000, 1_000_001, i64::MAX] {
                let bits = statistic_status(Some(metadata), value).bits();
                assert!(bits.count_ones() <= 1, "{} at {value}: {bits}", metadata.id);
                if metadata.ideal == Ideal::Unspecified {
                    assert_eq!(bits, 0, "{} at {value}", metadata.id);
                }
            }
        }
    }

    #[test]
    fn a_high_ideal_threshold_fails_at_or_below_it() {
        // no bundled statistic is "higher is better"; the fork's branch is ported all the same
        let metadata = DeviceStatisticMetadata {
            id: "devstat_0_0",
            display_name: "test",
            ideal: Ideal::High,
            critical: true,
            threshold: 10,
        };
        assert_eq!(statistic_status(Some(&metadata), 11), PASSED);
        assert_eq!(statistic_status(Some(&metadata), 10), FAILED);
        assert_eq!(statistic_status(Some(&metadata), 2_000_000), PASSED);
        let no_threshold = DeviceStatisticMetadata { threshold: 0, ..metadata };
        assert_eq!(statistic_status(Some(&no_threshold), 0), PASSED);
    }

    /// `TestFromCollectorSmartInfo_ATA_DeviceStatistics_StatusPropagation`.
    #[test]
    fn a_failed_statistic_fails_the_device() {
        for evaluation in [scrutiny(&[(7, 8, 100, true)]), strict(&[(7, 8, 100, true)])] {
            assert_eq!(evaluation.status, Status::Fail);
            assert_eq!(summary(&evaluation), [("devstat_7_8", Source::Devstat, Status::Fail)]);
            let finding = &evaluation.findings[0];
            assert_eq!(finding.name, "Percentage Used Endurance Indicator");
            assert_eq!(finding.raw_value, Some(100));
            assert!(finding.message.contains("threshold 100"), "{}", finding.message);
        }
    }

    /// `TestFromCollectorSmartInfo_ATA_DeviceStatistics_InvalidValue` (issue #84).
    #[test]
    fn an_invalid_statistic_is_reported_but_does_not_fail_the_device() {
        for evaluation in [
            scrutiny(&[(7, 8, 420_000_000_000, true)]),
            strict(&[(7, 8, 420_000_000_000, true)]),
        ] {
            assert_eq!(evaluation.status, Status::Pass);
            assert_eq!(summary(&evaluation), [("devstat_7_8", Source::Devstat, Status::Unknown)]);
            assert!(evaluation.findings[0].message.contains("corrupted"));
        }
    }

    #[test]
    fn a_warning_statistic_keeps_the_device_passed_in_scrutiny_mode() {
        let statistics = [(4, 8, 452, true)];
        let evaluation = scrutiny(&statistics);
        assert_eq!(evaluation.status, Status::Pass);
        assert_eq!(summary(&evaluation), [("devstat_4_8", Source::Devstat, Status::Warning)]);
        // strict: the verdict is the worst finding
        assert_eq!(strict(&statistics).status, Status::Warning);
    }

    #[test]
    fn statistics_flagged_invalid_by_the_drive_are_skipped() {
        let evaluation = scrutiny(&[(7, 8, 100, false), (4, 8, 3, false)]);
        assert_eq!(evaluation.status, Status::Pass);
        assert!(evaluation.findings.is_empty());
    }

    /// `TestFromCollectorSmartInfo_ATA_DeviceStatistics`: `models/testdata/smart-ata-full.json`
    /// reports 19 % used and no error count.
    #[test]
    fn healthy_ssd_fixture_has_no_statistic_finding() {
        let text = include_str!("../../tests/fixtures/smart-ata-full.json");
        let dev: SmartctlOutput = serde_json::from_str(text).unwrap();
        let statistics = dev.ata_device_statistics.as_ref().unwrap();
        let percentage_used = statistics
            .pages
            .iter()
            .filter(|page| page.number == 7)
            .flat_map(|page| &page.table)
            .find(|statistic| statistic.offset == 8)
            .unwrap();
        assert!(percentage_used.flags.valid);
        assert_eq!(percentage_used.value, 19);
        let mut findings = Vec::new();
        assert_eq!(evaluate(&dev, &mut findings, true), (true, false));
        assert!(findings.is_empty());
    }

    #[test]
    fn only_ata_devices_have_device_statistics() {
        // the fork processes the section under the ATA protocol only
        for protocol in ["SCSI", "NVMe", "ata"] {
            let mut dev = device(&[(7, 8, 100, true)]);
            dev.device.as_mut().unwrap().protocol = Some(protocol.to_string());
            let evaluation = evaluate_with(&dev, Policy::Scrutiny);
            assert!(evaluation.findings.iter().all(|f| f.source != Source::Devstat), "{protocol}");
        }
    }

    #[test]
    fn duplicated_statistic_last_occurrence_wins_but_a_failure_sticks() {
        // failing occurrence replaced by a passing one: nothing reported, device failed
        let statistics = [(7, 8, 100, true), (7, 8, 19, true)];
        let evaluation = scrutiny(&statistics);
        assert_eq!(evaluation.status, Status::Fail);
        assert!(evaluation.findings.is_empty());
        // strict reports every occurrence
        let evaluation = strict(&statistics);
        assert_eq!(evaluation.status, Status::Fail);
        assert_eq!(summary(&evaluation), [("devstat_7_8", Source::Devstat, Status::Fail)]);

        // the other way round: the last occurrence is reported
        let evaluation = scrutiny(&[(7, 8, 19, true), (7, 8, 100, true)]);
        assert_eq!(evaluation.status, Status::Fail);
        assert_eq!(summary(&evaluation), [("devstat_7_8", Source::Devstat, Status::Fail)]);

        // an overwritten warning or invalid value leaves no trace
        let evaluation = scrutiny(&[(4, 8, 3, true), (7, 8, 2_000_000, true), (4, 8, 0, true), (7, 8, 1, true)]);
        assert_eq!(evaluation.status, Status::Pass);
        assert!(evaluation.findings.is_empty());

        // an occurrence the drive flags invalid does not replace anything
        let evaluation = scrutiny(&[(4, 8, 3, true), (4, 8, 0, false)]);
        assert_eq!(summary(&evaluation), [("devstat_4_8", Source::Devstat, Status::Warning)]);
    }

    #[test]
    fn null_and_missing_fields_read_as_go_zero_values() {
        let dev: SmartctlOutput = serde_json::from_value(json!({
            "device": {"protocol": "ATA"},
            "smart_status": {"passed": true},
            "ata_device_statistics": {"pages": [
                null,
                {"number": null, "table": null},
                {"table": [null, {"flags": null}, {"flags": {"valid": null}}, {"value": 5, "flags": {"valid": true}}]},
                {"number": 4, "table": [{"offset": 8, "value": null, "flags": {"valid": true}}]},
                {"number": 4, "table": [{"offset": 24, "value": 2, "flags": {"valid": true}}]}
            ]}
        }))
        .unwrap();
        let statistics = dev.ata_device_statistics.as_ref().unwrap();
        assert_eq!(statistics.pages.len(), 5);
        assert_eq!(statistics.pages[2].number, 0);
        assert_eq!(statistics.pages[2].table.len(), 4);
        let evaluation = evaluate_with(&dev, Policy::Scrutiny);
        assert_eq!(summary(&evaluation), [("devstat_4_24", Source::Devstat, Status::Warning)]);

        for section in [json!(null), json!({}), json!({"pages": null}), json!({"pages": []})] {
            let dev: SmartctlOutput = serde_json::from_value(json!({
                "device": {"protocol": "ATA"},
                "smart_status": {"passed": true},
                "ata_device_statistics": section
            }))
            .unwrap();
            let mut findings = Vec::new();
            assert_eq!(evaluate(&dev, &mut findings, true), (false, false));
        }
    }
}
