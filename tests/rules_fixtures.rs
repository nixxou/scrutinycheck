//! Verdicts of the rule engine on real smartctl outputs.
//!
//! The fixtures are the test data of Scrutiny (Starosdev fork). Where the fork has a Go test
//! that loads the same file, the expected result here is the one that test asserts; the test
//! is named in the `oracle` of each case. The Go tests live in
//! `webapp/backend/pkg/models/measurements/smart_test.go` unless another file is given.
//!
//! How a Go expectation reads on this crate's scale (see the `rules` module documentation):
//! `DeviceStatusPassed` is `Pass`, `DeviceStatusFailedSmart` and `DeviceStatusFailedScrutiny`
//! are `Fail`.
//!
//! Cases marked "characterization" have no status assertion in the fork: the expectation
//! records what the ported rules give, so that a change of verdict is noticed.

use std::path::{Path, PathBuf};

use scrutinycheck::model::{AtaAttribute, SmartctlOutput};
use scrutinycheck::rules::ata::{self, AtaAttributeStatus};
use scrutinycheck::rules::{
    AttrStatus, Evaluation, Source, Status, evaluate, is_cumulative_counter,
};

struct Case {
    file: &'static str,
    status: Status,
    /// `(attribute, source, status)` of every finding, in order.
    findings: &'static [(&'static str, Source, Status)],
    oracle: &'static str,
}

const CASES: &[Case] = &[
    Case {
        file: "smart-ata.json",
        status: Status::Pass,
        findings: &[],
        oracle: "TestFromCollectorSmartInfo: DeviceStatusPassed",
    },
    Case {
        file: "smart-fail2.json",
        status: Status::Fail,
        findings: &[
            ("smart_status", Source::SmartOverall, Status::Fail),
            ("5", Source::Manufacturer, Status::Fail),
            ("196", Source::Backblaze, Status::Fail),
            ("197", Source::Backblaze, Status::Fail),
        ],
        oracle: "TestFromCollectorSmartInfo_Fail_ScrutinySmart: DeviceStatusFailedScrutiny|DeviceStatusFailedSmart",
    },
    Case {
        file: "smart-ata-failed-scrutiny.json",
        status: Status::Fail,
        findings: &[("199", Source::Backblaze, Status::Fail)],
        oracle: "TestFromCollectorSmartInfo_Fail_ScrutinyNonCriticalFailed: DeviceStatusFailedScrutiny, \
                 attribute 199 AttributeStatusFailedScrutiny",
    },
    Case {
        file: "smart-ata-issue587-realssd-m4.json",
        status: Status::Pass,
        findings: &[],
        oracle: "TestFromCollectorSmartInfo_ATA_Issue587VendorSpecificSsdAttribute: DeviceStatusPassed",
    },
    Case {
        file: "smart-nvme.json",
        status: Status::Pass,
        findings: &[],
        oracle: "TestFromCollectorSmartInfo_Nvme: DeviceStatusPassed",
    },
    Case {
        file: "smart-nvme2.json",
        status: Status::Pass,
        findings: &[],
        oracle: "webapp/backend/pkg/web/server_test.go, the smart-nvme2.json upload: DeviceStatusPassed",
    },
    Case {
        file: "smart-nvme-failed.json",
        status: Status::Fail,
        findings: &[("media_errors", Source::Nvme, Status::Fail)],
        oracle: "TestFromCollectorSmartInfo_NVMe_Fail_Scrutiny: DeviceStatusFailedScrutiny, \
                 media_errors AttributeStatusFailedScrutiny",
    },
    Case {
        file: "smart-scsi.json",
        status: Status::Pass,
        findings: &[],
        oracle: "TestFromCollectorSmartInfo_Scsi: DeviceStatusPassed",
    },
    Case {
        file: "smart-scsi-failed.json",
        status: Status::Fail,
        findings: &[
            ("scsi_grown_defect_list", Source::Scsi, Status::Fail),
            ("read_total_uncorrected_errors", Source::Scsi, Status::Fail),
        ],
        oracle: "TestFromCollectorSmartInfo_Scsi_Fail_Scrutiny: DeviceStatusFailedScrutiny, both attributes \
                 AttributeStatusFailedScrutiny",
    },
    // The fork reports this file as DeviceStatusFailedSmart (TestFromCollectorSmartInfo_Fail_Smart)
    // because a missing `smart_status` decodes to `passed == false` in Go. The file is a
    // smartctl "open device failed" error with no SMART data at all, which is Unknown here.
    Case {
        file: "smart-fail.json",
        status: Status::Unknown,
        findings: &[("smart", Source::NoData, Status::Unknown)],
        oracle: "deliberate deviation from TestFromCollectorSmartInfo_Fail_Smart, see above",
    },
    Case {
        file: "smart-ata2.json",
        status: Status::Pass,
        findings: &[],
        oracle: "characterization (healthy Samsung-like SSD)",
    },
    Case {
        file: "smart-ata-full.json",
        status: Status::Pass,
        findings: &[],
        oracle: "characterization; TestFromCollectorSmartInfo_ATA_DeviceStatistics only checks the device \
                 statistics, which are not ported",
    },
    Case {
        file: "smart-megaraid0.json",
        status: Status::Pass,
        findings: &[],
        oracle: "characterization (HDD behind a MegaRAID controller, all counters at 0)",
    },
    Case {
        file: "smart-scsi2.json",
        status: Status::Pass,
        findings: &[],
        oracle: "characterization; server_test.go uploads it but asserts no status",
    },
    Case {
        file: "smart-pass.json",
        status: Status::Pass,
        findings: &[],
        oracle: "characterization (`smartctl -H`: overall status only, passed)",
    },
    // `smartctl -A` output: no `smart_status`, no `rotation_rate`. See
    // `smart_sat_verdict_depends_on_the_missing_rotation_rate` below.
    Case {
        file: "smart-sat.json",
        status: Status::Pass,
        findings: &[],
        oracle: "characterization",
    },
    Case {
        file: "smart-ata-farm.json",
        status: Status::Unknown,
        findings: &[("smart", Source::NoData, Status::Unknown)],
        oracle: "characterization (`smartctl -l farm`: only the Seagate FARM log, which is not ported)",
    },
    Case {
        file: "scan-simple.json",
        status: Status::Unknown,
        findings: &[("smart", Source::NoData, Status::Unknown)],
        oracle: "characterization (`smartctl --scan` listing, not a device report)",
    },
];

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load(file: &str) -> SmartctlOutput {
    let path = fixtures_dir().join(file);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("{file}: {e}"))
}

fn summary(evaluation: &Evaluation) -> Vec<(&str, Source, Status)> {
    evaluation
        .findings
        .iter()
        .map(|f| (f.attribute.as_str(), f.source, f.status))
        .collect()
}

/// The attribute row of an ATA fixture and its evaluation, the way `evaluate` runs it.
fn ata_attribute(dev: &SmartctlOutput, id: i64) -> (&AtaAttribute, AtaAttributeStatus) {
    let table = &dev
        .ata_smart_attributes
        .as_ref()
        .expect("an ATA attribute table")
        .table;
    let attr = table
        .iter()
        .find(|a| a.id == id)
        .unwrap_or_else(|| panic!("attribute {id} not in the table"));
    (attr, ata::evaluate_attribute(attr, ata::is_ata_ssd(dev)))
}

fn ata_attribute_count(dev: &SmartctlOutput) -> usize {
    dev.ata_smart_attributes
        .as_ref()
        .map_or(0, |a| a.table.len())
}

#[test]
fn every_fixture_has_the_expected_verdict() {
    for case in CASES {
        let evaluation = evaluate(&load(case.file));
        assert_eq!(
            evaluation.status, case.status,
            "{} ({})",
            case.file, case.oracle
        );
        assert_eq!(
            summary(&evaluation),
            case.findings,
            "{} ({})",
            case.file,
            case.oracle
        );

        // contract: only non-passing findings, worst first, and the verdict is the worst one
        assert!(
            evaluation.findings.iter().all(|f| f.status != Status::Pass),
            "{}",
            case.file
        );
        assert!(
            evaluation
                .findings
                .windows(2)
                .all(|w| w[0].status >= w[1].status),
            "{}",
            case.file
        );
        let worst = evaluation
            .findings
            .iter()
            .map(|f| f.status)
            .max()
            .unwrap_or(Status::Pass);
        assert_eq!(evaluation.status, worst, "{}", case.file);
        assert!(
            evaluation
                .findings
                .iter()
                .all(|f| !f.message.is_empty() && !f.name.is_empty()),
            "{}",
            case.file
        );
    }
}

#[test]
fn every_fixture_is_covered() {
    let mut on_disk: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".json"))
        .collect();
    on_disk.sort();
    let mut covered: Vec<&str> = CASES.iter().map(|c| c.file).collect();
    covered.sort_unstable();
    assert_eq!(
        on_disk, covered,
        "each fixture needs exactly one case in CASES"
    );
}

// Fork: TestFromCollectorSmartInfo
#[test]
fn smart_ata_healthy_hdd() {
    let dev = load("smart-ata.json");
    assert_eq!(ata_attribute_count(&dev), 18);
    assert!(!ata::is_ata_ssd(&dev));

    // temperature and power-on hours are read through their transforms
    let (temperature, evaluated) = ata_attribute(&dev, 194);
    assert_eq!(
        temperature.raw.as_ref().unwrap().value,
        Some(163_210_330_144)
    );
    assert_eq!(evaluated.transformed_value, 32);
    assert_eq!(ata_attribute(&dev, 9).1.transformed_value, 1730);

    // This healthy drive must carry no verdict on its usage counters: 3 (vendor-scaled
    // normalized value, fork #1088), 4 at 9 cycles and 192 at 329 retracts (fork #1094).
    for id in [3, 4, 192] {
        let (_, evaluated) = ata_attribute(&dev, id);
        assert_eq!(evaluated.status, AttrStatus::PASSED, "attribute {id}");
        assert_eq!(evaluated.failure_rate, None, "attribute {id}");
    }
}

// Fork: TestFromCollectorSmartInfo_Fail_ScrutinySmart
#[test]
fn smart_fail2_failing_hdd() {
    let dev = load("smart-fail2.json");
    assert_eq!(ata_attribute_count(&dev), 17);

    let evaluation = evaluate(&dev);
    let by_attribute = |id: &str| {
        evaluation
            .findings
            .iter()
            .find(|f| f.attribute == id)
            .unwrap()
    };

    // the drive's own verdict: reallocated sectors below the manufacturer threshold
    let (_, reallocated) = ata_attribute(&dev, 5);
    assert_eq!(reallocated.status, AttrStatus::FAILED_SMART);
    assert_eq!(by_attribute("5").raw_value, Some(1975));
    assert_eq!(by_attribute("5").annual_failure_rate, None);
    assert_eq!(by_attribute("5").name, "Reallocated Sectors Count");

    // Scrutiny's verdict: two critical attributes above 10 % observed failure rate
    assert_eq!(
        ata_attribute(&dev, 196).1.status,
        AttrStatus::FAILED_SCRUTINY
    );
    assert_eq!(
        ata_attribute(&dev, 197).1.status,
        AttrStatus::FAILED_SCRUTINY
    );
    // 3831 reallocation events is far past the last bucket (27-45): the worst rate is kept
    assert_eq!(
        by_attribute("196").annual_failure_rate,
        Some(0.24701105346266636)
    );
    // 8 pending sectors: worst rate reached so far is the 2-6 bucket's, not the 6-16 one's
    assert_eq!(
        by_attribute("197").annual_failure_rate,
        Some(0.6823772508117681)
    );
    assert!(
        evaluation
            .findings
            .iter()
            .all(|f| !is_cumulative_counter(f))
    );
}

// Fork: TestFromCollectorSmartInfo_Fail_ScrutinyNonCriticalFailed and
// TestFromCollectorSmartInfo_ATA_SsdRuntimeBadBlockStillUsesGenericScoring
#[test]
fn smart_ata_failed_scrutiny_ssd_with_crc_errors() {
    let dev = load("smart-ata-failed-scrutiny.json");
    assert_eq!(ata_attribute_count(&dev), 14);
    assert!(ata::is_ata_ssd(&dev));

    let (_, crc) = ata_attribute(&dev, 199);
    assert_eq!(crc.status, AttrStatus::FAILED_SCRUTINY);

    // "Runtime_Bad_Block" is the attribute the generic buckets describe, so it is scored
    let (_, runtime_bad_block) = ata_attribute(&dev, 183);
    assert_eq!(runtime_bad_block.status, AttrStatus::PASSED);
    assert!(!runtime_bad_block.skipped_vendor_specific_ssd);
    assert!(runtime_bad_block.failure_rate.unwrap() > 0.0);

    // The only finding is the CRC error counter, which the fork evaluates by trend: this is
    // what a first submission looks like, before the fork has a previous value to compare.
    let evaluation = evaluate(&dev);
    assert_eq!(evaluation.findings.len(), 1);
    assert_eq!(evaluation.findings[0].raw_value, Some(108));
    assert_eq!(
        evaluation.findings[0].annual_failure_rate,
        Some(0.22336578581363)
    );
    assert!(is_cumulative_counter(&evaluation.findings[0]));
}

// Fork: TestFromCollectorSmartInfo_ATA_Issue587VendorSpecificSsdAttribute
#[test]
fn smart_ata_issue587_vendor_specific_ssd_attribute() {
    let dev = load("smart-ata-issue587-realssd-m4.json");
    assert!(ata::is_ata_ssd(&dev));

    // Crucial reuses id 189 for "Factory_Bad_Block_Ct" (81 here); the generic buckets are
    // about "High Fly Writes" and would fail it.
    let (factory_bad_blocks, evaluated) = ata_attribute(&dev, 189);
    assert_eq!(factory_bad_blocks.raw.as_ref().unwrap().value, Some(81));
    assert_eq!(evaluated.status, AttrStatus::PASSED);
    assert!(evaluated.skipped_vendor_specific_ssd);
    assert_eq!(evaluated.failure_rate, None);
}

// Fork: TestFromCollectorSmartInfo_ATA_HddHighFlyWritesStillUsesGenericScoring
#[test]
fn smart_sat_hdd_high_fly_writes_use_generic_scoring() {
    let mut dev = load("smart-sat.json");
    dev.rotation_rate = Some(7200);

    let (_, high_fly_writes) = ata_attribute(&dev, 189);
    assert_eq!(high_fly_writes.status, AttrStatus::PASSED);
    assert!(!high_fly_writes.skipped_vendor_specific_ssd);
    assert!(high_fly_writes.failure_rate.unwrap() > 0.0);

    // packed power-on hours, from the fork's TestAttribute9Transform_PackedValue
    assert_eq!(ata_attribute(&dev, 9).1.transformed_value, 2725);
}

// Not asserted by the fork. The file has no `rotation_rate`, which the fork reads as 0 and
// therefore as "SSD": attribute 196, which smartctl names "Reallocated_Event_Count" while the
// fork's table says "Reallocation Event Count", is then skipped as vendor-specific. Once the
// drive is known to spin, the same attribute fails on its packed raw value.
#[test]
fn smart_sat_verdict_depends_on_the_missing_rotation_rate() {
    let mut dev = load("smart-sat.json");
    assert_eq!(dev.rotation_rate, None);
    assert!(ata_attribute(&dev, 196).1.skipped_vendor_specific_ssd);
    assert_eq!(evaluate(&dev).status, Status::Pass);

    dev.rotation_rate = Some(7200);
    let evaluation = evaluate(&dev);
    assert_eq!(evaluation.status, Status::Fail);
    assert_eq!(
        summary(&evaluation),
        [("196", Source::Backblaze, Status::Fail)]
    );
    assert_eq!(evaluation.findings[0].raw_value, Some(53_416_508_262_463));
}

// Fork: TestFromCollectorSmartInfo_NVMe_Fail_Scrutiny
#[test]
fn smart_nvme_failed_media_errors() {
    let evaluation = evaluate(&load("smart-nvme-failed.json"));
    assert_eq!(evaluation.findings[0].name, "Media Errors");
    assert_eq!(evaluation.findings[0].raw_value, Some(7));
}

// Fork: server_test.go. The drive logged 8382 error-log entries, which the fork records
// without judging.
#[test]
fn smart_nvme2_error_log_entries_are_not_judged() {
    let dev = load("smart-nvme2.json");
    let log = dev.nvme_smart_health_information_log.as_ref().unwrap();
    assert_eq!(log.num_err_log_entries, Some(8382));
    assert_eq!(evaluate(&dev).status, Status::Pass);
}

// Fork: TestFromCollectorSmartInfo_Scsi_Fail_Scrutiny
#[test]
fn smart_scsi_failed_defects_and_uncorrected_reads() {
    let evaluation = evaluate(&load("smart-scsi-failed.json"));
    assert_eq!(evaluation.findings[0].name, "Grown Defect List");
    assert_eq!(evaluation.findings[0].raw_value, Some(5));
    assert_eq!(evaluation.findings[1].name, "Read Total Uncorrected Errors");
    assert_eq!(evaluation.findings[1].raw_value, Some(3));
}

// Fork: TestFromCollectorSmartInfo_Scsi. 300 million ECC-corrected reads are normal on a SAS
// drive and are not judged.
#[test]
fn smart_scsi_corrected_errors_are_not_judged() {
    let dev = load("smart-scsi.json");
    let read = dev
        .scsi_error_counter_log
        .as_ref()
        .unwrap()
        .read
        .as_ref()
        .unwrap();
    assert_eq!(read.errors_corrected_by_eccfast, Some(300_357_663));
    assert_eq!(dev.scsi_grown_defect_list, Some(0));
    // an HDD: no endurance indicator, and this smartctl run has no SAS PHY page
    assert!(dev.endurance_used.is_none());
    assert!(dev.scsi_sas_ports.0.is_empty());
    assert_eq!(evaluate(&dev).status, Status::Pass);
}

#[test]
fn smart_fail_reports_the_smartctl_error() {
    let evaluation = evaluate(&load("smart-fail.json"));
    assert!(
        evaluation.findings[0].message.contains("Open failed"),
        "{}",
        evaluation.findings[0].message
    );
}
