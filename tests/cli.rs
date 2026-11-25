//! CLI-level tests that run without smartctl or real disks.

use std::path::Path;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scrutinycheck"))
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn parse_scan_fixture() {
    let data = std::fs::read(fixture("scan-simple.json")).unwrap();
    let devs = scrutinycheck::collect::parse_scan(&data).unwrap();
    assert_eq!(devs.len(), 7);
    assert_eq!(devs[0].name, "/dev/sda");
    // "scsi" from --scan is dropped so smartctl autodetects SAT vs SCSI.
    assert_eq!(devs[0].dev_type, None);
}

#[test]
fn json_output_has_one_entry_per_file() {
    let out = bin()
        .args(["--json", "-f", &fixture("smart-ata.json"), "-f", &fixture("smart-nvme.json")])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["model"], "WDC WD140EDFZ-11A0VA0");
    assert_eq!(arr[0]["kind"], "HDD");
    assert_eq!(arr[1]["kind"], "SSD NVMe");
    for e in arr {
        assert!(e["status"].is_string());
        assert!(e["findings"].is_array());
    }
}

#[test]
fn unreadable_file_is_reported_not_fatal() {
    let out = bin()
        .args(["--json", "-f", &fixture("does-not-exist.json"), "-f", &fixture("smart-ata.json")])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v[0]["error"].is_string());
    assert!(v[1]["status"].is_string());
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn missing_smartctl_gives_clear_error() {
    let out = bin()
        .args(["--smartctl", "definitely-not-smartctl-xyz", "/dev/sda"])
        .output()
        .unwrap();
    // A device that cannot be read is reported per device (exit 2), not a crash.
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("smartmontools"), "{text}");
}

fn virtual_case(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/virtual")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// `tests/virtual/ata-warning-only.json`: smart-ata.json with attribute 1
/// `when_failed = "past"` (worst 40, thresh 44). Scrutiny's own code (oracle)
/// gives device_status 0 (passed) with attribute 1 = WarningScrutiny.
#[test]
fn warning_only_drive_is_ok_by_default_like_scrutiny() {
    let out = bin().args(["-f", &virtual_case("ata-warning-only.json")]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("OK (1 alert)"), "{text}");
    assert!(text.contains("[WARNING]"), "{text}");

    let out = bin().args(["--json", "-f", &virtual_case("ata-warning-only.json")]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["status"], "pass");
    assert_eq!(v[0]["findings"][0]["status"], "warning");
}

#[test]
fn strict_mode_turns_warnings_into_device_warning() {
    let out = bin()
        .args(["--strict", "-f", &virtual_case("ata-warning-only.json")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stdout).contains("WARNING"));
}

#[test]
fn failures_are_not_softened_by_default_policy() {
    let out = bin().args(["-f", &fixture("smart-fail2.json")]).output().unwrap();
    assert_eq!(out.status.code(), Some(4));
}

/// `tests/virtual/ata-manufacturer-now.json`: attribute 1 at 40 for a threshold
/// of 44, `when_failed = "now"`, smart_status passed. Oracle: device_status 0,
/// attribute 1 = FailedSmart.
#[test]
fn manufacturer_threshold_now_is_ok_like_scrutiny_and_fail_in_strict() {
    let f = virtual_case("ata-manufacturer-now.json");
    let out = bin().args(["-f", &f]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK (1 alert)"));
    let out = bin().args(["--strict", "-f", &f]).output().unwrap();
    assert_eq!(out.status.code(), Some(4));
}

/// smart-sat.json has no smart_status: Scrutiny counts it as a SMART failure
/// (oracle: device_status 1).
#[test]
fn missing_smart_status_fails_like_scrutiny_and_not_in_strict() {
    let f = fixture("smart-sat.json");
    let out = bin().args(["--json", "-f", &f]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["status"], "fail");
    assert_eq!(v[0]["findings"][0]["source"], "smart_overall");
    let out = bin().args(["--json", "--strict", "-f", &f]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["status"], "pass");
}

/// Writes a generated smartctl document where the tests may leave files.
fn generated_case(name: &str, doc: serde_json::Value) -> String {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, doc.to_string()).unwrap();
    path.to_string_lossy().into_owned()
}

/// An SSD at 100 % of its rated endurance (ATA device statistics, page 7 offset 8).
/// Oracle: device_status 2 (FailedScrutiny), devstat_7_8 = FailedScrutiny.
#[test]
fn worn_out_ssd_fails_on_its_device_statistics() {
    let f = generated_case(
        "devstat-percentage-used.json",
        serde_json::json!({
            "device": {"protocol": "ATA"},
            "rotation_rate": 0,
            "smart_status": {"passed": true},
            "ata_device_statistics": {"pages": [{"number": 7, "name": "Solid State Device Statistics", "table": [
                {"offset": 8, "name": "Percentage Used Endurance Indicator", "value": 100, "flags": {"valid": true}}
            ]}]}
        }),
    );
    for args in [vec!["-f", &f], vec!["--strict", "-f", &f]] {
        let out = bin().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(4), "{args:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("[FAILED] devstat_7_8 Percentage Used Endurance Indicator raw=100"), "{text}");
    }
}

/// A corrupted FARM counter and a corrupted device statistic (above 1,000,000 where lower
/// is better). Oracle: device_status 0, both attributes = InvalidValue (8).
#[test]
fn implausible_statistics_are_listed_but_never_change_the_verdict() {
    let f = generated_case(
        "devstat-farm-invalid.json",
        serde_json::json!({
            "device": {"protocol": "ATA"},
            "rotation_rate": 7200,
            "smart_status": {"passed": true},
            "ata_device_statistics": {"pages": [{"number": 3, "table": [
                {"offset": 32, "value": 281474976710655_i64, "flags": {"valid": true}}
            ]}]},
            "seagate_farm_log": {"supported": true, "page_3_error_statistics": {"total_crc_errors": 1000001}}
        }),
    );
    for args in [vec!["-f", &f], vec!["--strict", "-f", &f]] {
        let out = bin().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("OK (2 alerts)"), "{text}");
        assert!(text.contains("[UNKNOWN] devstat_3_32 Number of Reallocated Logical Sectors"), "{text}");
        assert!(text.contains("[UNKNOWN] farm_crc_errors CRC Errors (FARM) raw=1000001"), "{text}");
    }
    let out = bin().args(["--json", "-f", &f]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["status"], "pass");
    assert_eq!(v[0]["findings"][0]["source"], "devstat");
    assert_eq!(v[0]["findings"][0]["status"], "unknown");
    assert_eq!(v[0]["findings"][1]["source"], "farm");
}
