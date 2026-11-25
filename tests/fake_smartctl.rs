//! End-to-end tests of the collection path against a fake `smartctl` script,
//! so that "never wake a sleeping drive" is checked without real disks.
//!
//! The fake logs its arguments, lists /dev/sda (reported as "scsi", like a
//! SATA disk behind libata) and /dev/nvme0, and answers like smartctl does for
//! a drive in STANDBY when `-n standby` is given for /dev/sda.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const SCAN: &str = r#"{"devices":[{"name":"/dev/sda","info_name":"/dev/sda","type":"scsi","protocol":"SCSI"},{"name":"/dev/nvme0","info_name":"/dev/nvme0","type":"nvme","protocol":"NVMe"}]}"#;
const STANDBY: &str = r#"{"smartctl":{"exit_status":2,"messages":[{"string":"Device is in STANDBY mode, exit(2)","severity":"information"}]}}"#;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Fake {
    dir: PathBuf,
    exe: PathBuf,
}

impl Fake {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("scrutinycheck-fake-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        fs::write(dir.join("scan.json"), SCAN).unwrap();
        fs::write(dir.join("standby.json"), STANDBY).unwrap();
        fs::copy(fixtures.join("smart-ata.json"), dir.join("ata.json")).unwrap();
        fs::copy(fixtures.join("smart-nvme.json"), dir.join("nvme.json")).unwrap();
        let d = dir.display();
        let exe = if cfg!(windows) {
            let exe = dir.join("smartctl.cmd");
            let script = format!(
                "@echo off\r\n\
                 echo %*>>\"{d}\\args.log\"\r\n\
                 echo %* | findstr /C:\"--scan\" >nul && (type \"{d}\\scan.json\" & exit /b 0)\r\n\
                 echo %* | findstr /C:\"/dev/sda\" >nul && echo %* | findstr /C:\"-n standby\" >nul && (type \"{d}\\standby.json\" & exit /b 2)\r\n\
                 echo %* | findstr /C:\"/dev/sda\" >nul && (type \"{d}\\ata.json\" & exit /b 0)\r\n\
                 type \"{d}\\nvme.json\"\r\n\
                 exit /b 0\r\n"
            );
            fs::write(&exe, script).unwrap();
            exe
        } else {
            let exe = dir.join("smartctl");
            let script = format!(
                "#!/bin/sh\n\
                 echo \"$*\" >> '{d}/args.log'\n\
                 case \"$*\" in *--scan*) cat '{d}/scan.json'; exit 0;; esac\n\
                 case \"$*\" in *'-n standby'*/dev/sda*) cat '{d}/standby.json'; exit 2;; esac\n\
                 case \"$*\" in */dev/sda*) cat '{d}/ata.json'; exit 0;; esac\n\
                 cat '{d}/nvme.json'\n"
            );
            fs::write(&exe, script).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
            }
            exe
        };
        Fake { dir, exe }
    }

    fn run(&self, extra: &[&str]) -> (Option<i32>, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_scrutinycheck"))
            .arg("--smartctl")
            .arg(&self.exe)
            .args(extra)
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("args.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn discovery_never_opens_devices() {
    let fake = Fake::new();
    fake.run(&[]);
    let calls = fake.calls();
    assert!(calls.iter().any(|c| c.starts_with("--scan")), "{calls:?}");
    assert!(!calls.iter().any(|c| c.contains("--scan-open")), "{calls:?}");
}

#[test]
fn every_read_uses_n_standby_by_default() {
    let fake = Fake::new();
    fake.run(&[]);
    let reads: Vec<_> = fake.calls().into_iter().filter(|c| c.contains("/dev/")).collect();
    assert_eq!(reads.len(), 2, "{reads:?}");
    for r in &reads {
        assert!(r.contains("-n standby"), "{r}");
    }
}

#[test]
fn sata_reported_as_scsi_is_not_forced_to_dash_d_scsi() {
    let fake = Fake::new();
    fake.run(&[]);
    let sda = fake.calls().into_iter().find(|c| c.contains("/dev/sda")).unwrap();
    assert!(!sda.contains("-d scsi"), "{sda}");
    let nvme = fake.calls().into_iter().find(|c| c.contains("/dev/nvme0")).unwrap();
    assert!(nvme.contains("-d nvme"), "{nvme}");
}

#[test]
fn sleeping_drive_is_skipped_and_not_an_error() {
    let fake = Fake::new();
    let (code, text) = fake.run(&[]);
    assert!(text.contains("ASLEEP"), "{text}");
    assert!(text.contains("STANDBY"), "{text}");
    assert_eq!(code, Some(0), "{text}");

    let (_, json) = fake.run(&["--json"]);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let asleep = v.as_array().unwrap().iter().find(|e| e["device"] == "/dev/sda").unwrap();
    assert_eq!(asleep["skipped"], "asleep");
    assert_eq!(asleep["power_mode"], "STANDBY");
}

#[test]
fn wake_reads_the_sleeping_drive() {
    let fake = Fake::new();
    let (_, text) = fake.run(&["--wake"]);
    assert!(!text.contains("ASLEEP"), "{text}");
    assert!(text.contains("WDC WD140EDFZ"), "{text}");
    for c in fake.calls().iter().filter(|c| c.contains("/dev/")) {
        assert!(!c.contains("-n standby"), "{c}");
    }
}

#[test]
fn low_power_message_detection() {
    use scrutinycheck::collect::low_power_skip;
    assert_eq!(low_power_skip(STANDBY.as_bytes()).as_deref(), Some("STANDBY"));
    assert_eq!(
        low_power_skip(b"Device is in SLEEP mode, exit(7)").as_deref(),
        Some("SLEEP")
    );
    assert_eq!(low_power_skip(br#"{"model_name":"x"}"#), None);
    assert_eq!(low_power_skip(b"Device is in the room"), None);
}
