//! Scrutiny parity without Go: replays cases whose expected result was recorded from the
//! unmodified Scrutiny code (oracle/), and checks the default (Scrutiny) policy reproduces
//! it attribute by attribute and per device.
//!
//! - `tests/virtual/fuzz/*.json`: minimized documents of every mismatch class the
//!   differential fuzzer found and that was fixed (regenerate: `oracle/regressions.py`).
//! - `tests/virtual/corpus.jsonl`: diverse generated drives (regenerate:
//!   `oracle/fuzz.py --corpus N`).

use std::collections::BTreeMap;
use std::path::Path;

use scrutinycheck::model::SmartctlOutput;
use scrutinycheck::rules::{self, Finding, Policy, Source, Status};

#[derive(serde::Deserialize)]
struct Expected {
    error: bool,
    device_status: u8,
    bits: BTreeMap<String, u8>,
}

/// Fork attribute bit for a finding (FailedSmart 1, WarningScrutiny 2, FailedScrutiny 4).
fn bit(f: &Finding) -> u8 {
    match (f.status, f.source) {
        (Status::Warning, _) => 2,
        (Status::Fail, Source::Manufacturer) => 1,
        (Status::Fail, _) => 4,
        (Status::Unknown, _) => 8,
        (Status::Pass, _) => 0,
    }
}

/// None when the result matches the oracle, else a description of the difference.
fn check(doc: &str, exp: &Expected) -> Option<String> {
    let dev: SmartctlOutput = match serde_json::from_str(doc) {
        Ok(d) => d,
        Err(e) => {
            return (!exp.error).then(|| format!("rejected by scrutinycheck ({e}), accepted by Scrutiny"));
        }
    };
    if exp.error {
        // Go rejects some ill-typed documents scrutinycheck evaluates (accepted gap).
        return None;
    }
    let eval = rules::evaluate_with(&dev, Policy::Scrutiny);
    let mut bits: BTreeMap<String, u8> = BTreeMap::new();
    for f in &eval.findings {
        if matches!(f.source, Source::SmartOverall | Source::NoData) {
            continue;
        }
        *bits.entry(f.attribute.clone()).or_default() |= bit(f);
    }
    let mut problems = Vec::new();
    if bits != exp.bits {
        problems.push(format!("attribute bits {bits:?}, Scrutiny {:?}", exp.bits));
    }
    let smart = eval.findings.iter().any(|f| f.source == Source::SmartOverall);
    if smart != (exp.device_status & 1 != 0) {
        problems.push(format!("SMART-failed bit {smart}, Scrutiny device_status {}", exp.device_status));
    }
    if (eval.status == Status::Fail) != (exp.device_status != 0) {
        problems.push(format!("verdict {:?}, Scrutiny device_status {}", eval.status, exp.device_status));
    }
    (!problems.is_empty()).then(|| problems.join("; "))
}

#[test]
fn fixed_mismatch_classes_stay_fixed() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/virtual/fuzz");
    let mut checked = 0;
    let mut failures = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name.ends_with(".expected.json") {
            continue;
        }
        let doc = std::fs::read_to_string(&path).unwrap();
        let exp_path = path.with_extension("expected.json");
        let exp: Expected = serde_json::from_str(&std::fs::read_to_string(&exp_path).unwrap()).unwrap();
        if let Some(p) = check(&doc, &exp) {
            failures.push(format!("{name}: {p}"));
        }
        checked += 1;
    }
    assert!(checked >= 10, "only {checked} regression cases found in {}", dir.display());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn generated_corpus_matches_scrutiny() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/virtual/corpus.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut failures = Vec::new();
    let mut n = 0;
    for (i, line) in text.lines().enumerate() {
        #[derive(serde::Deserialize)]
        struct Case {
            doc: serde_json::Value,
            expected: Expected,
        }
        let case: Case = serde_json::from_str(line).unwrap();
        if let Some(p) = check(&case.doc.to_string(), &case.expected) {
            failures.push(format!("line {}: {p}", i + 1));
        }
        n += 1;
    }
    assert!(n >= 100, "corpus too small: {n}");
    assert!(failures.is_empty(), "{} of {n} cases differ:\n{}", failures.len(), failures.join("\n"));
}
