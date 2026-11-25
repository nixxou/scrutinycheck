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

/// Apply `oracle/mutfuzz.py` edit operations: ["set", path, v], ["del", path], ["ins", path, v].
fn apply_ops(doc: &mut serde_json::Value, ops: &[serde_json::Value]) {
    use serde_json::Value;
    for op in ops {
        let op = op.as_array().expect("op is an array");
        let kind = op[0].as_str().unwrap();
        let path = op[1].as_array().unwrap();
        if path.is_empty() {
            if kind == "set" {
                *doc = op[2].clone();
            }
            continue;
        }
        let mut parent = &mut *doc;
        for step in &path[..path.len() - 1] {
            parent = match step {
                Value::String(k) => parent.get_mut(k.as_str()).expect("path key"),
                Value::Number(i) => parent.get_mut(i.as_u64().unwrap() as usize).expect("path index"),
                _ => panic!("bad path step {step}"),
            };
        }
        let last = &path[path.len() - 1];
        match (kind, last, parent) {
            ("set", Value::String(k), Value::Object(m)) => {
                m.insert(k.clone(), op[2].clone());
            }
            ("set", Value::Number(i), Value::Array(a)) => a[i.as_u64().unwrap() as usize] = op[2].clone(),
            ("del", Value::String(k), Value::Object(m)) => {
                m.remove(k.as_str());
            }
            ("del", Value::Number(i), Value::Array(a)) => {
                a.remove(i.as_u64().unwrap() as usize);
            }
            ("ins", Value::Number(i), Value::Array(a)) => a.insert(i.as_u64().unwrap() as usize, op[2].clone()),
            (k, step, _) => panic!("cannot apply {k} at {step}"),
        }
    }
}

fn read_gz(path: &Path) -> String {
    use std::io::Read;
    let mut s = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_string(&mut s)
        .unwrap();
    s
}

/// `tests/virtual/corpus/`: tens of thousands of drives produced by the feedback-driven
/// mutation fuzzer (`oracle/mutfuzz.py --corpus N`), stored as base documents plus edit
/// operations, with Scrutiny's verdict recorded per case.
#[test]
fn mutation_corpus_matches_scrutiny() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/virtual/corpus");
    let bases: Vec<serde_json::Value> = serde_json::from_str(&read_gz(&dir.join("bases.json.gz"))).unwrap();
    let cases = read_gz(&dir.join("cases.jsonl.gz"));
    let mut failures = Vec::new();
    let mut per_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut n = 0;
    for (i, line) in cases.lines().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let mut doc = bases[v["b"].as_u64().unwrap() as usize].clone();
        apply_ops(&mut doc, v["ops"].as_array().unwrap());
        let exp = Expected {
            error: v.get("e").is_some(),
            device_status: v.get("d").and_then(|d| d.as_u64()).unwrap_or(0) as u8,
            bits: v.get("x").map(|x| serde_json::from_value(x.clone()).unwrap()).unwrap_or_default(),
        };
        if let Some(p) = check(&doc.to_string(), &exp) {
            failures.push(format!("case {} ({}): {p}", i + 1, v["t"]));
        }
        *per_type.entry(v["t"].as_str().unwrap_or("?").to_string()).or_default() += 1;
        n += 1;
    }
    assert!(n >= 50_000, "corpus too small: {n}");
    let focus: usize = ["sata-hdd", "sata-ssd", "nvme"].iter().map(|t| per_type.get(*t).copied().unwrap_or(0)).sum();
    assert!(focus * 100 >= n * 80, "SATA/NVMe share below 80%: {per_type:?}");
    assert!(
        failures.is_empty(),
        "{} of {n} cases differ (first 20):\n{}",
        failures.len(),
        failures.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
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
