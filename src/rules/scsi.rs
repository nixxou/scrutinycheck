//! SCSI / SAS rules.
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `webapp/backend/pkg/thresholds/scsi_attribute_metadata.go`,
//! `webapp/backend/pkg/models/measurements/smart_scsci_attribute.go`, `buildScsiAttributes` in
//! `webapp/backend/pkg/models/measurements/smart.go` and `parseScsiSasPhys` in
//! `webapp/backend/pkg/models/collector/smart.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! Each attribute is compared with a recommended threshold along its `Ideal` direction. The
//! attributes the fork judges are:
//!
//! * `scsi_grown_defect_list` (threshold 0);
//! * per error counter page (`read`, `write`, and `verify` when the drive has it):
//!   `errors_corrected_by_rereads_rewrites` and `total_uncorrected_errors` (threshold 0);
//! * the four per-PHY SAS transport error counters (threshold 0);
//! * `percentage_used`, the SAS SSD endurance indicator (threshold 100).
//!
//! Everything else the fork records (ECC fast/delayed corrections, bytes processed,
//! temperatures, background scan, start/stop and load/unload cycles) either has no threshold
//! or no `Ideal` direction and so can never fail; those are listed in [`SCSI_METADATA`] but not
//! evaluated.

use super::{AttrStatus, CUMULATIVE_HINT, Finding, Ideal, Source, recommended_threshold_status};
use crate::model::{ScsiErrorCounter, ScsiSasPorts, SmartctlOutput};

/// Metadata of one SCSI attribute, resolved for a concrete attribute id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScsiAttributeMetadata {
    pub display_name: String,
    pub ideal: Ideal,
    pub critical: bool,
    /// Cumulative counter that the fork judges by trend, not by absolute value.
    pub use_delta_evaluation: bool,
}

/// A row of the fork's metadata tables: `(id or id suffix, display name, ideal, critical,
/// use delta evaluation)`.
type Row = (&'static str, &'static str, Ideal, bool, bool);

const NONE: Ideal = Ideal::Unspecified;
const LOW: Ideal = Ideal::Low;

/// The fork's `ScsiMetadata` map, display names verbatim.
#[rustfmt::skip]
pub static SCSI_METADATA: &[Row] = &[
    ("scsi_grown_defect_list", "Grown Defect List", LOW, true, false),
    ("read_errors_corrected_by_eccfast", "Read Errors Corrected by ECC Fast", NONE, false, false),
    ("read_errors_corrected_by_eccdelayed", "Read Errors Corrected by ECC Delayed", NONE, false, false),
    ("read_errors_corrected_by_rereads_rewrites", "Read Errors Corrected by ReReads/ReWrites", LOW, true, false),
    ("read_total_errors_corrected", "Read Total Errors Corrected", NONE, false, false),
    ("read_correction_algorithm_invocations", "Read Correction Algorithm Invocations", NONE, false, false),
    ("read_total_uncorrected_errors", "Read Total Uncorrected Errors", LOW, true, false),
    ("write_errors_corrected_by_eccfast", "Write Errors Corrected by ECC Fast", NONE, false, false),
    ("write_errors_corrected_by_eccdelayed", "Write Errors Corrected by ECC Delayed", NONE, false, false),
    ("write_errors_corrected_by_rereads_rewrites", "Write Errors Corrected by ReReads/ReWrites", LOW, true, false),
    ("write_total_errors_corrected", "Write Total Errors Corrected", NONE, false, false),
    ("write_correction_algorithm_invocations", "Write Correction Algorithm Invocations", NONE, false, false),
    ("write_total_uncorrected_errors", "Write Total Uncorrected Errors", LOW, true, false),
    ("temperature", "Temperature", NONE, false, false),
    ("read_gigabytes_processed", "Data Read", NONE, false, false),
    ("write_gigabytes_processed", "Data Written", NONE, false, false),
    ("verify_errors_corrected_by_eccfast", "Verify Errors Corrected by ECC Fast", NONE, false, false),
    ("verify_errors_corrected_by_eccdelayed", "Verify Errors Corrected by ECC Delayed", NONE, false, false),
    ("verify_errors_corrected_by_rereads_rewrites", "Verify Errors Corrected by ReReads/ReWrites", LOW, true, true),
    ("verify_total_errors_corrected", "Verify Total Errors Corrected", NONE, false, false),
    ("verify_correction_algorithm_invocations", "Verify Correction Algorithm Invocations", NONE, false, false),
    ("verify_total_uncorrected_errors", "Verify Total Uncorrected Errors", LOW, true, false),
    ("verify_gigabytes_processed", "Data Verified", NONE, false, false),
    ("background_scans_performed", "Background Scans Performed", NONE, false, false),
    ("background_medium_scans_performed", "Background Medium Scans Performed", NONE, false, false),
    ("background_scan_status", "Background Scan Status", NONE, false, false),
    ("background_scan_progress_percent", "Background Scan Progress", NONE, false, false),
    ("start_stop_cycles", "Start/Stop Cycles", NONE, false, false),
    ("load_unload_cycles", "Load/Unload Cycles", NONE, false, false),
    ("percentage_used", "Percentage Used", LOW, true, false),
];

/// The fork's `scsiSasPhyMetadataTemplates`, keyed by the suffix of
/// `sas_port_<port>_phy_<phy>_<suffix>`.
#[rustfmt::skip]
pub static SAS_PHY_METADATA_TEMPLATES: &[Row] = &[
    ("invalid_dword_count", "Invalid DWORDs", LOW, true, true),
    ("running_disparity_error_count", "Running Disparity Errors", LOW, true, true),
    ("loss_of_dword_synchronization_count", "Loss of DWORD Synchronization", LOW, true, true),
    ("phy_reset_problem_count", "PHY Reset Problems", LOW, true, true),
    ("negotiated_link_rate_mbps", "Negotiated Link Rate, Mbps", Ideal::High, false, false),
];

/// The fork's `scsiEnvironmentalMetadataTemplates`, keyed by the suffix of
/// `temperature_<sensor>_<suffix>`.
#[rustfmt::skip]
pub static ENVIRONMENTAL_METADATA_TEMPLATES: &[Row] = &[
    ("lifetime_maximum", "Lifetime Maximum Temperature", NONE, false, false),
    ("lifetime_minimum", "Lifetime Minimum Temperature", NONE, false, false),
    ("maximum_since_power_on", "Maximum Temperature Since Power On", NONE, false, false),
    ("minimum_since_power_on", "Minimum Temperature Since Power On", NONE, false, false),
];

/// The per-PHY counters the fork evaluates, all against a threshold of 0.
const SAS_PHY_COUNTERS: [&str; 4] = [
    "invalid_dword_count",
    "running_disparity_error_count",
    "loss_of_dword_synchronization_count",
    "phy_reset_problem_count",
];

fn row(rows: &[Row], key: &str) -> Option<Row> {
    rows.iter().copied().find(|r| r.0 == key)
}

fn resolved(
    (_, display_name, ideal, critical, use_delta_evaluation): Row,
    qualifier: Option<String>,
) -> ScsiAttributeMetadata {
    ScsiAttributeMetadata {
        display_name: match qualifier {
            Some(qualifier) => format!("{display_name} ({qualifier})"),
            None => display_name.to_string(),
        },
        ideal,
        critical,
        use_delta_evaluation,
    }
}

/// Splits `<digits>_<rest>` (at least one digit, non-empty rest).
fn split_number(text: &str) -> Option<(&str, &str)> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let rest = text[digits..].strip_prefix('_')?;
    (digits > 0 && !rest.is_empty()).then_some((&text[..digits], rest))
}

/// `ScsiMetadataFor`: metadata of a SCSI attribute id, including the per-PHY SAS counters
/// (`sas_port_0_phy_1_invalid_dword_count`) and the per-sensor lifetime temperatures
/// (`temperature_1_lifetime_maximum`), whose ids depend on what the drive reports.
pub fn scsi_metadata_for(attribute_id: &str) -> Option<ScsiAttributeMetadata> {
    if let Some(found) = row(SCSI_METADATA, attribute_id) {
        return Some(resolved(found, None));
    }

    if let Some((port, rest)) = attribute_id
        .strip_prefix("sas_port_")
        .and_then(split_number)
        && let Some((phy, suffix)) = rest.strip_prefix("phy_").and_then(split_number)
        && let Some(template) = row(SAS_PHY_METADATA_TEMPLATES, suffix)
    {
        return Some(resolved(template, Some(format!("Port {port} PHY {phy}"))));
    }

    if let Some((sensor, suffix)) = attribute_id
        .strip_prefix("temperature_")
        .and_then(split_number)
        && let Some(template) = row(ENVIRONMENTAL_METADATA_TEMPLATES, suffix)
    {
        return Some(resolved(template, Some(format!("Sensor {sensor}"))));
    }

    None
}

/// `SmartScsiAttribute.PopulateAttributeStatus`. `threshold` is `None` where the fork uses -1.
pub fn evaluate_attribute(attribute_id: &str, value: i64, threshold: Option<i64>) -> AttrStatus {
    match scsi_metadata_for(attribute_id) {
        Some(metadata) => recommended_threshold_status(metadata.ideal, value, threshold),
        None => AttrStatus::PASSED,
    }
}

/// One PHY of one SAS port with the counters it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SasPhy {
    pub port: u32,
    pub phy: u32,
    /// `(counter name, value)` for each of the judged counters the PHY reports.
    pub counters: Vec<(&'static str, i64)>,
}

/// A key index as smartctl writes it: plain digits that round-trip, so that
/// `scsi_sas_port_0` and `scsi_sas_port_00` cannot both claim port 0.
fn key_index(key: &str, prefix: &str) -> Option<u32> {
    let suffix = key.strip_prefix(prefix)?;
    let index: u32 = suffix.parse().ok()?;
    (index.to_string() == suffix).then_some(index)
}

/// `parseScsiSasPhys`: every PHY of every SAS port, sorted by port then PHY.
pub fn sas_phys(ports: &ScsiSasPorts) -> Vec<SasPhy> {
    let mut phys = Vec::new();
    for (port_key, port_value) in &ports.0 {
        let (Some(port), Some(port_object)) = (
            key_index(port_key, ScsiSasPorts::KEY_PREFIX),
            port_value.as_object(),
        ) else {
            continue;
        };
        for (phy_key, phy_value) in port_object {
            let Some(phy) = key_index(phy_key, "phy_") else {
                continue;
            };
            let counters = SAS_PHY_COUNTERS
                .iter()
                .filter_map(|name| Some((*name, phy_value.get(name)?.as_i64()?)))
                .collect();
            phys.push(SasPhy {
                port,
                phy,
                counters,
            });
        }
    }
    phys.sort_by_key(|p| (p.port, p.phy));
    phys
}

/// The judged attributes of a device with their thresholds, in the order of the fork's
/// `buildScsiAttributes`: `(attribute id, value, threshold)`.
fn judged_attributes(dev: &SmartctlOutput) -> Vec<(String, i64, i64)> {
    let mut attributes = Vec::new();

    if let Some(defects) = dev.scsi_grown_defect_list {
        attributes.push(("scsi_grown_defect_list".to_string(), defects, 0));
    }

    if let Some(log) = &dev.scsi_error_counter_log {
        let pages: [(&str, &Option<ScsiErrorCounter>); 3] = [
            ("read", &log.read),
            ("write", &log.write),
            ("verify", &log.verify),
        ];
        for (prefix, page) in pages {
            let Some(page) = page else { continue };
            if let Some(value) = page.errors_corrected_by_rereads_rewrites {
                attributes.push((
                    format!("{prefix}_errors_corrected_by_rereads_rewrites"),
                    value,
                    0,
                ));
            }
            if let Some(value) = page.total_uncorrected_errors {
                attributes.push((format!("{prefix}_total_uncorrected_errors"), value, 0));
            }
        }
    }

    for phy in sas_phys(&dev.scsi_sas_ports) {
        for (counter, value) in phy.counters {
            attributes.push((
                format!("sas_port_{}_phy_{}_{counter}", phy.port, phy.phy),
                value,
                0,
            ));
        }
    }

    if let Some(percent) = dev.endurance_used.as_ref().and_then(|e| e.current_percent) {
        attributes.push(("percentage_used".to_string(), percent, 100));
    }

    attributes
}

/// Evaluate the SCSI log pages. Returns false when the device reports none of them.
pub(super) fn evaluate(dev: &SmartctlOutput, findings: &mut Vec<Finding>) -> bool {
    let usable = dev.scsi_grown_defect_list.is_some()
        || dev.scsi_error_counter_log.is_some()
        || dev.endurance_used.is_some()
        || !dev.scsi_sas_ports.0.is_empty();

    for (id, value, threshold) in judged_attributes(dev) {
        let status = evaluate_attribute(&id, value, Some(threshold));
        if status == AttrStatus::PASSED {
            continue;
        }
        let metadata = scsi_metadata_for(&id);
        let mut message = message(&id, value, threshold);
        if metadata.as_ref().is_some_and(|m| m.use_delta_evaluation) {
            message.push_str(CUMULATIVE_HINT);
        }
        findings.push(Finding {
            source: Source::Scsi,
            name: metadata.map_or_else(|| id.clone(), |m| m.display_name),
            attribute: id,
            raw_value: Some(value),
            status: status.to_status(),
            message,
            annual_failure_rate: None,
        });
    }
    usable
}

fn message(id: &str, value: i64, threshold: i64) -> String {
    let operation = match id.split('_').next() {
        Some("read") => "en lecture",
        Some("write") => "en écriture",
        Some("verify") => "en vérification",
        _ => "",
    };
    if id == "scsi_grown_defect_list" {
        format!("{value} défaut(s) de surface apparu(s) en service")
    } else if id.ends_with("_total_uncorrected_errors") {
        format!("{value} erreur(s) non corrigée(s) {operation}")
    } else if id.ends_with("_errors_corrected_by_rereads_rewrites") {
        format!("{value} erreur(s) {operation} corrigée(s) par relecture ou réécriture")
    } else if id.starts_with("sas_port_") {
        format!("{value} erreur(s) de liaison SAS")
    } else if id == "percentage_used" {
        format!("usure à {value} % de l'endurance annoncée")
    } else {
        format!("valeur {value} hors du seuil recommandé ({threshold})")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::{Status, is_cumulative_counter};
    use super::*;

    const FAILED: AttrStatus = AttrStatus::FAILED_SCRUTINY;

    fn device(value: serde_json::Value) -> SmartctlOutput {
        serde_json::from_value(value).unwrap()
    }

    fn run(value: serde_json::Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        assert!(evaluate(&device(value), &mut findings));
        findings
    }

    fn counters(rereads: i64, uncorrected: i64) -> serde_json::Value {
        json!({
            "errors_corrected_by_eccfast": 300_357_663, "errors_corrected_by_eccdelayed": 25,
            "errors_corrected_by_rereads_rewrites": rereads, "total_errors_corrected": 300_357_688,
            "correction_algorithm_invocations": 1_234, "gigabytes_processed": "176987.332",
            "total_uncorrected_errors": uncorrected
        })
    }

    #[test]
    fn metadata_matches_the_fork() {
        assert_eq!(SCSI_METADATA.len(), 30);
        let critical: Vec<&str> = SCSI_METADATA.iter().filter(|r| r.3).map(|r| r.0).collect();
        assert_eq!(
            critical,
            [
                "scsi_grown_defect_list",
                "read_errors_corrected_by_rereads_rewrites",
                "read_total_uncorrected_errors",
                "write_errors_corrected_by_rereads_rewrites",
                "write_total_uncorrected_errors",
                "verify_errors_corrected_by_rereads_rewrites",
                "verify_total_uncorrected_errors",
                "percentage_used",
            ]
        );
        // every critical attribute degrades upwards, and nothing else has a direction
        assert!(SCSI_METADATA.iter().all(|r| (r.2 == Ideal::Low) == r.3));
        let delta: Vec<&str> = SCSI_METADATA.iter().filter(|r| r.4).map(|r| r.0).collect();
        assert_eq!(delta, ["verify_errors_corrected_by_rereads_rewrites"]);
    }

    #[test]
    fn metadata_for_dynamic_ids() {
        let phy = scsi_metadata_for("sas_port_1_phy_0_invalid_dword_count").unwrap();
        assert_eq!(phy.display_name, "Invalid DWORDs (Port 1 PHY 0)");
        assert_eq!(phy.ideal, Ideal::Low);
        assert!(phy.critical && phy.use_delta_evaluation);

        let rate = scsi_metadata_for("sas_port_0_phy_12_negotiated_link_rate_mbps").unwrap();
        assert_eq!(
            rate.display_name,
            "Negotiated Link Rate, Mbps (Port 0 PHY 12)"
        );
        assert_eq!(rate.ideal, Ideal::High);

        let sensor = scsi_metadata_for("temperature_1_lifetime_maximum").unwrap();
        assert_eq!(
            sensor.display_name,
            "Lifetime Maximum Temperature (Sensor 1)"
        );

        assert_eq!(
            scsi_metadata_for("temperature").unwrap().display_name,
            "Temperature"
        );
        for unknown in [
            "sas_port_x_phy_0_invalid_dword_count",
            "sas_port_0_phy_0_",
            "sas_port_0_phy_0_unknown_counter",
            "sas_port__phy_0_invalid_dword_count",
            "temperature_1_unknown",
            "temperature_lifetime_maximum",
            "nope",
        ] {
            assert_eq!(scsi_metadata_for(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn attribute_thresholds() {
        assert_eq!(
            evaluate_attribute("scsi_grown_defect_list", 5, Some(0)),
            FAILED
        );
        assert_eq!(
            evaluate_attribute("scsi_grown_defect_list", 0, Some(0)),
            AttrStatus::PASSED
        );
        assert_eq!(
            evaluate_attribute("read_total_uncorrected_errors", 3, Some(0)),
            FAILED
        );
        assert_eq!(
            evaluate_attribute("percentage_used", 100, Some(100)),
            AttrStatus::PASSED
        );
        assert_eq!(
            evaluate_attribute("percentage_used", 101, Some(100)),
            FAILED
        );
        // recorded, never judged: no threshold
        assert_eq!(
            evaluate_attribute("read_errors_corrected_by_eccfast", 300_357_663, None),
            AttrStatus::PASSED
        );
        // Fork: TestFromCollectorSmartInfo_Scsi_StartStopCyclesPastRating. The rated cycle
        // count is the threshold, but the attribute has no direction, so it never fails.
        assert_eq!(
            evaluate_attribute("start_stop_cycles", 60_000, Some(50_000)),
            AttrStatus::PASSED
        );
        assert_eq!(
            evaluate_attribute("unknown", 9, Some(0)),
            AttrStatus::PASSED
        );
    }

    #[test]
    fn healthy_drive_has_no_finding() {
        let findings = run(json!({
            "scsi_grown_defect_list": 0,
            "scsi_error_counter_log": {"read": counters(0, 0), "write": counters(0, 0)}
        }));
        assert!(findings.is_empty());
    }

    #[test]
    fn defects_and_uncorrected_errors_fail() {
        let findings = run(json!({
            "scsi_grown_defect_list": 5,
            "scsi_error_counter_log": {
                "read": counters(0, 3), "write": counters(2, 0), "verify": counters(7, 1)
            }
        }));
        let ids: Vec<&str> = findings.iter().map(|f| f.attribute.as_str()).collect();
        assert_eq!(
            ids,
            [
                "scsi_grown_defect_list",
                "read_total_uncorrected_errors",
                "write_errors_corrected_by_rereads_rewrites",
                "verify_errors_corrected_by_rereads_rewrites",
                "verify_total_uncorrected_errors",
            ]
        );
        assert!(
            findings
                .iter()
                .all(|f| f.status == Status::Fail && f.source == Source::Scsi)
        );
        assert_eq!(findings[0].name, "Grown Defect List");
        assert_eq!(findings[1].raw_value, Some(3));
        assert_eq!(
            findings[1].message,
            "3 erreur(s) non corrigée(s) en lecture"
        );
        // only the verify re-read counter is trend-evaluated by the fork
        let cumulative: Vec<bool> = findings.iter().map(is_cumulative_counter).collect();
        assert_eq!(cumulative, [false, false, false, true, false]);
        assert!(findings[3].message.ends_with(CUMULATIVE_HINT));
    }

    #[test]
    fn endurance_indicator() {
        assert!(run(json!({"endurance_used": {"current_percent": 100}})).is_empty());
        let findings = run(json!({"endurance_used": {"current_percent": 105}}));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].attribute, "percentage_used");
        assert_eq!(findings[0].name, "Percentage Used");
    }

    // Fork: TestFromCollectorSmartInfo_Scsi_SasPhy (first sight of a non-zero counter fails)
    #[test]
    fn sas_phy_counters() {
        let dev = json!({
            "device": {"protocol": "SCSI"},
            "scsi_sas_port_0": {
                "phy_0": {
                    "invalid_dword_count": 4, "running_disparity_error_count": 0,
                    "loss_of_dword_synchronization_count": 1, "phy_reset_problem_count": 0,
                    "negotiated_logical_link_rate": "phy enabled; 12 Gbps"
                }
            },
            "scsi_sas_port_1": {
                "phy_0": {
                    "invalid_dword_count": 0, "running_disparity_error_count": 0,
                    "loss_of_dword_synchronization_count": 0, "phy_reset_problem_count": 0
                }
            },
            "scsi_sas_port_00": {"phy_0": {"invalid_dword_count": 99}},
            "scsi_sas_port_2": "not an object",
            "scsi_self_test_0": {"code": {"value": 1}}
        });

        let phys = sas_phys(&device(dev.clone()).scsi_sas_ports);
        let found: Vec<(u32, u32)> = phys.iter().map(|p| (p.port, p.phy)).collect();
        assert_eq!(found, [(0, 0), (1, 0)]);
        assert_eq!(phys[0].counters[0], ("invalid_dword_count", 4));

        let findings = run(dev);
        let ids: Vec<&str> = findings.iter().map(|f| f.attribute.as_str()).collect();
        assert_eq!(
            ids,
            [
                "sas_port_0_phy_0_invalid_dword_count",
                "sas_port_0_phy_0_loss_of_dword_synchronization_count"
            ]
        );
        assert_eq!(findings[0].name, "Invalid DWORDs (Port 0 PHY 0)");
        assert_eq!(findings[0].status, Status::Fail);
        assert!(findings.iter().all(is_cumulative_counter));
    }

    #[test]
    fn ports_sort_numerically() {
        let dev = device(json!({
            "scsi_sas_port_10": {"phy_0": {"invalid_dword_count": 0}},
            "scsi_sas_port_2": {"phy_1": {"invalid_dword_count": 0}, "phy_0": {"invalid_dword_count": 0}}
        }));
        let found: Vec<(u32, u32)> = sas_phys(&dev.scsi_sas_ports)
            .iter()
            .map(|p| (p.port, p.phy))
            .collect();
        assert_eq!(found, [(2, 0), (2, 1), (10, 0)]);
    }

    #[test]
    fn no_scsi_section_is_not_usable_data() {
        let mut findings = Vec::new();
        assert!(!evaluate(
            &device(json!({"device": {"protocol": "SCSI"}})),
            &mut findings
        ));
        assert!(findings.is_empty());
    }
}
