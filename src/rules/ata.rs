//! ATA attribute evaluation.
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `webapp/backend/pkg/models/measurements/smart_ata_attribute.go` and the ATA part of
//! `webapp/backend/pkg/models/measurements/smart.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! Two layers, in the fork's order:
//!
//! 1. Manufacturer threshold, as smartctl reports it in `when_failed`: `"now"` is a failure
//!    and ends the evaluation of the attribute, `"past"` is a warning. The fork does not
//!    compare `value` with `thresh` itself; smartctl already derived `when_failed` from them.
//! 2. Observed failure rate. The attribute value (raw, normalized or transformed, as the
//!    metadata says) is rated at the worst annual failure rate observed by the time an
//!    attribute has degraded that far along its `Ideal` direction (fork PR #1088), then the
//!    rate is compared with [`CRITICAL_FAIL_RATE`], [`NON_CRITICAL_FAIL_RATE`] and
//!    [`NON_CRITICAL_WARN_RATE`].

use super::ata_thresholds::{AtaAttributeMetadata, DisplayType, ObservedThreshold, ata_metadata};
use super::{AttrStatus, CUMULATIVE_HINT, Finding, Ideal, Source, Status};
use crate::model::{AtaAttribute, SmartctlOutput};

/// smartctl's `ata_smart_attributes.table[].when_failed` values.
const WHEN_FAILED_NOW: &str = "now";
const WHEN_FAILED_PAST: &str = "past";

/// A critical attribute fails from this observed annual failure rate.
pub const CRITICAL_FAIL_RATE: f64 = 0.10;
/// A non-critical attribute fails from this observed annual failure rate.
pub const NON_CRITICAL_FAIL_RATE: f64 = 0.20;
/// A non-critical attribute warns from this observed annual failure rate.
pub const NON_CRITICAL_WARN_RATE: f64 = 0.10;

/// Tokens that do not distinguish one attribute name from another.
const IGNORED_NAME_TOKENS: [&str; 3] = ["ct", "count", "total"];

/// Outcome of the fork's `SmartAtaAttribute.PopulateAttributeStatus` for one attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct AtaAttributeStatus {
    pub status: AttrStatus,
    /// Result of the metadata transform, 0 when the attribute has none.
    pub transformed_value: i64,
    /// Observed annual failure rate, `None` when no bucket applied.
    pub failure_rate: Option<f64>,
    /// `when_failed == "now"`.
    pub failing_now: bool,
    /// `when_failed == "past"`.
    pub failed_in_the_past: bool,
    /// Generic buckets were not applied: on an ATA SSD the attribute id is reused by the
    /// vendor for something else than what the buckets were measured on.
    pub skipped_vendor_specific_ssd: bool,
}

/// Buckets to score an attribute with.
///
/// Extension point: the fork substitutes the buckets of a matched consumer drive profile
/// here (`profile.AtaObservedThresholds[id]`) when the profile carries some for the id.
pub fn observed_thresholds_for(metadata: &AtaAttributeMetadata) -> &'static [ObservedThreshold] {
    metadata.observed_thresholds
}

/// `isAtaSsdSmartInfo`: an ATA device whose rotation rate is 0. smartctl output without
/// `rotation_rate` decodes to 0 in the fork, so it counts as an SSD there too.
pub fn is_ata_ssd(dev: &SmartctlOutput) -> bool {
    dev.rotation_rate.unwrap_or(0) == 0
}

/// Evaluate one attribute: manufacturer threshold, then observed failure rate.
pub fn evaluate_attribute(attr: &AtaAttribute, is_ata_ssd: bool) -> AtaAttributeStatus {
    // Absent fields read as Go zero values, as they do in the fork.
    let normalized = attr.value.unwrap_or(0);
    let raw = attr.raw.as_ref().and_then(|r| r.value).unwrap_or(0);
    let raw_string = attr
        .raw
        .as_ref()
        .and_then(|r| r.string.as_deref())
        .unwrap_or("");
    let when_failed = attr.when_failed.as_deref().unwrap_or("");
    let metadata = ata_metadata(attr.id);

    let mut result = AtaAttributeStatus {
        status: AttrStatus::PASSED,
        transformed_value: metadata
            .and_then(|m| m.transform)
            .map_or(0, |transform| transform(normalized, raw, raw_string)),
        failure_rate: None,
        failing_now: false,
        failed_in_the_past: false,
        skipped_vendor_specific_ssd: false,
    };

    if when_failed.eq_ignore_ascii_case(WHEN_FAILED_NOW) {
        // The drive's own verdict stands: no need to look at observed thresholds.
        result.status.set(AttrStatus::FAILED_SMART);
        result.failing_now = true;
        return result;
    } else if when_failed.eq_ignore_ascii_case(WHEN_FAILED_PAST) {
        result.status.set(AttrStatus::WARNING_SCRUTINY);
        result.failed_in_the_past = true;
    }

    let Some(metadata) = metadata else {
        return result;
    };

    if result.status == AttrStatus::PASSED
        && should_skip_ssd_observed_thresholds(
            is_ata_ssd,
            metadata,
            attr.name.as_deref().unwrap_or(""),
        )
    {
        result.skipped_vendor_specific_ssd = true;
        return result;
    }

    let value = match metadata.display_type {
        DisplayType::Normalized => normalized,
        DisplayType::Transformed => result.transformed_value,
        DisplayType::Raw | DisplayType::Unspecified => raw,
    };
    if let Some(rate) =
        observed_failure_rate_at(metadata.ideal, observed_thresholds_for(metadata), value)
    {
        result.failure_rate = Some(rate);
        result
            .status
            .set(failure_rate_status(metadata.critical, rate));
    }
    result
}

/// `shouldSkipAtaSsdObservedThresholdScoring`: on an ATA SSD, generic buckets only apply when
/// the name the drive reports for the id agrees with the attribute the buckets describe.
fn should_skip_ssd_observed_thresholds(
    is_ata_ssd: bool,
    metadata: &AtaAttributeMetadata,
    reported_name: &str,
) -> bool {
    if !is_ata_ssd || metadata.observed_thresholds.is_empty() {
        return false;
    }
    !attribute_names_semantically_match(reported_name, metadata.display_name)
}

/// `ataAttributeNamesSemanticallyMatch`: the tokens of the shorter name appear, in order, in
/// the longer one ("Runtime_Bad_Block" matches "SATA Downshift Error Count or Runtime Bad Block").
pub fn attribute_names_semantically_match(reported_name: &str, metadata_name: &str) -> bool {
    let reported = name_tokens(reported_name);
    let metadata = name_tokens(metadata_name);
    if reported.is_empty() || metadata.is_empty() {
        return false;
    }
    let (shorter, longer) = if reported.len() > metadata.len() {
        (metadata, reported)
    } else {
        (reported, metadata)
    };

    let mut matched = 0;
    for token in &longer {
        if shorter[matched] != *token {
            continue;
        }
        matched += 1;
        if matched == shorter.len() {
            return true;
        }
    }
    false
}

fn name_tokens(name: &str) -> Vec<String> {
    name.trim()
        .to_lowercase()
        .split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit()))
        .filter(|token| !token.is_empty() && !IGNORED_NAME_TOKENS.contains(token))
        .map(str::to_string)
        .collect()
}

/// `observedFailureRateAt`: the failure rate to score for `value`, `None` when no bucket applies.
///
/// The buckets are annual failure rates measured over a mixed-drive population, not an ordinal
/// severity scale: sparse buckets are non-monotonic and the covered range stops well short of
/// the worst value a drive can report. With an `Ideal` direction the rate is therefore the
/// worst one observed by the time the attribute has degraded to `value`, which never improves
/// as the attribute worsens and carries the worst rate out past the last bucket. Without a
/// direction, only the bucket containing `value` is scored.
pub fn observed_failure_rate_at(
    ideal: Ideal,
    thresholds: &[ObservedThreshold],
    value: i64,
) -> Option<f64> {
    match ideal {
        Ideal::Low | Ideal::High => thresholds
            .iter()
            .filter(|bucket| bucket_reached_by(bucket, ideal, value))
            .map(bucket_failure_rate)
            .reduce(f64::max),
        Ideal::Unspecified => thresholds
            .iter()
            .find(|bucket| bucket_contains(bucket, value))
            .map(bucket_failure_rate),
    }
}

/// `observedThresholdReachedBy`: an attribute degrading to `value` has passed through this
/// bucket. The edges are those of [`bucket_contains`], so no value changes bucket; the
/// envelope only adds the buckets already passed.
fn bucket_reached_by(bucket: &ObservedThreshold, ideal: Ideal, value: i64) -> bool {
    if ideal == Ideal::High {
        return value <= bucket.high;
    }
    if bucket.low == bucket.high {
        return value >= bucket.low;
    }
    // a span bucket's lowest covered value is low + 1, written as a strict inequality so that
    // a bucket whose floor is i64::MAX cannot overflow
    value > bucket.low
}

/// `observedThresholdContains`.
fn bucket_contains(bucket: &ObservedThreshold, value: i64) -> bool {
    (bucket.low == bucket.high && value == bucket.low)
        || (bucket.low < value && value <= bucket.high)
}

/// `observedFailureRate`: the bucket's annual failure rate, or the midpoint of its error
/// interval when the rate is 0 but the interval is not.
fn bucket_failure_rate(bucket: &ObservedThreshold) -> f64 {
    let [low, high] = bucket.error_interval;
    if bucket.annual_failure_rate == 0.0 && (low != 0.0 || high != 0.0) {
        (low + high) / 2.0
    } else {
        bucket.annual_failure_rate
    }
}

/// `applyFailureRateStatus`: critical attributes fail from 10 %; the others fail from 20 % and
/// warn from 10 %.
pub fn failure_rate_status(critical: bool, rate: f64) -> AttrStatus {
    if critical {
        if rate >= CRITICAL_FAIL_RATE {
            AttrStatus::FAILED_SCRUTINY
        } else {
            AttrStatus::PASSED
        }
    } else if rate >= NON_CRITICAL_FAIL_RATE {
        AttrStatus::FAILED_SCRUTINY
    } else if rate >= NON_CRITICAL_WARN_RATE {
        AttrStatus::WARNING_SCRUTINY
    } else {
        AttrStatus::PASSED
    }
}

/// Evaluate the attribute table. Returns false when the device reports no attribute.
pub(super) fn evaluate(dev: &SmartctlOutput, findings: &mut Vec<Finding>) -> bool {
    let table = match &dev.ata_smart_attributes {
        Some(attributes) if !attributes.table.is_empty() => &attributes.table,
        _ => return false,
    };
    let is_ssd = is_ata_ssd(dev);
    for attr in table {
        push_findings(attr, &evaluate_attribute(attr, is_ssd), findings);
    }
    true
}

fn push_findings(attr: &AtaAttribute, result: &AtaAttributeStatus, findings: &mut Vec<Finding>) {
    let metadata = ata_metadata(attr.id);
    let name = match (metadata, &attr.name) {
        (Some(m), _) => m.display_name.to_string(),
        (None, Some(reported)) => reported.clone(),
        (None, None) => format!("Attribut {}", attr.id),
    };
    let finding = |source, status, message, annual_failure_rate| Finding {
        source,
        attribute: attr.id.to_string(),
        name: name.clone(),
        raw_value: attr.raw.as_ref().and_then(|r| r.value),
        status,
        message,
        annual_failure_rate,
    };
    let thresh = attr.thresh.unwrap_or(0);

    if result.failing_now {
        findings.push(finding(
            Source::Manufacturer,
            Status::Fail,
            format!(
                "seuil constructeur franchi (valeur {}, seuil {thresh})",
                attr.value.unwrap_or(0)
            ),
            None,
        ));
    }
    if result.failed_in_the_past {
        findings.push(finding(
            Source::Manufacturer,
            Status::Warning,
            format!(
                "seuil constructeur franchi par le passé (pire valeur {}, seuil {thresh})",
                attr.worst.unwrap_or(0)
            ),
            None,
        ));
    }

    let (Some(metadata), Some(rate)) = (metadata, result.failure_rate) else {
        return;
    };
    let status = failure_rate_status(metadata.critical, rate).to_status();
    if status == Status::Pass {
        return;
    }
    let mut message = match (metadata.critical, status) {
        (true, _) => "risque de panne élevé pour un attribut critique (seuil 10 %)",
        (false, Status::Fail) => "risque de panne élevé (seuil 20 %)",
        (false, _) => "risque de panne accru (seuil 10 %)",
    }
    .to_string();
    match metadata.display_type {
        DisplayType::Normalized => {
            message.push_str(&format!(", valeur normalisée {}", attr.value.unwrap_or(0)))
        }
        DisplayType::Transformed => message.push_str(&format!(
            ", valeur interprétée {}",
            result.transformed_value
        )),
        DisplayType::Raw | DisplayType::Unspecified => {}
    }
    if metadata.use_delta_evaluation {
        message.push_str(CUMULATIVE_HINT);
    }
    findings.push(finding(Source::Backblaze, status, message, Some(rate)));
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::ata_thresholds::ATA_METADATA;
    use super::*;

    const PASSED: AttrStatus = AttrStatus::PASSED;
    const WARNING: AttrStatus = AttrStatus::WARNING_SCRUTINY;
    const FAILED: AttrStatus = AttrStatus::FAILED_SCRUTINY;

    fn attr(value: serde_json::Value) -> AtaAttribute {
        serde_json::from_value(value).unwrap()
    }

    fn device(value: serde_json::Value) -> SmartctlOutput {
        serde_json::from_value(value).unwrap()
    }

    fn meta(id: i64) -> &'static AtaAttributeMetadata {
        ata_metadata(id).unwrap()
    }

    fn one_bucket(annual_failure_rate: f64, error_interval: [f64; 2]) -> [ObservedThreshold; 1] {
        [ObservedThreshold {
            low: 0,
            high: 10,
            annual_failure_rate,
            error_interval,
        }]
    }

    /// Status of `value` scored against a bundled attribute, the fork's `ValidateThreshold`.
    fn bundled(id: i64, value: i64) -> (AttrStatus, Option<f64>) {
        let m = meta(id);
        let rate = observed_failure_rate_at(m.ideal, m.observed_thresholds, value);
        (
            rate.map_or(PASSED, |r| failure_rate_status(m.critical, r)),
            rate,
        )
    }

    fn assert_close(actual: Option<f64>, expected: f64) {
        let actual = actual.expect("a bucket should apply");
        assert!((actual - expected).abs() < 0.001, "{actual} != {expected}");
    }

    // The tests below mirror the fork's smart_ata_attribute_test.go; the Go test name is given
    // above each one.

    // TestValidateThreshold_NonZeroAnnualFailureRate_Unchanged
    #[test]
    fn non_zero_rate_is_used_as_is() {
        let rate = observed_failure_rate_at(Ideal::Unspecified, &one_bucket(0.15, [0.12, 0.18]), 5);
        assert_close(rate, 0.15);
        assert_eq!(failure_rate_status(true, rate.unwrap()), FAILED);
    }

    // TestValidateThreshold_ZeroRate_ZeroInterval_NoChange
    #[test]
    fn zero_rate_with_zero_interval_stays_zero() {
        let rate = observed_failure_rate_at(Ideal::Unspecified, &one_bucket(0.0, [0.0, 0.0]), 5);
        assert_eq!(rate, Some(0.0));
        assert_eq!(failure_rate_status(false, 0.0), PASSED);
    }

    // TestValidateThreshold_ZeroRate_RealInterval_MidpointUsed
    // TestValidateThreshold_NonCriticalAttribute_InferredRate_TriggersWarning
    #[test]
    fn zero_rate_with_real_interval_uses_the_midpoint() {
        let rate = observed_failure_rate_at(Ideal::Unspecified, &one_bucket(0.0, [0.08, 0.12]), 5);
        assert_close(rate, 0.10);
        assert_eq!(failure_rate_status(false, rate.unwrap()), WARNING);
    }

    // TestValidateThreshold_CriticalAttribute_InferredRate_TriggersFailure
    #[test]
    fn inferred_rate_fails_a_critical_attribute() {
        let rate = observed_failure_rate_at(Ideal::Unspecified, &one_bucket(0.0, [0.10, 0.14]), 5);
        assert_close(rate, 0.12);
        assert_eq!(failure_rate_status(true, rate.unwrap()), FAILED);
    }

    // TestValidateThreshold_NonCriticalAttribute_InferredRate_TriggersFailure
    #[test]
    fn inferred_rate_fails_a_non_critical_attribute() {
        let rate = observed_failure_rate_at(Ideal::Unspecified, &one_bucket(0.0, [0.18, 0.26]), 5);
        assert_close(rate, 0.22);
        assert_eq!(failure_rate_status(false, rate.unwrap()), FAILED);
    }

    #[test]
    fn failure_rate_cutoffs() {
        assert_eq!(failure_rate_status(true, 0.0999), PASSED);
        assert_eq!(failure_rate_status(true, 0.10), FAILED);
        assert_eq!(failure_rate_status(false, 0.0999), PASSED);
        assert_eq!(failure_rate_status(false, 0.10), WARNING);
        assert_eq!(failure_rate_status(false, 0.1999), WARNING);
        assert_eq!(failure_rate_status(false, 0.20), FAILED);
    }

    #[test]
    fn without_an_ideal_only_the_containing_bucket_is_scored() {
        let buckets = one_bucket(0.5, [0.4, 0.6]);
        assert_eq!(
            observed_failure_rate_at(Ideal::Unspecified, &buckets, 0),
            None
        );
        assert_eq!(
            observed_failure_rate_at(Ideal::Unspecified, &buckets, 10),
            Some(0.5)
        );
        assert_eq!(
            observed_failure_rate_at(Ideal::Unspecified, &buckets, 11),
            None
        );
        // with a direction the worst rate is carried past the last bucket
        assert_eq!(
            observed_failure_rate_at(Ideal::Low, &buckets, 11),
            Some(0.5)
        );
        assert_eq!(observed_failure_rate_at(Ideal::Low, &buckets, 0), None);
        assert_eq!(observed_failure_rate_at(Ideal::High, &buckets, 11), None);
        assert_eq!(
            observed_failure_rate_at(Ideal::High, &buckets, -3),
            Some(0.5)
        );
    }

    // TestValidateThreshold_Attr177_* (Wear Leveling Count, normalized, ideal high)
    #[test]
    fn attr177_wear_leveling_count() {
        for (normalized, fails) in [
            (100, false),
            (85, false),
            (40, false),
            (15, true),
            (0, true),
            (25, false),
            (24, true),
            (110, false),
        ] {
            let result = evaluate_attribute(&attr(json!({"id": 177, "value": normalized})), false);
            let rate = result.failure_rate.unwrap();
            assert_eq!(rate >= 0.10, fails, "normalized {normalized}: rate {rate}");
            assert_eq!(result.status.has(FAILED), fails, "normalized {normalized}");
            assert!(!result.status.has(WARNING), "normalized {normalized}");
        }
    }

    // TestPopulateAttributeStatus_FallsBackWithoutProfile
    #[test]
    fn attr5_forty_reallocated_sectors_fail() {
        let result = evaluate_attribute(&attr(json!({"id": 5, "raw": {"value": 40}})), false);
        assert_close(result.failure_rate, 0.23589260654405794);
        assert!(result.status.has(FAILED));
    }

    // TestAtaAttributeNamesSemanticallyMatch
    #[test]
    fn attribute_names_semantic_match() {
        assert!(attribute_names_semantically_match(
            "High_Fly_Writes",
            "High Fly Writes"
        ));
        assert!(attribute_names_semantically_match(
            "Runtime_Bad_Block",
            "SATA Downshift Error Count or Runtime Bad Block"
        ));
        assert!(attribute_names_semantically_match(
            "Factory_Bad_Block_Ct",
            "Factory Bad Block Count"
        ));
        assert!(!attribute_names_semantically_match(
            "Factory_Bad_Block_Ct",
            "High Fly Writes"
        ));
        assert!(!attribute_names_semantically_match("", "High Fly Writes"));
        assert!(!attribute_names_semantically_match(
            "Total_Count",
            "High Fly Writes"
        ));
    }

    // TestPopulateAttributeStatus_SkipsGenericObservedThresholdsForVendorSpecificAtaSsd
    #[test]
    fn vendor_specific_ssd_attribute_skips_generic_buckets() {
        let factory_bad_blocks = attr(json!({
            "id": 189, "name": "Factory_Bad_Block_Ct", "value": 100, "raw": {"value": 81}
        }));

        let on_ssd = evaluate_attribute(&factory_bad_blocks, true);
        assert_eq!(on_ssd.status, PASSED);
        assert!(on_ssd.skipped_vendor_specific_ssd);
        assert_eq!(on_ssd.failure_rate, None);

        // the same id and value on a spinning drive is scored: 81 high-fly writes
        let on_hdd = evaluate_attribute(&factory_bad_blocks, false);
        assert!(!on_hdd.skipped_vendor_specific_ssd);
        assert!(on_hdd.status.has(FAILED));
    }

    #[test]
    fn ssd_attribute_with_a_matching_name_is_still_scored() {
        let result = evaluate_attribute(
            &attr(json!({"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 3}})),
            true,
        );
        assert!(!result.skipped_vendor_specific_ssd);
        assert!(result.status.has(FAILED));
    }

    /// The name match is literal, token by token. smartctl's usual names for 5, 187, 196 and
    /// 199 ("UDMA_...") do not match the fork's display names ("sector" is not "sectors"), so
    /// on an ATA SSD the fork leaves these attributes to the manufacturer threshold alone.
    #[test]
    fn smartctl_names_that_do_not_match_are_skipped_on_ssd() {
        for (id, smartctl_name) in [
            (5, "Reallocated_Sector_Ct"),
            (187, "Reported_Uncorrect"),
            (196, "Reallocated_Event_Count"),
            (199, "UDMA_CRC_Error_Count"),
        ] {
            let row = attr(json!({"id": id, "name": smartctl_name, "raw": {"value": 5000}}));
            let on_ssd = evaluate_attribute(&row, true);
            assert!(on_ssd.skipped_vendor_specific_ssd, "attribute {id}");
            assert_eq!(on_ssd.status, PASSED, "attribute {id}");
            assert!(
                evaluate_attribute(&row, false).status.has(FAILED),
                "attribute {id}"
            );
        }
        // names that do match, and are scored on an SSD as well
        for (id, smartctl_name) in [
            (183, "Runtime_Bad_Block"),
            (188, "Command_Timeout"),
            (197, "Current_Pending_Sector"),
            (198, "Offline_Uncorrectable"),
            (199, "CRC_Error_Count"),
        ] {
            let row = attr(
                json!({"id": id, "name": smartctl_name, "raw": {"value": 5000, "string": "5000"}}),
            );
            let on_ssd = evaluate_attribute(&row, true);
            assert!(!on_ssd.skipped_vendor_specific_ssd, "attribute {id}");
            assert!(on_ssd.status.has(FAILED), "attribute {id}");
        }
    }

    #[test]
    fn past_failure_is_not_hidden_by_the_ssd_skip() {
        // the skip only applies to an attribute that is still "passed"
        let result = evaluate_attribute(
            &attr(json!({
                "id": 189, "name": "Factory_Bad_Block_Ct", "when_failed": "past", "raw": {"value": 81}
            })),
            true,
        );
        assert!(!result.skipped_vendor_specific_ssd);
        assert!(result.status.has(WARNING));
        assert!(result.status.has(FAILED));
    }

    // TestValidateThreshold_ObservedSeverityNeverImprovesAsAttributeWorsens
    #[test]
    fn observed_severity_never_improves_as_an_attribute_worsens() {
        fn rank(status: AttrStatus) -> u8 {
            if status.has(FAILED) {
                2
            } else if status.has(WARNING) {
                1
            } else {
                0
            }
        }

        for m in ATA_METADATA
            .iter()
            .filter(|m| !m.observed_thresholds.is_empty())
        {
            // every bucket edge, one value either side of it, and zero
            let mut values = vec![0];
            for bucket in m.observed_thresholds {
                values.extend([
                    bucket.low - 1,
                    bucket.low,
                    bucket.low + 1,
                    bucket.high,
                    bucket.high + 1,
                ]);
            }
            values.sort_unstable();
            values.dedup();
            // walk from the healthiest value to the worst one
            if m.ideal == Ideal::High {
                values.reverse();
            }

            let mut worst_so_far = 0;
            for value in values {
                let current = rank(bundled(m.id, value).0);
                assert!(
                    current >= worst_so_far,
                    "attribute {} ({}) is milder at {value} than at a healthier value",
                    m.id,
                    m.display_name
                );
                worst_so_far = current;
            }
        }
    }

    // TestValidateThreshold_Attr198_BeyondLastBucket_Fails
    // TestValidateThreshold_Attr198_ZeroSectors_Passes
    #[test]
    fn attr198_offline_uncorrectable() {
        // seventeen sectors is past the last bucket
        assert_eq!(bundled(198, 17).0, FAILED);
        assert_eq!(bundled(198, 0).0, PASSED);
    }

    // TestValidateThreshold_Attr5_BucketEdgeUnchanged
    #[test]
    fn attr5_bucket_edge() {
        assert_eq!(bundled(5, 16).0, PASSED);
        assert_eq!(bundled(5, 17).0, FAILED);
        // far past the last bucket (70000): still the worst rate of the covered range
        assert_eq!(bundled(5, 1_000_000), (FAILED, Some(2.0659987547404763)));
    }

    // TestValidateThreshold_Attr4_UsageCounterNeverScoresAVerdict
    // TestValidateThreshold_Attr192_UsageCounterNeverScoresAVerdict
    #[test]
    fn usage_counters_never_score_a_verdict() {
        for value in [0, 9, 27, 69, 95, 500, 1860] {
            assert_eq!(
                bundled(4, value),
                (PASSED, None),
                "start/stop count {value}"
            );
        }
        for value in [0, 7, 17, 234, 909, 1600, 5000] {
            assert_eq!(
                bundled(192, value),
                (PASSED, None),
                "power-off retract count {value}"
            );
        }
    }

    // TestValidateThreshold_Attr3_VendorNormalizedSpinUpTime_Passes
    #[test]
    fn attr3_vendor_normalized_spin_up_time_passes() {
        let result = evaluate_attribute(
            &attr(json!({"id": 3, "value": 83, "raw": {"value": 349}})),
            false,
        );
        assert_eq!(result.status, PASSED);
        assert_eq!(result.failure_rate, None);
    }

    // TestValidateThreshold_CriticalWithoutObservedThresholds_StaysPassed
    #[test]
    fn critical_attribute_without_buckets_stays_passed() {
        assert!(meta(201).critical);
        let result = evaluate_attribute(
            &attr(json!({"id": 201, "value": 23, "raw": {"value": 23}})),
            false,
        );
        assert_eq!(result.status, PASSED);
        assert_eq!(result.failure_rate, None);
    }

    // TestPopulateAttributeStatus_WhenFailed
    #[test]
    fn when_failed() {
        for (when_failed, expected) in [
            ("now", AttrStatus::FAILED_SMART),
            ("past", WARNING),
            ("Now", AttrStatus::FAILED_SMART),
            ("", PASSED),
            // the pre-JSON smartctl wording is not a value smartctl --json emits
            ("FAILING_NOW", PASSED),
        ] {
            let result = evaluate_attribute(
                &attr(json!({"id": 2, "value": 100, "thresh": 0, "when_failed": when_failed})),
                false,
            );
            assert_eq!(result.status, expected, "when_failed {when_failed:?}");
        }
    }

    #[test]
    fn failing_now_ends_the_evaluation() {
        // 40 reallocated sectors would also fail the observed threshold, but the fork returns
        // as soon as the manufacturer threshold is failing.
        let result = evaluate_attribute(
            &attr(
                json!({"id": 5, "value": 1, "thresh": 5, "when_failed": "now", "raw": {"value": 40}}),
            ),
            false,
        );
        assert_eq!(result.status, AttrStatus::FAILED_SMART);
        assert_eq!(result.failure_rate, None);
    }

    #[test]
    fn unknown_attribute_only_has_the_manufacturer_layer() {
        let passed = evaluate_attribute(
            &attr(json!({"id": 253, "value": 1, "raw": {"value": 999}})),
            false,
        );
        assert_eq!(passed.status, PASSED);
        let past = evaluate_attribute(&attr(json!({"id": 253, "when_failed": "past"})), false);
        assert_eq!(past.status, WARNING);
    }

    #[test]
    fn transformed_attribute_is_scored_on_the_transformed_value() {
        // Seagate packed command timeout: 2 timeouts in the low word, large raw value
        let packed = attr(
            json!({"id": 188, "value": 100, "raw": {"value": 8_590_065_666_i64, "string": "2 2 2"}}),
        );
        let result = evaluate_attribute(&packed, false);
        assert_eq!(result.transformed_value, 2);
        assert_eq!(result.status, PASSED);
        assert_close(result.failure_rate, 0.024893587674442153);

        // more than 100 timeouts crosses the 10 % bucket of this critical attribute
        let many = attr(json!({"id": 188, "value": 100, "raw": {"value": 101, "string": "101"}}));
        assert!(evaluate_attribute(&many, false).status.has(FAILED));
    }

    #[test]
    fn rotation_rate_decides_ssd() {
        assert!(is_ata_ssd(&device(json!({"rotation_rate": 0}))));
        assert!(!is_ata_ssd(&device(json!({"rotation_rate": 7200}))));
        // absent decodes to 0 in the fork
        assert!(is_ata_ssd(&device(json!({}))));
    }

    fn run(dev: serde_json::Value) -> Vec<Finding> {
        let mut findings = Vec::new();
        assert!(evaluate(&device(dev), &mut findings));
        findings
    }

    #[test]
    fn findings_for_manufacturer_and_observed_layers() {
        let findings = run(json!({
            "rotation_rate": 7200,
            "ata_smart_attributes": {"table": [
                {"id": 5, "name": "Reallocated_Sector_Ct", "value": 1, "worst": 1, "thresh": 5,
                 "when_failed": "now", "raw": {"value": 2000, "string": "2000"}},
                {"id": 190, "name": "Airflow_Temperature_Cel", "value": 72, "worst": 37, "thresh": 40,
                 "when_failed": "past", "raw": {"value": 28, "string": "28"}},
                {"id": 197, "name": "Current_Pending_Sector", "value": 100, "worst": 100, "thresh": 0,
                 "when_failed": "", "raw": {"value": 3, "string": "3"}},
                {"id": 11, "name": "Calibration_Retry_Count", "value": 100, "worst": 100, "thresh": 0,
                 "when_failed": "", "raw": {"value": 0, "string": "0"}},
                {"id": 199, "name": "UDMA_CRC_Error_Count", "value": 200, "worst": 200, "thresh": 0,
                 "when_failed": "", "raw": {"value": 3, "string": "3"}}
            ]}
        }));
        let summary: Vec<(&str, Source, Status)> = findings
            .iter()
            .map(|f| (f.attribute.as_str(), f.source, f.status))
            .collect();
        assert_eq!(
            summary,
            [
                ("5", Source::Manufacturer, Status::Fail),
                ("190", Source::Manufacturer, Status::Warning),
                ("197", Source::Backblaze, Status::Fail),
                ("199", Source::Backblaze, Status::Warning),
            ]
        );
        assert_eq!(findings[0].name, "Reallocated Sectors Count");
        assert_eq!(findings[0].raw_value, Some(2000));
        assert_eq!(findings[0].annual_failure_rate, None);
        assert!(findings[1].message.contains("pire valeur 37, seuil 40"));
        assert_close(findings[2].annual_failure_rate, 0.6823772508117681);
        assert!(findings[3].message.ends_with(CUMULATIVE_HINT));
        assert!(super::super::is_cumulative_counter(&findings[3]));
        assert!(!super::super::is_cumulative_counter(&findings[2]));
    }

    #[test]
    fn empty_table_is_not_usable_data() {
        let mut findings = Vec::new();
        assert!(!evaluate(
            &device(json!({"ata_smart_attributes": {"table": []}})),
            &mut findings
        ));
        assert!(!evaluate(&device(json!({})), &mut findings));
        assert!(findings.is_empty());
    }
}
