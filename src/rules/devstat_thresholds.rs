//! ATA Device Statistics metadata (GP log 0x04).
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `AtaDeviceStatisticsMetadata` and `AtaDeviceStatsMetadata` in
//! `webapp/backend/pkg/thresholds/ata_attribute_metadata.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! [`ATA_DEVICE_STATS_METADATA`] is a mechanical conversion of the fork's map: same
//! statistics, same order, same numbers. The English descriptions and the display type
//! (always "raw") are left out. The Seagate FARM layer ([`super::farm`]) uses the same
//! metadata type, as it does in the fork.

use super::Ideal;

/// The fork's `AtaDeviceStatisticsMetadata`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceStatisticMetadata {
    /// Key of the fork's map: `devstat_<page>_<offset>`, or a `farm_` name.
    pub id: &'static str,
    pub display_name: &'static str,
    pub ideal: Ideal,
    pub critical: bool,
    /// Fixed threshold; 0 means none (the fork then only warns on critical error counts).
    pub threshold: i64,
}

pub(super) const fn meta(
    id: &'static str,
    display_name: &'static str,
    ideal: Ideal,
    critical: bool,
    threshold: i64,
) -> DeviceStatisticMetadata {
    DeviceStatisticMetadata { id, display_name, ideal, critical, threshold }
}

/// `MaxReasonableFailureCount`: an `Ideal::Low` statistic above this is taken for corrupted
/// data and is not judged (fork issue #84).
pub const MAX_REASONABLE_FAILURE_COUNT: i64 = 1_000_000;

/// Default of the fork's `failures.ignored.devstat` setting: statistics whose
/// `FailedScrutiny` does not fail the device. The fork ships it empty.
pub const IGNORED_DEVSTAT: &[&str] = &[];

/// `isDevstatIgnored`.
pub fn is_devstat_ignored(id: &str) -> bool {
    IGNORED_DEVSTAT.contains(&id)
}

/// Metadata of a device statistic id (`devstat_<page>_<offset>`), if Scrutiny knows it.
pub fn devstat_metadata(id: &str) -> Option<&'static DeviceStatisticMetadata> {
    ATA_DEVICE_STATS_METADATA.iter().find(|m| m.id == id)
}

/// The fork's `AtaDeviceStatsMetadata` map, display names verbatim.
pub static ATA_DEVICE_STATS_METADATA: &[DeviceStatisticMetadata] = &[
    // Page 7 (Solid State Device Statistics)
    meta("devstat_7_8", "Percentage Used Endurance Indicator", Ideal::Low, true, 100),
    // Page 1 (General Statistics)
    meta("devstat_1_8", "Lifetime Power-On Resets", Ideal::Unspecified, false, 0),
    meta("devstat_1_16", "Power-on Hours (Device Stats)", Ideal::Unspecified, false, 0),
    meta("devstat_1_24", "Logical Sectors Written", Ideal::Unspecified, false, 0),
    meta("devstat_1_32", "Number of Write Commands", Ideal::Unspecified, false, 0),
    meta("devstat_1_40", "Logical Sectors Read", Ideal::Unspecified, false, 0),
    meta("devstat_1_48", "Number of Read Commands", Ideal::Unspecified, false, 0),
    // Page 5 (Temperature Statistics)
    meta("devstat_5_8", "Current Temperature (Device Stats)", Ideal::Unspecified, false, 0),
    meta("devstat_5_16", "Average Short-term Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_24", "Average Long-term Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_32", "Highest Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_40", "Lowest Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_88", "Time in Over-temperature", Ideal::Low, false, 0),
    // Page 2 (Free-Fall Statistics)
    meta("devstat_2_16", "Number of Free-Fall Events Detected", Ideal::Low, false, 0),
    // Page 4 (General Errors Statistics)
    meta("devstat_4_8", "Number of Reported Uncorrectable Errors", Ideal::Low, true, 0),
    meta("devstat_4_16", "Number of Interface CRC Errors", Ideal::Low, false, 0),
    // Page 6 (Transport Statistics)
    meta("devstat_6_8", "Number of Hardware Resets", Ideal::Low, false, 0),
    meta("devstat_6_16", "Number of ASR Events", Ideal::Low, false, 0),
    meta("devstat_6_24", "Number of Interface CRC Errors (Transport)", Ideal::Low, false, 0),
    // Page 3 (Rotating Media Statistics)
    meta("devstat_3_8", "Spindle Motor Power-on Hours", Ideal::Unspecified, false, 0),
    meta("devstat_3_16", "Head Flying Hours", Ideal::Unspecified, false, 0),
    meta("devstat_3_24", "Head Load Events", Ideal::Unspecified, false, 0),
    meta("devstat_3_32", "Number of Reallocated Logical Sectors", Ideal::Low, true, 0),
    meta("devstat_3_40", "Read Recovery Attempts", Ideal::Low, false, 0),
    meta("devstat_3_48", "Number of Mechanical Start Failures", Ideal::Low, true, 0),
    meta("devstat_3_56", "Number of Reallocation Candidate Logical Sectors", Ideal::Low, true, 0),
    meta("devstat_3_64", "Number of High Priority Unload Events", Ideal::Low, false, 0),
    // Page 5 (Temperature Statistics), additional entries
    meta("devstat_5_48", "Highest Average Short-term Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_56", "Lowest Average Short-term Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_64", "Highest Average Long-term Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_72", "Lowest Average Long-term Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_80", "Time in Under-temperature", Ideal::Low, false, 0),
    meta("devstat_5_96", "Specified Maximum Operating Temperature", Ideal::Unspecified, false, 0),
    meta("devstat_5_104", "Specified Minimum Operating Temperature", Ideal::Unspecified, false, 0),
    // Page 4 (General Errors Statistics), additional entry
    meta("devstat_4_24", "Number of Unrecoverable Read Errors", Ideal::Low, true, 0),
    // Page 255 (Vendor Specific Statistics)
    meta("devstat_255_8", "Vendor Specific Statistic 1", Ideal::Unspecified, false, 0),
    meta("devstat_255_16", "Vendor Specific Statistic 2", Ideal::Unspecified, false, 0),
    meta("devstat_255_24", "Vendor Specific Statistic 3", Ideal::Unspecified, false, 0),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_the_fork() {
        assert_eq!(ATA_DEVICE_STATS_METADATA.len(), 38);
        for (index, metadata) in ATA_DEVICE_STATS_METADATA.iter().enumerate() {
            assert!(metadata.id.starts_with("devstat_"), "{}", metadata.id);
            assert!(
                ATA_DEVICE_STATS_METADATA[..index].iter().all(|m| m.id != metadata.id),
                "duplicate id {}",
                metadata.id
            );
        }
        // the only statistic with a fixed threshold
        let with_threshold: Vec<_> = ATA_DEVICE_STATS_METADATA
            .iter()
            .filter(|m| m.threshold != 0)
            .map(|m| (m.id, m.threshold))
            .collect();
        assert_eq!(with_threshold, [("devstat_7_8", 100)]);
        // the critical ones: those warn on a non-zero count, or fail on their threshold
        let critical: Vec<_> = ATA_DEVICE_STATS_METADATA
            .iter()
            .filter(|m| m.critical)
            .map(|m| m.id)
            .collect();
        assert_eq!(
            critical,
            [
                "devstat_7_8",
                "devstat_4_8",
                "devstat_3_32",
                "devstat_3_48",
                "devstat_3_56",
                "devstat_4_24"
            ]
        );
        assert!(ATA_DEVICE_STATS_METADATA.iter().all(|m| m.ideal != Ideal::High));
        assert!(ATA_DEVICE_STATS_METADATA.iter().filter(|m| m.critical).all(|m| m.ideal == Ideal::Low));
    }

    #[test]
    fn lookup_is_by_exact_id() {
        assert_eq!(devstat_metadata("devstat_7_8").unwrap().display_name, "Percentage Used Endurance Indicator");
        assert!(devstat_metadata("devstat_99_99").is_none());
        assert!(devstat_metadata("devstat_7_08").is_none());
        assert!(devstat_metadata("farm_poh").is_none());
    }

    #[test]
    fn nothing_is_ignored_by_default() {
        // config.go sets no default for failures.ignored.devstat; example.scrutiny.yaml: []
        assert!(IGNORED_DEVSTAT.is_empty());
        assert!(!is_devstat_ignored("devstat_7_8"));
    }
}
