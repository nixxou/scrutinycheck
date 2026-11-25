//! ATA attribute metadata and observed-threshold buckets.
//!
//! Ported from Scrutiny, Starosdev fork (`master`):
//! `webapp/backend/pkg/thresholds/ata_attribute_metadata.go`
//! <https://github.com/Starosdev/scrutiny>, MIT License, Copyright (c) 2020 Jason Kulatunga.
//! See `THIRD_PARTY_NOTICES.md` at the crate root.
//!
//! [`ATA_METADATA`] is a mechanical conversion of the fork's `AtaMetadata` map: same
//! attributes, same order, same numbers. The English descriptions are left out. The buckets
//! are annual failure rates that Scrutiny derived from Backblaze drive statistics; attributes
//! 3, 184 and 195 (vendor-scaled normalized values, fork PR #1088) and 4 and 192 (usage
//! counters, fork PR #1094) carry none.

use super::Ideal;

/// Which value of an attribute the buckets are compared with (`DisplayType` in the fork).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayType {
    /// The fork leaves the field empty for a few attributes; it then scores the raw value.
    Unspecified,
    Raw,
    Normalized,
    Transformed,
}

/// Extracts a comparable value from `(normalized, raw, raw string)`.
pub type Transform = fn(i64, i64, &str) -> i64;

/// One observed failure-rate bucket.
///
/// A bucket with `low == high` covers that single value; otherwise it covers
/// `low < value <= high`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ObservedThreshold {
    pub low: i64,
    pub high: i64,
    /// Fraction per year: 0.06 is 6 %.
    pub annual_failure_rate: f64,
    /// Confidence interval of the rate, `[low, high]`.
    pub error_interval: [f64; 2],
}

#[derive(Debug, Clone, Copy)]
pub struct AtaAttributeMetadata {
    pub id: i64,
    pub display_name: &'static str,
    pub ideal: Ideal,
    pub critical: bool,
    /// Cumulative counter that the fork judges by trend, not by absolute value.
    pub use_delta_evaluation: bool,
    pub display_type: DisplayType,
    pub transform: Option<Transform>,
    pub transform_value_unit: Option<&'static str>,
    /// Must be expressed in the unit selected by `display_type`.
    pub observed_thresholds: &'static [ObservedThreshold],
}

/// Metadata of an ATA attribute id, if Scrutiny knows it.
pub fn ata_metadata(id: i64) -> Option<&'static AtaAttributeMetadata> {
    ATA_METADATA
        .binary_search_by_key(&id, |m| m.id)
        .ok()
        .map(|index| &ATA_METADATA[index])
}

/// Attribute 9, Power-On Hours: hours from the forms smartctl prints.
pub fn transform_power_on_hours(_normalized: i64, raw: i64, raw_string: &str) -> i64 {
    // smartctl "h+m+s" format, e.g. "1730h+05m+02.453s"
    if let Some(index) = raw_string.find("h+")
        && index > 0
        && let Ok(hours) = raw_string[..index].parse::<i64>()
    {
        return hours;
    }

    // smartctl parenthetical hours, e.g. "103800 (1730 hours)" when the raw value is in minutes
    if raw_string.contains("hours)")
        && let Some(paren) = raw_string.find('(')
    {
        let inner = &raw_string[paren + 1..];
        if let Some(space) = inner.find(' ')
            && space > 0
            && let Ok(hours) = inner[..space].parse::<i64>()
        {
            return hours;
        }
    }

    // Packed 48-bit raw value: some manufacturers keep other data in the upper bytes and the
    // hours in the lower 32 bits.
    if raw > 0xFFFF_FFFF {
        return raw & 0xFFFF_FFFF;
    }

    raw
}

/// Attribute 188, Command Timeout: total timeout count out of Seagate's packed raw value.
pub fn transform_command_timeout(_normalized: i64, raw: i64, raw_string: &str) -> i64 {
    // Seagate prints three numbers; accept them when each is <= the next (sanity check).
    // See https://github.com/AnalogJ/scrutiny/issues/522
    let pieces: Vec<&str> = raw_string.split(' ').collect();
    if pieces.len() == 3 {
        let mut values = [0i64; 3];
        for (value, piece) in values.iter_mut().zip(&pieces) {
            match piece.parse::<i64>() {
                Ok(parsed) => *value = parsed,
                Err(_) => return raw,
            }
        }
        if values[2] >= values[1] && values[1] >= values[0] {
            return values[2];
        }
    }

    // Packed 48-bit format, three 16-bit fields: bytes 1-0 total timeouts, bytes 3-2 commands
    // that took more than 5 s, bytes 5-4 commands that took more than 7.5 s.
    if raw > 0xFFFF {
        return raw & 0xFFFF;
    }

    raw
}

/// Attribute 194, Temperature: the lowest byte of the raw value is the temperature in °C.
pub fn transform_temperature(_normalized: i64, raw: i64, _raw_string: &str) -> i64 {
    raw & 0xFF
}

const fn bucket(
    low: i64,
    high: i64,
    annual_failure_rate: f64,
    error_interval: [f64; 2],
) -> ObservedThreshold {
    ObservedThreshold {
        low,
        high,
        annual_failure_rate,
        error_interval,
    }
}

/// Sorted by attribute id (see [`ata_metadata`]). One bucket per line, as generated from the
/// fork's table, to keep it comparable with the Go source.
#[rustfmt::skip]
pub static ATA_METADATA: &[AtaAttributeMetadata] = &[
    AtaAttributeMetadata {
        id: 1,
        display_name: "Read Error Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 2,
        display_name: "Throughput Performance",
        ideal: Ideal::High,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 3,
        display_name: "Spin-Up Time",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 4,
        display_name: "Start/Stop Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 5,
        display_name: "Reallocated Sectors Count",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.025169175350572493, [0.022768612038746357, 0.027753988579272894]),
            bucket(1, 4, 0.027432608477803388, [0.010067283827589948, 0.05970923963096652]),
            bucket(4, 16, 0.07501976284584981, [0.039944864177334186, 0.12828607921150972]),
            bucket(16, 70, 0.23589260654405794, [0.1643078435800227, 0.32806951196017664]),
            bucket(70, 260, 0.36193219378600433, [0.2608488901774093, 0.4892271827875412]),
            bucket(260, 1100, 0.5676621428968173, [0.4527895568499355, 0.702804359408436]),
            bucket(1100, 4500, 1.5028253400346423, [1.2681757596263297, 1.768305221795894]),
            bucket(4500, 17000, 2.0659987547404763, [1.6809790460512237, 2.512808045182302]),
            bucket(17000, 70000, 1.7755385684503124, [1.2796520259849835, 2.400012341226441]),
        ],
    },
    AtaAttributeMetadata {
        id: 6,
        display_name: "Read Channel Margin",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 7,
        display_name: "Seek Error Rate",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 8,
        display_name: "Seek Time Performance",
        ideal: Ideal::High,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 9,
        display_name: "Power-On Hours",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Transformed,
        transform: Some(transform_power_on_hours),
        transform_value_unit: Some("hours"),
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 10,
        display_name: "Spin Retry Count",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.05459827163896099, [0.05113785787727033, 0.05823122757702782]),
            bucket(0, 80, 0.5555555555555556, [0.014065448880161053, 3.095357439410498]),
        ],
    },
    AtaAttributeMetadata {
        id: 11,
        display_name: "Recalibration Retries or Calibration Retry Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.04658866433672694, [0.03357701137320878, 0.06297433993055492]),
            bucket(0, 80, 0.5555555555555556, [0.014065448880161053, 3.095357439410498]),
            bucket(80, 160, 0.0, [0.0, 0.0]),
            bucket(160, 240, 0.0, [0.0, 0.0]),
            bucket(240, 320, 0.0, [0.0, 0.0]),
            bucket(320, 400, 0.0, [0.0, 0.0]),
            bucket(400, 480, 0.0, [0.0, 0.0]),
            bucket(480, 560, 0.0, [0.0, 0.0]),
        ],
    },
    AtaAttributeMetadata {
        id: 12,
        display_name: "Power Cycle Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 13,
        display_name: "Soft Read Error Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 18,
        display_name: "Head Health Self-Assessment",
        ideal: Ideal::High,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 22,
        display_name: "Current Helium Level",
        ideal: Ideal::High,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 23,
        display_name: "Helium Condition Lower",
        ideal: Ideal::High,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 24,
        display_name: "Helium Condition Upper",
        ideal: Ideal::High,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 170,
        display_name: "Available Reserved Space",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 171,
        display_name: "SSD Program Fail Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 172,
        display_name: "SSD Erase Fail Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 173,
        display_name: "SSD Wear Leveling Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 174,
        display_name: "Unexpected Power Loss Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Unspecified,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 175,
        display_name: "Power Loss Protection Failure",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 176,
        display_name: "Erase Fail Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 177,
        display_name: "Wear Leveling Count",
        ideal: Ideal::High,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.30, [0.20, 0.40]),
            bucket(0, 9, 0.20, [0.15, 0.25]),
            bucket(9, 24, 0.12, [0.09, 0.15]),
            bucket(24, 49, 0.05, [0.03, 0.07]),
            bucket(49, 74, 0.02, [0.01, 0.03]),
            bucket(74, 99, 0.01, [0.005, 0.015]),
            bucket(99, 255, 0.008, [0.004, 0.012]),
        ],
    },
    AtaAttributeMetadata {
        id: 179,
        display_name: "Used Reserved Block Count Total",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 180,
        display_name: "Unused Reserved Block Count Total",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 181,
        display_name: "Program Fail Count Total",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 182,
        display_name: "Erase Fail Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 183,
        display_name: "SATA Downshift Error Count or Runtime Bad Block",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.09084549203210031, [0.08344373475686712, 0.09872777224842152]),
            bucket(1, 2, 0.05756065656498585, [0.04657000847949464, 0.07036491775108872]),
            bucket(2, 4, 0.6193088626208925, [0.41784508895529787, 0.8841019099092139]),
            bucket(4, 8, 0.5533447034299792, [0.31628430884775033, 0.8985971312402635]),
            bucket(8, 16, 0.3882388694727245, [0.21225380267814295, 0.6513988534774338]),
            bucket(16, 35, 0.37116708385481856, [0.19763084005134446, 0.6347070173754686]),
            bucket(35, 70, 0.2561146752205292, [0.10297138269895259, 0.5276941165819332]),
            bucket(70, 130, 0.40299684542586756, [0.16202563309223209, 0.8303275247667772]),
            bucket(130, 260, 0.0, [0.0, 0.0]),
        ],
    },
    AtaAttributeMetadata {
        id: 184,
        display_name: "End-to-End error",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 185,
        display_name: "Head Stability",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 186,
        display_name: "Induced Op-Vibration Detection",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 187,
        display_name: "Reported Uncorrectable Errors",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.028130798308190524, [0.024487830609364304, 0.032162944988161336]),
            bucket(1, 1, 0.33877621175661743, [0.22325565823630591, 0.4929016016666955]),
            bucket(1, 3, 0.24064820598237213, [0.14488594021076606, 0.3758019832614595]),
            bucket(3, 6, 0.5014425058387142, [0.3062941096766342, 0.7744372808405151]),
            bucket(6, 11, 0.38007108544136836, [0.2989500188963677, 0.4764223967570595]),
            bucket(11, 20, 0.5346094598348444, [0.40595137663302483, 0.6911066985735377]),
            bucket(20, 35, 0.8428063943161636, [0.6504601819243522, 1.0742259350903411]),
            bucket(35, 65, 1.4429071005017484, [1.1405581860945952, 1.8008133631629157]),
            bucket(65, 120, 1.6190935390549661, [1.0263664163011208, 2.4294352761068576]),
        ],
    },
    AtaAttributeMetadata {
        id: 188,
        display_name: "Command Timeout",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Transformed,
        transform: Some(transform_command_timeout),
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.024893587674442153, [0.020857343769186413, 0.0294830350167543]),
            bucket(0, 100, 0.024893587674442153, [0.020857343769186413, 0.0294830350167543]),
            bucket(100, 13000000000, 0.10044174089362015, [0.0812633664077498, 0.1227848196758574]),
            bucket(13000000000, 26000000000, 0.334030592234279, [0.2523231196342665, 0.4337665082489293]),
            bucket(26000000000, 39000000000, 0.36724705400842445, [0.30398009356575617, 0.4397986538328568]),
            bucket(39000000000, 52000000000, 0.29848155926978354, [0.2509254838615984, 0.35242890006477073]),
            bucket(52000000000, 65000000000, 0.2203079701535098, [0.18366082845676174, 0.26212468677179274]),
            bucket(65000000000, 78000000000, 0.3018169948863018, [0.23779746376787655, 0.37776897542831006]),
            bucket(78000000000, 91000000000, 0.32854928239235887, [0.2301118782147336, 0.4548506948185028]),
            bucket(91000000000, 104000000000, 0.28488916640649387, [0.1366154288236293, 0.5239213202729072]),
        ],
    },
    AtaAttributeMetadata {
        id: 189,
        display_name: "High Fly Writes",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.09070551401946862, [0.08018892683853401, 0.10221801211956287]),
            bucket(1, 2, 0.0844336097370013, [0.07299813695315267, 0.09715235540340669]),
            bucket(2, 5, 0.07943219628781906, [0.06552176680630226, 0.09542233189887633]),
            bucket(5, 13, 0.09208847603893404, [0.07385765060838133, 0.11345557807163456]),
            bucket(13, 30, 0.18161161650924224, [0.13858879602902988, 0.23377015012749933]),
            bucket(30, 70, 0.2678117886102384, [0.19044036194841887, 0.36610753129699186]),
            bucket(70, 150, 0.26126480798826107, [0.15958733218826962, 0.4035023060905559]),
            bucket(150, 350, 0.11337164155924832, [0.030889956621649995, 0.2902764300762812]),
        ],
    },
    AtaAttributeMetadata {
        id: 190,
        display_name: "Temperature Difference",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 191,
        display_name: "G-sense Error Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 192,
        display_name: "Power-off Retract Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 193,
        display_name: "Load Cycle Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 194,
        display_name: "Temperature",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Transformed,
        transform: Some(transform_temperature),
        transform_value_unit: Some("°C"),
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 195,
        display_name: "Hardware ECC Recovered",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 196,
        display_name: "Reallocation Event Count",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.007389855800729792, [0.005652654139732716, 0.009492578928212054]),
            bucket(1, 1, 0.026558331312151347, [0.005476966404484466, 0.07761471429677293]),
            bucket(1, 2, 0.02471894893674658, [0.0006258296027540169, 0.13772516847438018]),
            bucket(2, 4, 0.03200912040691046, [0.0008104007642081744, 0.17834340416493005]),
            bucket(4, 7, 0.043078012510326925, [0.001090640849081295, 0.24001532369794615]),
            bucket(7, 11, 0.033843300880853036, [0.0008568381932559863, 0.18856280368036135]),
            bucket(11, 17, 0.16979376647542252, [0.035015556653263225, 0.49620943874336304]),
            bucket(17, 27, 0.059042381106438044, [0.0014948236677880642, 0.32896309247698113]),
            bucket(27, 45, 0.24701105346266636, [0.050939617608142244, 0.721871118983972]),
        ],
    },
    AtaAttributeMetadata {
        id: 197,
        display_name: "Current Pending Sector Count",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.025540791394761345, [0.023161777231213983, 0.02809784482748174]),
            bucket(1, 2, 0.34196613799103254, [0.22723401523750225, 0.4942362818474496]),
            bucket(2, 6, 0.6823772508117681, [0.41083568090070416, 1.0656166047061635]),
            bucket(6, 16, 0.6108100007493069, [0.47336936083368364, 0.7757071095273286]),
            bucket(16, 40, 0.9564879341127684, [0.7701044196378299, 1.174355230793638]),
            bucket(40, 100, 1.6519989942167461, [1.328402276482456, 2.0305872327541317]),
            bucket(100, 250, 2.5137741046831956, [1.9772427971560862, 3.1510376077891613]),
            bucket(250, 650, 3.3203378817413904, [2.5883662702274406, 4.195047163573006]),
            bucket(650, 1600, 3.133047210300429, [1.1497731080460096, 6.819324775707182]),
        ],
    },
    AtaAttributeMetadata {
        id: 198,
        display_name: "(Offline) Uncorrectable Sector Count",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 0, 0.028675322159886437, [0.026159385510707116, 0.03136793218577656]),
            bucket(0, 2, 0.8135764944275583, [0.40613445471964466, 1.4557130815309443]),
            bucket(2, 4, 1.1173469387755102, [0.5773494680315332, 1.9517802404552516]),
            bucket(4, 6, 1.3558692421991083, [0.4402470522980859, 3.1641465148237544]),
            bucket(6, 8, 0.7324414715719062, [0.15104704003805655, 2.140504796291604]),
            bucket(8, 10, 0.5777213677766163, [0.43275294849366835, 0.7556737733062419]),
            bucket(10, 12, 1.7464114832535886, [0.47583835092536914, 4.471507017371231]),
            bucket(12, 14, 2.6449275362318843, [0.3203129951758959, 9.554387676519005]),
            bucket(14, 16, 0.796943231441048, [0.5519063550198366, 1.113648286331181]),
        ],
    },
    AtaAttributeMetadata {
        id: 199,
        display_name: "UltraDMA CRC Error Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: true,
        display_type: DisplayType::Raw,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[
            bucket(0, 1, 0.04068379316116366, [0.037534031558106425, 0.04402730201866553]),
            bucket(1, 2, 0.1513481259734218, [0.12037165605991791, 0.18786293065527596]),
            bucket(2, 4, 0.16849758722418978, [0.12976367397863445, 0.2151676572000481]),
            bucket(4, 8, 0.15385127340491614, [0.10887431782430312, 0.21117289306426648]),
            bucket(8, 16, 0.14882894050104387, [0.09631424312463635, 0.2197008753522735]),
            bucket(16, 35, 0.20878219917249793, [0.14086447304552446, 0.29804957135975]),
            bucket(35, 70, 0.13742940270409038, [0.06860426267470295, 0.24589916335290812]),
            bucket(70, 130, 0.22336578581363, [0.11150339549604707, 0.39966309081252904]),
            bucket(130, 260, 0.18277416124186283, [0.07890890989692058, 0.3601379610272007]),
        ],
    },
    AtaAttributeMetadata {
        id: 200,
        display_name: "Multi-Zone Error Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 201,
        display_name: "Soft Read Error Rate",
        ideal: Ideal::Low,
        critical: true,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 202,
        display_name: "Data Address Mark errors",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 203,
        display_name: "Run Out Cancel",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 204,
        display_name: "Soft ECC Correction",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Unspecified,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 205,
        display_name: "Thermal Asperity Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 206,
        display_name: "Flying Height",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 207,
        display_name: "Spin High Current",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 208,
        display_name: "Spin Buzz",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 209,
        display_name: "Offline Seek Performance",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 210,
        display_name: "Vibration During Write",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 211,
        display_name: "Vibration During Write",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 212,
        display_name: "Shock During Write",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 220,
        display_name: "Disk Shift",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 221,
        display_name: "G-Sense Error Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 222,
        display_name: "Loaded Hours",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 223,
        display_name: "Load/Unload Retry Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 224,
        display_name: "Load Friction",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 225,
        display_name: "Load/Unload Cycle Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 226,
        display_name: "Load \"In\"-time",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 227,
        display_name: "Torque Amplification Count",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Unspecified,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 228,
        display_name: "Power-Off Retract Cycle",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Unspecified,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 230,
        display_name: "GMR Head Amplitude ",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 231,
        display_name: "Life Left",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 232,
        display_name: "Endurance Remaining",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 233,
        display_name: "Media Wearout Indicator",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 234,
        display_name: "Average erase count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 235,
        display_name: "Good Block Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 240,
        display_name: "Head Flying Hours",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 241,
        display_name: "Total LBAs Written",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 242,
        display_name: "Total LBAs Read",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 243,
        display_name: "Total LBAs Written Expanded",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 244,
        display_name: "Total LBAs Read Expanded",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 246,
        display_name: "Total Host Sector Writes",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 247,
        display_name: "Host Program Page Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 248,
        display_name: "FTL Program Page Count",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 249,
        display_name: "NAND Writes (1GiB)",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 250,
        display_name: "Read Error Retry Rate",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 251,
        display_name: "Minimum Spares Remaining",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 252,
        display_name: "Newly Added Bad Flash Block",
        ideal: Ideal::Unspecified,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
    AtaAttributeMetadata {
        id: 254,
        display_name: "Free Fall Protection",
        ideal: Ideal::Low,
        critical: false,
        use_delta_evaluation: false,
        display_type: DisplayType::Normalized,
        transform: None,
        transform_value_unit: None,
        observed_thresholds: &[],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: i64) -> &'static AtaAttributeMetadata {
        ata_metadata(id).unwrap_or_else(|| panic!("attribute {id} missing from the table"))
    }

    #[test]
    fn table_is_sorted_and_complete() {
        assert!(ATA_METADATA.windows(2).all(|pair| pair[0].id < pair[1].id));
        // Counts taken from the fork's AtaMetadata map at the time of the port.
        assert_eq!(ATA_METADATA.len(), 87);
        let bucketed: Vec<i64> = ATA_METADATA
            .iter()
            .filter(|m| !m.observed_thresholds.is_empty())
            .map(|m| m.id)
            .collect();
        assert_eq!(
            bucketed,
            [5, 10, 11, 177, 183, 187, 188, 189, 196, 197, 198, 199]
        );
        let buckets: usize = ATA_METADATA
            .iter()
            .map(|m| m.observed_thresholds.len())
            .sum();
        assert_eq!(buckets, 98);
        let rate_sum: f64 = ATA_METADATA
            .iter()
            .flat_map(|m| m.observed_thresholds)
            .map(|b| b.annual_failure_rate)
            .sum();
        assert!(
            (rate_sum - 45.791_362_310_141_65).abs() < 1e-9,
            "{rate_sum}"
        );
    }

    #[test]
    fn critical_attributes_match_the_fork() {
        let critical: Vec<i64> = ATA_METADATA
            .iter()
            .filter(|m| m.critical)
            .map(|m| m.id)
            .collect();
        assert_eq!(critical, [5, 10, 177, 184, 187, 188, 196, 197, 198, 201]);
    }

    // Fork: TestAtaMetadata_BucketedAttributesDeclareAnIdealDirection
    #[test]
    fn bucketed_attributes_declare_an_ideal_direction() {
        for m in ATA_METADATA
            .iter()
            .filter(|m| !m.observed_thresholds.is_empty())
        {
            assert_ne!(m.ideal, Ideal::Unspecified, "attribute {}", m.id);
        }
    }

    // Fork: TestAtaMetadata_UsageCountersCarryNoBuckets (#1094) and
    // TestAtaMetadata_VendorScaledNormalizedAttributesCarryNoBuckets (#1088)
    #[test]
    fn usage_counters_and_vendor_scaled_attributes_carry_no_buckets() {
        for id in [3, 4, 184, 192, 195] {
            assert!(meta(id).observed_thresholds.is_empty(), "attribute {id}");
        }
    }

    #[test]
    fn spot_check_rows() {
        let reallocated = meta(5);
        assert_eq!(reallocated.display_name, "Reallocated Sectors Count");
        assert_eq!(reallocated.display_type, DisplayType::Raw);
        assert_eq!(reallocated.ideal, Ideal::Low);
        assert_eq!(reallocated.observed_thresholds.len(), 9);
        assert_eq!(
            reallocated.observed_thresholds[3],
            bucket(
                16,
                70,
                0.23589260654405794,
                [0.1643078435800227, 0.32806951196017664]
            )
        );

        let wear = meta(177);
        assert_eq!(wear.display_type, DisplayType::Normalized);
        assert_eq!(wear.ideal, Ideal::High);

        let crc = meta(199);
        assert!(crc.use_delta_evaluation);
        assert!(!crc.critical);
        assert_eq!(
            ATA_METADATA
                .iter()
                .filter(|m| m.use_delta_evaluation)
                .count(),
            1
        );

        assert_eq!(meta(174).display_type, DisplayType::Unspecified);
        assert_eq!(meta(194).transform_value_unit, Some("°C"));
        assert!(ata_metadata(0).is_none());
        assert!(ata_metadata(253).is_none());
    }

    #[test]
    fn only_three_attributes_are_transformed() {
        let transformed: Vec<i64> = ATA_METADATA
            .iter()
            .filter(|m| m.transform.is_some())
            .map(|m| m.id)
            .collect();
        assert_eq!(transformed, [9, 188, 194]);
        for id in transformed {
            assert_eq!(meta(id).display_type, DisplayType::Transformed);
        }
    }

    // Fork: TestAttribute9Transform_* (smart_ata_attribute_test.go)
    #[test]
    fn power_on_hours_transform() {
        let transform = meta(9).transform.unwrap();
        assert_eq!(transform(100, 1730, "1730"), 1730);
        assert_eq!(transform(100, 0, "0"), 0);
        // from smart-sat.json: raw 0x97ea00000aa5, real hours 2725
        assert_eq!(transform(97, 167_031_278_144_165, "2725 (151 234 0)"), 2725);
        assert_eq!(transform(85, 0x001E_0000_2A30, "10800"), 10800);
        assert_eq!(transform(97, 1730, "1730h+05m+02.453s"), 1730);
        assert_eq!(transform(90, 103_800, "103800 (1730 hours)"), 1730);
        assert_eq!(transform(50, 100_000, "100000"), 100_000);
    }

    #[test]
    fn command_timeout_transform() {
        let transform = meta(188).transform.unwrap();
        // three ascending pieces: the last one is the total
        assert_eq!(transform(100, 0x0001_0001_0001, "1 1 1"), 1);
        assert_eq!(transform(100, 5, "0 0 5"), 5);
        // not ascending: fall back on the lower 16 bits of the packed value
        assert_eq!(transform(100, 0x0003_0002_0001, "3 2 1"), 1);
        // not numbers: the raw value is returned untouched, as in the fork
        assert_eq!(transform(100, 0x0001_0000, "a b c"), 0x0001_0000);
        assert_eq!(transform(100, 7, "7"), 7);
        assert_eq!(transform(100, 0x0002_0000_0009, "8589934601"), 9);
    }

    #[test]
    fn temperature_transform_keeps_the_low_byte() {
        let transform = meta(194).transform.unwrap();
        // from smart-ata.json
        assert_eq!(transform(0, 163_210_330_144, "32 (Min/Max 24/38)"), 32);
    }
}
