//! Typed subset of `smartctl --json` output (smartmontools >= 7.0).
//!
//! Every field is optional: smartctl omits sections the device or the
//! transport does not support. Unknown fields are ignored.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SmartctlOutput {
    #[serde(default)]
    pub smartctl: Option<SmartctlMeta>,
    #[serde(default)]
    pub device: Option<DeviceInfo>,
    #[serde(default)]
    pub model_family: Option<String>,
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(default)]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub firmware_version: Option<String>,
    #[serde(default)]
    pub user_capacity: Option<UserCapacity>,
    /// 0 = SSD, otherwise RPM. Absent on NVMe.
    #[serde(default)]
    pub rotation_rate: Option<i64>,
    #[serde(default)]
    pub smart_status: Option<SmartStatus>,
    #[serde(default)]
    pub power_on_time: Option<PowerOnTime>,
    #[serde(default)]
    pub temperature: Option<Temperature>,
    #[serde(default)]
    pub ata_smart_attributes: Option<AtaSmartAttributes>,
    /// ATA Device Statistics (GP log 0x04).
    #[serde(default)]
    pub ata_device_statistics: Option<AtaDeviceStatistics>,
    /// Seagate FARM (Field Accessible Reliability Metrics) log, `smartctl -l farm`.
    #[serde(default)]
    pub seagate_farm_log: Option<SeagateFarmLog>,
    #[serde(default)]
    pub nvme_smart_health_information_log: Option<NvmeHealthLog>,
    #[serde(default)]
    pub scsi_grown_defect_list: Option<i64>,
    #[serde(default)]
    pub scsi_error_counter_log: Option<ScsiErrorCounterLog>,
    /// SAS SSD "percentage used endurance indicator" (Solid State Media log page).
    #[serde(default)]
    pub endurance_used: Option<ScsiEnduranceUsed>,
    /// SAS Protocol log page, one `scsi_sas_port_<n>` key per port.
    #[serde(flatten)]
    pub scsi_sas_ports: ScsiSasPorts,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SmartctlMeta {
    #[serde(default)]
    pub exit_status: Option<i64>,
    #[serde(default)]
    pub messages: Option<Vec<SmartctlMessage>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SmartctlMessage {
    #[serde(default)]
    pub string: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DeviceInfo {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub info_name: Option<String>,
    #[serde(default, rename = "type")]
    pub dev_type: Option<String>,
    /// "ATA", "NVMe" or "SCSI".
    #[serde(default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UserCapacity {
    #[serde(default)]
    /// int64 like the fork's collector model (a negative value is decoded, not rejected).
    pub bytes: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SmartStatus {
    #[serde(default)]
    pub passed: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PowerOnTime {
    #[serde(default)]
    pub hours: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Temperature {
    #[serde(default)]
    pub current: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaSmartAttributes {
    #[serde(default, deserialize_with = "null_as_default")]
    pub table: Vec<AtaAttribute>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaAttribute {
    /// Like Go's zero value, a missing or `null` id reads as 0.
    #[serde(default, deserialize_with = "null_as_default")]
    pub id: i64,
    #[serde(default)]
    pub name: Option<String>,
    /// Normalized current value.
    #[serde(default)]
    pub value: Option<i64>,
    #[serde(default)]
    pub worst: Option<i64>,
    /// Manufacturer threshold for the normalized value.
    #[serde(default)]
    pub thresh: Option<i64>,
    /// "", "now" or "past".
    #[serde(default)]
    pub when_failed: Option<String>,
    #[serde(default)]
    pub flags: Option<AtaAttributeFlags>,
    #[serde(default)]
    pub raw: Option<AtaRaw>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaAttributeFlags {
    #[serde(default)]
    pub value: Option<i64>,
    #[serde(default)]
    pub prefailure: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaRaw {
    #[serde(default)]
    pub value: Option<i64>,
    #[serde(default)]
    pub string: Option<String>,
}

/// `ata_device_statistics`. Like the fork's collector model, absent or `null` fields read
/// as Go zero values: no page, page number 0, offset 0, value 0, `valid == false`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaDeviceStatistics {
    #[serde(default, deserialize_with = "null_items_as_default")]
    pub pages: Vec<AtaDeviceStatisticsPage>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaDeviceStatisticsPage {
    #[serde(default, deserialize_with = "null_as_default")]
    pub number: i64,
    #[serde(default, deserialize_with = "null_items_as_default")]
    pub table: Vec<AtaDeviceStatistic>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaDeviceStatistic {
    /// Byte offset of the statistic in its page; with the page number it identifies it.
    #[serde(default, deserialize_with = "null_as_default")]
    pub offset: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub value: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub flags: AtaDeviceStatisticFlags,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AtaDeviceStatisticFlags {
    /// The drive supports the statistic and its value is meaningful.
    #[serde(default, deserialize_with = "null_as_default")]
    pub valid: bool,
}

/// `seagate_farm_log`: the pages the fork evaluates. A page that is absent or `null` is
/// `None` (a nil pointer in the fork); inside a page, absent or `null` counters read as 0.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SeagateFarmLog {
    #[serde(default, deserialize_with = "null_as_default")]
    pub supported: bool,
    #[serde(default)]
    pub page_1_drive_information: Option<FarmDriveInformation>,
    #[serde(default)]
    pub page_2_workload_statistics: Option<FarmWorkloadStatistics>,
    #[serde(default)]
    pub page_3_error_statistics: Option<FarmErrorStatistics>,
    #[serde(default)]
    pub page_4_environment_statistics: Option<FarmEnvironmentStatistics>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FarmDriveInformation {
    #[serde(default, deserialize_with = "null_as_default")]
    pub poh: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub spoh: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub head_flight_hours: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub head_load_events: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub power_cycle_count: i64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FarmWorkloadStatistics {
    #[serde(default, deserialize_with = "null_as_default")]
    pub total_read_commands: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub total_write_commands: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub logical_sectors_written: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub logical_sectors_read: i64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FarmErrorStatistics {
    #[serde(default, deserialize_with = "null_as_default")]
    pub number_of_unrecoverable_read_errors: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub number_of_unrecoverable_write_errors: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub number_of_reallocated_sectors: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub number_of_reallocated_candidate_sectors: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub total_crc_errors: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub command_time_out_count_total: i64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FarmEnvironmentStatistics {
    /// smartctl spells the key this way.
    #[serde(default, deserialize_with = "null_as_default")]
    pub curent_temp: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub highest_temp: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub lowest_temp: i64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NvmeHealthLog {
    #[serde(default)]
    pub critical_warning: Option<i64>,
    #[serde(default)]
    pub temperature: Option<i64>,
    #[serde(default)]
    pub available_spare: Option<i64>,
    #[serde(default)]
    pub available_spare_threshold: Option<i64>,
    #[serde(default)]
    pub percentage_used: Option<i64>,
    #[serde(default)]
    pub data_units_read: Option<i64>,
    #[serde(default)]
    pub data_units_written: Option<i64>,
    #[serde(default)]
    pub power_on_hours: Option<i64>,
    #[serde(default)]
    pub unsafe_shutdowns: Option<i64>,
    #[serde(default)]
    pub media_errors: Option<i64>,
    #[serde(default)]
    pub num_err_log_entries: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ScsiErrorCounterLog {
    #[serde(default)]
    pub read: Option<ScsiErrorCounter>,
    #[serde(default)]
    pub write: Option<ScsiErrorCounter>,
    #[serde(default)]
    pub verify: Option<ScsiErrorCounter>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ScsiErrorCounter {
    #[serde(default)]
    pub errors_corrected_by_eccfast: Option<i64>,
    #[serde(default)]
    pub errors_corrected_by_eccdelayed: Option<i64>,
    #[serde(default)]
    pub errors_corrected_by_rereads_rewrites: Option<i64>,
    #[serde(default)]
    pub total_errors_corrected: Option<i64>,
    #[serde(default)]
    pub correction_algorithm_invocations: Option<i64>,
    #[serde(default)]
    pub total_uncorrected_errors: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ScsiEnduranceUsed {
    #[serde(default)]
    pub current_percent: Option<i64>,
}

/// The `scsi_sas_port_<n>` objects of the SAS Protocol log page, by JSON key.
///
/// smartctl emits one numbered top-level key per port instead of an array, each holding one
/// `phy_<m>` object per PHY, so there is no fixed field to decode into. This collects those
/// keys (as raw JSON) from the top-level object and drops every other unknown key.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct ScsiSasPorts(pub BTreeMap<String, serde_json::Value>);

impl ScsiSasPorts {
    pub const KEY_PREFIX: &'static str = "scsi_sas_port_";
}

impl<'de> Deserialize<'de> for ScsiSasPorts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PortsVisitor;

        impl<'de> Visitor<'de> for PortsVisitor {
            type Value = ScsiSasPorts;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a smartctl JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut ports = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if key.starts_with(ScsiSasPorts::KEY_PREFIX) {
                        ports.insert(key, map.next_value()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(ScsiSasPorts(ports))
            }
        }

        deserializer.deserialize_map(PortsVisitor)
    }
}

impl SmartctlOutput {
    pub fn protocol(&self) -> Option<&str> {
        self.device.as_ref()?.protocol.as_deref()
    }

    pub fn device_name(&self) -> Option<&str> {
        self.device.as_ref()?.name.as_deref()
    }
}

/// Go's `encoding/json` leaves a field at its zero value for JSON `null`; serde would
/// reject `null` for a non-`Option` field. Used where the fork's model has a plain value.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// [`null_as_default`] for a list and for each of its elements: in Go a `null` slice is
/// empty and a `null` element is a zero-valued struct.
fn null_items_as_default<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<Vec<Option<T>>>::deserialize(deserializer)?
        .unwrap_or_default()
        .into_iter()
        .map(Option::unwrap_or_default)
        .collect())
}
