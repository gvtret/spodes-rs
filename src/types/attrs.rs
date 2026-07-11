//! Typed attributes for COSEM interface classes (IEC 62056-6-2).
//!
//! Each IC has specific attribute types defined in the standard. This module
//! provides strongly-typed structs for these attributes, replacing the generic
//! `CosemDataType` where possible while maintaining BER compatibility.

use crate::obis::ObisCode;
use crate::types::CosemDataType;
use serde::{Deserialize, Serialize};

/// Logical name (OBIS code) — attribute 1 of all ICs.
pub type LogicalName = ObisCode;

/// CHOICE type — any COSEM data type (for value, status, etc.).
/// This maintains backward compatibility with the generic CosemDataType.
pub type Choice = CosemDataType;

/// Date-time value (12 octets) per IEC 62056-6-2, 4.1.6.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateTime(pub [u8; 12]);

impl DateTime {
    /// Creates a new DateTime from raw bytes.
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Creates a DateTime from year, month, day, hour, minute, second.
    pub fn from_ymdhms(year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8) -> Self {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&year.to_be_bytes());
        buf[2] = month;
        buf[3] = day;
        buf[4] = 0xFF; // day of week (any)
        buf[5] = hour;
        buf[6] = min;
        buf[7] = sec;
        buf[8] = 0; // hundredths
        buf[9..12].copy_from_slice(&[0, 0, 0]); // deviation, clocks, reserved
        Self(buf)
    }
}

impl From<DateTime> for CosemDataType {
    fn from(dt: DateTime) -> Self {
        CosemDataType::DateTime(dt.0.to_vec())
    }
}

impl TryFrom<&CosemDataType> for DateTime {
    type Error = String;

    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::DateTime(bytes) if bytes.len() == 12 => {
                let mut buf = [0u8; 12];
                buf.copy_from_slice(bytes);
                Ok(DateTime(buf))
            }
            CosemDataType::OctetString(bytes) if bytes.len() == 12 => {
                let mut buf = [0u8; 12];
                buf.copy_from_slice(bytes);
                Ok(DateTime(buf))
            }
            _ => Err("expected 12-byte date-time or octet-string".to_string()),
        }
    }
}

/// Bit-string value (held as raw octets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitString(pub Vec<u8>);

impl BitString {
    /// Creates a new BitString from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Checks if bit `n` is set.
    pub fn get(&self, n: usize) -> bool {
        let byte = n / 8;
        let bit = n % 8;
        byte < self.0.len() && (self.0[byte] & (1 << (7 - bit))) != 0
    }
}

impl From<BitString> for CosemDataType {
    fn from(bs: BitString) -> Self {
        CosemDataType::BitString(bs.0)
    }
}

/// ScalerUnit: structure { scaler: integer, unit: enum }
/// per IEC 62056-6-2, Table 41.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalerUnit {
    /// The scaler (power of 10): value = raw × 10^scaler.
    pub scaler: i8,
    /// The unit code per IEC 62056-6-2, Table 42.
    pub unit: u8,
}

impl ScalerUnit {
    /// Creates a new ScalerUnit.
    pub fn new(scaler: i8, unit: u8) -> Self {
        Self { scaler, unit }
    }

    /// Converts a raw value to the scaled value.
    pub fn apply(&self, raw: i64) -> f64 {
        raw as f64 * 10f64.powi(self.scaler as i32)
    }
}

impl From<ScalerUnit> for CosemDataType {
    fn from(su: ScalerUnit) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Integer(su.scaler),
            CosemDataType::Enum(su.unit),
        ])
    }
}

impl TryFrom<&CosemDataType> for ScalerUnit {
    type Error = String;

    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let scaler = match &fields[0] {
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("scaler must be integer".to_string()),
                };
                let unit = match &fields[1] {
                    CosemDataType::Enum(v) => *v,
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("unit must be enum".to_string()),
                };
                Ok(ScalerUnit { scaler, unit })
            }
            _ => Err("expected structure {scaler, unit}".to_string()),
        }
    }
}

/// Capture object definition: structure { class_id, logical_name, attribute_index, data_index }
/// per IEC 62056-6-2, 4.3.6.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureObjectDefinition {
    /// The class id of the captured object.
    pub class_id: u16,
    /// The logical name (OBIS code) of the captured object.
    pub logical_name: ObisCode,
    /// The attribute index to capture.
    pub attribute_index: u8,
    /// The data index (0 for the whole attribute).
    pub data_index: u8,
}

impl CaptureObjectDefinition {
    /// Creates a new CaptureObjectDefinition.
    pub fn new(class_id: u16, logical_name: ObisCode, attribute_index: u8, data_index: u8) -> Self {
        Self { class_id, logical_name, attribute_index, data_index }
    }
}

impl From<CaptureObjectDefinition> for CosemDataType {
    fn from(cod: CaptureObjectDefinition) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(cod.class_id),
            CosemDataType::OctetString(cod.logical_name.to_bytes()),
            CosemDataType::Unsigned(cod.attribute_index),
            CosemDataType::Unsigned(cod.data_index),
        ])
    }
}

impl TryFrom<&CosemDataType> for CaptureObjectDefinition {
    type Error = String;

    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 4 => {
                let class_id = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("class_id must be long-unsigned".to_string()),
                };
                let logical_name = match &fields[1] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("logical_name must be 6-byte octet-string".to_string()),
                };
                let attribute_index = match &fields[2] {
                    CosemDataType::Unsigned(v) => *v,
                    CosemDataType::Integer(v) => *v as u8,
                    _ => return Err("attribute_index must be unsigned".to_string()),
                };
                let data_index = match &fields[3] {
                    CosemDataType::Unsigned(v) => *v,
                    CosemDataType::LongUnsigned(v) => *v as u8,
                    _ => return Err("data_index must be unsigned".to_string()),
                };
                Ok(CaptureObjectDefinition { class_id, logical_name, attribute_index, data_index })
            }
            _ => Err("expected structure {class_id, logical_name, attribute_index, data_index}".to_string()),
        }
    }
}

/// Sort method for Profile generic (IEC 62056-6-2, 4.3.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortMethod {
    /// FIFO (first in, first out).
    Fifo = 1,
    /// LIFO (last in, first out).
    Lifo = 2,
    /// Largest value first.
    Largest = 3,
    /// Smallest value first.
    Smallest = 4,
    /// Nearest to zero.
    NearestToZero = 5,
    /// Farthest from zero.
    FarthestFromZero = 6,
}

impl SortMethod {
    /// Parses a sort method from its numeric value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Fifo),
            2 => Some(Self::Lifo),
            3 => Some(Self::Largest),
            4 => Some(Self::Smallest),
            5 => Some(Self::NearestToZero),
            6 => Some(Self::FarthestFromZero),
            _ => None,
        }
    }
}

/// Association status (IEC 62056-6-2, 4.4.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssociationStatus {
    /// Non-associated.
    NonAssociated = 0,
    /// Association pending.
    AssociationPending = 1,
    /// Associated.
    Associated = 2,
}

// ============================================================================
// Typed attribute structs for each IC (IEC 62056-6-2)
// ============================================================================

/// Data class (class_id = 1) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: value (CHOICE)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAttrs {
    pub logical_name: LogicalName,
    pub value: Choice,
}

/// Register class (class_id = 3) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: value (CHOICE)
/// - attr 3: scaler_unit (scal_unit_type)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAttrs {
    pub logical_name: LogicalName,
    pub value: Choice,
    pub scaler_unit: ScalerUnit,
}

/// Extended register class (class_id = 4) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: value (CHOICE)
/// - attr 3: scaler_unit (scal_unit_type)
/// - attr 4: status (CHOICE)
/// - attr 5: capture_time (octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRegisterAttrs {
    pub logical_name: LogicalName,
    pub value: Choice,
    pub scaler_unit: ScalerUnit,
    pub status: Choice,
    pub capture_time: Choice,
}

/// Demand register class (class_id = 5) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: current_average_value (CHOICE)
/// - attr 3: last_average_value (CHOICE)
/// - attr 4: scaler_unit (scal_unit_type)
/// - attr 5: status (CHOICE)
/// - attr 6: capture_time (octet-string)
/// - attr 7: start_time_current (octet-string)
/// - attr 8: period (double-long-unsigned)
/// - attr 9: number_of_periods (long-unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemandRegisterAttrs {
    pub logical_name: LogicalName,
    pub current_average_value: Choice,
    pub last_average_value: Choice,
    pub scaler_unit: ScalerUnit,
    pub status: Choice,
    pub capture_time: Choice,
    pub start_time_current: Choice,
    pub period: u32,
    pub number_of_periods: u16,
}

/// Profile generic class (class_id = 7) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: buffer (array)
/// - attr 3: capture_objects (array)
/// - attr 4: capture_period (double-long-unsigned)
/// - attr 5: sort_method (enum)
/// - attr 6: sort_object (capture_object_definition)
/// - attr 7: entries_in_use (double-long-unsigned)
/// - attr 8: profile_entries (double-long-unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileGenericAttrs {
    pub logical_name: LogicalName,
    pub buffer: Vec<Choice>,
    pub capture_objects: Vec<CaptureObjectDefinition>,
    pub capture_period: u32,
    pub sort_method: SortMethod,
    pub sort_object: Option<CaptureObjectDefinition>,
    pub entries_in_use: u32,
    pub profile_entries: u32,
}

/// Clock class (class_id = 8) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: time (date-time)
/// - attr 3: time_zone (long)
/// - attr 4: status (bit-string)
/// - attr 5: daylight_savings_begin (date-time)
/// - attr 6: daylight_savings_end (date-time)
/// - attr 7: daylight_savings_deviation (integer)
/// - attr 8: daylight_savings_enabled (boolean)
/// - attr 9: clock_base (enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockAttrs {
    pub logical_name: LogicalName,
    pub time: DateTime,
    pub time_zone: i16,
    pub status: u8,
    pub daylight_savings_begin: DateTime,
    pub daylight_savings_end: DateTime,
    pub daylight_savings_deviation: i8,
    pub daylight_savings_enabled: bool,
    pub clock_base: u8,
}

/// Script table class (class_id = 9) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: scripts (array of {script_id, actions})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptTableAttrs {
    pub logical_name: LogicalName,
    pub scripts: Vec<Choice>,
}

/// Schedule class (class_id = 10) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: entries (array of {switch_time, day_profile_table, week_profile_table, month_profile_table})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleAttrs {
    pub logical_name: LogicalName,
    pub entries: Vec<Choice>,
}

/// Special days table class (class_id = 11) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: entries (array of {date, day_id})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialDaysTableAttrs {
    pub logical_name: LogicalName,
    pub entries: Vec<Choice>,
}

/// Association LN class (class_id = 15) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: object_list (object_list_type)
/// - attr 3: associated_partners_id (associated_partners_type)
/// - attr 4: application_context_name (context_name_type)
/// - attr 5: xDLMS_context_info (xDLMS_context_type)
/// - attr 6: authentication_mechanism_name (mechanism_name_type)
/// - attr 7: secret (octet-string)
/// - attr 8: association_status (enum)
/// - attr 9: security_setup_reference (octet-string) [v1+]
/// - attr 10: user_list (array) [v2]
/// - attr 11: current_user (structure) [v2]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationLnAttrs {
    pub logical_name: LogicalName,
    pub object_list: Vec<Choice>,
    pub associated_partners_id: Choice,
    pub application_context_name: Choice,
    pub xdlms_context_info: Choice,
    pub authentication_mechanism_name: u8,
    pub secret: Vec<u8>,
    pub association_status: AssociationStatus,
    pub security_setup_reference: Option<ObisCode>,
    pub user_list: Vec<Choice>,
    pub current_user: Option<Choice>,
}

/// SAP assignment class (class_id = 17) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: sap_assignment_list (array of {sap_name, sap_address})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SapAssignmentAttrs {
    pub logical_name: LogicalName,
    pub sap_assignment_list: Vec<Choice>,
}

/// Activity calendar class (class_id = 20) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: calendar_name (octet-string)
/// - attr 3: week_profile_table (array)
/// - attr 4: day_profile_table (array)
/// - attr 5: month_profile_table (array)
/// - attr 6: active_calendar (octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityCalendarAttrs {
    pub logical_name: LogicalName,
    pub calendar_name: Vec<u8>,
    pub week_profile_table: Vec<Choice>,
    pub day_profile_table: Vec<Choice>,
    pub month_profile_table: Vec<Choice>,
    pub active_calendar: Vec<u8>,
}

/// Register monitor class (class_id = 21) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: thresholds (array of {value, script})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMonitorAttrs {
    pub logical_name: LogicalName,
    pub thresholds: Vec<Choice>,
}

/// Single action schedule class (class_id = 22) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: executed_script (capture_object_definition)
/// - attr 3: execution_time (array of octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleActionScheduleAttrs {
    pub logical_name: LogicalName,
    pub executed_script: CaptureObjectDefinition,
    pub execution_time: Vec<Choice>,
}

/// Image transfer class (class_id = 18) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: block_size (long-unsigned)
/// - attr 3: transferred_blocks (double-long-unsigned)
/// - attr 4: last_block_number (double-long-unsigned)
/// - attr 5: transfer_status (enum)
/// - attr 6: image_transfer_enabled (boolean)
/// - attr 7: image_transferred_block_status (bit-string)
/// - attr 8: image_first_not_transferred_block_number (double-long-unsigned)
/// - attr 9: image_block_transfer_trigger (enum)
/// - attr 10: image_transfer_service_enable (boolean)
/// - attr 11: image_activation_info (array)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTransferAttrs {
    pub logical_name: LogicalName,
    pub block_size: u16,
    pub transferred_blocks: u32,
    pub last_block_number: u32,
    pub transfer_status: u8,
    pub image_transfer_enabled: bool,
    pub image_transferred_block_status: Vec<u8>,
    pub image_first_not_transferred_block_number: u32,
    pub image_block_transfer_trigger: u8,
    pub image_transfer_service_enable: bool,
    pub image_activation_info: Vec<Choice>,
}

/// Disconnect control class (class_id = 70) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: output_state (boolean)
/// - attr 3: control_mode (enum)
/// - attr 4: physical_output_name (octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectControlAttrs {
    pub logical_name: LogicalName,
    pub output_state: bool,
    pub control_mode: u8,
    pub physical_output_name: Vec<u8>,
}

/// Limiter class (class_id = 71) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: monitored_value (CHOICE)
/// - attr 3: threshold_normal (CHOICE)
/// - attr 4: threshold_min_operation (CHOICE)
/// - attr 5: threshold_max_operation (CHOICE)
/// - attr 6: min_over_threshold_duration (long-unsigned)
/// - attr 7: min_under_threshold_duration (long-unsigned)
/// - attr 8: emergency_profile (capture_object_definition)
/// - attr 9: emergency_profile_action (enum)
/// - attr 10: active_calendar_name (octet-string)
/// - attr 11: emergency_profile_group_id (long-unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimiterAttrs {
    pub logical_name: LogicalName,
    pub monitored_value: Choice,
    pub threshold_normal: Choice,
    pub threshold_min_operation: Choice,
    pub threshold_max_operation: Choice,
    pub min_over_threshold_duration: u16,
    pub min_under_threshold_duration: u16,
    pub emergency_profile: CaptureObjectDefinition,
    pub emergency_profile_action: u8,
    pub active_calendar_name: Vec<u8>,
    pub emergency_profile_group_id: u16,
}

/// TCP-UDP setup class (class_id = 41) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: port (long-unsigned)
/// - attr 3: tcp-udp_protocol (octet-string)
/// - attr 4: ip_reference (octet-string)
/// - attr 5: maximum_simultaneous_connections (long-unsigned)
/// - attr 6: maximum_segment_size (long-unsigned)
/// - attr 7: inactivity_timeout (long-unsigned)
/// - attr 8: transport_security (enum)
/// - attr 9: password_setup (octet-string)
/// - attr 10: password (visible-string)
/// - attr 11: default_password_status (enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpUdpSetupAttrs {
    pub logical_name: LogicalName,
    pub port: u16,
    pub tcp_udp_protocol: Vec<u8>,
    pub ip_reference: Vec<u8>,
    pub maximum_simultaneous_connections: u16,
    pub maximum_segment_size: u16,
    pub inactivity_timeout: u16,
    pub transport_security: u8,
    pub password_setup: Vec<u8>,
    pub password: Vec<u8>,
    pub default_password_status: u8,
}

/// IPv4 setup class (class_id = 42) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: ip_address (octet-string, 4 bytes)
/// - attr 3: subnet_mask (octet-string, 4 bytes)
/// - attr 4: gateway_ip_address (octet-string, 4 bytes)
/// - attr 5: use_dhcp (boolean)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4SetupAttrs {
    pub logical_name: LogicalName,
    pub ip_address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway_ip_address: [u8; 4],
    pub use_dhcp: bool,
}

/// IPv6 setup class (class_id = 48) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: ip_address (octet-string, 16 bytes)
/// - attr 3: prefix_length (octet-string)
/// - attr 4: gateway_ip_address (octet-string, 16 bytes)
/// - attr 5: use_dhcp (boolean)
/// - attr 6: multicast_address (octet-string, 16 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6SetupAttrs {
    pub logical_name: LogicalName,
    pub ip_address: [u8; 16],
    pub prefix_length: u8,
    pub gateway_ip_address: [u8; 16],
    pub use_dhcp: bool,
    pub multicast_address: [u8; 16],
}

/// MAC address setup class (class_id = 43) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: unicast_mac_address (octet-string, 6 bytes)
/// - attr 3: broadcast_mac_address (octet-string, 6 bytes)
/// - attr 4: multicast_mac_address (octet-string, 6 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAddressSetupAttrs {
    pub logical_name: LogicalName,
    pub unicast_mac_address: [u8; 6],
    pub broadcast_mac_address: [u8; 6],
    pub multicast_mac_address: [u8; 6],
}

/// GPRS modem setup class (class_id = 45) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: apn (visible-string)
/// - attr 3: pin_code (visible-string)
/// - attr 4: username (visible-string)
/// - attr 5: password (visible-string)
/// - attr 6: ask_for_password (boolean)
/// - attr 7: ip_address (octet-string, 4 bytes)
/// - attr 8: ip_port (long-unsigned)
/// - attr 9: transfer_services (bit-string)
/// - attr 10: default_transfers (octet-string)
/// - attr 11: gprs_timeout (long-unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GprsModemSetupAttrs {
    pub logical_name: LogicalName,
    pub apn: Vec<u8>,
    pub pin_code: Vec<u8>,
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub ask_for_password: bool,
    pub ip_address: [u8; 4],
    pub ip_port: u16,
    pub transfer_services: Vec<u8>,
    pub default_transfers: Vec<u8>,
    pub gprs_timeout: u16,
}

/// GSM diagnostic class (class_id = 47) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: cell_id (octet-string)
/// - attr 3: location_id (octet-string)
/// - attr 4: imsi (octet-string)
/// - attr 5: imei (octet-string)
/// - attr 6: rn (octet-string)
/// - attr 7: cn (octet-string)
/// - attr 8: signal_quality (octet-string)
/// - attr 9: signal_strength (octet-string)
/// - attr 10: channel_number (octet-string)
/// - attr 11: cell_parameter_id (octet-string)
/// - attr 12: bsic (octet-string)
/// - attr 13: iccid (octet-string)
/// - attr 14: lac (octet-string)
/// - attr 15: mcc (octet-string)
/// - attr 16: mnc (octet-string)
/// - attr 17: tmsi (octet-string)
/// - attr 18: tmgi (octet-string)
/// - attr 19: gprs_status (octet-string)
/// - attr 20: routing_area_code (octet-string)
/// - attr 21: geographic_address (octet-string)
/// - attr 22: access_point_name (visible-string)
/// - attr 23: data_transport_state (octet-string)
/// - attr 24: nma_message (octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GsmDiagnosticAttrs {
    pub logical_name: LogicalName,
    pub cell_id: Vec<u8>,
    pub location_id: Vec<u8>,
    pub imsi: Vec<u8>,
    pub imei: Vec<u8>,
    pub rn: Vec<u8>,
    pub cn: Vec<u8>,
    pub signal_quality: Vec<u8>,
    pub signal_strength: Vec<u8>,
    pub channel_number: Vec<u8>,
    pub cell_parameter_id: Vec<u8>,
    pub bsic: Vec<u8>,
    pub iccid: Vec<u8>,
    pub lac: Vec<u8>,
    pub mcc: Vec<u8>,
    pub mnc: Vec<u8>,
    pub tmsi: Vec<u8>,
    pub tmgi: Vec<u8>,
    pub gprs_status: Vec<u8>,
    pub routing_area_code: Vec<u8>,
    pub geographic_address: Vec<u8>,
    pub access_point_name: Vec<u8>,
    pub data_transport_state: Vec<u8>,
    pub nma_message: Vec<u8>,
}

/// Arbitrator class (class_id = 68) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: capture_groups (array of capture_object_definition)
/// - attr 3: action_groups (array of array)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitratorAttrs {
    pub logical_name: LogicalName,
    pub capture_groups: Vec<CaptureObjectDefinition>,
    pub action_groups: Vec<Choice>,
}

/// IEC HDLC setup class (class_id = 23) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: channel (unsigned)
/// - attr 3: wait (array)
/// - attr 4: client_address (long-unsigned)
/// - attr 5: server_address (long-unsigned)
/// - attr 6: window_size_tx (unsigned)
/// - attr 7: window_size_rx (unsigned)
/// - attr 8: max_info_tx (long-unsigned)
/// - attr 9: max_info_rx (long-unsigned)
/// - attr 10: max_timeout_tx (long-unsigned)
/// - attr 11: max_retries_tx (long-unsigned)
/// - attr 12: max_timeout_respond (long-unsigned)
/// - attr 13: max_retries_respond (long-unsigned)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IecHdlcSetupAttrs {
    pub logical_name: LogicalName,
    pub channel: u8,
    pub wait: Vec<Choice>,
    pub client_address: u16,
    pub server_address: u16,
    pub window_size_tx: u8,
    pub window_size_rx: u8,
    pub max_info_tx: u16,
    pub max_info_rx: u16,
    pub max_timeout_tx: u16,
    pub max_retries_tx: u8,
    pub max_timeout_respond: u16,
    pub max_retries_respond: u8,
}

/// IEC local port setup class (class_id = 19) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: mode (enum)
/// - attr 3: communication_speed (unsigned)
/// - attr 4: max_size_info_field (long-unsigned)
/// - attr 5: device_address (octet-string)
/// - attr 6: password1 (octet-string)
/// - attr 7: password2 (octet-string)
/// - attr 8: password3 (octet-string)
/// - attr 9: client_address (octet-string)
/// - attr 10: point_to_point_address (octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IecLocalPortSetupAttrs {
    pub logical_name: LogicalName,
    pub mode: u8,
    pub communication_speed: u8,
    pub max_size_info_field: u16,
    pub device_address: Vec<u8>,
    pub password1: Vec<u8>,
    pub password2: Vec<u8>,
    pub password3: Vec<u8>,
    pub client_address: Vec<u8>,
    pub point_to_point_address: Vec<u8>,
}

/// M-Bus slave port setup class (class_id = 25) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: mbus_address (octet-string)
/// - attr 3: identification_number (octet-string)
/// - attr 4: manufacturer_id (octet-string)
/// - attr 5: data_type (octet-string)
/// - attr 6: max_slave_pifs (long-unsigned)
/// - attr 7: max_master_pifs (long-unsigned)
/// - attr 8: character_encoding (octet-string)
/// - attr 9: m_bus_mode (enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbusSlavePortSetupAttrs {
    pub logical_name: LogicalName,
    pub mbus_address: Vec<u8>,
    pub identification_number: Vec<u8>,
    pub manufacturer_id: Vec<u8>,
    pub data_type: Vec<u8>,
    pub max_slave_pifs: u16,
    pub max_master_pifs: u16,
    pub character_encoding: Vec<u8>,
    pub m_bus_mode: u8,
}

/// Data protection class (class_id = 30) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: protection_method (enum)
/// - attr 3: protection_key (octet-string)
/// - attr 4: key_translation_table_1 (array)
/// - attr 5: key_translation_table_2 (array)
/// - attr 6: key_translation_table_3 (array)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProtectionAttrs {
    pub logical_name: LogicalName,
    pub protection_method: u8,
    pub protection_key: Vec<u8>,
    pub key_translation_table_1: Vec<Choice>,
    pub key_translation_table_2: Vec<Choice>,
    pub key_translation_table_3: Vec<Choice>,
}

/// Security setup class (class_id = 64) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: security_policy (enum)
/// - attr 3: security_suite (enum)
/// - attr 4: client_system_title (octet-string)
/// - attr 5: server_system_title (octet-string)
/// - attr 6: certificates (array)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySetupAttrs {
    pub logical_name: LogicalName,
    pub security_policy: u8,
    pub security_suite: u8,
    pub client_system_title: Vec<u8>,
    pub server_system_title: Vec<u8>,
    pub certificates: Vec<Choice>,
}

impl AssociationStatus {
    /// Parses an association status from its numeric value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NonAssociated),
            1 => Some(Self::AssociationPending),
            2 => Some(Self::Associated),
            _ => None,
        }
    }
}

/// Clock base (IEC 62056-6-2, 4.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockBase {
    /// No clock base.
    None = 0,
    /// Internal crystal.
    InternalCrystal = 1,
    /// Mains frequency.
    MainsFrequency = 2,
    /// GPS.
    Gps = 3,
    /// Radio clock.
    RadioClock = 4,
}

impl ClockBase {
    /// Parses a clock base from its numeric value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::InternalCrystal),
            2 => Some(Self::MainsFrequency),
            3 => Some(Self::Gps),
            4 => Some(Self::RadioClock),
            _ => None,
        }
    }
}
