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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Attribute value (CHOICE type, attribute 2).
    pub value: Choice,
}

/// Register class (class_id = 3) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: value (CHOICE)
/// - attr 3: scaler_unit (scal_unit_type)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Attribute value (CHOICE type, attribute 2).
    pub value: Choice,
    /// Scaler and unit (attribute 3).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Attribute value (CHOICE type, attribute 2).
    pub value: Choice,
    /// Scaler and unit (attribute 3).
    pub scaler_unit: ScalerUnit,
    /// Status value (CHOICE type, attribute 4).
    pub status: Choice,
    /// Capture time (attribute 5).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Current average value (CHOICE type, attribute 2).
    pub current_average_value: Choice,
    /// Last average value (CHOICE type, attribute 3).
    pub last_average_value: Choice,
    /// Scaler and unit (attribute 4).
    pub scaler_unit: ScalerUnit,
    /// Status value (CHOICE type, attribute 5).
    pub status: Choice,
    /// Capture time (attribute 6).
    pub capture_time: Choice,
    /// Start time for current period (attribute 7).
    pub start_time_current: Choice,
    /// Period in seconds (attribute 8).
    pub period: u32,
    /// Number of periods (attribute 9).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Buffer of captured data records (attribute 2).
    pub buffer: Vec<Choice>,
    /// Capture objects definition (attribute 3).
    pub capture_objects: Vec<CaptureObjectDefinition>,
    /// Capture period in seconds (attribute 4).
    pub capture_period: u32,
    /// Sort method (attribute 5).
    pub sort_method: SortMethod,
    /// Sort object (attribute 6).
    pub sort_object: Option<CaptureObjectDefinition>,
    /// Number of entries currently in buffer (attribute 7).
    pub entries_in_use: u32,
    /// Maximum number of profile entries (attribute 8).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Current date and time (attribute 2).
    pub time: DateTime,
    /// Time zone deviation from UTC in minutes (attribute 3).
    pub time_zone: i16,
    /// Clock status bit-string (attribute 4).
    pub status: u8,
    /// Daylight savings begin time (attribute 5).
    pub daylight_savings_begin: DateTime,
    /// Daylight savings end time (attribute 6).
    pub daylight_savings_end: DateTime,
    /// Daylight savings deviation in minutes (attribute 7).
    pub daylight_savings_deviation: i8,
    /// Daylight savings enabled flag (attribute 8).
    pub daylight_savings_enabled: bool,
    /// Clock base source (attribute 9).
    pub clock_base: u8,
}

/// Script table class (class_id = 9) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: scripts (array of {script_id, actions})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptTableAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Array of script entries (attribute 2).
    pub scripts: Vec<Choice>,
}

/// Schedule class (class_id = 10) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: entries (array of {switch_time, day_profile_table, week_profile_table, month_profile_table})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Array of schedule entries (attribute 2).
    pub entries: Vec<Choice>,
}

/// Special days table class (class_id = 11) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: entries (array of {date, day_id})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialDaysTableAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Array of special day entries (attribute 2).
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
/// - attr 10: user_list (array) \[v2\]
/// - attr 11: current_user (structure) \[v2\]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationLnAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Object list (attribute 2).
    pub object_list: Vec<Choice>,
    /// Associated partners identifier (attribute 3).
    pub associated_partners_id: Choice,
    /// Application context name (attribute 4).
    pub application_context_name: Choice,
    /// xDLMS context info (attribute 5).
    pub xdlms_context_info: Choice,
    /// Authentication mechanism name (attribute 6).
    pub authentication_mechanism_name: u8,
    /// Secret / password (attribute 7).
    pub secret: Vec<u8>,
    /// Association status (attribute 8).
    pub association_status: AssociationStatus,
    /// Security setup reference (attribute 9, v1+).
    pub security_setup_reference: Option<ObisCode>,
    /// User list (attribute 10, v2).
    pub user_list: Vec<Choice>,
    /// Current user (attribute 11, v2).
    pub current_user: Option<Choice>,
}

/// SAP assignment class (class_id = 17) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: sap_assignment_list (array of {sap_name, sap_address})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SapAssignmentAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// SAP assignment list (attribute 2).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Calendar name (attribute 2).
    pub calendar_name: Vec<u8>,
    /// Week profile table (attribute 3).
    pub week_profile_table: Vec<Choice>,
    /// Day profile table (attribute 4).
    pub day_profile_table: Vec<Choice>,
    /// Month profile table (attribute 5).
    pub month_profile_table: Vec<Choice>,
    /// Active calendar name (attribute 6).
    pub active_calendar: Vec<u8>,
}

/// Register monitor class (class_id = 21) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: thresholds (array of {value, script})
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMonitorAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Threshold definitions (attribute 2).
    pub thresholds: Vec<Choice>,
}

/// Single action schedule class (class_id = 22) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: executed_script (capture_object_definition)
/// - attr 3: execution_time (array of octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleActionScheduleAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Executed script reference (attribute 2).
    pub executed_script: CaptureObjectDefinition,
    /// Execution time array (attribute 3).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Block size for transfer (attribute 2).
    pub block_size: u16,
    /// Number of transferred blocks (attribute 3).
    pub transferred_blocks: u32,
    /// Last block number transferred (attribute 4).
    pub last_block_number: u32,
    /// Transfer status (attribute 5).
    pub transfer_status: u8,
    /// Image transfer enabled flag (attribute 6).
    pub image_transfer_enabled: bool,
    /// Block transfer status bit-string (attribute 7).
    pub image_transferred_block_status: Vec<u8>,
    /// First not transferred block number (attribute 8).
    pub image_first_not_transferred_block_number: u32,
    /// Block transfer trigger (attribute 9).
    pub image_block_transfer_trigger: u8,
    /// Transfer service enable flag (attribute 10).
    pub image_transfer_service_enable: bool,
    /// Activation info array (attribute 11).
    pub image_activation_info: Vec<Choice>,
}

/// Disconnect control class (class_id = 70) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: output_state (boolean)
/// - attr 3: control_mode (enum)
/// - attr 4: physical_output_name (octet-string)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectControlAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Output state (attribute 2).
    pub output_state: bool,
    /// Control mode (attribute 3).
    pub control_mode: u8,
    /// Physical output name (attribute 4).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Monitored value (attribute 2).
    pub monitored_value: Choice,
    /// Normal threshold (attribute 3).
    pub threshold_normal: Choice,
    /// Minimum operation threshold (attribute 4).
    pub threshold_min_operation: Choice,
    /// Maximum operation threshold (attribute 5).
    pub threshold_max_operation: Choice,
    /// Minimum over-threshold duration (attribute 6).
    pub min_over_threshold_duration: u16,
    /// Minimum under-threshold duration (attribute 7).
    pub min_under_threshold_duration: u16,
    /// Emergency profile (attribute 8).
    pub emergency_profile: CaptureObjectDefinition,
    /// Emergency profile action (attribute 9).
    pub emergency_profile_action: u8,
    /// Active calendar name (attribute 10).
    pub active_calendar_name: Vec<u8>,
    /// Emergency profile group ID (attribute 11).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Port number (attribute 2).
    pub port: u16,
    /// TCP/UDP protocol type (attribute 3).
    pub tcp_udp_protocol: Vec<u8>,
    /// IP reference logical name (attribute 4).
    pub ip_reference: Vec<u8>,
    /// Maximum simultaneous connections (attribute 5).
    pub maximum_simultaneous_connections: u16,
    /// Maximum segment size (attribute 6).
    pub maximum_segment_size: u16,
    /// Inactivity timeout in seconds (attribute 7).
    pub inactivity_timeout: u16,
    /// Transport security mode (attribute 8).
    pub transport_security: u8,
    /// Password setup reference (attribute 9).
    pub password_setup: Vec<u8>,
    /// Password (attribute 10).
    pub password: Vec<u8>,
    /// Default password status (attribute 11).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// IP address, 4 bytes (attribute 2).
    pub ip_address: [u8; 4],
    /// Subnet mask, 4 bytes (attribute 3).
    pub subnet_mask: [u8; 4],
    /// Gateway IP address, 4 bytes (attribute 4).
    pub gateway_ip_address: [u8; 4],
    /// Use DHCP flag (attribute 5).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// IP address, 16 bytes (attribute 2).
    pub ip_address: [u8; 16],
    /// Prefix length (attribute 3).
    pub prefix_length: u8,
    /// Gateway IP address, 16 bytes (attribute 4).
    pub gateway_ip_address: [u8; 16],
    /// Use DHCP flag (attribute 5).
    pub use_dhcp: bool,
    /// Multicast address, 16 bytes (attribute 6).
    pub multicast_address: [u8; 16],
}

/// MAC address setup class (class_id = 43) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: unicast_mac_address (octet-string, 6 bytes)
/// - attr 3: broadcast_mac_address (octet-string, 6 bytes)
/// - attr 4: multicast_mac_address (octet-string, 6 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAddressSetupAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Unicast MAC address, 6 bytes (attribute 2).
    pub unicast_mac_address: [u8; 6],
    /// Broadcast MAC address, 6 bytes (attribute 3).
    pub broadcast_mac_address: [u8; 6],
    /// Multicast MAC address, 6 bytes (attribute 4).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Access point name (attribute 2).
    pub apn: Vec<u8>,
    /// PIN code (attribute 3).
    pub pin_code: Vec<u8>,
    /// Username (attribute 4).
    pub username: Vec<u8>,
    /// Password (attribute 5).
    pub password: Vec<u8>,
    /// Ask for password flag (attribute 6).
    pub ask_for_password: bool,
    /// IP address, 4 bytes (attribute 7).
    pub ip_address: [u8; 4],
    /// IP port number (attribute 8).
    pub ip_port: u16,
    /// Transfer services (attribute 9).
    pub transfer_services: Vec<u8>,
    /// Default transfers (attribute 10).
    pub default_transfers: Vec<u8>,
    /// GPRS timeout in seconds (attribute 11).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Cell ID (attribute 2).
    pub cell_id: Vec<u8>,
    /// Location area ID (attribute 3).
    pub location_id: Vec<u8>,
    /// IMSI (attribute 4).
    pub imsi: Vec<u8>,
    /// IMEI (attribute 5).
    pub imei: Vec<u8>,
    /// Routing area code (attribute 6).
    pub rn: Vec<u8>,
    /// Cell ID (attribute 7).
    pub cn: Vec<u8>,
    /// Signal quality (attribute 8).
    pub signal_quality: Vec<u8>,
    /// Signal strength (attribute 9).
    pub signal_strength: Vec<u8>,
    /// Channel number (attribute 10).
    pub channel_number: Vec<u8>,
    /// Cell parameter ID (attribute 11).
    pub cell_parameter_id: Vec<u8>,
    /// Base station ID code (attribute 12).
    pub bsic: Vec<u8>,
    /// SIM card ICCID (attribute 13).
    pub iccid: Vec<u8>,
    /// Location area code (attribute 14).
    pub lac: Vec<u8>,
    /// Mobile country code (attribute 15).
    pub mcc: Vec<u8>,
    /// Mobile network code (attribute 16).
    pub mnc: Vec<u8>,
    /// Temporary mobile subscriber ID (attribute 17).
    pub tmsi: Vec<u8>,
    /// Temporary mobile group ID (attribute 18).
    pub tmgi: Vec<u8>,
    /// GPRS status (attribute 19).
    pub gprs_status: Vec<u8>,
    /// Routing area code (attribute 20).
    pub routing_area_code: Vec<u8>,
    /// Geographic address (attribute 21).
    pub geographic_address: Vec<u8>,
    /// Access point name (attribute 22).
    pub access_point_name: Vec<u8>,
    /// Data transport state (attribute 23).
    pub data_transport_state: Vec<u8>,
    /// NMA message (attribute 24).
    pub nma_message: Vec<u8>,
}

/// Arbitrator class (class_id = 68) attributes.
/// - attr 1: logical_name (octet-string)
/// - attr 2: capture_groups (array of capture_object_definition)
/// - attr 3: action_groups (array of array)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitratorAttrs {
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Capture groups (attribute 2).
    pub capture_groups: Vec<CaptureObjectDefinition>,
    /// Action groups (attribute 3).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Communication channel (attribute 2).
    pub channel: u8,
    /// Wait time array (attribute 3).
    pub wait: Vec<Choice>,
    /// Client HDLC address (attribute 4).
    pub client_address: u16,
    /// Server HDLC address (attribute 5).
    pub server_address: u16,
    /// TX window size (attribute 6).
    pub window_size_tx: u8,
    /// RX window size (attribute 7).
    pub window_size_rx: u8,
    /// Max info field TX (attribute 8).
    pub max_info_tx: u16,
    /// Max info field RX (attribute 9).
    pub max_info_rx: u16,
    /// Max timeout TX in ms (attribute 10).
    pub max_timeout_tx: u16,
    /// Max retries TX (attribute 11).
    pub max_retries_tx: u8,
    /// Max timeout for respond in ms (attribute 12).
    pub max_timeout_respond: u16,
    /// Max retries for respond (attribute 13).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Communication mode (attribute 2).
    pub mode: u8,
    /// Communication speed (attribute 3).
    pub communication_speed: u8,
    /// Maximum info field size (attribute 4).
    pub max_size_info_field: u16,
    /// Device address (attribute 5).
    pub device_address: Vec<u8>,
    /// Password 1 (attribute 6).
    pub password1: Vec<u8>,
    /// Password 2 (attribute 7).
    pub password2: Vec<u8>,
    /// Password 3 (attribute 8).
    pub password3: Vec<u8>,
    /// Client address (attribute 9).
    pub client_address: Vec<u8>,
    /// Point-to-point address (attribute 10).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// M-Bus slave address (attribute 2).
    pub mbus_address: Vec<u8>,
    /// Identification number (attribute 3).
    pub identification_number: Vec<u8>,
    /// Manufacturer ID (attribute 4).
    pub manufacturer_id: Vec<u8>,
    /// Data type (attribute 5).
    pub data_type: Vec<u8>,
    /// Max slave PI frames (attribute 6).
    pub max_slave_pifs: u16,
    /// Max master PI frames (attribute 7).
    pub max_master_pifs: u16,
    /// Character encoding (attribute 8).
    pub character_encoding: Vec<u8>,
    /// M-Bus mode (attribute 9).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Protection method (attribute 2).
    pub protection_method: u8,
    /// Protection key (attribute 3).
    pub protection_key: Vec<u8>,
    /// Key translation table 1 (attribute 4).
    pub key_translation_table_1: Vec<Choice>,
    /// Key translation table 2 (attribute 5).
    pub key_translation_table_2: Vec<Choice>,
    /// Key translation table 3 (attribute 6).
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
    /// OBIS logical name (attribute 1).
    pub logical_name: LogicalName,
    /// Security policy (attribute 2).
    pub security_policy: u8,
    /// Security suite (attribute 3).
    pub security_suite: u8,
    /// Client system title (attribute 4).
    pub client_system_title: Vec<u8>,
    /// Server system title (attribute 5).
    pub server_system_title: Vec<u8>,
    /// Certificates array (attribute 6).
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

// ============================================================================
// Shared COSEM typed structures (Blue Book / IEC 62056-6-2)
// ============================================================================

/// `access_right` — structure { attribute_access, method_access }
/// Used by Association LN (attr 2) and Association SN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRight {
    /// Attribute access permissions.
    pub attribute_access: Vec<AttributeAccessItem>,
    /// Method access permissions.
    pub method_access: Vec<MethodAccessItem>,
}

impl From<AccessRight> for CosemDataType {
    fn from(ar: AccessRight) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Array(ar.attribute_access.into_iter().map(CosemDataType::from).collect()),
            CosemDataType::Array(ar.method_access.into_iter().map(CosemDataType::from).collect()),
        ])
    }
}

impl TryFrom<&CosemDataType> for AccessRight {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let attribute_access = match &fields[0] {
                    CosemDataType::Array(items) => items
                        .iter()
                        .map(AttributeAccessItem::try_from)
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("attribute_access must be array".to_string()),
                };
                let method_access = match &fields[1] {
                    CosemDataType::Array(items) => items
                        .iter()
                        .map(MethodAccessItem::try_from)
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("method_access must be array".to_string()),
                };
                Ok(AccessRight { attribute_access, method_access })
            }
            _ => Err("expected structure {attribute_access, method_access}".to_string()),
        }
    }
}

/// `attribute_access_item` — structure { attribute_id, access_mode, access_selectors }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeAccessItem {
    /// Attribute identifier.
    pub attribute_id: i8,
    /// Access mode for the attribute.
    pub access_mode: u8,
    /// Optional access selectors.
    pub access_selectors: Option<Vec<i8>>,
}

impl From<AttributeAccessItem> for CosemDataType {
    fn from(item: AttributeAccessItem) -> Self {
        let access_selectors = match item.access_selectors {
            Some(ids) => CosemDataType::Array(ids.into_iter().map(CosemDataType::Integer).collect()),
            None => CosemDataType::Null,
        };
        CosemDataType::Structure(vec![
            CosemDataType::Integer(item.attribute_id),
            CosemDataType::Enum(item.access_mode),
            access_selectors,
        ])
    }
}

impl TryFrom<&CosemDataType> for AttributeAccessItem {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let attribute_id = match &fields[0] {
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("attribute_id must be integer".to_string()),
                };
                let access_mode = match &fields[1] {
                    CosemDataType::Enum(v) => *v,
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("access_mode must be enum".to_string()),
                };
                let access_selectors = match &fields[2] {
                    CosemDataType::Null => None,
                    CosemDataType::Array(items) => {
                        let ids = items
                            .iter()
                            .map(|item| match item {
                                CosemDataType::Integer(v) => Ok(*v),
                                CosemDataType::Long(v) => Ok(*v as i8),
                                _ => Err("selector must be integer".to_string()),
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        Some(ids)
                    }
                    _ => None,
                };
                Ok(AttributeAccessItem { attribute_id, access_mode, access_selectors })
            }
            _ => Err("expected structure {attribute_id, access_mode, access_selectors}".to_string()),
        }
    }
}

/// `method_access_item` — structure { method_id, access_mode }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodAccessItem {
    /// Method identifier.
    pub method_id: i8,
    /// Access mode for the method.
    pub access_mode: u8,
}

impl From<MethodAccessItem> for CosemDataType {
    fn from(item: MethodAccessItem) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Integer(item.method_id),
            CosemDataType::Enum(item.access_mode),
        ])
    }
}

impl TryFrom<&CosemDataType> for MethodAccessItem {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let method_id = match &fields[0] {
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("method_id must be integer".to_string()),
                };
                let access_mode = match &fields[1] {
                    CosemDataType::Enum(v) => *v,
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("access_mode must be enum".to_string()),
                };
                Ok(MethodAccessItem { method_id, access_mode })
            }
            _ => Err("expected structure {method_id, access_mode}".to_string()),
        }
    }
}

/// `object_list_element` — structure { class_id, version, logical_name, access_rights }
/// Used in Association LN attr 2 (object_list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectListElement {
    /// COSEM class identifier.
    pub class_id: u16,
    /// Class version number.
    pub version: u8,
    /// OBIS logical name.
    pub logical_name: ObisCode,
    /// Access rights for this object.
    pub access_rights: AccessRight,
}

impl From<ObjectListElement> for CosemDataType {
    fn from(e: ObjectListElement) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(e.class_id),
            CosemDataType::Unsigned(e.version),
            CosemDataType::OctetString(e.logical_name.to_bytes()),
            CosemDataType::from(e.access_rights),
        ])
    }
}

impl TryFrom<&CosemDataType> for ObjectListElement {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 4 => {
                let class_id = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("class_id must be long-unsigned".to_string()),
                };
                let version = match &fields[1] {
                    CosemDataType::Unsigned(v) => *v,
                    CosemDataType::LongUnsigned(v) => *v as u8,
                    _ => return Err("version must be unsigned".to_string()),
                };
                let logical_name = match &fields[2] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("logical_name must be 6-byte octet-string".to_string()),
                };
                let access_rights = AccessRight::try_from(&fields[3])?;
                Ok(ObjectListElement { class_id, version, logical_name, access_rights })
            }
            _ => Err("expected structure {class_id, version, logical_name, access_rights}".to_string()),
        }
    }
}

/// `associated_partners_type` — structure { client_SAP, server_SAP }
/// Used in Association LN attr 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociatedPartnersId {
    /// Client SAP address.
    pub client_sap: i8,
    /// Server SAP address.
    pub server_sap: u16,
}

impl From<AssociatedPartnersId> for CosemDataType {
    fn from(ap: AssociatedPartnersId) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Integer(ap.client_sap),
            CosemDataType::LongUnsigned(ap.server_sap),
        ])
    }
}

impl TryFrom<&CosemDataType> for AssociatedPartnersId {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let client_sap = match &fields[0] {
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("client_SAP must be integer".to_string()),
                };
                let server_sap = match &fields[1] {
                    CosemDataType::LongUnsigned(v) => *v,
                    CosemDataType::Unsigned(v) => *v as u16,
                    _ => return Err("server_SAP must be long-unsigned".to_string()),
                };
                Ok(AssociatedPartnersId { client_sap, server_sap })
            }
            _ => Err("expected structure {client_SAP, server_SAP}".to_string()),
        }
    }
}

/// `context_name_type` — CHOICE of structure or octet-string.
/// Used in Association LN attr 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextName {
    /// Encoded as a 7-element structure of OID arc components.
    Structure {
        /// Joint-iso-ccitt arc (2).
        joint_iso_ctt: u8,
        /// Country arc.
        country: u8,
        /// Country name arc.
        country_name: u16,
        /// Identified organization arc.
        identified_organization: u8,
        /// DLMS UA arc.
        dlms_ua: u8,
        /// Application context arc.
        application_context: u8,
        /// Context identifier arc.
        context_id: u8,
    },
    /// Encoded as raw octet-string (OBJECT IDENTIFIER).
    OctetString(Vec<u8>),
}

impl From<ContextName> for CosemDataType {
    fn from(cn: ContextName) -> Self {
        match cn {
            ContextName::Structure {
                joint_iso_ctt,
                country,
                country_name,
                identified_organization,
                dlms_ua,
                application_context,
                context_id,
            } => CosemDataType::Structure(vec![
                CosemDataType::Unsigned(joint_iso_ctt),
                CosemDataType::Unsigned(country),
                CosemDataType::LongUnsigned(country_name),
                CosemDataType::Unsigned(identified_organization),
                CosemDataType::Unsigned(dlms_ua),
                CosemDataType::Unsigned(application_context),
                CosemDataType::Unsigned(context_id),
            ]),
            ContextName::OctetString(bytes) => CosemDataType::OctetString(bytes),
        }
    }
}

impl TryFrom<&CosemDataType> for ContextName {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 7 => {
                let joint_iso_ctt = match &fields[0] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("joint_iso_ctt must be unsigned".to_string()),
                };
                let country = match &fields[1] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("country must be unsigned".to_string()),
                };
                let country_name = match &fields[2] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("country_name must be long-unsigned".to_string()),
                };
                let identified_organization = match &fields[3] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("identified_organization must be unsigned".to_string()),
                };
                let dlms_ua = match &fields[4] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("DLMS_UA must be unsigned".to_string()),
                };
                let application_context = match &fields[5] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("application_context must be unsigned".to_string()),
                };
                let context_id = match &fields[6] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("context_id must be unsigned".to_string()),
                };
                Ok(ContextName::Structure {
                    joint_iso_ctt,
                    country,
                    country_name,
                    identified_organization,
                    dlms_ua,
                    application_context,
                    context_id,
                })
            }
            CosemDataType::OctetString(bytes) => Ok(ContextName::OctetString(bytes.clone())),
            _ => Err("expected structure or octet-string for context_name".to_string()),
        }
    }
}

/// `xDLMS-context-type` — structure { conformance, max_receive_pdu_size, ... }
/// Used in Association LN attr 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XDLMSContextInfo {
    /// Conformance block (bit-string).
    pub conformance: Vec<u8>,
    /// Maximum receive PDU size in bytes.
    pub max_receive_pdu_size: u16,
    /// Maximum send PDU size in bytes.
    pub max_send_pdu_size: u16,
    /// DLMS version number.
    pub dlms_version_number: u8,
    /// Quality of service (-1 = default).
    pub quality_of_service: i8,
    /// Cyphering info (octet-string).
    pub cyphering_info: Vec<u8>,
}

impl From<XDLMSContextInfo> for CosemDataType {
    fn from(ctx: XDLMSContextInfo) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::BitString(ctx.conformance),
            CosemDataType::LongUnsigned(ctx.max_receive_pdu_size),
            CosemDataType::LongUnsigned(ctx.max_send_pdu_size),
            CosemDataType::Unsigned(ctx.dlms_version_number),
            CosemDataType::Integer(ctx.quality_of_service),
            CosemDataType::OctetString(ctx.cyphering_info),
        ])
    }
}

impl TryFrom<&CosemDataType> for XDLMSContextInfo {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 6 => {
                let conformance = match &fields[0] {
                    CosemDataType::BitString(v) => v.clone(),
                    _ => return Err("conformance must be bit-string".to_string()),
                };
                let max_receive_pdu_size = match &fields[1] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("max_receive_pdu_size must be long-unsigned".to_string()),
                };
                let max_send_pdu_size = match &fields[2] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("max_send_pdu_size must be long-unsigned".to_string()),
                };
                let dlms_version_number = match &fields[3] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("dlms_version_number must be unsigned".to_string()),
                };
                let quality_of_service = match &fields[4] {
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("quality_of_service must be integer".to_string()),
                };
                let cyphering_info = match &fields[5] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("cyphering_info must be octet-string".to_string()),
                };
                Ok(XDLMSContextInfo {
                    conformance,
                    max_receive_pdu_size,
                    max_send_pdu_size,
                    dlms_version_number,
                    quality_of_service,
                    cyphering_info,
                })
            }
            _ => Err("expected structure for xDLMS_context_info".to_string()),
        }
    }
}

/// `value_definition` — structure { class_id, logical_name, attribute_index }
/// Used in Register Monitor (attr 3) and Limiter (attr 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueDefinition {
    /// COSEM class identifier.
    pub class_id: u16,
    /// OBIS logical name of the target object.
    pub logical_name: ObisCode,
    /// Attribute index to read.
    pub attribute_index: i8,
}

impl From<ValueDefinition> for CosemDataType {
    fn from(vd: ValueDefinition) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(vd.class_id),
            CosemDataType::OctetString(vd.logical_name.to_bytes()),
            CosemDataType::Integer(vd.attribute_index),
        ])
    }
}

impl TryFrom<&CosemDataType> for ValueDefinition {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
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
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("attribute_index must be integer".to_string()),
                };
                Ok(ValueDefinition { class_id, logical_name, attribute_index })
            }
            _ => Err("expected structure {class_id, logical_name, attribute_index}".to_string()),
        }
    }
}

/// `action_item` — structure { script_logical_name, script_selector }
/// Used in Register Monitor, Limiter, and other ICs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionItem {
    /// Logical name of the Script Table object.
    pub script_logical_name: ObisCode,
    /// Script identifier to execute.
    pub script_selector: u16,
}

impl From<ActionItem> for CosemDataType {
    fn from(ai: ActionItem) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(ai.script_logical_name.to_bytes()),
            CosemDataType::LongUnsigned(ai.script_selector),
        ])
    }
}

impl TryFrom<&CosemDataType> for ActionItem {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let script_logical_name = match &fields[0] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("script_logical_name must be 6-byte octet-string".to_string()),
                };
                let script_selector = match &fields[1] {
                    CosemDataType::LongUnsigned(v) => *v,
                    CosemDataType::Unsigned(v) => *v as u16,
                    _ => return Err("script_selector must be long-unsigned".to_string()),
                };
                Ok(ActionItem { script_logical_name, script_selector })
            }
            _ => Err("expected structure {script_logical_name, script_selector}".to_string()),
        }
    }
}

/// `action_set` — structure { action_up, action_down }
/// Used in Register Monitor (attr 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSet {
    /// Action to execute on threshold increase.
    pub action_up: ActionItem,
    /// Action to execute on threshold decrease.
    pub action_down: ActionItem,
}

impl From<ActionSet> for CosemDataType {
    fn from(a: ActionSet) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::from(a.action_up),
            CosemDataType::from(a.action_down),
        ])
    }
}

impl TryFrom<&CosemDataType> for ActionSet {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let action_up = ActionItem::try_from(&fields[0])?;
                let action_down = ActionItem::try_from(&fields[1])?;
                Ok(ActionSet { action_up, action_down })
            }
            _ => Err("expected structure {action_up, action_down}".to_string()),
        }
    }
}

/// `action_specification` — structure { service_id, class_id, logical_name, index, parameter }
/// Used in Script Table (attr 2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionSpecification {
    /// Service ID (method number).
    pub service_id: u8,
    /// Target class identifier.
    pub class_id: u16,
    /// OBIS logical name of the target object.
    pub logical_name: ObisCode,
    /// Attribute index (0 for methods).
    pub index: i8,
    /// Parameter value for the service.
    pub parameter: Choice,
}

impl From<ActionSpecification> for CosemDataType {
    fn from(aspec: ActionSpecification) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Enum(aspec.service_id),
            CosemDataType::LongUnsigned(aspec.class_id),
            CosemDataType::OctetString(aspec.logical_name.to_bytes()),
            CosemDataType::Integer(aspec.index),
            aspec.parameter,
        ])
    }
}

impl TryFrom<&CosemDataType> for ActionSpecification {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 5 => {
                let service_id = match &fields[0] {
                    CosemDataType::Enum(v) => *v,
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("service_id must be enum".to_string()),
                };
                let class_id = match &fields[1] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("class_id must be long-unsigned".to_string()),
                };
                let logical_name = match &fields[2] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("logical_name must be 6-byte octet-string".to_string()),
                };
                let index = match &fields[3] {
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("index must be integer".to_string()),
                };
                let parameter = fields[4].clone();
                Ok(ActionSpecification { service_id, class_id, logical_name, index, parameter })
            }
            _ => Err("expected structure {service_id, class_id, logical_name, index, parameter}".to_string()),
        }
    }
}

/// `script` — structure { script_identifier, actions }
/// Used in Script Table (attr 2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Script {
    /// Script identifier (unique within the Script Table).
    pub script_identifier: u16,
    /// Ordered list of actions to execute.
    pub actions: Vec<ActionSpecification>,
}

impl From<Script> for CosemDataType {
    fn from(s: Script) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(s.script_identifier),
            CosemDataType::Array(s.actions.into_iter().map(CosemDataType::from).collect()),
        ])
    }
}

impl TryFrom<&CosemDataType> for Script {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let script_identifier = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("script_identifier must be long-unsigned".to_string()),
                };
                let actions = match &fields[1] {
                    CosemDataType::Array(items) => items
                        .iter()
                        .map(ActionSpecification::try_from)
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("actions must be array".to_string()),
                };
                Ok(Script { script_identifier, actions })
            }
            _ => Err("expected structure {script_identifier, actions}".to_string()),
        }
    }
}

/// `schedule_table_entry` — structure { index, enable, script_logical_name, ... }
/// Used in Schedule (attr 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleTableEntry {
    /// Entry index.
    pub index: u16,
    /// Enable flag.
    pub enable: bool,
    /// Logical name of the Script Table.
    pub script_logical_name: ObisCode,
    /// Script selector.
    pub script_selector: u16,
    /// Switch time.
    pub switch_time: Vec<u8>,
    /// Validity window in seconds.
    pub validity_window: u16,
    /// Execution weekdays bit-string.
    pub exec_weekdays: Vec<u8>,
    /// Execution special days bit-string.
    pub exec_specdays: Vec<u8>,
    /// Begin date.
    pub begin_date: Vec<u8>,
    /// End date.
    pub end_date: Vec<u8>,
}

impl From<ScheduleTableEntry> for CosemDataType {
    fn from(e: ScheduleTableEntry) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(e.index),
            CosemDataType::Boolean(e.enable),
            CosemDataType::OctetString(e.script_logical_name.to_bytes()),
            CosemDataType::LongUnsigned(e.script_selector),
            CosemDataType::OctetString(e.switch_time),
            CosemDataType::LongUnsigned(e.validity_window),
            CosemDataType::BitString(e.exec_weekdays),
            CosemDataType::BitString(e.exec_specdays),
            CosemDataType::OctetString(e.begin_date),
            CosemDataType::OctetString(e.end_date),
        ])
    }
}

impl TryFrom<&CosemDataType> for ScheduleTableEntry {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 10 => {
                let index = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("index must be long-unsigned".to_string()),
                };
                let enable = match &fields[1] {
                    CosemDataType::Boolean(v) => *v,
                    _ => return Err("enable must be boolean".to_string()),
                };
                let script_logical_name = match &fields[2] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("script_logical_name must be 6-byte octet-string".to_string()),
                };
                let script_selector = match &fields[3] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("script_selector must be long-unsigned".to_string()),
                };
                let switch_time = match &fields[4] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("switch_time must be octet-string".to_string()),
                };
                let validity_window = match &fields[5] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("validity_window must be long-unsigned".to_string()),
                };
                let exec_weekdays = match &fields[6] {
                    CosemDataType::BitString(v) => v.clone(),
                    _ => return Err("exec_weekdays must be bit-string".to_string()),
                };
                let exec_specdays = match &fields[7] {
                    CosemDataType::BitString(v) => v.clone(),
                    _ => return Err("exec_specdays must be bit-string".to_string()),
                };
                let begin_date = match &fields[8] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("begin_date must be octet-string".to_string()),
                };
                let end_date = match &fields[9] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("end_date must be octet-string".to_string()),
                };
                Ok(ScheduleTableEntry {
                    index,
                    enable,
                    script_logical_name,
                    script_selector,
                    switch_time,
                    validity_window,
                    exec_weekdays,
                    exec_specdays,
                    begin_date,
                    end_date,
                })
            }
            _ => Err("expected 10-element structure for schedule_table_entry".to_string()),
        }
    }
}

/// `spec_day_entry` — structure { index, specialday_date, day_id }
/// Used in Special Days Table (attr 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecialDayEntry {
    /// Entry index.
    pub index: u16,
    /// Special day date.
    pub specialday_date: Vec<u8>,
    /// Day profile ID to use.
    pub day_id: u8,
}

impl From<SpecialDayEntry> for CosemDataType {
    fn from(e: SpecialDayEntry) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(e.index),
            CosemDataType::OctetString(e.specialday_date),
            CosemDataType::Unsigned(e.day_id),
        ])
    }
}

impl TryFrom<&CosemDataType> for SpecialDayEntry {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let index = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("index must be long-unsigned".to_string()),
                };
                let specialday_date = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("specialday_date must be octet-string".to_string()),
                };
                let day_id = match &fields[2] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("day_id must be unsigned".to_string()),
                };
                Ok(SpecialDayEntry { index, specialday_date, day_id })
            }
            _ => Err("expected structure {index, specialday_date, day_id}".to_string()),
        }
    }
}

/// `season_profile` — structure { season_profile_name, season_start, week_name }
/// Used in Activity Calendar (attr 3/7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeasonProfile {
    /// Season profile name.
    pub season_profile_name: Vec<u8>,
    /// Season start date-time.
    pub season_start: Vec<u8>,
    /// Week profile name to use.
    pub week_name: Vec<u8>,
}

impl From<SeasonProfile> for CosemDataType {
    fn from(sp: SeasonProfile) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(sp.season_profile_name),
            CosemDataType::OctetString(sp.season_start),
            CosemDataType::OctetString(sp.week_name),
        ])
    }
}

impl TryFrom<&CosemDataType> for SeasonProfile {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let season_profile_name = match &fields[0] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("season_profile_name must be octet-string".to_string()),
                };
                let season_start = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("season_start must be octet-string".to_string()),
                };
                let week_name = match &fields[2] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("week_name must be octet-string".to_string()),
                };
                Ok(SeasonProfile { season_profile_name, season_start, week_name })
            }
            _ => Err("expected structure for season_profile".to_string()),
        }
    }
}

/// `week_profile` — structure { week_profile_name, monday..sunday: day_id }
/// Used in Activity Calendar (attr 4/8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeekProfile {
    /// Week profile name.
    pub week_profile_name: Vec<u8>,
    /// Day profile ID for Monday.
    pub monday: u8,
    /// Day profile ID for Tuesday.
    pub tuesday: u8,
    /// Day profile ID for Wednesday.
    pub wednesday: u8,
    /// Day profile ID for Thursday.
    pub thursday: u8,
    /// Day profile ID for Friday.
    pub friday: u8,
    /// Day profile ID for Saturday.
    pub saturday: u8,
    /// Day profile ID for Sunday.
    pub sunday: u8,
}

impl From<WeekProfile> for CosemDataType {
    fn from(wp: WeekProfile) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(wp.week_profile_name),
            CosemDataType::Unsigned(wp.monday),
            CosemDataType::Unsigned(wp.tuesday),
            CosemDataType::Unsigned(wp.wednesday),
            CosemDataType::Unsigned(wp.thursday),
            CosemDataType::Unsigned(wp.friday),
            CosemDataType::Unsigned(wp.saturday),
            CosemDataType::Unsigned(wp.sunday),
        ])
    }
}

impl TryFrom<&CosemDataType> for WeekProfile {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 8 => {
                let week_profile_name = match &fields[0] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("week_profile_name must be octet-string".to_string()),
                };
                let get_u8 = |f: &CosemDataType| -> Result<u8, String> {
                    match f {
                        CosemDataType::Unsigned(v) => Ok(*v),
                        _ => Err("day_id must be unsigned".to_string()),
                    }
                };
                Ok(WeekProfile {
                    week_profile_name,
                    monday: get_u8(&fields[1])?,
                    tuesday: get_u8(&fields[2])?,
                    wednesday: get_u8(&fields[3])?,
                    thursday: get_u8(&fields[4])?,
                    friday: get_u8(&fields[5])?,
                    saturday: get_u8(&fields[6])?,
                    sunday: get_u8(&fields[7])?,
                })
            }
            _ => Err("expected 8-element structure for week_profile".to_string()),
        }
    }
}

/// `day_profile_action` — structure { start_time, script_logical_name, script_selector }
/// Used inside `day_profile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DayProfileAction {
    /// Start time of the action.
    pub start_time: Vec<u8>,
    /// Logical name of the Script Table.
    pub script_logical_name: ObisCode,
    /// Script selector.
    pub script_selector: u16,
}

impl From<DayProfileAction> for CosemDataType {
    fn from(a: DayProfileAction) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(a.start_time),
            CosemDataType::OctetString(a.script_logical_name.to_bytes()),
            CosemDataType::LongUnsigned(a.script_selector),
        ])
    }
}

impl TryFrom<&CosemDataType> for DayProfileAction {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let start_time = match &fields[0] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("start_time must be octet-string".to_string()),
                };
                let script_logical_name = match &fields[1] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("script_logical_name must be 6-byte octet-string".to_string()),
                };
                let script_selector = match &fields[2] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("script_selector must be long-unsigned".to_string()),
                };
                Ok(DayProfileAction { start_time, script_logical_name, script_selector })
            }
            _ => Err("expected structure for day_profile_action".to_string()),
        }
    }
}

/// `day_profile` — structure { day_id, day_schedule: array day_profile_action }
/// Used in Activity Calendar (attr 5/9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DayProfile {
    /// Day profile identifier.
    pub day_id: u8,
    /// Ordered list of day schedule actions.
    pub day_schedule: Vec<DayProfileAction>,
}

impl From<DayProfile> for CosemDataType {
    fn from(dp: DayProfile) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Unsigned(dp.day_id),
            CosemDataType::Array(dp.day_schedule.into_iter().map(CosemDataType::from).collect()),
        ])
    }
}

impl TryFrom<&CosemDataType> for DayProfile {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let day_id = match &fields[0] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("day_id must be unsigned".to_string()),
                };
                let day_schedule = match &fields[1] {
                    CosemDataType::Array(items) => items
                        .iter()
                        .map(DayProfileAction::try_from)
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("day_schedule must be array".to_string()),
                };
                Ok(DayProfile { day_id, day_schedule })
            }
            _ => Err("expected structure {day_id, day_schedule}".to_string()),
        }
    }
}

/// `send_destination_and_method` — structure { transport_service, destination, message }
/// Used in Push Setup (attr 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendDestinationAndMethod {
    /// Transport service identifier.
    pub transport_service: u8,
    /// Destination address or identifier.
    pub destination: Vec<u8>,
    /// Message type.
    pub message: u8,
}

impl From<SendDestinationAndMethod> for CosemDataType {
    fn from(s: SendDestinationAndMethod) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Enum(s.transport_service),
            CosemDataType::OctetString(s.destination),
            CosemDataType::Enum(s.message),
        ])
    }
}

impl TryFrom<&CosemDataType> for SendDestinationAndMethod {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let transport_service = match &fields[0] {
                    CosemDataType::Enum(v) => *v,
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("transport_service must be enum".to_string()),
                };
                let destination = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("destination must be octet-string".to_string()),
                };
                let message = match &fields[2] {
                    CosemDataType::Enum(v) => *v,
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("message must be enum".to_string()),
                };
                Ok(SendDestinationAndMethod { transport_service, destination, message })
            }
            _ => Err("expected structure for send_destination_and_method".to_string()),
        }
    }
}

/// `communication_window` entry — structure { begin, end: date-time }
/// Used in Push Setup (attr 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunicationWindow {
    /// Begin date-time of the communication window.
    pub begin: DateTime,
    /// End date-time of the communication window.
    pub end: DateTime,
}

impl From<CommunicationWindow> for CosemDataType {
    fn from(cw: CommunicationWindow) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::DateTime(cw.begin.0.to_vec()),
            CosemDataType::DateTime(cw.end.0.to_vec()),
        ])
    }
}

impl TryFrom<&CosemDataType> for CommunicationWindow {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let begin = DateTime::try_from(&fields[0])?;
                let end = DateTime::try_from(&fields[1])?;
                Ok(CommunicationWindow { begin, end })
            }
            _ => Err("expected structure {begin, end}".to_string()),
        }
    }
}

/// `emergency_profile` — structure { emergency_profile_id, emergency_activation_time, emergency_duration }
/// Used in Limiter (attr 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyProfile {
    /// Emergency profile group ID.
    pub emergency_profile_id: u16,
    /// Emergency activation time.
    pub emergency_activation_time: Vec<u8>,
    /// Emergency duration in seconds.
    pub emergency_duration: u32,
}

impl From<EmergencyProfile> for CosemDataType {
    fn from(ep: EmergencyProfile) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(ep.emergency_profile_id),
            CosemDataType::OctetString(ep.emergency_activation_time),
            CosemDataType::DoubleLongUnsigned(ep.emergency_duration),
        ])
    }
}

impl TryFrom<&CosemDataType> for EmergencyProfile {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let emergency_profile_id = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("emergency_profile_id must be long-unsigned".to_string()),
                };
                let emergency_activation_time = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("emergency_activation_time must be octet-string".to_string()),
                };
                let emergency_duration = match &fields[2] {
                    CosemDataType::DoubleLongUnsigned(v) => *v,
                    _ => return Err("emergency_duration must be double-long-unsigned".to_string()),
                };
                Ok(EmergencyProfile { emergency_profile_id, emergency_activation_time, emergency_duration })
            }
            _ => Err("expected structure for emergency_profile".to_string()),
        }
    }
}

/// `limiter_action` — structure { action_over_threshold, action_under_threshold }
/// Used in Limiter (attr 11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimiterAction {
    /// Action to execute when threshold is exceeded.
    pub action_over_threshold: ActionItem,
    /// Action to execute when value returns below threshold.
    pub action_under_threshold: ActionItem,
}

impl From<LimiterAction> for CosemDataType {
    fn from(a: LimiterAction) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::from(a.action_over_threshold),
            CosemDataType::from(a.action_under_threshold),
        ])
    }
}

impl TryFrom<&CosemDataType> for LimiterAction {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let action_over_threshold = ActionItem::try_from(&fields[0])?;
                let action_under_threshold = ActionItem::try_from(&fields[1])?;
                Ok(LimiterAction { action_over_threshold, action_under_threshold })
            }
            _ => Err("expected structure {action_over_threshold, action_under_threshold}".to_string()),
        }
    }
}

/// `object_definition` — structure { class_id, logical_name }
/// Used in Register Activation (attr 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectDefinition {
    /// COSEM class identifier.
    pub class_id: u16,
    /// OBIS logical name.
    pub logical_name: ObisCode,
}

impl From<ObjectDefinition> for CosemDataType {
    fn from(od: ObjectDefinition) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(od.class_id),
            CosemDataType::OctetString(od.logical_name.to_bytes()),
        ])
    }
}

impl TryFrom<&CosemDataType> for ObjectDefinition {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
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
                Ok(ObjectDefinition { class_id, logical_name })
            }
            _ => Err("expected structure {class_id, logical_name}".to_string()),
        }
    }
}

/// `register_act_mask` — structure { mask_name, index_list: array unsigned }
/// Used in Register Activation (attr 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterActMask {
    /// Mask name (visible string).
    pub mask_name: Vec<u8>,
    /// List of attribute indexes for the mask.
    pub index_list: Vec<u8>,
}

impl From<RegisterActMask> for CosemDataType {
    fn from(m: RegisterActMask) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(m.mask_name),
            CosemDataType::Array(m.index_list.into_iter().map(CosemDataType::Unsigned).collect()),
        ])
    }
}

impl TryFrom<&CosemDataType> for RegisterActMask {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let mask_name = match &fields[0] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("mask_name must be octet-string".to_string()),
                };
                let index_list = match &fields[1] {
                    CosemDataType::Array(items) => items
                        .iter()
                        .map(|item| match item {
                            CosemDataType::Unsigned(v) => Ok(*v),
                            _ => Err("index must be unsigned".to_string()),
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    _ => return Err("index_list must be array".to_string()),
                };
                Ok(RegisterActMask { mask_name, index_list })
            }
            _ => Err("expected structure {mask_name, index_list}".to_string()),
        }
    }
}

/// `image_to_activate_info` entry — structure { image_block_number, image_block_value }
/// Used in Image Transfer (attr 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageToActivateInfo {
    /// Image block number.
    pub image_block_number: u32,
    /// Image block data.
    pub image_block_value: Vec<u8>,
}

impl From<ImageToActivateInfo> for CosemDataType {
    fn from(info: ImageToActivateInfo) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::DoubleLongUnsigned(info.image_block_number),
            CosemDataType::OctetString(info.image_block_value),
        ])
    }
}

impl TryFrom<&CosemDataType> for ImageToActivateInfo {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let image_block_number = match &fields[0] {
                    CosemDataType::DoubleLongUnsigned(v) => *v,
                    _ => return Err("image_block_number must be double-long-unsigned".to_string()),
                };
                let image_block_value = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("image_block_value must be octet-string".to_string()),
                };
                Ok(ImageToActivateInfo { image_block_number, image_block_value })
            }
            _ => Err("expected structure for image_to_activate_info".to_string()),
        }
    }
}

/// `single_action_schedule_executed_script` — structure { script_logical_name, script_selector }
/// Used in Single Action Schedule (attr 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedScript {
    /// Logical name of the Script Table.
    pub script_logical_name: ObisCode,
    /// Script selector.
    pub script_selector: u16,
}

impl From<ExecutedScript> for CosemDataType {
    fn from(es: ExecutedScript) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(es.script_logical_name.to_bytes()),
            CosemDataType::LongUnsigned(es.script_selector),
        ])
    }
}

impl TryFrom<&CosemDataType> for ExecutedScript {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let script_logical_name = match &fields[0] {
                    CosemDataType::OctetString(bytes) if bytes.len() == 6 => {
                        ObisCode::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
                    }
                    _ => return Err("script_logical_name must be 6-byte octet-string".to_string()),
                };
                let script_selector = match &fields[1] {
                    CosemDataType::LongUnsigned(v) => *v,
                    _ => return Err("script_selector must be long-unsigned".to_string()),
                };
                Ok(ExecutedScript { script_logical_name, script_selector })
            }
            _ => Err("expected structure {script_logical_name, script_selector}".to_string()),
        }
    }
}

/// `sap_assignment_entry` — structure { SAP: long-unsigned, logical_device_name: octet-string }
/// Used in SAP Assignment (attr 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SapAssignmentEntry {
    /// SAP address.
    pub sap: u16,
    /// Logical device name.
    pub logical_device_name: Vec<u8>,
}

impl From<SapAssignmentEntry> for CosemDataType {
    fn from(entry: SapAssignmentEntry) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(entry.sap),
            CosemDataType::OctetString(entry.logical_device_name),
        ])
    }
}

impl TryFrom<&CosemDataType> for SapAssignmentEntry {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let sap = match &fields[0] {
                    CosemDataType::LongUnsigned(v) => *v,
                    CosemDataType::Unsigned(v) => *v as u16,
                    _ => return Err("SAP must be long-unsigned".to_string()),
                };
                let logical_device_name = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("logical_device_name must be octet-string".to_string()),
                };
                Ok(SapAssignmentEntry { sap, logical_device_name })
            }
            _ => Err("expected structure {SAP, logical_device_name}".to_string()),
        }
    }
}

/// `gsm_adjacent_cell` — structure { cell_id, signal_quality, signal_strength }
/// Used in GSM Diagnostic (attr 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GsmAdjacentCell {
    /// Cell ID.
    pub cell_id: Vec<u8>,
    /// Signal quality.
    pub signal_quality: Vec<u8>,
    /// Signal strength.
    pub signal_strength: Vec<u8>,
}

impl From<GsmAdjacentCell> for CosemDataType {
    fn from(cell: GsmAdjacentCell) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(cell.cell_id),
            CosemDataType::OctetString(cell.signal_quality),
            CosemDataType::OctetString(cell.signal_strength),
        ])
    }
}

impl TryFrom<&CosemDataType> for GsmAdjacentCell {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
                let cell_id = match &fields[0] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("cell_id must be octet-string".to_string()),
                };
                let signal_quality = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("signal_quality must be octet-string".to_string()),
                };
                let signal_strength = match &fields[2] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("signal_strength must be octet-string".to_string()),
                };
                Ok(GsmAdjacentCell { cell_id, signal_quality, signal_strength })
            }
            _ => Err("expected structure {cell_id, signal_quality, signal_strength}".to_string()),
        }
    }
}

/// `protection_object` — structure { class_id, logical_name, attribute_index }
/// Used in Data Protection and Security Setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionObject {
    /// COSEM class identifier.
    pub class_id: u16,
    /// OBIS logical name.
    pub logical_name: ObisCode,
    /// Attribute index.
    pub attribute_index: i8,
}

impl From<ProtectionObject> for CosemDataType {
    fn from(po: ProtectionObject) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(po.class_id),
            CosemDataType::OctetString(po.logical_name.to_bytes()),
            CosemDataType::Integer(po.attribute_index),
        ])
    }
}

impl TryFrom<&CosemDataType> for ProtectionObject {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 3 => {
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
                    CosemDataType::Integer(v) => *v,
                    CosemDataType::Long(v) => *v as i8,
                    _ => return Err("attribute_index must be integer".to_string()),
                };
                Ok(ProtectionObject { class_id, logical_name, attribute_index })
            }
            _ => Err("expected structure {class_id, logical_name, attribute_index}".to_string()),
        }
    }
}

/// `ip_option` — structure { option_type: unsigned, option_value: octet-string }
/// Used in IPv4/IPv6 setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpOption {
    /// IP option type code.
    pub option_type: u8,
    /// IP option value data.
    pub option_value: Vec<u8>,
}

impl From<IpOption> for CosemDataType {
    fn from(opt: IpOption) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::Unsigned(opt.option_type),
            CosemDataType::OctetString(opt.option_value),
        ])
    }
}

impl TryFrom<&CosemDataType> for IpOption {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let option_type = match &fields[0] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err("option_type must be unsigned".to_string()),
                };
                let option_value = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("option_value must be octet-string".to_string()),
                };
                Ok(IpOption { option_type, option_value })
            }
            _ => Err("expected structure {option_type, option_value}".to_string()),
        }
    }
}

/// `neighbor_discovery_setup` — structure { ip_address, hardware_address }
/// Used in IPv6 neighbor discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborDiscoverySetup {
    /// IP address of the neighbor.
    pub ip_address: Vec<u8>,
    /// Hardware (MAC) address.
    pub hardware_address: Vec<u8>,
}

impl From<NeighborDiscoverySetup> for CosemDataType {
    fn from(nd: NeighborDiscoverySetup) -> Self {
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(nd.ip_address),
            CosemDataType::OctetString(nd.hardware_address),
        ])
    }
}

impl TryFrom<&CosemDataType> for NeighborDiscoverySetup {
    type Error = String;
    fn try_from(value: &CosemDataType) -> Result<Self, String> {
        match value {
            CosemDataType::Structure(fields) if fields.len() >= 2 => {
                let ip_address = match &fields[0] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("ip_address must be octet-string".to_string()),
                };
                let hardware_address = match &fields[1] {
                    CosemDataType::OctetString(v) => v.clone(),
                    _ => return Err("hardware_address must be octet-string".to_string()),
                };
                Ok(NeighborDiscoverySetup { ip_address, hardware_address })
            }
            _ => Err("expected structure {ip_address, hardware_address}".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obis::ObisCode;

    // Helper: round-trip a value through CosemDataType and back
    fn round_trip<T: for<'a> TryFrom<&'a CosemDataType, Error = String> + Into<CosemDataType> + Clone + PartialEq + std::fmt::Debug>(
        val: &T,
    ) {
        let cd: CosemDataType = val.clone().into();
        let back = T::try_from(&cd).expect("TryFrom should succeed");
        assert_eq!(*val, back);
    }

    fn obis(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> ObisCode {
        ObisCode::new(a, b, c, d, e, f)
    }

    // ========================================================================
    // DateTime
    // ========================================================================

    #[test]
    fn datetime_round_trip() {
        let dt = DateTime::new([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00]);
        round_trip(&dt);
    }

    #[test]
    fn datetime_from_ymdhms() {
        let dt = DateTime::from_ymdhms(2025, 5, 1, 16, 30, 0);
        assert_eq!(dt.0[0..2], 2025u16.to_be_bytes());
        assert_eq!(dt.0[2], 5);
        assert_eq!(dt.0[3], 1);
        assert_eq!(dt.0[5], 16);
        assert_eq!(dt.0[6], 30);
    }

    #[test]
    fn datetime_try_from_octet_string() {
        let bytes = vec![0x07, 0xE5, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cd = CosemDataType::OctetString(bytes);
        let dt = DateTime::try_from(&cd).unwrap();
        assert_eq!(dt.0[0..2], [0x07, 0xE5]);
    }

    #[test]
    fn datetime_try_from_wrong_length() {
        let cd = CosemDataType::OctetString(vec![0u8; 10]);
        assert!(DateTime::try_from(&cd).is_err());
    }

    // ========================================================================
    // ScalerUnit
    // ========================================================================

    #[test]
    fn scaler_unit_round_trip() {
        let su = ScalerUnit::new(-2, 30);
        round_trip(&su);
    }

    #[test]
    fn scaler_unit_apply() {
        let su = ScalerUnit::new(-2, 30);
        assert_eq!(su.apply(100), 1.0);
        assert_eq!(su.apply(12345), 123.45);
    }

    #[test]
    fn scaler_unit_from_structure() {
        let cd = CosemDataType::Structure(vec![
            CosemDataType::Integer(0),
            CosemDataType::Enum(27),
        ]);
        let su = ScalerUnit::try_from(&cd).unwrap();
        assert_eq!(su.scaler, 0);
        assert_eq!(su.unit, 27);
    }

    // ========================================================================
    // CaptureObjectDefinition
    // ========================================================================

    #[test]
    fn capture_object_definition_round_trip() {
        let cod = CaptureObjectDefinition::new(3, obis(0, 0, 1, 0, 0, 255), 2, 0);
        round_trip(&cod);
    }

    // ========================================================================
    // SortMethod
    // ========================================================================

    #[test]
    fn sort_method_from_u8() {
        assert_eq!(SortMethod::from_u8(1), Some(SortMethod::Fifo));
        assert_eq!(SortMethod::from_u8(2), Some(SortMethod::Lifo));
        assert_eq!(SortMethod::from_u8(3), Some(SortMethod::Largest));
        assert_eq!(SortMethod::from_u8(4), Some(SortMethod::Smallest));
        assert_eq!(SortMethod::from_u8(5), Some(SortMethod::NearestToZero));
        assert_eq!(SortMethod::from_u8(6), Some(SortMethod::FarthestFromZero));
        assert_eq!(SortMethod::from_u8(0), None);
        assert_eq!(SortMethod::from_u8(7), None);
    }

    // ========================================================================
    // AssociationStatus
    // ========================================================================

    #[test]
    fn association_status_from_u8() {
        assert_eq!(AssociationStatus::from_u8(0), Some(AssociationStatus::NonAssociated));
        assert_eq!(AssociationStatus::from_u8(1), Some(AssociationStatus::AssociationPending));
        assert_eq!(AssociationStatus::from_u8(2), Some(AssociationStatus::Associated));
        assert_eq!(AssociationStatus::from_u8(3), None);
    }

    // ========================================================================
    // ClockBase
    // ========================================================================

    #[test]
    fn clock_base_from_u8() {
        assert_eq!(ClockBase::from_u8(0), Some(ClockBase::None));
        assert_eq!(ClockBase::from_u8(1), Some(ClockBase::InternalCrystal));
        assert_eq!(ClockBase::from_u8(2), Some(ClockBase::MainsFrequency));
        assert_eq!(ClockBase::from_u8(3), Some(ClockBase::Gps));
        assert_eq!(ClockBase::from_u8(4), Some(ClockBase::RadioClock));
        assert_eq!(ClockBase::from_u8(5), None);
    }

    // ========================================================================
    // AccessRight + AttributeAccessItem + MethodAccessItem
    // ========================================================================

    #[test]
    fn attribute_access_item_round_trip() {
        let item = AttributeAccessItem {
            attribute_id: 2,
            access_mode: 1,
            access_selectors: None,
        };
        round_trip(&item);
    }

    #[test]
    fn attribute_access_item_with_selectors() {
        let item = AttributeAccessItem {
            attribute_id: 3,
            access_mode: 3,
            access_selectors: Some(vec![1, 2]),
        };
        let cd: CosemDataType = item.clone().into();
        let back = AttributeAccessItem::try_from(&cd).unwrap();
        assert_eq!(back.access_selectors, Some(vec![1, 2]));
    }

    #[test]
    fn method_access_item_round_trip() {
        let item = MethodAccessItem { method_id: 1, access_mode: 1 };
        round_trip(&item);
    }

    #[test]
    fn access_right_round_trip() {
        let ar = AccessRight {
            attribute_access: vec![
                AttributeAccessItem { attribute_id: 1, access_mode: 1, access_selectors: None },
                AttributeAccessItem { attribute_id: 2, access_mode: 3, access_selectors: None },
            ],
            method_access: vec![
                MethodAccessItem { method_id: 1, access_mode: 1 },
            ],
        };
        round_trip(&ar);
    }

    // ========================================================================
    // ObjectListElement
    // ========================================================================

    #[test]
    fn object_list_element_round_trip() {
        let ole = ObjectListElement {
            class_id: 3,
            version: 0,
            logical_name: obis(0, 0, 1, 0, 0, 255),
            access_rights: AccessRight {
                attribute_access: vec![],
                method_access: vec![],
            },
        };
        round_trip(&ole);
    }

    // ========================================================================
    // AssociatedPartnersId
    // ========================================================================

    #[test]
    fn associated_partners_id_round_trip() {
        let ap = AssociatedPartnersId { client_sap: 1, server_sap: 16 };
        round_trip(&ap);
    }

    #[test]
    fn associated_partners_id_try_from_wrong_type() {
        let cd = CosemDataType::Null;
        assert!(AssociatedPartnersId::try_from(&cd).is_err());
    }

    // ========================================================================
    // ContextName
    // ========================================================================

    #[test]
    fn context_name_structure_round_trip() {
        let cn = ContextName::Structure {
            joint_iso_ctt: 2,
            country: 16,
            country_name: 756,
            identified_organization: 5,
            dlms_ua: 8,
            application_context: 1,
            context_id: 1,
        };
        round_trip(&cn);
    }

    #[test]
    fn context_name_octet_string_round_trip() {
        let cn = ContextName::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]);
        let cd: CosemDataType = cn.clone().into();
        let back = ContextName::try_from(&cd).unwrap();
        assert_eq!(cn, back);
    }

    // ========================================================================
    // XDLMSContextInfo
    // ========================================================================

    #[test]
    fn xdlms_context_info_round_trip() {
        let ctx = XDLMSContextInfo {
            conformance: vec![0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            max_receive_pdu_size: 1024,
            max_send_pdu_size: 1024,
            dlms_version_number: 6,
            quality_of_service: -1,
            cyphering_info: vec![],
        };
        round_trip(&ctx);
    }

    // ========================================================================
    // ValueDefinition
    // ========================================================================

    #[test]
    fn value_definition_round_trip() {
        let vd = ValueDefinition {
            class_id: 3,
            logical_name: obis(0, 0, 1, 0, 0, 255),
            attribute_index: 2,
        };
        round_trip(&vd);
    }

    // ========================================================================
    // ActionItem
    // ========================================================================

    #[test]
    fn action_item_round_trip() {
        let ai = ActionItem {
            script_logical_name: obis(0, 0, 10, 100, 0, 255),
            script_selector: 1,
        };
        round_trip(&ai);
    }

    // ========================================================================
    // ActionSet
    // ========================================================================

    #[test]
    fn action_set_round_trip() {
        let aset = ActionSet {
            action_up: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 },
            action_down: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 2 },
        };
        round_trip(&aset);
    }

    // ========================================================================
    // ActionSpecification
    // ========================================================================

    #[test]
    fn action_specification_round_trip() {
        let aspec = ActionSpecification {
            service_id: 1,
            class_id: 3,
            logical_name: obis(0, 0, 1, 0, 0, 255),
            index: 2,
            parameter: CosemDataType::Null,
        };
        round_trip(&aspec);
    }

    #[test]
    fn action_specification_with_parameter() {
        let aspec = ActionSpecification {
            service_id: 2,
            class_id: 9,
            logical_name: obis(0, 0, 10, 100, 0, 255),
            index: 1,
            parameter: CosemDataType::LongUnsigned(42),
        };
        let cd: CosemDataType = aspec.clone().into();
        let back = ActionSpecification::try_from(&cd).unwrap();
        assert_eq!(back.parameter, CosemDataType::LongUnsigned(42));
    }

    // ========================================================================
    // Script
    // ========================================================================

    #[test]
    fn script_round_trip() {
        let script = Script {
            script_identifier: 1,
            actions: vec![
                ActionSpecification {
                    service_id: 1,
                    class_id: 3,
                    logical_name: obis(0, 0, 1, 0, 0, 255),
                    index: 2,
                    parameter: CosemDataType::DoubleLongUnsigned(1000),
                },
            ],
        };
        round_trip(&script);
    }

    #[test]
    fn script_empty_actions() {
        let script = Script { script_identifier: 0, actions: vec![] };
        round_trip(&script);
    }

    // ========================================================================
    // ScheduleTableEntry
    // ========================================================================

    #[test]
    fn schedule_table_entry_round_trip() {
        let ste = ScheduleTableEntry {
            index: 1,
            enable: true,
            script_logical_name: obis(0, 0, 10, 100, 0, 255),
            script_selector: 1,
            switch_time: vec![0x10, 0x00, 0x00],
            validity_window: 0xFFFF,
            exec_weekdays: vec![0x7F],
            exec_specdays: vec![0x00],
            begin_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF],
            end_date: vec![0x07, 0xE5, 0x12, 0x31, 0xFF],
        };
        round_trip(&ste);
    }

    // ========================================================================
    // SpecialDayEntry
    // ========================================================================

    #[test]
    fn special_day_entry_round_trip() {
        let sde = SpecialDayEntry {
            index: 1,
            specialday_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF, 0xFF, 0xFF],
            day_id: 3,
        };
        round_trip(&sde);
    }

    // ========================================================================
    // SeasonProfile
    // ========================================================================

    #[test]
    fn season_profile_round_trip() {
        let sp = SeasonProfile {
            season_profile_name: b"Summer".to_vec(),
            season_start: vec![0x07, 0xE5, 0x04, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            week_name: b"WeekA".to_vec(),
        };
        round_trip(&sp);
    }

    // ========================================================================
    // WeekProfile
    // ========================================================================

    #[test]
    fn week_profile_round_trip() {
        let wp = WeekProfile {
            week_profile_name: b"WeekA".to_vec(),
            monday: 1,
            tuesday: 2,
            wednesday: 3,
            thursday: 4,
            friday: 5,
            saturday: 6,
            sunday: 7,
        };
        round_trip(&wp);
    }

    // ========================================================================
    // DayProfileAction + DayProfile
    // ========================================================================

    #[test]
    fn day_profile_action_round_trip() {
        let dpa = DayProfileAction {
            start_time: vec![0x08, 0x00, 0x00],
            script_logical_name: obis(0, 0, 10, 100, 0, 255),
            script_selector: 1,
        };
        round_trip(&dpa);
    }

    #[test]
    fn day_profile_round_trip() {
        let dp = DayProfile {
            day_id: 1,
            day_schedule: vec![
                DayProfileAction {
                    start_time: vec![0x08, 0x00, 0x00],
                    script_logical_name: obis(0, 0, 10, 100, 0, 255),
                    script_selector: 1,
                },
                DayProfileAction {
                    start_time: vec![0x18, 0x00, 0x00],
                    script_logical_name: obis(0, 0, 10, 100, 0, 255),
                    script_selector: 2,
                },
            ],
        };
        round_trip(&dp);
    }

    #[test]
    fn day_profile_empty_schedule() {
        let dp = DayProfile { day_id: 1, day_schedule: vec![] };
        round_trip(&dp);
    }

    // ========================================================================
    // SendDestinationAndMethod
    // ========================================================================

    #[test]
    fn send_destination_and_method_round_trip() {
        let sdm = SendDestinationAndMethod {
            transport_service: 0,
            destination: b"192.168.1.100:4059".to_vec(),
            message: 2,
        };
        round_trip(&sdm);
    }

    // ========================================================================
    // CommunicationWindow
    // ========================================================================

    #[test]
    fn communication_window_round_trip() {
        let cw = CommunicationWindow {
            begin: DateTime::from_ymdhms(2025, 1, 1, 8, 0, 0),
            end: DateTime::from_ymdhms(2025, 12, 31, 18, 0, 0),
        };
        round_trip(&cw);
    }

    // ========================================================================
    // EmergencyProfile
    // ========================================================================

    #[test]
    fn emergency_profile_round_trip() {
        let ep = EmergencyProfile {
            emergency_profile_id: 1,
            emergency_activation_time: vec![0x07, 0xE5, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            emergency_duration: 3600,
        };
        round_trip(&ep);
    }

    // ========================================================================
    // LimiterAction
    // ========================================================================

    #[test]
    fn limiter_action_round_trip() {
        let la = LimiterAction {
            action_over_threshold: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 },
            action_under_threshold: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 2 },
        };
        round_trip(&la);
    }

    // ========================================================================
    // ObjectDefinition
    // ========================================================================

    #[test]
    fn object_definition_round_trip() {
        let od = ObjectDefinition {
            class_id: 3,
            logical_name: obis(0, 0, 1, 0, 0, 255),
        };
        round_trip(&od);
    }

    // ========================================================================
    // RegisterActMask
    // ========================================================================

    #[test]
    fn register_act_mask_round_trip() {
        let ram = RegisterActMask {
            mask_name: b"DayTariff".to_vec(),
            index_list: vec![1, 3, 5],
        };
        round_trip(&ram);
    }

    // ========================================================================
    // ImageToActivateInfo
    // ========================================================================

    #[test]
    fn image_to_activate_info_round_trip() {
        let itai = ImageToActivateInfo {
            image_block_number: 1,
            image_block_value: vec![0x01, 0x02, 0x03, 0x04],
        };
        round_trip(&itai);
    }

    // ========================================================================
    // ExecutedScript
    // ========================================================================

    #[test]
    fn executed_script_round_trip() {
        let es = ExecutedScript {
            script_logical_name: obis(0, 0, 10, 100, 0, 255),
            script_selector: 1,
        };
        round_trip(&es);
    }

    // ========================================================================
    // SapAssignmentEntry
    // ========================================================================

    #[test]
    fn sap_assignment_entry_round_trip() {
        let sae = SapAssignmentEntry {
            sap: 1,
            logical_device_name: b"Meter01".to_vec(),
        };
        round_trip(&sae);
    }

    // ========================================================================
    // GsmAdjacentCell
    // ========================================================================

    #[test]
    fn gsm_adjacent_cell_round_trip() {
        let gac = GsmAdjacentCell {
            cell_id: vec![0x01, 0x02],
            signal_quality: vec![0x03],
            signal_strength: vec![0x04],
        };
        round_trip(&gac);
    }

    // ========================================================================
    // ProtectionObject
    // ========================================================================

    #[test]
    fn protection_object_round_trip() {
        let po = ProtectionObject {
            class_id: 3,
            logical_name: obis(0, 0, 1, 0, 0, 255),
            attribute_index: 2,
        };
        round_trip(&po);
    }

    // ========================================================================
    // IpOption
    // ========================================================================

    #[test]
    fn ip_option_round_trip() {
        let io = IpOption {
            option_type: 7,
            option_value: vec![0xC0, 0xA8, 0x01, 0x01],
        };
        round_trip(&io);
    }

    // ========================================================================
    // NeighborDiscoverySetup
    // ========================================================================

    #[test]
    fn neighbor_discovery_setup_round_trip() {
        let nds = NeighborDiscoverySetup {
            ip_address: vec![0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            hardware_address: vec![0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
        };
        round_trip(&nds);
    }

    // ========================================================================
    // BER serialization round-trip tests
    // ========================================================================

    #[test]
    fn ber_round_trip_access_right() {
        let ar = AccessRight {
            attribute_access: vec![
                AttributeAccessItem { attribute_id: 1, access_mode: 1, access_selectors: None },
            ],
            method_access: vec![
                MethodAccessItem { method_id: 1, access_mode: 1 },
            ],
        };
        let cd: CosemDataType = ar.clone().into();
        let mut buf = Vec::new();
        cd.serialize_ber(&mut buf).unwrap();
        let (decoded, rest) = CosemDataType::deserialize_ber(&buf).unwrap();
        assert!(rest.is_empty());
        let back = AccessRight::try_from(&decoded).unwrap();
        assert_eq!(ar, back);
    }

    #[test]
    fn ber_round_trip_object_list_element() {
        let ole = ObjectListElement {
            class_id: 15,
            version: 1,
            logical_name: obis(0, 0, 40, 0, 0, 255),
            access_rights: AccessRight {
                attribute_access: vec![],
                method_access: vec![],
            },
        };
        let cd: CosemDataType = ole.clone().into();
        let mut buf = Vec::new();
        cd.serialize_ber(&mut buf).unwrap();
        let (decoded, rest) = CosemDataType::deserialize_ber(&buf).unwrap();
        assert!(rest.is_empty());
        let back = ObjectListElement::try_from(&decoded).unwrap();
        assert_eq!(ole, back);
    }

    #[test]
    fn ber_round_trip_script() {
        let script = Script {
            script_identifier: 42,
            actions: vec![
                ActionSpecification {
                    service_id: 1,
                    class_id: 3,
                    logical_name: obis(0, 0, 1, 0, 0, 255),
                    index: 2,
                    parameter: CosemDataType::DoubleLongUnsigned(12345),
                },
            ],
        };
        let cd: CosemDataType = script.clone().into();
        let mut buf = Vec::new();
        cd.serialize_ber(&mut buf).unwrap();
        let (decoded, rest) = CosemDataType::deserialize_ber(&buf).unwrap();
        assert!(rest.is_empty());
        let back = Script::try_from(&decoded).unwrap();
        assert_eq!(script, back);
    }

    #[test]
    fn ber_round_trip_schedule_table_entry() {
        let ste = ScheduleTableEntry {
            index: 1,
            enable: true,
            script_logical_name: obis(0, 0, 10, 100, 0, 255),
            script_selector: 1,
            switch_time: vec![0x10, 0x00, 0x00],
            validity_window: 60,
            exec_weekdays: vec![0x7F],
            exec_specdays: vec![0x00],
            begin_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF],
            end_date: vec![0x07, 0xE5, 0x12, 0x31, 0xFF],
        };
        let cd: CosemDataType = ste.clone().into();
        let mut buf = Vec::new();
        cd.serialize_ber(&mut buf).unwrap();
        let (decoded, rest) = CosemDataType::deserialize_ber(&buf).unwrap();
        assert!(rest.is_empty());
        let back = ScheduleTableEntry::try_from(&decoded).unwrap();
        assert_eq!(ste, back);
    }

    #[test]
    fn ber_round_trip_emergency_profile() {
        let ep = EmergencyProfile {
            emergency_profile_id: 5,
            emergency_activation_time: vec![0x07, 0xE5, 0x06, 0x15, 0xFF, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            emergency_duration: 7200,
        };
        let cd: CosemDataType = ep.clone().into();
        let mut buf = Vec::new();
        cd.serialize_ber(&mut buf).unwrap();
        let (decoded, rest) = CosemDataType::deserialize_ber(&buf).unwrap();
        assert!(rest.is_empty());
        let back = EmergencyProfile::try_from(&decoded).unwrap();
        assert_eq!(ep, back);
    }

    // ========================================================================
    // Error cases
    // ========================================================================

    #[test]
    fn access_right_wrong_type() {
        assert!(AccessRight::try_from(&CosemDataType::Null).is_err());
        assert!(AccessRight::try_from(&CosemDataType::Unsigned(1)).is_err());
    }

    #[test]
    fn action_item_wrong_type() {
        assert!(ActionItem::try_from(&CosemDataType::Null).is_err());
    }

    #[test]
    fn context_name_wrong_type() {
        assert!(ContextName::try_from(&CosemDataType::Unsigned(1)).is_err());
    }

    #[test]
    fn xdlms_context_info_wrong_fields() {
        let cd = CosemDataType::Structure(vec![
            CosemDataType::BitString(vec![0]),
            CosemDataType::LongUnsigned(1024),
        ]);
        assert!(XDLMSContextInfo::try_from(&cd).is_err());
    }

    #[test]
    fn value_definition_wrong_type() {
        assert!(ValueDefinition::try_from(&CosemDataType::Null).is_err());
    }

    #[test]
    fn script_wrong_type() {
        assert!(Script::try_from(&CosemDataType::Null).is_err());
        assert!(Script::try_from(&CosemDataType::Array(vec![])).is_err());
    }

    #[test]
    fn send_destination_and_method_wrong_type() {
        assert!(SendDestinationAndMethod::try_from(&CosemDataType::Null).is_err());
    }

    #[test]
    fn emergency_profile_wrong_type() {
        assert!(EmergencyProfile::try_from(&CosemDataType::Null).is_err());
    }

    #[test]
    fn image_to_activate_info_wrong_type() {
        assert!(ImageToActivateInfo::try_from(&CosemDataType::Null).is_err());
    }

    // ========================================================================
    // Batch test: all struct types round-trip through BER
    // ========================================================================

    #[test]
    fn all_types_ber_round_trip() {
        // Helper macro to test BER round-trip for a given value
        macro_rules! test_ber {
            ($val:expr, $type:ty) => {{
                let val: $type = $val;
                let cd: CosemDataType = val.clone().into();
                let mut buf = Vec::new();
                cd.serialize_ber(&mut buf).unwrap();
                let (decoded, rest) = CosemDataType::deserialize_ber(&buf).unwrap();
                assert!(rest.is_empty(), "trailing bytes");
                let back = <$type>::try_from(&decoded).unwrap();
                assert_eq!(val, back);
            }};
        }

        test_ber!(ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 }, ActionItem);
        test_ber!(ObjectDefinition { class_id: 3, logical_name: obis(0, 0, 1, 0, 0, 255) }, ObjectDefinition);
        test_ber!(ExecutedScript { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 2 }, ExecutedScript);
        test_ber!(ValueDefinition { class_id: 5, logical_name: obis(0, 0, 96, 1, 0, 255), attribute_index: 2 }, ValueDefinition);
        test_ber!(ProtectionObject { class_id: 3, logical_name: obis(0, 0, 1, 0, 0, 255), attribute_index: 1 }, ProtectionObject);
        test_ber!(SapAssignmentEntry { sap: 1, logical_device_name: b"Meter".to_vec() }, SapAssignmentEntry);
        test_ber!(IpOption { option_type: 7, option_value: vec![192, 168, 1, 1] }, IpOption);
        test_ber!(GsmAdjacentCell { cell_id: vec![1], signal_quality: vec![2], signal_strength: vec![3] }, GsmAdjacentCell);
        test_ber!(RegisterActMask { mask_name: b"Day".to_vec(), index_list: vec![1, 2] }, RegisterActMask);
        test_ber!(ImageToActivateInfo { image_block_number: 1, image_block_value: vec![0xAA] }, ImageToActivateInfo);
        test_ber!(
            SpecialDayEntry { index: 1, specialday_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF, 0xFF, 0xFF], day_id: 1 },
            SpecialDayEntry
        );
        test_ber!(
            SeasonProfile { season_profile_name: b"Summer".to_vec(), season_start: vec![0u8; 12], week_name: b"W1".to_vec() },
            SeasonProfile
        );
        test_ber!(
            WeekProfile { week_profile_name: b"W1".to_vec(), monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6, sunday: 7 },
            WeekProfile
        );
        test_ber!(
            DayProfileAction { start_time: vec![8, 0, 0], script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 },
            DayProfileAction
        );
        test_ber!(
            DayProfile { day_id: 1, day_schedule: vec![DayProfileAction { start_time: vec![8, 0, 0], script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 }] },
            DayProfile
        );
        test_ber!(
            NeighborDiscoverySetup { ip_address: vec![0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], hardware_address: vec![0, 1, 2, 3, 4, 5] },
            NeighborDiscoverySetup
        );
        test_ber!(
            AssociatedPartnersId { client_sap: 1, server_sap: 16 },
            AssociatedPartnersId
        );
        test_ber!(
            XDLMSContextInfo { conformance: vec![0; 18], max_receive_pdu_size: 1024, max_send_pdu_size: 1024, dlms_version_number: 6, quality_of_service: -1, cyphering_info: vec![] },
            XDLMSContextInfo
        );
        test_ber!(
            CommunicationWindow { begin: DateTime::from_ymdhms(2025, 1, 1, 8, 0, 0), end: DateTime::from_ymdhms(2025, 12, 31, 18, 0, 0) },
            CommunicationWindow
        );
        test_ber!(
            EmergencyProfile { emergency_profile_id: 1, emergency_activation_time: vec![0u8; 12], emergency_duration: 3600 },
            EmergencyProfile
        );
        test_ber!(
            LimiterAction {
                action_over_threshold: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 },
                action_under_threshold: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 2 },
            },
            LimiterAction
        );
        test_ber!(
            ActionSet {
                action_up: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1 },
                action_down: ActionItem { script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 2 },
            },
            ActionSet
        );
        test_ber!(
            SendDestinationAndMethod { transport_service: 0, destination: b"192.168.1.1:4059".to_vec(), message: 2 },
            SendDestinationAndMethod
        );
        test_ber!(
            ActionSpecification { service_id: 1, class_id: 3, logical_name: obis(0, 0, 1, 0, 0, 255), index: 2, parameter: CosemDataType::Null },
            ActionSpecification
        );
        test_ber!(
            Script { script_identifier: 1, actions: vec![] },
            Script
        );
        test_ber!(
            ScheduleTableEntry {
                index: 1, enable: true, script_logical_name: obis(0, 0, 10, 100, 0, 255), script_selector: 1,
                switch_time: vec![0x10, 0, 0], validity_window: 60, exec_weekdays: vec![0x7F], exec_specdays: vec![0],
                begin_date: vec![0x07, 0xE5, 1, 1, 0xFF], end_date: vec![0x07, 0xE5, 12, 31, 0xFF],
            },
            ScheduleTableEntry
        );
        test_ber!(
            DateTime::new([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00]),
            DateTime
        );
        test_ber!(ScalerUnit::new(-2, 30), ScalerUnit);
        test_ber!(CaptureObjectDefinition::new(3, obis(0, 0, 1, 0, 0, 255), 2, 0), CaptureObjectDefinition);
        test_ber!(AttributeAccessItem { attribute_id: 1, access_mode: 1, access_selectors: None }, AttributeAccessItem);
        test_ber!(MethodAccessItem { method_id: 1, access_mode: 1 }, MethodAccessItem);
        test_ber!(
            AccessRight {
                attribute_access: vec![AttributeAccessItem { attribute_id: 1, access_mode: 1, access_selectors: None }],
                method_access: vec![MethodAccessItem { method_id: 1, access_mode: 1 }],
            },
            AccessRight
        );
        test_ber!(
            ObjectListElement {
                class_id: 3, version: 0, logical_name: obis(0, 0, 1, 0, 0, 255),
                access_rights: AccessRight { attribute_access: vec![], method_access: vec![] },
            },
            ObjectListElement
        );
        test_ber!(
            ContextName::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
            ContextName
        );
    }
}
