//! Typed attributes for COSEM interface classes (IEC 62056-6-2).
//!
//! Each IC has specific attribute types defined in the standard. This module
//! provides strongly-typed structs for these attributes, replacing the generic
//! `CosemDataType` where possible while maintaining BER compatibility.

use crate::obis::ObisCode;
use crate::types::CosemDataType;

/// Logical name (OBIS code) — attribute 1 of all ICs.
pub type LogicalName = ObisCode;

/// CHOICE type — any COSEM data type (for value, status, etc.).
/// This maintains backward compatibility with the generic CosemDataType.
pub type Choice = CosemDataType;

/// Date-time value (12 octets) per IEC 62056-6-2, 4.1.6.1.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Sort method for Profile generic (IEC 62056-6-2, 4.3.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationStatus {
    /// Non-associated.
    NonAssociated = 0,
    /// Association pending.
    AssociationPending = 1,
    /// Associated.
    Associated = 2,
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
