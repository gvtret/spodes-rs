use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::DateTime;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration used to build a `Clock` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ClockConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: the current date and time (date-time, 12 octets).
    pub time: DateTime,
    /// Attribute 3: deviation of local time from GMT, in minutes (long).
    pub time_zone: i16,
    /// Attribute 4: clock status flags (unsigned bit-string).
    pub status: u8,
    /// Attribute 5: date and time at which daylight saving begins (date-time).
    pub daylight_savings_begin: DateTime,
    /// Attribute 6: date and time at which daylight saving ends (date-time).
    pub daylight_savings_end: DateTime,
    /// Attribute 7: daylight-saving offset added to `time`, in minutes (integer).
    pub daylight_savings_deviation: i8,
    /// Attribute 8: whether daylight saving is applied (boolean).
    pub daylight_savings_enabled: bool,
    /// Attribute 9: the underlying clock base / source (enum).
    pub clock_base: u8,
}

/// The `Clock` interface class (class_id = 8) managing time and date
/// per IEC 62056-6-2.
///
/// Attributes (IEC 62056-6-2, Table 15):
/// - attr 1: logical_name (octet-string) — OBIS code
/// - attr 2: time (date-time) — current date and time
/// - attr 3: time_zone (long) — deviation from GMT in minutes
/// - attr 4: status (bit-string) — clock status flags
/// - attr 5: daylight_savings_begin (date-time)
/// - attr 6: daylight_savings_end (date-time)
/// - attr 7: daylight_savings_deviation (integer) — offset in minutes
/// - attr 8: daylight_savings_enabled (boolean)
/// - attr 9: clock_base (enum) — clock source
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Clock {
    logical_name: ObisCode,
    time: DateTime,
    time_zone: i16,
    status: u8,
    daylight_savings_begin: DateTime,
    daylight_savings_end: DateTime,
    daylight_savings_deviation: i8,
    daylight_savings_enabled: bool,
    clock_base: u8,
}

impl Clock {
    /// Creates a new `Clock` object from its configuration.
    ///
    /// # Arguments
    /// * `config` - The configuration used to build the object.
    ///
    /// # Returns
    /// A new `Clock`.
    pub fn new(config: ClockConfig) -> Self {
        Clock {
            logical_name: config.logical_name,
            time: config.time,
            time_zone: config.time_zone,
            status: config.status,
            daylight_savings_begin: config.daylight_savings_begin,
            daylight_savings_end: config.daylight_savings_end,
            daylight_savings_deviation: config.daylight_savings_deviation,
            daylight_savings_enabled: config.daylight_savings_enabled,
            clock_base: config.clock_base,
        }
    }

    /// Returns the time attribute (attr 2).
    pub fn time(&self) -> &DateTime {
        &self.time
    }

    /// Returns the time_zone attribute (attr 3).
    pub fn time_zone(&self) -> i16 {
        self.time_zone
    }

    /// Returns the status attribute (attr 4).
    pub fn status(&self) -> u8 {
        self.status
    }

    /// Returns the clock_base attribute (attr 9).
    pub fn clock_base(&self) -> u8 {
        self.clock_base
    }

    /// Adjusts the time to the nearest quarter hour (minute 0, 15, 30 or 45).
    fn adjust_to_quarter(&mut self) -> CosemDataType {
        let minutes = u32::from(self.time.0[6]);
        let new_minutes: u8 = if minutes < 8 {
            0
        } else if minutes < 23 {
            15
        } else if minutes < 37 {
            30
        } else {
            45
        };
        self.time.0[6] = new_minutes;
        self.time.0[7] = 0;
        self.time.0[8] = 0;
        CosemDataType::Null
    }

    /// Adjusts the time to the measuring period (stub — C++ parity).
    fn adjust_to_measuring_period(&mut self) -> CosemDataType {
        CosemDataType::Null
    }

    /// Adjusts the time to the nearest minute.
    fn adjust_to_minute(&mut self) -> CosemDataType {
        self.time.0[7] = 0;
        self.time.0[8] = 0;
        CosemDataType::Null
    }

    /// Sets a preset time.
    fn adjust_to_preset_time(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        if let Some(CosemDataType::DateTime(dt) | CosemDataType::OctetString(dt)) = params {
            if dt.len() == 12 {
                let mut buf = [0u8; 12];
                buf.copy_from_slice(&dt);
                self.time = DateTime(buf);
                return Ok(CosemDataType::Null);
            }
        }
        Err("Invalid DateTime parameter".to_string())
    }

    /// Preset-time adjustment (stub).
    fn preset_adjusting_time() -> CosemDataType {
        CosemDataType::Null
    }

    /// Shifts the clock by a relative offset in seconds (Blue Book method 6).
    /// Parameter is ignored for success/failure — C++ returns null without applying.
    fn shift_time(_params: Option<CosemDataType>) -> CosemDataType {
        CosemDataType::Null
    }
}

impl InterfaceClass for Clock {
    fn class_id(&self) -> u16 {
        8
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        // Blue Book date-time attributes are carried as octet-string (tag 0x09),
        // matching `osp_val_cosem_datetime` / common client expectations — not tag 0x19.
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::OctetString(self.time.0.to_vec())),
            (3, CosemDataType::Long(self.time_zone)),
            (4, CosemDataType::Unsigned(self.status)),
            (5, CosemDataType::OctetString(self.daylight_savings_begin.0.to_vec())),
            (6, CosemDataType::OctetString(self.daylight_savings_end.0.to_vec())),
            (7, CosemDataType::Integer(self.daylight_savings_deviation)),
            (8, CosemDataType::Boolean(self.daylight_savings_enabled)),
            (9, CosemDataType::Enum(self.clock_base)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "adjust_to_quarter".to_string()),
            (2, "adjust_to_measuring_period".to_string()),
            (3, "adjust_to_minute".to_string()),
            (4, "adjust_to_preset_time".to_string()),
            (5, "preset_adjusting_time".to_string()),
            (6, "shift_time".to_string()),
        ]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf); // length = element count
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        if let CosemDataType::Structure(seq) = tlv {
            if seq.len() == 10 {
                if let CosemDataType::LongUnsigned(class_id) = seq[0] {
                    if class_id != self.class_id() {
                        return Err(BerError::InvalidValue);
                    }
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::OctetString(obis) = &seq[1] {
                    if obis.len() == 6 {
                        self.logical_name = ObisCode::new(obis[0], obis[1], obis[2], obis[3], obis[4], obis[5]);
                    } else {
                        return Err(BerError::InvalidLength);
                    }
                } else {
                    return Err(BerError::InvalidTag);
                }
                // Parse typed attributes from CosemDataType
                self.time = DateTime::try_from(&seq[2]).map_err(|_| BerError::InvalidValue)?;
                self.time_zone = match &seq[3] {
                    CosemDataType::Long(v) => *v,
                    _ => return Err(BerError::InvalidTag),
                };
                self.status = match &seq[4] {
                    CosemDataType::Unsigned(v) => *v,
                    _ => return Err(BerError::InvalidTag),
                };
                self.daylight_savings_begin = DateTime::try_from(&seq[5]).map_err(|_| BerError::InvalidValue)?;
                self.daylight_savings_end = DateTime::try_from(&seq[6]).map_err(|_| BerError::InvalidValue)?;
                self.daylight_savings_deviation = match &seq[7] {
                    CosemDataType::Integer(v) => *v,
                    _ => return Err(BerError::InvalidTag),
                };
                self.daylight_savings_enabled = match &seq[8] {
                    CosemDataType::Boolean(v) => *v,
                    _ => return Err(BerError::InvalidTag),
                };
                self.clock_base = match &seq[9] {
                    CosemDataType::Enum(v) => *v,
                    _ => return Err(BerError::InvalidTag),
                };
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
        match attribute_id {
            2 => {
                self.time = DateTime::try_from(&value)?;
                Ok(())
            }
            3 => match value {
                CosemDataType::Long(v) => {
                    self.time_zone = v;
                    Ok(())
                }
                _ => Err("time_zone must be long".into()),
            },
            // Attr 4 (status) is read-only in the ACL mask.
            5 => {
                self.daylight_savings_begin = DateTime::try_from(&value)?;
                Ok(())
            }
            6 => {
                self.daylight_savings_end = DateTime::try_from(&value)?;
                Ok(())
            }
            7 => match value {
                CosemDataType::Integer(v) => {
                    self.daylight_savings_deviation = v;
                    Ok(())
                }
                _ => Err("daylight_savings_deviation must be integer".into()),
            },
            8 => match value {
                CosemDataType::Boolean(v) => {
                    self.daylight_savings_enabled = v;
                    Ok(())
                }
                _ => Err("daylight_savings_enabled must be boolean".into()),
            },
            // Attr 9 (clock_base) is read-only.
            _ => Err(format!("Clock attribute {attribute_id} is not writable")),
        }
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => Ok(self.adjust_to_quarter()),
            2 => Ok(self.adjust_to_measuring_period()),
            3 => Ok(self.adjust_to_minute()),
            4 => self.adjust_to_preset_time(params),
            5 => Ok(Self::preset_adjusting_time()),
            6 => Ok(Self::shift_time(params)),
            _ => Err(format!("Method {method_id} not supported for Clock class")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a length in BER (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
fn write_length(length: usize, buf: &mut Vec<u8>) {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
}
