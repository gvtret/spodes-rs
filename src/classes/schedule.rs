use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::ScheduleTableEntry;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration used to build a `Schedule` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScheduleConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: array of `schedule_table_entry` structures.
    pub entries: Vec<ScheduleTableEntry>,
    /// Whether the schedule is currently enabled.
    pub enabled: bool,
}

/// The `Schedule` interface class (class_id = 10) managing schedules that
/// define the times at which actions run, per IEC 62056-6-2.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Schedule {
    logical_name: ObisCode,
    entries: Vec<ScheduleTableEntry>,
    enabled: bool, // schedule state (enabled/disabled)
}

impl Schedule {
    /// Creates a new `Schedule` object from its configuration.
    ///
    /// # Arguments
    /// * `config` - The configuration used to build the object.
    ///
    /// # Returns
    /// A new `Schedule`.
    pub fn new(config: ScheduleConfig) -> Self {
        Schedule { logical_name: config.logical_name, entries: config.entries, enabled: config.enabled }
    }

    /// Method 1: `enable_disable` — toggles the `enable` flag of the entry at
    /// the given 0-based index (IEC 62056-6-2 §4.5.3).
    fn enable_disable(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let idx = index_param(params.as_ref()).ok_or("enable_disable requires an entry index")?;
        let entry = self.entries.get_mut(idx).ok_or_else(|| format!("No schedule entry at index {idx}"))?;
        entry.enable = !entry.enable;
        Ok(CosemDataType::Null)
    }

    /// Method 2: `insert` — appends a new `schedule_table_entry`
    /// (IEC 62056-6-2 §4.5.3).
    fn insert(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let value = params.ok_or("insert requires a schedule_table_entry structure")?;
        let entry = ScheduleTableEntry::try_from(&value).map_err(|e| format!("Invalid schedule_table_entry: {e}"))?;
        self.entries.push(entry);
        Ok(CosemDataType::Null)
    }

    /// Method 3: `delete` — removes the entry at the given 0-based index
    /// (IEC 62056-6-2 §4.5.3).
    fn delete(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let idx = index_param(params.as_ref()).ok_or("delete requires an entry index")?;
        if idx >= self.entries.len() {
            return Err(format!("No schedule entry at index {idx}"));
        }
        self.entries.remove(idx);
        Ok(CosemDataType::Null)
    }

    /// Returns the schedule state (enabled/disabled).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the schedule entries.
    pub fn entries(&self) -> &[ScheduleTableEntry] {
        &self.entries
    }
}

/// Extracts an entry index from an unsigned method parameter.
fn index_param(value: Option<&CosemDataType>) -> Option<usize> {
    match value? {
        CosemDataType::Unsigned(v) => Some(*v as usize),
        CosemDataType::LongUnsigned(v) => Some(*v as usize),
        CosemDataType::DoubleLongUnsigned(v) => Some(*v as usize),
        _ => None,
    }
}

impl InterfaceClass for Schedule {
    fn class_id(&self) -> u16 {
        10
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Array(self.entries.iter().cloned().map(CosemDataType::from).collect())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "enable_disable".to_string()), (2, "insert".to_string()), (3, "delete".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        seq_buf.push(0x03); // boolean [3]
        seq_buf.push(if self.enabled { 0xFF } else { 0x00 }); // enabled value
        buf.push(0x02); // structure [2]
        write_length(2 + self.attributes().len(), buf)?; // element count: class_id + attributes + enabled
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
        };
        if seq.len() == 4 {
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
            if let CosemDataType::Array(entries) = &seq[2] {
                self.entries = entries
                    .iter()
                    .map(ScheduleTableEntry::try_from)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| BerError::InvalidValue)?;
            } else {
                return Err(BerError::InvalidTag);
            }
            if let CosemDataType::Boolean(enabled) = seq[3] {
                self.enabled = enabled;
            } else {
                return Err(BerError::InvalidTag);
            }
            Ok(())
        } else {
            Err(BerError::InvalidLength)
        }
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.enable_disable(params),
            2 => self.insert(params),
            3 => self.delete(params),
            _ => Err(format!("Method {method_id} not supported for Schedule class")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a length in BER (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
fn write_length(length: usize, buf: &mut Vec<u8>) -> Result<(), BerError> {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
    Ok(())
}
