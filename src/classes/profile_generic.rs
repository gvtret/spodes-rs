use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{CaptureObjectDefinition, Choice, SortMethod};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Configuration structure used to build a `ProfileGeneric` object.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProfileGenericConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Class version: 0 or 1. Version 0 additionally exposes the
    /// `get_buffer_by_range` and `get_buffer_by_index` methods.
    pub version: u8,
    /// Attribute 2: the captured data buffer (array of entry structures).
    pub buffer: Vec<Choice>,
    /// Attribute 3: the objects captured into each buffer entry, paired with the
    /// captured attribute index.
    #[serde(skip)]
    pub capture_objects: Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)>,
    /// Attribute 4: the capturing period, in seconds (0 = event-driven).
    pub capture_period: u32,
    /// Attribute 5: sort method (1 = FIFO, 2 = LIFO, 3 = largest, 4 = smallest).
    pub sort_method: SortMethod,
    /// Attribute 6: `capture_object_definition` used as the sort key.
    pub sort_object: Option<CaptureObjectDefinition>,
    /// Attribute 7: number of entries currently stored in the buffer.
    pub entries_in_use: u32,
    /// Attribute 8: maximum number of entries the buffer can hold.
    pub profile_entries: u32,
}

impl fmt::Debug for ProfileGenericConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileGenericConfig")
            .field("logical_name", &self.logical_name)
            .field("buffer", &self.buffer)
            .field("capture_objects", &format_args!("Vec<...> (len={})", self.capture_objects.len()))
            .field("capture_period", &self.capture_period)
            .field("sort_method", &self.sort_method)
            .field("sort_object", &self.sort_object)
            .field("entries_in_use", &self.entries_in_use)
            .field("profile_entries", &self.profile_entries)
            .finish()
    }
}

/// `ProfileGeneric` interface class (class_id = 7, version = 1) for storing data
/// profiles such as load profiles or event logs, per IEC 62056-6-2 §4.3.6 in the
/// `spodes-rs` library.
///
/// Supports capturing data from the specified objects and their attributes.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProfileGeneric {
    version: u8,
    logical_name: ObisCode,
    buffer: Vec<Choice>,
    #[serde(skip)]
    capture_objects: Vec<(Arc<dyn InterfaceClass + Send + Sync>, u8)>,
    capture_period: u32,
    sort_method: SortMethod,
    sort_object: Option<CaptureObjectDefinition>,
    entries_in_use: u32,
    profile_entries: u32,
}

impl fmt::Debug for ProfileGeneric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileGeneric")
            .field("logical_name", &self.logical_name)
            .field("buffer", &self.buffer)
            .field("capture_objects", &format_args!("Vec<...> (len={})", self.capture_objects.len()))
            .field("capture_period", &self.capture_period)
            .field("sort_method", &self.sort_method)
            .field("sort_object", &self.sort_object)
            .field("entries_in_use", &self.entries_in_use)
            .field("profile_entries", &self.profile_entries)
            .finish()
    }
}

impl ProfileGeneric {
    /// Builds a new `ProfileGeneric` object from its configuration.
    ///
    /// # Arguments
    /// * `config` - Configuration used to build the object.
    ///
    /// # Returns
    /// A new `ProfileGeneric` structure.
    pub fn new(config: ProfileGenericConfig) -> Self {
        ProfileGeneric {
            version: config.version,
            logical_name: config.logical_name,
            buffer: config.buffer,
            capture_objects: config.capture_objects,
            capture_period: config.capture_period,
            sort_method: config.sort_method,
            sort_object: config.sort_object,
            entries_in_use: config.entries_in_use,
            profile_entries: config.profile_entries,
        }
    }

    /// Resets the profile buffer, clearing all entries.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - If the reset succeeded.
    /// * `Err(String)` - If an error occurred.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        self.buffer.clear();
        self.entries_in_use = 0;
        Ok(CosemDataType::Null)
    }

    /// Captures a new entry into the profile buffer, reading the attribute values
    /// from the objects listed in `capture_objects`.
    ///
    /// An entry holds only the values of the captured objects (a timestamp, if
    /// needed, is provided by a `Clock` object included in `capture_objects`). For
    /// an unsorted profile the buffer behaves as a FIFO: when full, the oldest
    /// entry is evicted (IEC 62056-6-2, §5.2.1.2.5).
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - If the capture succeeded.
    /// * `Err(String)` - If a captured object's attribute is not found.
    fn capture(&mut self) -> Result<CosemDataType, String> {
        let mut captured_values = Vec::new();

        for (obj, attr_id) in &self.capture_objects {
            let attributes = obj.attributes();
            if let Some((_, value)) = attributes.iter().find(|(id, _)| *id == *attr_id) {
                captured_values.push(value.clone());
            } else {
                return Err(format!("Attribute {attr_id} not found in object"));
            }
        }

        let new_entry = CosemDataType::Structure(captured_values);

        // When the buffer is full, evict the oldest entry (FIFO).
        if self.profile_entries > 0 && self.entries_in_use >= self.profile_entries && !self.buffer.is_empty() {
            self.buffer.remove(0);
            self.entries_in_use -= 1;
        }

        self.buffer.push(new_entry);
        self.entries_in_use += 1;

        Ok(CosemDataType::Null)
    }

    /// Method 3 (version 0 only): `get_buffer_by_range` — returns the buffer
    /// entries whose sort value falls within a range (IEC 62056-6-2 §5.2.1.2.3).
    ///
    /// Full range filtering requires evaluating the sort object of each entry;
    /// that ordering logic is not modelled here, so this returns the whole
    /// buffer as a best effort.
    fn get_buffer_by_range(&self, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Ok(CosemDataType::Array(self.buffer.clone()))
    }

    /// Method 4 (version 0 only): `get_buffer_by_index` — returns the buffer
    /// entries in the 1-based inclusive range `[from_entry, to_entry]`
    /// (IEC 62056-6-2 §5.2.1.2.4).
    ///
    /// The parameter is `structure { from_entry: double-long-unsigned,
    /// to_entry: double-long-unsigned, .. }`; when it is absent, the whole
    /// buffer is returned.
    fn get_buffer_by_index(&self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let (from_entry, to_entry) = match params {
            Some(CosemDataType::Structure(fields)) if fields.len() >= 2 => {
                let from = as_u32(&fields[0]).ok_or("from_entry must be an unsigned integer")?;
                let to = as_u32(&fields[1]).ok_or("to_entry must be an unsigned integer")?;
                (from, to)
            }
            None => return Ok(CosemDataType::Array(self.buffer.clone())),
            _ => return Err("Expected structure { from_entry, to_entry, .. }".to_string()),
        };
        if from_entry == 0 || to_entry < from_entry {
            return Err("Invalid entry range (1-based, from ≤ to)".to_string());
        }
        let start = (from_entry - 1) as usize;
        let end = (to_entry as usize).min(self.buffer.len());
        let slice = if start < end { self.buffer[start..end].to_vec() } else { Vec::new() };
        Ok(CosemDataType::Array(slice))
    }
}

/// Reads a non-negative COSEM integer as `u32` (used for entry indices).
fn as_u32(value: &CosemDataType) -> Option<u32> {
    match value {
        CosemDataType::DoubleLongUnsigned(v) => Some(*v),
        CosemDataType::LongUnsigned(v) => Some(u32::from(*v)),
        CosemDataType::Unsigned(v) => Some(u32::from(*v)),
        _ => None,
    }
}

impl InterfaceClass for ProfileGeneric {
    fn class_id(&self) -> u16 {
        7
    }

    fn version(&self) -> u8 {
        // Both versions share the same attributes. In version 0 the buffer can
        // also be read via the get_buffer_by_range/index methods; in version 1
        // (required by СТО 34.01-5.1-006-2023, Table 7.1) those are reserved and
        // buffer access uses selective GET instead.
        self.version
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        let capture_objects = CosemDataType::Array(
            self.capture_objects
                .iter()
                .map(|(obj, attr_id)| {
                    CosemDataType::Structure(vec![
                        CosemDataType::LongUnsigned(obj.class_id()),
                        CosemDataType::OctetString(obj.logical_name().to_bytes()),
                        CosemDataType::Integer(*attr_id as i8), // attribute_index (integer)
                        CosemDataType::LongUnsigned(0),         // data_index (long-unsigned, default 0)
                    ])
                })
                .collect(),
        );

        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Array(self.buffer.clone())),
            (3, capture_objects),
            (4, CosemDataType::DoubleLongUnsigned(self.capture_period)),
            (5, CosemDataType::Unsigned(self.sort_method as u8)),
            (6, self.sort_object.as_ref().map(|c| c.clone().into()).unwrap_or(CosemDataType::Null)),
            (7, CosemDataType::DoubleLongUnsigned(self.entries_in_use)),
            (8, CosemDataType::DoubleLongUnsigned(self.profile_entries)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // Version 0 additionally exposes the buffer-reading methods 3 and 4.
        if self.version == 0 {
            vec![
                (1, "reset".to_string()),
                (2, "capture".to_string()),
                (3, "get_buffer_by_range".to_string()),
                (4, "get_buffer_by_index".to_string()),
            ]
        } else {
            vec![(1, "reset".to_string()), (2, "capture".to_string())]
        }
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf)?; // length = element count
        buf.extend_from_slice(&seq_buf);
        Ok(())
    }

    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError> {
        let (tlv, rest) = CosemDataType::deserialize_ber(data)?;
        if !rest.is_empty() {
            return Err(BerError::InvalidTag);
        }
        if let CosemDataType::Structure(seq) = tlv {
            if seq.len() == 9 {
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
                if let CosemDataType::Array(buffer) = &seq[2] {
                    self.buffer.clone_from(buffer);
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::Array(_) = &seq[3] {
                    // capture_objects are deserialized separately, if needed
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::DoubleLongUnsigned(capture_period) = seq[4] {
                    self.capture_period = capture_period;
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::Unsigned(sort_method) = seq[5] {
                    self.sort_method = SortMethod::from_u8(sort_method).unwrap_or(SortMethod::Fifo);
                } else {
                    return Err(BerError::InvalidTag);
                }
                self.sort_object = CaptureObjectDefinition::try_from(&seq[6]).ok();
                if let CosemDataType::DoubleLongUnsigned(entries_in_use) = seq[7] {
                    self.entries_in_use = entries_in_use;
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::DoubleLongUnsigned(profile_entries) = seq[8] {
                    self.profile_entries = profile_entries;
                } else {
                    return Err(BerError::InvalidTag);
                }
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.reset(),
            2 => self.capture(),
            // Methods 3 and 4 exist only in version 0.
            3 if self.version == 0 => self.get_buffer_by_range(params),
            4 if self.version == 0 => self.get_buffer_by_index(params),
            _ => Err(format!("Method {} not supported for ProfileGeneric version {}", method_id, self.version)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a BER length octet (short or long form).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    fn versioned_profile(version: u8, profile_entries: u32) -> ProfileGeneric {
        ProfileGeneric::new(ProfileGenericConfig {
            logical_name: ObisCode::new(1, 0, 99, 1, 0, 255),
            version,
            buffer: vec![],
            capture_objects: vec![],
            capture_period: 0,
            sort_method: SortMethod::Fifo,
            sort_object: None,
            entries_in_use: 0,
            profile_entries,
        })
    }

    fn empty_profile(profile_entries: u32) -> ProfileGeneric {
        versioned_profile(1, profile_entries)
    }

    /// When the buffer is full, an unsorted profile evicts the oldest entry
    /// (FIFO) instead of returning an error.
    #[test]
    fn capture_evicts_oldest_when_full() {
        let mut p = empty_profile(2);
        for _ in 0..3 {
            p.invoke_method(2, None).expect("capture failed");
        }
        // Buffer and counter never exceed the capacity.
        assert_eq!(p.attributes()[6].1, CosemDataType::DoubleLongUnsigned(2)); // entries_in_use
        if let CosemDataType::Array(buf) = &p.attributes()[1].1 {
            assert_eq!(buf.len(), 2);
        } else {
            panic!("buffer must be an array");
        }
    }

    #[test]
    fn reset_clears_buffer() {
        let mut p = empty_profile(4);
        p.invoke_method(2, None).unwrap();
        p.invoke_method(1, None).unwrap(); // reset
        assert_eq!(p.attributes()[6].1, CosemDataType::DoubleLongUnsigned(0));
    }

    #[test]
    fn method_set_depends_on_version() {
        // Version 0 exposes the two extra buffer-reading methods.
        assert_eq!(versioned_profile(0, 4).methods().len(), 4);
        assert_eq!(versioned_profile(1, 4).methods().len(), 2);
        // Method 4 is available only in version 0.
        assert!(versioned_profile(1, 4).invoke_method(4, None).is_err());
    }

    #[test]
    fn get_buffer_by_index_slices_entries() {
        let mut p = versioned_profile(0, 10);
        for _ in 0..5 {
            p.invoke_method(2, None).unwrap();
        }
        // Entries 2..=4 (1-based, inclusive) → 3 entries.
        let params =
            CosemDataType::Structure(vec![CosemDataType::DoubleLongUnsigned(2), CosemDataType::DoubleLongUnsigned(4)]);
        let result = p.invoke_method(4, Some(params)).unwrap();
        if let CosemDataType::Array(entries) = result {
            assert_eq!(entries.len(), 3);
        } else {
            panic!("get_buffer_by_index must return an array");
        }
    }
}
