use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration used to build a `RegisterActivation` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterActivationConfig {
    pub logical_name: ObisCode,
    pub register_assignment: Vec<CosemDataType>,
    pub mask_list: Vec<CosemDataType>,
    pub active_mask: CosemDataType,
}

/// The `RegisterActivation` interface class (class_id = 6) managing the
/// activation of registers such as tariff registers, per IEC 62056-6-2.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterActivation {
    logical_name: ObisCode,
    register_assignment: Vec<CosemDataType>, // Array of Structure (class_id, logical_name, attribute_index)
    mask_list: Vec<CosemDataType>, // Array of Structure (mask_name, register_indices)
    active_mask: CosemDataType, // OctetString
}

impl RegisterActivation {
    /// Creates a new `RegisterActivation` object from its configuration.
    ///
    /// # Arguments
    /// * `config` - The configuration used to build the object.
    ///
    /// # Returns
    /// A new `RegisterActivation`.
    pub fn new(config: RegisterActivationConfig) -> Self {
        RegisterActivation {
            logical_name: config.logical_name,
            register_assignment: config.register_assignment,
            mask_list: config.mask_list,
            active_mask: config.active_mask,
        }
    }

    /// Adds a new activation mask to `mask_list`.
    ///
    /// # Arguments
    /// * `params` - A `CosemDataType::Structure` (mask_name, register_indices).
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - If the mask was added.
    /// * `Err(String)` - If the parameter is invalid or the mask already exists.
    fn add_mask(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        if let Some(CosemDataType::Structure(mask_data)) = params {
            if mask_data.len() == 2 {
                if let CosemDataType::OctetString(mask_name) = &mask_data[0] {
                    // Check whether a mask with this name already exists.
                    for existing_mask in &self.mask_list {
                        if let CosemDataType::Structure(existing_data) = existing_mask {
                            if let CosemDataType::OctetString(existing_name) = &existing_data[0] {
                                if existing_name == mask_name {
                                    return Err("Mask with this name already exists".to_string());
                                }
                            }
                        }
                    }
                    self.mask_list.push(CosemDataType::Structure(mask_data));
                    return Ok(CosemDataType::Null);
                }
            }
        }
        Err("Invalid mask parameter".to_string())
    }

    /// Removes an activation mask from `mask_list` by name.
    ///
    /// # Arguments
    /// * `params` - A `CosemDataType::OctetString` (the mask name).
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - If the mask was removed.
    /// * `Err(String)` - If the mask was not found or the parameter is invalid.
    fn delete_mask(&mut self, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        if let Some(CosemDataType::OctetString(mask_name)) = params {
            let initial_len = self.mask_list.len();
            self.mask_list.retain(|mask| {
                if let CosemDataType::Structure(data) = mask {
                    if let CosemDataType::OctetString(existing_name) = &data[0] {
                        return existing_name != &mask_name;
                    }
                }
                true
            });
            if self.mask_list.len() < initial_len {
                // If the currently active mask was removed, clear active_mask.
                if let CosemDataType::OctetString(active_mask_name) = &self.active_mask {
                    if active_mask_name == &mask_name {
                        self.active_mask = CosemDataType::Null;
                    }
                }
                return Ok(CosemDataType::Null);
            }
            return Err("Mask not found".to_string());
        }
        Err("Invalid mask name parameter".to_string())
    }
}

impl InterfaceClass for RegisterActivation {
    fn class_id(&self) -> u16 {
        6
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
            (2, CosemDataType::Array(self.register_assignment.clone())),
            (3, CosemDataType::Array(self.mask_list.clone())),
            (4, self.active_mask.clone()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "add_mask".to_string()), (2, "delete_mask".to_string())]
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
            if seq.len() == 5 {
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
                if let CosemDataType::Array(register_assignment) = &seq[2] {
                    self.register_assignment = register_assignment.clone();
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::Array(mask_list) = &seq[3] {
                    self.mask_list = mask_list.clone();
                } else {
                    return Err(BerError::InvalidTag);
                }
                self.active_mask = seq[4].clone();
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.add_mask(params),
            2 => self.delete_mask(params),
            _ => Err(format!("Method {} not supported for RegisterActivation class", method_id)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a length in BER (short or long form).
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