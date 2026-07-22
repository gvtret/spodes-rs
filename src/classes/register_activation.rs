use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{ObjectDefinition, RegisterActMask};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration used to build a `RegisterActivation` object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterActivationConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: array of `object_definition` structures the masks may select.
    pub register_assignment: Vec<ObjectDefinition>,
    /// Attribute 3: array of `mask` structures { mask_name, index list }.
    pub mask_list: Vec<RegisterActMask>,
    /// Attribute 4: name of the currently active mask.
    pub active_mask: Vec<u8>,
}

/// The `RegisterActivation` interface class (class_id = 6) managing the
/// activation of registers such as tariff registers, per IEC 62056-6-2.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterActivation {
    logical_name: ObisCode,
    register_assignment: Vec<ObjectDefinition>,
    mask_list: Vec<RegisterActMask>,
    active_mask: Vec<u8>,
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
        let param = params.ok_or("Invalid mask parameter".to_string())?;
        let mask = RegisterActMask::try_from(&param).map_err(|e| format!("Invalid mask parameter: {e}"))?;
        if self.mask_list.iter().any(|m| m.mask_name == mask.mask_name) {
            return Err("Mask with this name already exists".to_string());
        }
        self.mask_list.push(mask);
        Ok(CosemDataType::Null)
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
        let Some(CosemDataType::OctetString(mask_name)) = params else {
            return Err("Invalid mask name parameter".to_string());
        };
        let initial_len = self.mask_list.len();
        self.mask_list.retain(|m| m.mask_name != mask_name);
        if self.mask_list.len() < initial_len {
            if self.active_mask == mask_name {
                self.active_mask.clear();
            }
            return Ok(CosemDataType::Null);
        }
        Err("Mask not found".to_string())
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
            (
                2,
                CosemDataType::Array(
                    self.register_assignment.iter().map(|od| CosemDataType::from(od.clone())).collect(),
                ),
            ),
            (3, CosemDataType::Array(self.mask_list.iter().map(|m| CosemDataType::from(m.clone())).collect())),
            (4, CosemDataType::OctetString(self.active_mask.clone())),
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
                if let CosemDataType::Array(items) = &seq[2] {
                    self.register_assignment = items
                        .iter()
                        .map(ObjectDefinition::try_from)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| BerError::InvalidValue)?;
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::Array(items) = &seq[3] {
                    self.mask_list = items
                        .iter()
                        .map(RegisterActMask::try_from)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| BerError::InvalidValue)?;
                } else {
                    return Err(BerError::InvalidTag);
                }
                if let CosemDataType::OctetString(bytes) = &seq[4] {
                    self.active_mask.clone_from(bytes);
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
            1 => self.add_mask(params),
            2 => self.delete_mask(params),
            _ => Err(format!("Method {method_id} not supported for RegisterActivation class")),
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
