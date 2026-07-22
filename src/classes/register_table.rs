use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::ScalerUnit;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`RegisterTable`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterTableConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: the table cell values.
    pub table_cell_values: Vec<CosemDataType>,
    /// Attribute 3: `table_cell_definition` structure describing the cells.
    pub table_cell_definition: CosemDataType,
    /// Attribute 4: `scaler_unit` applied to every cell value.
    pub scaler_unit: ScalerUnit,
}

/// `Register table` interface class (class_id = 61, version = 0) per
/// IEC 62056-6-2 §4.3.7. Holds a table of identically-scaled register values
/// selected by the table cell definition.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegisterTable {
    logical_name: ObisCode,
    table_cell_values: Vec<CosemDataType>,
    table_cell_definition: CosemDataType,
    scaler_unit: ScalerUnit,
}

impl RegisterTable {
    /// Builds a new [`RegisterTable`] from its configuration.
    pub fn new(config: RegisterTableConfig) -> Self {
        RegisterTable {
            logical_name: config.logical_name,
            table_cell_values: config.table_cell_values,
            table_cell_definition: config.table_cell_definition,
            scaler_unit: config.scaler_unit,
        }
    }

    /// Method 1: `reset` — clears the table cell values.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        self.table_cell_values.clear();
        Ok(CosemDataType::Null)
    }

    /// Returns the table cell values (attribute 2).
    pub fn table_cell_values(&self) -> &[CosemDataType] {
        &self.table_cell_values
    }
}

impl InterfaceClass for RegisterTable {
    fn class_id(&self) -> u16 {
        61
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
            (2, CosemDataType::Array(self.table_cell_values.clone())),
            (3, self.table_cell_definition.clone()),
            (4, self.scaler_unit.clone().into()),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "reset".to_string()), (2, "capture".to_string())]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf)?;
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
        if seq.len() != 5 {
            return Err(BerError::InvalidLength);
        }
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
        self.table_cell_values = match &seq[2] {
            CosemDataType::Array(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.table_cell_definition = seq[3].clone();
        self.scaler_unit = ScalerUnit::try_from(&seq[4]).map_err(|_| BerError::InvalidValue)?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.reset(),
            // Method 2 `capture` is host-driven: the values live outside the
            // object model, so capturing is delegated to the application.
            2 => Ok(CosemDataType::Null),
            _ => Err(format!("Method {method_id} not supported for Register table class")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a BER length octet (short or long form).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RegisterTable {
        RegisterTable::new(RegisterTableConfig {
            logical_name: ObisCode::new(1, 0, 98, 10, 0, 255),
            table_cell_values: vec![CosemDataType::DoubleLongUnsigned(100), CosemDataType::DoubleLongUnsigned(200)],
            table_cell_definition: CosemDataType::Structure(vec![
                CosemDataType::LongUnsigned(3),
                CosemDataType::OctetString(vec![1, 0, 1, 8, 0, 255]),
                CosemDataType::Integer(2),
            ]),
            scaler_unit: ScalerUnit { scaler: 0, unit: 30 },
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 61);
        assert_eq!(obj.attributes().len(), 4);
        assert_eq!(obj.methods().len(), 2);
    }

    #[test]
    fn reset_clears_values() {
        let mut obj = sample();
        obj.invoke_method(1, None).unwrap();
        assert!(obj.table_cell_values().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
