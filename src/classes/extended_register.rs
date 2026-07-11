use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{Choice, ScalerUnit};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// The `ExtendedRegister` interface class (class_id = 4): the current value of a
/// measured quantity with extra metadata such as status and capture time, per
/// IEC 62056-6-2.
///
/// Attributes (IEC 62056-6-2, Table 9):
/// - attr 1: logical_name (octet-string) — OBIS code
/// - attr 2: value (CHOICE) — any numeric type
/// - attr 3: scaler_unit (scal_unit_type) — {scaler, unit}
/// - attr 4: status (CHOICE) — measurement status
/// - attr 5: capture_time (octet-string) — date-time
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ExtendedRegister {
    logical_name: ObisCode,
    value: Choice,
    scaler_unit: ScalerUnit,
    status: Choice,
    capture_time: Choice,
}

impl ExtendedRegister {
    /// Creates a new `ExtendedRegister` object.
    pub fn new(
        logical_name: ObisCode,
        value: Choice,
        scaler_unit: ScalerUnit,
        status: Choice,
        capture_time: Choice,
    ) -> Self {
        ExtendedRegister { logical_name, value, scaler_unit, status, capture_time }
    }

    /// Returns the value attribute (attr 2).
    pub fn value(&self) -> &Choice {
        &self.value
    }

    /// Returns the scaler_unit attribute (attr 3).
    pub fn scaler_unit(&self) -> &ScalerUnit {
        &self.scaler_unit
    }

    /// Returns the status attribute (attr 4).
    pub fn status(&self) -> &Choice {
        &self.status
    }

    /// Returns the capture_time attribute (attr 5).
    pub fn capture_time(&self) -> &Choice {
        &self.capture_time
    }

    /// Resets the register value to 0 and clears the status and capture time.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - On successful reset.
    /// * `Err(String)` - If the value type does not support reset.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        match &self.value {
            CosemDataType::Integer(_) => {
                self.value = CosemDataType::Integer(0);
                self.status = CosemDataType::Null;
                self.capture_time = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            CosemDataType::Long(_) => {
                self.value = CosemDataType::Long(0);
                self.status = CosemDataType::Null;
                self.capture_time = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            CosemDataType::DoubleLong(_) => {
                self.value = CosemDataType::DoubleLong(0);
                self.status = CosemDataType::Null;
                self.capture_time = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            CosemDataType::Unsigned(_) => {
                self.value = CosemDataType::Unsigned(0);
                self.status = CosemDataType::Null;
                self.capture_time = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            CosemDataType::LongUnsigned(_) => {
                self.value = CosemDataType::LongUnsigned(0);
                self.status = CosemDataType::Null;
                self.capture_time = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            CosemDataType::DoubleLongUnsigned(_) => {
                self.value = CosemDataType::DoubleLongUnsigned(0);
                self.status = CosemDataType::Null;
                self.capture_time = CosemDataType::Null;
                Ok(CosemDataType::Null)
            }
            _ => Err("Unsupported value type for reset".to_string()),
        }
    }

    /// Captures the current value, updating the status and capture time.
    ///
    /// # Returns
    /// * `Ok(CosemDataType::Null)` - On a successful capture.
    /// * `Err(String)` - On error.
    fn capture(&mut self) -> Result<CosemDataType, String> {
        self.status = CosemDataType::Unsigned(1);
        self.capture_time = CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for ExtendedRegister {
    fn class_id(&self) -> u16 {
        4
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
            (2, self.value.clone()),
            (3, self.scaler_unit.clone().into()),
            (4, self.status.clone()),
            (5, self.capture_time.clone()),
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
            if seq.len() == 6 {
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
                self.value = seq[2].clone();
                self.scaler_unit = ScalerUnit::try_from(&seq[3]).map_err(|_| BerError::InvalidValue)?;
                self.status = seq[4].clone();
                self.capture_time = seq[5].clone();
                return Ok(());
            }
            return Err(BerError::InvalidLength);
        }
        Err(BerError::InvalidTag)
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.reset(),
            2 => self.capture(),
            _ => Err(format!("Method {} not supported for ExtendedRegister class", method_id)),
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
