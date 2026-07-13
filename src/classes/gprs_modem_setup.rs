use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::QualityOfService;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`GprsModemSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GprsModemSetupConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: access point name (octet-string).
    pub apn: Vec<u8>,
    /// Attribute 3: PIN code.
    pub pin_code: u16,
    /// Attribute 4: `quality_of_service` structure (default and requested).
    pub quality_of_service: QualityOfService,
}

/// `GPRS modem setup` interface class (class_id = 45, version = 0) per
/// IEC 62056-6-2 §4.7.7. Configures the GPRS modem (APN, PIN, quality of service).
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GprsModemSetup {
    logical_name: ObisCode,
    apn: Vec<u8>,
    pin_code: u16,
    quality_of_service: QualityOfService,
}

impl GprsModemSetup {
    /// Builds a new [`GprsModemSetup`] from its configuration.
    pub fn new(config: GprsModemSetupConfig) -> Self {
        GprsModemSetup {
            logical_name: config.logical_name,
            apn: config.apn,
            pin_code: config.pin_code,
            quality_of_service: config.quality_of_service,
        }
    }
}

impl InterfaceClass for GprsModemSetup {
    fn class_id(&self) -> u16 {
        45
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
            (2, CosemDataType::OctetString(self.apn.clone())),
            (3, CosemDataType::LongUnsigned(self.pin_code)),
            (4, CosemDataType::from(self.quality_of_service.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The GPRS modem setup class defines no specific methods.
        vec![]
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
        let seq = match tlv {
            CosemDataType::Structure(seq) => seq,
            _ => return Err(BerError::InvalidTag),
        };
        // class_id + 4 attributes.
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
        self.apn = match &seq[2] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.pin_code = match seq[3] {
            CosemDataType::LongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.quality_of_service = QualityOfService::try_from(&seq[4]).map_err(|_| BerError::InvalidValue)?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {} not supported for GPRS modem setup (no specific methods)", method_id))
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
    use crate::types::attrs::{GsmServiceParameter, QualityOfService};

    fn sample() -> GprsModemSetup {
        let zero_param = GsmServiceParameter {
            delay_class: 0,
            reliability_class: 0,
            precedence_class: 0,
            peak_throughput: 0,
            mean_throughput: 0,
        };
        GprsModemSetup::new(GprsModemSetupConfig {
            logical_name: ObisCode::new(0, 0, 25, 4, 0, 255),
            apn: b"internet".to_vec(),
            pin_code: 0,
            quality_of_service: QualityOfService { default: zero_param.clone(), requested: zero_param },
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 45);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 4);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.pin_code = 9999;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
