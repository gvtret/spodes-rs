use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`IecHdlcSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IecHdlcSetupConfig {
    pub logical_name: ObisCode,
    /// Class version: 0 or 1. In version 0 attributes 5 and 6 are `unsigned`;
    /// in version 1 they are `long-unsigned` (wider maximum info field length).
    pub version: u8,
    /// Attribute 2: communication speed (enum).
    pub comm_speed: u8,
    /// Attribute 3: transmit window size.
    pub window_size_transmit: u8,
    /// Attribute 4: receive window size.
    pub window_size_receive: u8,
    /// Attribute 5: maximum transmit info field length.
    pub max_info_field_length_transmit: u16,
    /// Attribute 6: maximum receive info field length.
    pub max_info_field_length_receive: u16,
    /// Attribute 7: inter-octet time-out, in milliseconds.
    pub inter_octet_time_out: u16,
    /// Attribute 8: inactivity time-out, in seconds.
    pub inactivity_time_out: u16,
    /// Attribute 9: HDLC device (physical) address.
    pub device_address: u16,
}

/// `IEC HDLC setup` interface class (class_id = 23) per IEC 62056-6-2 §4.7.2.
/// Configures the HDLC data link layer.
///
/// Both versions are supported: they share the same nine attributes, differing
/// only in the type of the two maximum-info-field-length attributes
/// (`unsigned` in version 0, `long-unsigned` in version 1). This class defines
/// no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IecHdlcSetup {
    version: u8,
    logical_name: ObisCode,
    comm_speed: u8,
    window_size_transmit: u8,
    window_size_receive: u8,
    max_info_field_length_transmit: u16,
    max_info_field_length_receive: u16,
    inter_octet_time_out: u16,
    inactivity_time_out: u16,
    device_address: u16,
}

impl IecHdlcSetup {
    /// Builds a new [`IecHdlcSetup`] from its configuration.
    pub fn new(config: IecHdlcSetupConfig) -> Self {
        IecHdlcSetup {
            version: config.version,
            logical_name: config.logical_name,
            comm_speed: config.comm_speed,
            window_size_transmit: config.window_size_transmit,
            window_size_receive: config.window_size_receive,
            max_info_field_length_transmit: config.max_info_field_length_transmit,
            max_info_field_length_receive: config.max_info_field_length_receive,
            inter_octet_time_out: config.inter_octet_time_out,
            inactivity_time_out: config.inactivity_time_out,
            device_address: config.device_address,
        }
    }

    /// Encodes a maximum-info-field-length attribute with the version-dependent
    /// type: `unsigned` in version 0, `long-unsigned` in version 1.
    fn max_info(&self, value: u16) -> CosemDataType {
        if self.version >= 1 {
            CosemDataType::LongUnsigned(value)
        } else {
            CosemDataType::Unsigned(value as u8)
        }
    }
}

impl InterfaceClass for IecHdlcSetup {
    fn class_id(&self) -> u16 {
        23
    }

    fn version(&self) -> u8 {
        self.version
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Enum(self.comm_speed)),
            (3, CosemDataType::Unsigned(self.window_size_transmit)),
            (4, CosemDataType::Unsigned(self.window_size_receive)),
            (5, self.max_info(self.max_info_field_length_transmit)),
            (6, self.max_info(self.max_info_field_length_receive)),
            (7, CosemDataType::LongUnsigned(self.inter_octet_time_out)),
            (8, CosemDataType::LongUnsigned(self.inactivity_time_out)),
            (9, CosemDataType::LongUnsigned(self.device_address)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The IEC HDLC setup class defines no specific methods.
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
        // class_id + 9 attributes.
        if seq.len() != 10 {
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
        self.comm_speed = match seq[2] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.window_size_transmit = take_unsigned(&seq[3])?;
        self.window_size_receive = take_unsigned(&seq[4])?;
        // The type of attribute 5/6 identifies the version.
        self.version = match &seq[5] {
            CosemDataType::LongUnsigned(_) => 1,
            _ => 0,
        };
        self.max_info_field_length_transmit = take_u16(&seq[5])?;
        self.max_info_field_length_receive = take_u16(&seq[6])?;
        self.inter_octet_time_out = take_long_unsigned(&seq[7])?;
        self.inactivity_time_out = take_long_unsigned(&seq[8])?;
        self.device_address = take_long_unsigned(&seq[9])?;
        Ok(())
    }

    fn invoke_method(
        &mut self,
        method_id: u8,
        _params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String> {
        Err(format!("Method {} not supported for IEC HDLC setup (no specific methods)", method_id))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_unsigned(value: &CosemDataType) -> Result<u8, BerError> {
    match value {
        CosemDataType::Unsigned(v) => Ok(*v),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_long_unsigned(value: &CosemDataType) -> Result<u16, BerError> {
    match value {
        CosemDataType::LongUnsigned(v) => Ok(*v),
        _ => Err(BerError::InvalidTag),
    }
}

/// Reads either an `unsigned` (v0) or a `long-unsigned` (v1) as `u16`.
fn take_u16(value: &CosemDataType) -> Result<u16, BerError> {
    match value {
        CosemDataType::LongUnsigned(v) => Ok(*v),
        CosemDataType::Unsigned(v) => Ok(*v as u16),
        _ => Err(BerError::InvalidTag),
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

    fn sample_versioned(version: u8) -> IecHdlcSetup {
        IecHdlcSetup::new(IecHdlcSetupConfig {
            logical_name: ObisCode::new(0, 0, 22, 0, 0, 255),
            version,
            comm_speed: 5,
            window_size_transmit: 1,
            window_size_receive: 1,
            max_info_field_length_transmit: 128,
            max_info_field_length_receive: 128,
            inter_octet_time_out: 25,
            inactivity_time_out: 120,
            device_address: 0x0010,
        })
    }

    #[test]
    fn attribute_type_depends_on_version() {
        let v0 = sample_versioned(0);
        assert_eq!(v0.attributes().len(), 9);
        assert!(v0.methods().is_empty());
        assert_eq!(v0.attributes()[4].1, CosemDataType::Unsigned(128));
        let v1 = sample_versioned(1);
        assert_eq!(v1.attributes()[4].1, CosemDataType::LongUnsigned(128));
    }

    #[test]
    fn round_trip_all_versions() {
        for version in 0..=1u8 {
            let obj = sample_versioned(version);
            let mut buf = Vec::new();
            obj.serialize_ber(&mut buf).unwrap();
            let mut decoded = sample_versioned(1 - version);
            decoded.deserialize_ber(&buf).unwrap();
            assert_eq!(decoded.version(), version);
            assert_eq!(decoded.attributes(), obj.attributes());
        }
    }
}
