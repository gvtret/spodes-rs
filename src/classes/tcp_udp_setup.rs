use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`TcpUdpSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TcpUdpSetupConfig {
    pub logical_name: ObisCode,
    /// Attribute 2: TCP or UDP port the server listens on.
    pub tcp_udp_port: u16,
    /// Attribute 3: reference to the IP setup object (octet-string logical name).
    pub ip_reference: Vec<u8>,
    /// Attribute 4: maximum segment size (default 576).
    pub mss: u16,
    /// Attribute 5: number of simultaneous connections.
    pub nb_of_sim_conn: u8,
    /// Attribute 6: inactivity time-out in seconds (default 180).
    pub inactivity_time_out: u16,
}

/// `TCP-UDP setup` interface class (class_id = 41, version = 0) per
/// IEC 62056-6-2 §4.9.1. Configures the TCP/UDP transport sub-layer used by the
/// wrapper communication profile.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TcpUdpSetup {
    logical_name: ObisCode,
    tcp_udp_port: u16,
    ip_reference: Vec<u8>,
    mss: u16,
    nb_of_sim_conn: u8,
    inactivity_time_out: u16,
}

impl TcpUdpSetup {
    /// Builds a new [`TcpUdpSetup`] from its configuration.
    pub fn new(config: TcpUdpSetupConfig) -> Self {
        TcpUdpSetup {
            logical_name: config.logical_name,
            tcp_udp_port: config.tcp_udp_port,
            ip_reference: config.ip_reference,
            mss: config.mss,
            nb_of_sim_conn: config.nb_of_sim_conn,
            inactivity_time_out: config.inactivity_time_out,
        }
    }
}

impl InterfaceClass for TcpUdpSetup {
    fn class_id(&self) -> u16 {
        41
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
            (2, CosemDataType::LongUnsigned(self.tcp_udp_port)),
            (3, CosemDataType::OctetString(self.ip_reference.clone())),
            (4, CosemDataType::LongUnsigned(self.mss)),
            (5, CosemDataType::Unsigned(self.nb_of_sim_conn)),
            (6, CosemDataType::LongUnsigned(self.inactivity_time_out)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The TCP-UDP setup class defines no specific methods.
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
        // class_id + 6 attributes.
        if seq.len() != 7 {
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
        self.tcp_udp_port = match seq[2] {
            CosemDataType::LongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.ip_reference = match &seq[3] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.mss = match seq[4] {
            CosemDataType::LongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.nb_of_sim_conn = match seq[5] {
            CosemDataType::Unsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.inactivity_time_out = match seq[6] {
            CosemDataType::LongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {} not supported for TCP-UDP setup (no specific methods)", method_id))
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

    fn sample() -> TcpUdpSetup {
        TcpUdpSetup::new(TcpUdpSetupConfig {
            logical_name: ObisCode::new(0, 0, 25, 0, 0, 255),
            tcp_udp_port: 4059,
            ip_reference: vec![0, 0, 25, 1, 0, 255],
            mss: 576,
            nb_of_sim_conn: 1,
            inactivity_time_out: 180,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 41);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 6);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.tcp_udp_port = 0;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }
}
