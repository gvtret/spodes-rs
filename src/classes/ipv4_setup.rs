use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`Ipv4Setup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ipv4SetupConfig {
    pub logical_name: ObisCode,
    /// Attribute 2: reference to the data link layer setup object.
    pub dl_reference: Vec<u8>,
    /// Attribute 3: the IPv4 address.
    pub ip_address: u32,
    /// Attribute 4: array of multicast IP addresses (double-long-unsigned).
    pub multicast_ip_address: Vec<CosemDataType>,
    /// Attribute 5: array of IP options.
    pub ip_options: Vec<CosemDataType>,
    /// Attribute 6: subnet mask.
    pub subnet_mask: u32,
    /// Attribute 7: gateway IP address.
    pub gateway_ip_address: u32,
    /// Attribute 8: whether DHCP is used to obtain the address.
    pub use_dhcp_flag: bool,
    /// Attribute 9: primary DNS address.
    pub primary_dns_address: u32,
    /// Attribute 10: secondary DNS address.
    pub secondary_dns_address: u32,
}

/// `IPv4 setup` interface class (class_id = 42, version = 0) per IEC 62056-6-2
/// §4.9.2. Configures the IPv4 network layer.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ipv4Setup {
    logical_name: ObisCode,
    dl_reference: Vec<u8>,
    ip_address: u32,
    multicast_ip_address: Vec<CosemDataType>,
    ip_options: Vec<CosemDataType>,
    subnet_mask: u32,
    gateway_ip_address: u32,
    use_dhcp_flag: bool,
    primary_dns_address: u32,
    secondary_dns_address: u32,
}

impl Ipv4Setup {
    /// Builds a new [`Ipv4Setup`] from its configuration.
    pub fn new(config: Ipv4SetupConfig) -> Self {
        Ipv4Setup {
            logical_name: config.logical_name,
            dl_reference: config.dl_reference,
            ip_address: config.ip_address,
            multicast_ip_address: config.multicast_ip_address,
            ip_options: config.ip_options,
            subnet_mask: config.subnet_mask,
            gateway_ip_address: config.gateway_ip_address,
            use_dhcp_flag: config.use_dhcp_flag,
            primary_dns_address: config.primary_dns_address,
            secondary_dns_address: config.secondary_dns_address,
        }
    }

    /// Method 1: `add_mc_IP_address` — adds a multicast IP address.
    fn add_mc_ip_address(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        match data {
            CosemDataType::DoubleLongUnsigned(_) => {
                if !self.multicast_ip_address.contains(&data) {
                    self.multicast_ip_address.push(data);
                }
                Ok(CosemDataType::Null)
            }
            _ => Err("add_mc_IP_address expects a double-long-unsigned".to_string()),
        }
    }

    /// Method 2: `delete_mc_IP_address` — removes a multicast IP address.
    fn delete_mc_ip_address(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let before = self.multicast_ip_address.len();
        self.multicast_ip_address.retain(|a| a != &data);
        if self.multicast_ip_address.len() == before {
            return Err("Multicast IP address not found".to_string());
        }
        Ok(CosemDataType::Null)
    }

    /// Method 3: `get_nbof_mc_IP_addresses` — returns the number of multicast IP
    /// addresses currently configured.
    fn get_nbof_mc_ip_addresses(&self) -> Result<CosemDataType, String> {
        Ok(CosemDataType::LongUnsigned(self.multicast_ip_address.len() as u16))
    }
}

impl InterfaceClass for Ipv4Setup {
    fn class_id(&self) -> u16 {
        42
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
            (2, CosemDataType::OctetString(self.dl_reference.clone())),
            (3, CosemDataType::DoubleLongUnsigned(self.ip_address)),
            (4, CosemDataType::Array(self.multicast_ip_address.clone())),
            (5, CosemDataType::Array(self.ip_options.clone())),
            (6, CosemDataType::DoubleLongUnsigned(self.subnet_mask)),
            (7, CosemDataType::DoubleLongUnsigned(self.gateway_ip_address)),
            (8, CosemDataType::Boolean(self.use_dhcp_flag)),
            (9, CosemDataType::DoubleLongUnsigned(self.primary_dns_address)),
            (10, CosemDataType::DoubleLongUnsigned(self.secondary_dns_address)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "add_mc_IP_address".to_string()),
            (2, "delete_mc_IP_address".to_string()),
            (3, "get_nbof_mc_IP_addresses".to_string()),
        ]
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
        // class_id + 10 attributes.
        if seq.len() != 11 {
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
        self.dl_reference = match &seq[2] {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.ip_address = take_dlu(&seq[3])?;
        self.multicast_ip_address = take_array(&seq[4])?;
        self.ip_options = take_array(&seq[5])?;
        self.subnet_mask = take_dlu(&seq[6])?;
        self.gateway_ip_address = take_dlu(&seq[7])?;
        self.use_dhcp_flag = match seq[8] {
            CosemDataType::Boolean(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.primary_dns_address = take_dlu(&seq[9])?;
        self.secondary_dns_address = take_dlu(&seq[10])?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.add_mc_ip_address(params.ok_or("Missing method parameter")?),
            2 => self.delete_mc_ip_address(params.ok_or("Missing method parameter")?),
            3 => self.get_nbof_mc_ip_addresses(),
            _ => Err(format!("Method {} not supported for IPv4 setup", method_id)),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_dlu(value: &CosemDataType) -> Result<u32, BerError> {
    match value {
        CosemDataType::DoubleLongUnsigned(v) => Ok(*v),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_array(value: &CosemDataType) -> Result<Vec<CosemDataType>, BerError> {
    match value {
        CosemDataType::Array(list) => Ok(list.clone()),
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

    fn sample() -> Ipv4Setup {
        Ipv4Setup::new(Ipv4SetupConfig {
            logical_name: ObisCode::new(0, 0, 25, 1, 0, 255),
            dl_reference: vec![0, 0, 25, 2, 0, 255],
            ip_address: 0xC0A80001,
            multicast_ip_address: vec![],
            ip_options: vec![],
            subnet_mask: 0xFFFFFF00,
            gateway_ip_address: 0xC0A800FE,
            use_dhcp_flag: false,
            primary_dns_address: 0x08080808,
            secondary_dns_address: 0x08080404,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 42);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 10);
        assert_eq!(obj.methods().len(), 3);
    }

    #[test]
    fn round_trip() {
        let mut obj = sample();
        obj.multicast_ip_address = vec![CosemDataType::DoubleLongUnsigned(0xE0000001)];
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn multicast_methods() {
        let mut obj = sample();
        obj.invoke_method(1, Some(CosemDataType::DoubleLongUnsigned(0xE0000001))).unwrap();
        obj.invoke_method(1, Some(CosemDataType::DoubleLongUnsigned(0xE0000002))).unwrap();
        assert_eq!(obj.invoke_method(3, None).unwrap(), CosemDataType::LongUnsigned(2));
        obj.invoke_method(2, Some(CosemDataType::DoubleLongUnsigned(0xE0000001))).unwrap();
        assert_eq!(obj.invoke_method(3, None).unwrap(), CosemDataType::LongUnsigned(1));
        // Deleting a missing address fails.
        assert!(obj.invoke_method(2, Some(CosemDataType::DoubleLongUnsigned(0x12345678))).is_err());
    }
}
