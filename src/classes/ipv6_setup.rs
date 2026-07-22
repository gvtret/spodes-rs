use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::NeighborDiscoverySetup;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build an [`Ipv6Setup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ipv6SetupConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: reference to the data link layer setup object.
    pub dl_reference: Vec<u8>,
    /// Attribute 3: address configuration mode (enum).
    pub address_config_mode: u8,
    /// Attribute 4: array of unicast IPv6 addresses (octet-string, 16 octets).
    pub unicast_ipv6_addresses: Vec<Vec<u8>>,
    /// Attribute 5: array of multicast IPv6 addresses.
    pub multicast_ipv6_addresses: Vec<Vec<u8>>,
    /// Attribute 6: array of gateway IPv6 addresses.
    pub gateway_ipv6_addresses: Vec<Vec<u8>>,
    /// Attribute 7: primary DNS address (octet-string).
    pub primary_dns_address: Vec<u8>,
    /// Attribute 8: secondary DNS address (octet-string).
    pub secondary_dns_address: Vec<u8>,
    /// Attribute 9: traffic class (0..63).
    pub traffic_class: u8,
    /// Attribute 10: array of neighbor discovery setup structures.
    pub neighbor_discovery_setup: Vec<NeighborDiscoverySetup>,
}

/// `IPv6 setup` interface class (class_id = 48, version = 0) per IEC 62056-6-2
/// §4.9.3. Configures the IPv6 network layer.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Ipv6Setup {
    logical_name: ObisCode,
    dl_reference: Vec<u8>,
    address_config_mode: u8,
    unicast_ipv6_addresses: Vec<Vec<u8>>,
    multicast_ipv6_addresses: Vec<Vec<u8>>,
    gateway_ipv6_addresses: Vec<Vec<u8>>,
    primary_dns_address: Vec<u8>,
    secondary_dns_address: Vec<u8>,
    traffic_class: u8,
    neighbor_discovery_setup: Vec<NeighborDiscoverySetup>,
}

impl Ipv6Setup {
    /// Builds a new [`Ipv6Setup`] from its configuration.
    pub fn new(config: Ipv6SetupConfig) -> Self {
        Ipv6Setup {
            logical_name: config.logical_name,
            dl_reference: config.dl_reference,
            address_config_mode: config.address_config_mode,
            unicast_ipv6_addresses: config.unicast_ipv6_addresses,
            multicast_ipv6_addresses: config.multicast_ipv6_addresses,
            gateway_ipv6_addresses: config.gateway_ipv6_addresses,
            primary_dns_address: config.primary_dns_address,
            secondary_dns_address: config.secondary_dns_address,
            traffic_class: config.traffic_class,
            neighbor_discovery_setup: config.neighbor_discovery_setup,
        }
    }

    /// Method 1: `add_IPv6_address` — adds a unicast IPv6 address.
    fn add_ipv6_address(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        match &data {
            CosemDataType::OctetString(addr) => {
                if !self.unicast_ipv6_addresses.contains(addr) {
                    self.unicast_ipv6_addresses.push(addr.clone());
                }
                Ok(CosemDataType::Null)
            }
            _ => Err("add_IPv6_address expects an octet-string".to_string()),
        }
    }

    /// Method 2: `remove_IPv6_address` — removes a unicast IPv6 address.
    fn remove_ipv6_address(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let addr = match &data {
            CosemDataType::OctetString(v) => v.clone(),
            _ => return Err("remove_IPv6_address expects an octet-string".to_string()),
        };
        let before = self.unicast_ipv6_addresses.len();
        self.unicast_ipv6_addresses.retain(|a| *a != addr);
        if self.unicast_ipv6_addresses.len() == before {
            return Err("IPv6 address not found".to_string());
        }
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for Ipv6Setup {
    fn class_id(&self) -> u16 {
        48
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
            (3, CosemDataType::Enum(self.address_config_mode)),
            (
                4,
                CosemDataType::Array(
                    self.unicast_ipv6_addresses.iter().cloned().map(CosemDataType::OctetString).collect(),
                ),
            ),
            (
                5,
                CosemDataType::Array(
                    self.multicast_ipv6_addresses.iter().cloned().map(CosemDataType::OctetString).collect(),
                ),
            ),
            (
                6,
                CosemDataType::Array(
                    self.gateway_ipv6_addresses.iter().cloned().map(CosemDataType::OctetString).collect(),
                ),
            ),
            (7, CosemDataType::OctetString(self.primary_dns_address.clone())),
            (8, CosemDataType::OctetString(self.secondary_dns_address.clone())),
            (9, CosemDataType::Unsigned(self.traffic_class)),
            (
                10,
                CosemDataType::Array(self.neighbor_discovery_setup.iter().cloned().map(CosemDataType::from).collect()),
            ),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "add_IPv6_address".to_string()), (2, "remove_IPv6_address".to_string())]
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
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
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
        self.dl_reference = take_octet_string(&seq[2])?;
        self.address_config_mode = match seq[3] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.unicast_ipv6_addresses = take_octet_string_array(&seq[4])?;
        self.multicast_ipv6_addresses = take_octet_string_array(&seq[5])?;
        self.gateway_ipv6_addresses = take_octet_string_array(&seq[6])?;
        self.primary_dns_address = take_octet_string(&seq[7])?;
        self.secondary_dns_address = take_octet_string(&seq[8])?;
        self.traffic_class = match seq[9] {
            CosemDataType::Unsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.neighbor_discovery_setup = take_nds_array(&seq[10])?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.add_ipv6_address(params.ok_or("Missing method parameter")?),
            2 => self.remove_ipv6_address(params.ok_or("Missing method parameter")?),
            _ => Err(format!("Method {method_id} not supported for IPv6 setup")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn take_octet_string(value: &CosemDataType) -> Result<Vec<u8>, BerError> {
    match value {
        CosemDataType::OctetString(bytes) => Ok(bytes.clone()),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_octet_string_array(value: &CosemDataType) -> Result<Vec<Vec<u8>>, BerError> {
    match value {
        CosemDataType::Array(list) => list
            .iter()
            .map(|item| match item {
                CosemDataType::OctetString(v) => Ok(v.clone()),
                _ => Err(BerError::InvalidTag),
            })
            .collect(),
        _ => Err(BerError::InvalidTag),
    }
}

fn take_nds_array(value: &CosemDataType) -> Result<Vec<NeighborDiscoverySetup>, BerError> {
    match value {
        CosemDataType::Array(list) => {
            list.iter().map(|item| NeighborDiscoverySetup::try_from(item).map_err(|_| BerError::InvalidValue)).collect()
        }
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

    fn sample() -> Ipv6Setup {
        Ipv6Setup::new(Ipv6SetupConfig {
            logical_name: ObisCode::new(0, 0, 25, 7, 0, 255),
            dl_reference: vec![0, 0, 25, 2, 0, 255],
            address_config_mode: 0,
            unicast_ipv6_addresses: vec![],
            multicast_ipv6_addresses: vec![],
            gateway_ipv6_addresses: vec![],
            primary_dns_address: vec![0; 16],
            secondary_dns_address: vec![0; 16],
            traffic_class: 0,
            neighbor_discovery_setup: vec![],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 48);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 10);
        assert_eq!(obj.methods().len(), 2);
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.traffic_class = 9;
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn add_remove_ipv6_address() {
        let mut obj = sample();
        let addr = CosemDataType::OctetString(vec![0xFEu8; 16]);
        obj.invoke_method(1, Some(addr.clone())).unwrap();
        assert_eq!(obj.unicast_ipv6_addresses.len(), 1);
        obj.invoke_method(2, Some(addr)).unwrap();
        assert_eq!(obj.unicast_ipv6_addresses.len(), 0);
        assert!(obj.invoke_method(2, Some(CosemDataType::OctetString(vec![0x11; 16]))).is_err());
    }
}
