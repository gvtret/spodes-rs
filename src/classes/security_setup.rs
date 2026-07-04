use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::BTreeMap;

/// Symmetric key identifiers used by `key_transfer` (IEC 62056-6-2 §4.4.7.3.2).
pub mod key_id {
    /// Global unicast encryption key (GUEK).
    pub const GLOBAL_UNICAST_ENCRYPTION: u8 = 0;
    /// Global broadcast encryption key (GBEK).
    pub const GLOBAL_BROADCAST_ENCRYPTION: u8 = 1;
    /// Authentication key (AK).
    pub const AUTHENTICATION: u8 = 2;
    /// Master key / key encrypting key (KEK).
    pub const MASTER: u8 = 3;
}

/// Configuration structure used to build a [`SecuritySetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SecuritySetupConfig {
    pub logical_name: ObisCode,
    /// Class version: 0 or 1. Version 1 adds the `certificates` attribute and the
    /// PKI/ECDH methods.
    pub version: u8,
    /// Attribute 2: security policy (enum). See IEC 62056-6-2 §4.4.7.2.2.
    pub security_policy: u8,
    /// Attribute 3: security suite (enum). 0 = AES-GCM-128 with AES-128 key wrap.
    pub security_suite: u8,
    /// Attribute 4: client system title (octet-string).
    pub client_system_title: Vec<u8>,
    /// Attribute 5: server system title (octet-string).
    pub server_system_title: Vec<u8>,
    /// Attribute 6: certificates (array). Empty for security suite 0.
    pub certificates: Vec<CosemDataType>,
}

/// `Security setup` interface class (class_id = 64) per IEC 62056-6-2 §4.4.7.
/// Holds the security policy, suite, system titles and certificates, and manages
/// the server's symmetric keys.
///
/// Both versions are supported:
/// * version 0 — attributes 1..5, methods `security_activate` and
///   `global_key_transfer`;
/// * version 1 — attributes 1..6 (adds `certificates`), methods 1..8.
///
/// Only the mechanisms required by security suite 0 (AES-GCM-128) are
/// implemented: `security_activate` and the key transfer method. The PKI/ECDH
/// methods (`key_agreement`, `generate_key_pair`, certificate handling) belong
/// to suites 1 and 2 and return an unsupported error here.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SecuritySetup {
    version: u8,
    logical_name: ObisCode,
    security_policy: u8,
    security_suite: u8,
    client_system_title: Vec<u8>,
    server_system_title: Vec<u8>,
    certificates: Vec<CosemDataType>,
    /// Installed symmetric keys, indexed by `key_id`. Transient security
    /// material, not exposed as a COSEM attribute.
    #[serde(skip)]
    keys: BTreeMap<u8, Vec<u8>>,
}

impl SecuritySetup {
    /// Builds a new [`SecuritySetup`] from its configuration.
    pub fn new(config: SecuritySetupConfig) -> Self {
        SecuritySetup {
            version: config.version,
            logical_name: config.logical_name,
            security_policy: config.security_policy,
            security_suite: config.security_suite,
            client_system_title: config.client_system_title,
            server_system_title: config.server_system_title,
            certificates: config.certificates,
            keys: BTreeMap::new(),
        }
    }

    /// Returns the installed key for `key_id`, if any.
    pub fn key(&self, key_id: u8) -> Option<&Vec<u8>> {
        self.keys.get(&key_id)
    }

    /// Method 1: `security_activate` — activates and strengthens the security
    /// policy (IEC 62056-6-2 §4.4.7.3.1). Strengthening is one-way: a value
    /// weaker than the current policy is rejected.
    fn security_activate(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let new_policy = match data {
            CosemDataType::Enum(v) => v,
            _ => return Err("security_activate expects an enum".to_string()),
        };
        if new_policy < self.security_policy {
            return Err("security policy cannot be weakened".to_string());
        }
        self.security_policy = new_policy;
        Ok(CosemDataType::Null)
    }

    /// Method 2: `key_transfer` — installs one or more symmetric keys
    /// (IEC 62056-6-2 §4.4.7.3.2). The parameter is an array of
    /// `key_transfer_data ::= structure { key_id: enum, key_wrapped: octet-string }`.
    ///
    /// The keys are stored as received. Unwrapping (AES key unwrap with the KEK)
    /// is not performed here, since the master key management belongs to the
    /// ciphering layer, which is out of scope for this data-model class.
    fn key_transfer(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        let entries = match data {
            CosemDataType::Array(entries) => entries,
            _ => return Err("key_transfer expects an array of key_transfer_data".to_string()),
        };
        let mut staged = BTreeMap::new();
        for entry in &entries {
            let fields = match entry {
                CosemDataType::Structure(fields) => fields,
                _ => return Err("key_transfer_data must be a structure".to_string()),
            };
            if fields.len() != 2 {
                return Err("key_transfer_data must hold key_id and key_wrapped".to_string());
            }
            let key_id = match &fields[0] {
                CosemDataType::Enum(id) => *id,
                _ => return Err("key_id must be an enum".to_string()),
            };
            let key = match &fields[1] {
                CosemDataType::OctetString(bytes) => bytes.clone(),
                _ => return Err("key_wrapped must be an octet-string".to_string()),
            };
            staged.insert(key_id, key);
        }
        // Apply atomically only after every entry has been validated.
        self.keys.extend(staged);
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for SecuritySetup {
    fn class_id(&self) -> u16 {
        64
    }

    fn version(&self) -> u8 {
        self.version
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        // Attributes 1..5 are common to both versions.
        let mut attrs = vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Enum(self.security_policy)),
            (3, CosemDataType::Enum(self.security_suite)),
            (4, CosemDataType::OctetString(self.client_system_title.clone())),
            (5, CosemDataType::OctetString(self.server_system_title.clone())),
        ];
        // The `certificates` attribute was added in version 1.
        if self.version >= 1 {
            attrs.push((6, CosemDataType::Array(self.certificates.clone())));
        }
        attrs
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // Method identifiers per IEC 62056-6-2 §4.4.7.1 / §5.3.8.1.
        if self.version >= 1 {
            vec![
                (1, "security_activate".to_string()),
                (2, "key_transfer".to_string()),
                (3, "key_agreement".to_string()),
                (4, "generate_key_pair".to_string()),
                (5, "generate_certificate_request".to_string()),
                (6, "import_certificate".to_string()),
                (7, "export_certificate".to_string()),
                (8, "remove_certificate".to_string()),
            ]
        } else {
            // Version 0 has only these two methods.
            vec![(1, "security_activate".to_string()), (2, "global_key_transfer".to_string())]
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
        let seq = match tlv {
            CosemDataType::Structure(seq) => seq,
            _ => return Err(BerError::InvalidTag),
        };
        // The element count (class_id + attributes) identifies the version:
        // 6 → v0, 7 → v1.
        self.version = match seq.len() {
            6 => 0,
            7 => 1,
            _ => return Err(BerError::InvalidLength),
        };
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
        self.security_policy = match seq[2] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.security_suite = match seq[3] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.client_system_title = match &seq[4] {
            CosemDataType::OctetString(bytes) => bytes.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.server_system_title = match &seq[5] {
            CosemDataType::OctetString(bytes) => bytes.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        if self.version >= 1 {
            self.certificates = match &seq[6] {
                CosemDataType::Array(list) => list.clone(),
                _ => return Err(BerError::InvalidTag),
            };
        }
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let params = params.ok_or("Missing method parameter")?;
        match method_id {
            1 => self.security_activate(params),
            2 => self.key_transfer(params),
            3..=8 if self.version >= 1 => Err(format!(
                "Method {} requires security suite 1 or 2 (PKI/ECDH); not supported for suite 0",
                method_id
            )),
            _ => Err(format!("Method {} not supported for Security setup version {}", method_id, self.version)),
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

    fn sample_versioned(version: u8) -> SecuritySetup {
        SecuritySetup::new(SecuritySetupConfig {
            logical_name: ObisCode::new(0, 0, 43, 0, 0, 255),
            version,
            security_policy: 0,
            security_suite: 0,
            client_system_title: b"CLIENT01".to_vec(),
            server_system_title: b"SERVER01".to_vec(),
            certificates: vec![],
        })
    }

    fn sample() -> SecuritySetup {
        sample_versioned(1)
    }

    #[test]
    fn attribute_and_method_counts_per_version() {
        let expected = [(0u8, 5usize, 2usize), (1, 6, 8)];
        for (version, attr_count, method_count) in expected {
            let obj = sample_versioned(version);
            assert_eq!(obj.class_id(), 64);
            assert_eq!(obj.version(), version);
            assert_eq!(obj.attributes().len(), attr_count, "attrs for v{}", version);
            assert_eq!(obj.methods().len(), method_count, "methods for v{}", version);
        }
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

    #[test]
    fn security_activate_only_strengthens() {
        let mut obj = sample();
        obj.security_policy = 1;
        // Stronger policy is accepted.
        obj.invoke_method(1, Some(CosemDataType::Enum(3))).unwrap();
        assert_eq!(obj.attributes()[1].1, CosemDataType::Enum(3));
        // Weaker policy is rejected and leaves the attribute unchanged.
        assert!(obj.invoke_method(1, Some(CosemDataType::Enum(1))).is_err());
        assert_eq!(obj.attributes()[1].1, CosemDataType::Enum(3));
    }

    #[test]
    fn key_transfer_installs_keys() {
        let mut obj = sample();
        let data = CosemDataType::Array(vec![
            CosemDataType::Structure(vec![
                CosemDataType::Enum(key_id::GLOBAL_UNICAST_ENCRYPTION),
                CosemDataType::OctetString(vec![0x01; 16]),
            ]),
            CosemDataType::Structure(vec![
                CosemDataType::Enum(key_id::AUTHENTICATION),
                CosemDataType::OctetString(vec![0x02; 16]),
            ]),
        ]);
        obj.invoke_method(2, Some(data)).unwrap();
        assert_eq!(obj.key(key_id::GLOBAL_UNICAST_ENCRYPTION), Some(&vec![0x01; 16]));
        assert_eq!(obj.key(key_id::AUTHENTICATION), Some(&vec![0x02; 16]));
    }

    #[test]
    fn pki_methods_unsupported_for_suite0() {
        let mut obj = sample();
        for method_id in 3..=8 {
            assert!(obj.invoke_method(method_id, Some(CosemDataType::Null)).is_err());
        }
    }
}
