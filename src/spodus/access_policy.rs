//! Meter access policies (СТО 34.01-5.1-013-2023, §10.6, `0.0.94.7.132.255`).
//!
//! The credentials the ИВКЭ uses to open an association with each meter are held
//! as a `Data` (IC 1) object whose value is an `array meters_passwords`, per
//! §10.6:
//!
//! ```text
//! meters_passwords ::= structure {
//!     meter_id: octet-string,
//!     police_id: byte,          // security policy
//!     suit_id: byte,            // cryptographic suite
//!     array security_list { type: byte, key: octet-string }
//! }
//! ```

use crate::classes::data::Data;
use crate::types::CosemDataType;

use super::obis;

/// `type` values of a `security_list` item (§10.6).
pub mod security_item_type {
    /// Low-security password.
    pub const LLS_PASSWORD: u8 = 0;
    /// Low-security authentication key.
    pub const LLS_AUTHENTICATION_KEY: u8 = 1;
    /// Low-security encryption key.
    pub const LLS_ENCRYPTION_KEY: u8 = 2;
    /// High-security authentication key.
    pub const HLS_AUTHENTICATION_KEY: u8 = 3;
    /// High-security encryption key.
    pub const HLS_ENCRYPTION_KEY: u8 = 4;
    /// Key-encryption key (KEK).
    pub const KEK: u8 = 5;
}

/// One `security_list` entry: a typed key or password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityItem {
    /// Item type (see [`security_item_type`]).
    pub item_type: u8,
    /// Key or password value.
    pub key: Vec<u8>,
}

/// The access policy for a single meter (`meters_passwords`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessPolicy {
    /// Meter identifier the policy applies to.
    pub meter_id: Vec<u8>,
    /// Security policy id (`police_id`).
    pub policy_id: u8,
    /// Cryptographic suite id (`suit_id`).
    pub suite_id: u8,
    /// Keys and passwords for this meter.
    pub security_list: Vec<SecurityItem>,
}

impl AccessPolicy {
    /// The COSEM `meters_passwords` structure for this policy.
    fn to_structure(&self) -> CosemDataType {
        let security_list = self
            .security_list
            .iter()
            .map(|item| {
                CosemDataType::Structure(vec![
                    CosemDataType::Unsigned(item.item_type),
                    CosemDataType::OctetString(item.key.clone()),
                ])
            })
            .collect();
        CosemDataType::Structure(vec![
            CosemDataType::OctetString(self.meter_id.clone()),
            CosemDataType::Unsigned(self.policy_id),
            CosemDataType::Unsigned(self.suite_id),
            CosemDataType::Array(security_list),
        ])
    }
}

/// The access-policy list (§10.6, `0.0.94.7.132.255`).
#[derive(Clone, Debug, Default)]
pub struct AccessPolicies {
    policies: Vec<AccessPolicy>,
}

impl AccessPolicies {
    /// Creates an empty policy list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a meter access policy.
    pub fn add(&mut self, policy: AccessPolicy) {
        self.policies.push(policy);
    }

    /// Finds the policy for a given meter id.
    pub fn find(&self, meter_id: &[u8]) -> Option<&AccessPolicy> {
        self.policies.iter().find(|p| p.meter_id == meter_id)
    }

    /// Builds the COSEM `Data` (IC 1) object holding the policy array.
    pub fn build(&self) -> Data {
        let array = self.policies.iter().map(AccessPolicy::to_structure).collect();
        Data::new(obis::access_policies(), CosemDataType::Array(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn access_policies_build_data_object() {
        let mut policies = AccessPolicies::new();
        policies.add(AccessPolicy {
            meter_id: b"SIT12260004".to_vec(),
            policy_id: 3,
            suite_id: 0,
            security_list: vec![
                SecurityItem { item_type: security_item_type::LLS_PASSWORD, key: b"12345678".to_vec() },
                SecurityItem { item_type: security_item_type::HLS_ENCRYPTION_KEY, key: vec![0xAB; 16] },
            ],
        });

        assert_eq!(policies.find(b"SIT12260004").unwrap().policy_id, 3);
        assert!(policies.find(b"unknown").is_none());

        let object = policies.build();
        assert_eq!(object.class_id(), 1);
        assert_eq!(object.logical_name(), &obis::access_policies());

        // Attribute 2: array of one meters_passwords structure.
        let CosemDataType::Array(rows) = &object.attributes()[1].1 else { panic!("array") };
        assert_eq!(rows.len(), 1);
        let CosemDataType::Structure(fields) = &rows[0] else { panic!("structure") };
        assert_eq!(fields[0], CosemDataType::OctetString(b"SIT12260004".to_vec()));
        assert_eq!(fields[1], CosemDataType::Unsigned(3));
        assert_eq!(fields[2], CosemDataType::Unsigned(0));
        let CosemDataType::Array(items) = &fields[3] else { panic!("security_list array") };
        assert_eq!(items.len(), 2);
    }
}
