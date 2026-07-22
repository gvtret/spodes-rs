use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{EmergencyProfile, LimiterAction, ValueDefinition};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Configuration structure used to build a [`Limiter`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LimiterConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: `value_definition` structure { class_id, logical_name, attribute_index }.
    pub monitored_value: ValueDefinition,
    /// Attribute 3: active threshold (same type as the monitored attribute).
    pub threshold_active: CosemDataType,
    /// Attribute 4: threshold used during normal operation.
    pub threshold_normal: CosemDataType,
    /// Attribute 5: threshold used while an emergency profile is active.
    pub threshold_emergency: CosemDataType,
    /// Attribute 6: minimal over-threshold duration in seconds.
    pub min_over_threshold_duration: u32,
    /// Attribute 7: minimal under-threshold duration in seconds.
    pub min_under_threshold_duration: u32,
    /// Attribute 8: `emergency_profile` structure { id, activation_time, duration }.
    pub emergency_profile: EmergencyProfile,
    /// Attribute 9: array of emergency profile group ids.
    pub emergency_profile_group_id_list: Vec<u16>,
    /// Attribute 10: whether an emergency profile is currently active.
    pub emergency_profile_active: bool,
    /// Attribute 11: `action` structure of over/under-threshold scripts.
    pub actions: LimiterAction,
}

/// `Limiter` interface class (class_id = 71, version = 0) per IEC 62056-6-2
/// §4.5.9. Monitors a value attribute of another object and triggers actions
/// when it crosses the active threshold for at least the minimal duration.
///
/// This class defines no specific methods.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Limiter {
    logical_name: ObisCode,
    monitored_value: ValueDefinition,
    threshold_active: CosemDataType,
    threshold_normal: CosemDataType,
    threshold_emergency: CosemDataType,
    min_over_threshold_duration: u32,
    min_under_threshold_duration: u32,
    emergency_profile: EmergencyProfile,
    emergency_profile_group_id_list: Vec<u16>,
    emergency_profile_active: bool,
    actions: LimiterAction,
}

impl Limiter {
    /// Builds a new [`Limiter`] from its configuration.
    pub fn new(config: LimiterConfig) -> Self {
        Limiter {
            logical_name: config.logical_name,
            monitored_value: config.monitored_value,
            threshold_active: config.threshold_active,
            threshold_normal: config.threshold_normal,
            threshold_emergency: config.threshold_emergency,
            min_over_threshold_duration: config.min_over_threshold_duration,
            min_under_threshold_duration: config.min_under_threshold_duration,
            emergency_profile: config.emergency_profile,
            emergency_profile_group_id_list: config.emergency_profile_group_id_list,
            emergency_profile_active: config.emergency_profile_active,
            actions: config.actions,
        }
    }
}

impl InterfaceClass for Limiter {
    fn class_id(&self) -> u16 {
        71
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
            (2, CosemDataType::from(self.monitored_value.clone())),
            (3, self.threshold_active.clone()),
            (4, self.threshold_normal.clone()),
            (5, self.threshold_emergency.clone()),
            (6, CosemDataType::DoubleLongUnsigned(self.min_over_threshold_duration)),
            (7, CosemDataType::DoubleLongUnsigned(self.min_under_threshold_duration)),
            (8, CosemDataType::from(self.emergency_profile.clone())),
            (
                9,
                CosemDataType::Array(
                    self.emergency_profile_group_id_list.iter().map(|id| CosemDataType::LongUnsigned(*id)).collect(),
                ),
            ),
            (10, CosemDataType::Boolean(self.emergency_profile_active)),
            (11, CosemDataType::from(self.actions.clone())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // The Limiter class defines no specific methods.
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
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
        };
        // class_id + 11 attributes.
        if seq.len() != 12 {
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
        self.monitored_value = ValueDefinition::try_from(&seq[2]).map_err(|_| BerError::InvalidValue)?;
        self.threshold_active = seq[3].clone();
        self.threshold_normal = seq[4].clone();
        self.threshold_emergency = seq[5].clone();
        self.min_over_threshold_duration = match seq[6] {
            CosemDataType::DoubleLongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.min_under_threshold_duration = match seq[7] {
            CosemDataType::DoubleLongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.emergency_profile = EmergencyProfile::try_from(&seq[8]).map_err(|_| BerError::InvalidValue)?;
        self.emergency_profile_group_id_list = match &seq[9] {
            CosemDataType::Array(list) => list
                .iter()
                .map(|e| match e {
                    CosemDataType::LongUnsigned(v) => Ok(*v),
                    _ => Err(BerError::InvalidTag),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(BerError::InvalidTag),
        };
        self.emergency_profile_active = match seq[10] {
            CosemDataType::Boolean(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.actions = LimiterAction::try_from(&seq[11]).map_err(|_| BerError::InvalidValue)?;
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        Err(format!("Method {method_id} not supported for Limiter (no specific methods)"))
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

    fn sample() -> Limiter {
        use crate::types::attrs::ActionItem;
        Limiter::new(LimiterConfig {
            logical_name: ObisCode::new(0, 0, 17, 0, 0, 255),
            monitored_value: ValueDefinition {
                class_id: 3,
                logical_name: ObisCode::new(1, 0, 1, 7, 0, 255),
                attribute_index: 2,
            },
            threshold_active: CosemDataType::LongUnsigned(5000),
            threshold_normal: CosemDataType::LongUnsigned(5000),
            threshold_emergency: CosemDataType::LongUnsigned(8000),
            min_over_threshold_duration: 60,
            min_under_threshold_duration: 120,
            emergency_profile: EmergencyProfile {
                emergency_profile_id: 1,
                emergency_activation_time: vec![0; 12],
                emergency_duration: 3600,
            },
            emergency_profile_group_id_list: vec![1],
            emergency_profile_active: false,
            actions: LimiterAction {
                action_over_threshold: ActionItem {
                    script_logical_name: ObisCode::new(0, 0, 10, 0, 1, 255),
                    script_selector: 1,
                },
                action_under_threshold: ActionItem {
                    script_logical_name: ObisCode::new(0, 0, 10, 0, 1, 255),
                    script_selector: 2,
                },
            },
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 71);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 11);
        assert!(obj.methods().is_empty());
    }

    #[test]
    fn round_trip() {
        let obj = sample();
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = Limiter::new(LimiterConfig {
            logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
            monitored_value: ValueDefinition {
                class_id: 0,
                logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
                attribute_index: 0,
            },
            threshold_active: CosemDataType::Null,
            threshold_normal: CosemDataType::Null,
            threshold_emergency: CosemDataType::Null,
            min_over_threshold_duration: 0,
            min_under_threshold_duration: 0,
            emergency_profile: EmergencyProfile {
                emergency_profile_id: 0,
                emergency_activation_time: vec![],
                emergency_duration: 0,
            },
            emergency_profile_group_id_list: vec![],
            emergency_profile_active: true,
            actions: LimiterAction {
                action_over_threshold: crate::types::attrs::ActionItem {
                    script_logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
                    script_selector: 0,
                },
                action_under_threshold: crate::types::attrs::ActionItem {
                    script_logical_name: ObisCode::new(0, 0, 0, 0, 0, 0),
                    script_selector: 0,
                },
            },
        });
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn no_methods_supported() {
        let mut obj = sample();
        assert!(obj.invoke_method(1, None).is_err());
    }
}
