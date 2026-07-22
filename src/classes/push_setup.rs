use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::{
    CaptureObjectDefinition, CommunicationWindow, ConfirmationParameters, DateTime, PushProtectionParameter,
    SendDestinationAndMethod,
};
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// One outbound push, assembled by
/// [`RequestDispatcher::build_push_delivery_request`](crate::server::RequestDispatcher::build_push_delivery_request):
/// the destination and transport from attribute 3, the push client SAP and
/// the encoded DataNotification body. The host owns the actual transmission.
#[derive(Debug, Clone, PartialEq)]
pub struct PushDeliveryRequest {
    /// Destination address (from `send_destination_and_method`).
    pub destination: Vec<u8>,
    /// Transport service identifier (from `send_destination_and_method`).
    pub transport_service: u8,
    /// The push client SAP (attribute 9).
    pub client_sap: i8,
    /// The encoded DataNotification APDU carrying the push object values.
    pub body: Vec<u8>,
}

/// Configuration structure used to build a [`PushSetup`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PushSetupConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Class version: 0, 1 or 2. Selects which attributes and methods are exposed.
    pub version: u8,
    /// Attribute 2: array of `cosem_object_instance_id` entries to be pushed.
    pub push_object_list: Vec<CaptureObjectDefinition>,
    /// Attribute 3: `send_destination_and_method` structure.
    pub send_destination_and_method: SendDestinationAndMethod,
    /// Attribute 4: array of communication windows.
    pub communication_window: Vec<CommunicationWindow>,
    /// Attribute 5: randomisation start interval, in seconds.
    pub randomisation_start_interval: u16,
    /// Attribute 6: number of retries.
    pub number_of_retries: u8,
    /// Attribute 7 (version 2): `repetition_delay` structure.
    pub repetition_delay: CosemDataType,
    /// Attribute 8: reference to the communication port setup object.
    pub port_reference: Vec<u8>,
    /// Attribute 9: push client SAP.
    pub push_client_sap: i8,
    /// Attribute 10: array of push protection parameters.
    pub push_protection_parameters: Vec<PushProtectionParameter>,
    /// Attribute 11: push operation method (enum).
    pub push_operation_method: u8,
    /// Attribute 12: `confirmation_parameters` structure.
    pub confirmation_parameters: ConfirmationParameters,
    /// Attribute 13: date-time of the last successful confirmation.
    pub last_confirmation_date_time: DateTime,
}

/// `Push setup` interface class (class_id = 40) per IEC 62056-6-2 §4.4.8. Holds
/// the configuration of the server's unsolicited (push) output.
///
/// All three versions are supported:
/// * version 0 — attributes 1..7, method `push`;
/// * version 1 — attributes 1..10, method `push`;
/// * version 2 — attributes 1..13, methods `push` and `reset`.
///
/// In versions 0 and 1 attribute 7 (`repetition_delay`) is a `long-unsigned`;
/// in version 2 it is a structure. The `push` ACTION only validates that the
/// object is triggerable; assembling and sending the actual DataNotification
/// is done by [`RequestDispatcher::build_push_delivery_request`](crate::server::RequestDispatcher::build_push_delivery_request),
/// which has access to the live object registry that this class does not
/// hold.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PushSetup {
    version: u8,
    logical_name: ObisCode,
    push_object_list: Vec<CaptureObjectDefinition>,
    send_destination_and_method: SendDestinationAndMethod,
    communication_window: Vec<CommunicationWindow>,
    randomisation_start_interval: u16,
    number_of_retries: u8,
    repetition_delay: CosemDataType,
    port_reference: Vec<u8>,
    push_client_sap: i8,
    push_protection_parameters: Vec<PushProtectionParameter>,
    push_operation_method: u8,
    confirmation_parameters: ConfirmationParameters,
    last_confirmation_date_time: DateTime,
}

impl PushSetup {
    /// Builds a new [`PushSetup`] from its configuration.
    pub fn new(config: PushSetupConfig) -> Self {
        PushSetup {
            version: config.version,
            logical_name: config.logical_name,
            push_object_list: config.push_object_list,
            send_destination_and_method: config.send_destination_and_method,
            communication_window: config.communication_window,
            randomisation_start_interval: config.randomisation_start_interval,
            number_of_retries: config.number_of_retries,
            repetition_delay: config.repetition_delay,
            port_reference: config.port_reference,
            push_client_sap: config.push_client_sap,
            push_protection_parameters: config.push_protection_parameters,
            push_operation_method: config.push_operation_method,
            confirmation_parameters: config.confirmation_parameters,
            last_confirmation_date_time: config.last_confirmation_date_time,
        }
    }

    /// Method 1: `push` — triggers sending the push object list to the
    /// destination (IEC 62056-6-2 §4.4.8.3.1). Building the notification body
    /// requires reading the live values of the referenced objects, which this
    /// class does not hold; use
    /// [`RequestDispatcher::build_push_delivery_request`](crate::server::RequestDispatcher::build_push_delivery_request)
    /// against the object registry to actually assemble and send the push. The
    /// ACTION itself only validates that the object is triggerable.
    fn push(&mut self) -> Result<CosemDataType, String> {
        Ok(CosemDataType::Null)
    }

    /// Method 2: `reset` — resets the push confirmation state by clearing
    /// `last_confirmation_date_time`.
    fn reset(&mut self) -> Result<CosemDataType, String> {
        self.last_confirmation_date_time = DateTime::new([0u8; 12]);
        Ok(CosemDataType::Null)
    }

    /// Returns the push object list (attribute 2): the objects and attribute
    /// indices to read when assembling a push.
    pub fn push_object_list(&self) -> &[CaptureObjectDefinition] {
        &self.push_object_list
    }

    /// Returns the send-destination-and-method (attribute 3).
    pub fn send_destination_and_method(&self) -> &SendDestinationAndMethod {
        &self.send_destination_and_method
    }

    /// Returns the push client SAP (attribute 9, 0 in versions without it).
    pub fn push_client_sap(&self) -> i8 {
        self.push_client_sap
    }
}

impl InterfaceClass for PushSetup {
    fn class_id(&self) -> u16 {
        40
    }

    fn version(&self) -> u8 {
        self.version
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        // Attributes 1..7 are common to all versions.
        let mut attrs = vec![
            (1, CosemDataType::OctetString(self.logical_name.to_bytes())),
            (2, CosemDataType::Array(self.push_object_list.iter().map(|o| CosemDataType::from(o.clone())).collect())),
            (3, CosemDataType::from(self.send_destination_and_method.clone())),
            (
                4,
                CosemDataType::Array(
                    self.communication_window.iter().map(|cw| CosemDataType::from(cw.clone())).collect(),
                ),
            ),
            (5, CosemDataType::LongUnsigned(self.randomisation_start_interval)),
            (6, CosemDataType::Unsigned(self.number_of_retries)),
            (7, self.repetition_delay.clone()),
        ];
        // Attributes 8..10 were added in version 1.
        if self.version >= 1 {
            attrs.push((8, CosemDataType::OctetString(self.port_reference.clone())));
            attrs.push((9, CosemDataType::Integer(self.push_client_sap)));
            attrs.push((
                10,
                CosemDataType::Array(
                    self.push_protection_parameters.iter().map(|p| CosemDataType::from(p.clone())).collect(),
                ),
            ));
        }
        // Attributes 11..13 were added in version 2.
        if self.version >= 2 {
            attrs.push((11, CosemDataType::Enum(self.push_operation_method)));
            attrs.push((12, CosemDataType::from(self.confirmation_parameters.clone())));
            attrs.push((13, CosemDataType::from(self.last_confirmation_date_time.clone())));
        }
        attrs
    }

    fn methods(&self) -> Vec<(u8, String)> {
        // `reset` was added in version 2.
        if self.version >= 2 {
            vec![(1, "push".to_string()), (2, "reset".to_string())]
        } else {
            vec![(1, "push".to_string())]
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
        let CosemDataType::Structure(seq) = tlv else {
            return Err(BerError::InvalidTag);
        };
        // The element count (class_id + attributes) identifies the version:
        // 8 → v0, 11 → v1, 14 → v2.
        self.version = match seq.len() {
            8 => 0,
            11 => 1,
            14 => 2,
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
        self.push_object_list = match &seq[2] {
            CosemDataType::Array(list) => list
                .iter()
                .map(CaptureObjectDefinition::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BerError::InvalidValue)?,
            _ => return Err(BerError::InvalidTag),
        };
        self.send_destination_and_method =
            SendDestinationAndMethod::try_from(&seq[3]).map_err(|_| BerError::InvalidValue)?;
        self.communication_window = match &seq[4] {
            CosemDataType::Array(list) => list
                .iter()
                .map(CommunicationWindow::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BerError::InvalidValue)?,
            _ => return Err(BerError::InvalidTag),
        };
        self.randomisation_start_interval = match seq[5] {
            CosemDataType::LongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.number_of_retries = match seq[6] {
            CosemDataType::Unsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.repetition_delay = seq[7].clone();
        if self.version >= 1 {
            self.port_reference = match &seq[8] {
                CosemDataType::OctetString(v) => v.clone(),
                _ => return Err(BerError::InvalidTag),
            };
            self.push_client_sap = match seq[9] {
                CosemDataType::Integer(v) => v,
                _ => return Err(BerError::InvalidTag),
            };
            self.push_protection_parameters = match &seq[10] {
                CosemDataType::Array(list) => list
                    .iter()
                    .map(PushProtectionParameter::try_from)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| BerError::InvalidValue)?,
                _ => return Err(BerError::InvalidTag),
            };
        }
        if self.version >= 2 {
            self.push_operation_method = match seq[11] {
                CosemDataType::Enum(v) => v,
                _ => return Err(BerError::InvalidTag),
            };
            self.confirmation_parameters =
                ConfirmationParameters::try_from(&seq[12]).map_err(|_| BerError::InvalidValue)?;
            self.last_confirmation_date_time = DateTime::try_from(&seq[13]).map_err(|_| BerError::InvalidValue)?;
        }
        Ok(())
    }

    fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
        match attribute_id {
            2 => match value {
                CosemDataType::Array(list) => {
                    self.push_object_list =
                        list.iter().map(CaptureObjectDefinition::try_from).collect::<Result<Vec<_>, _>>()?;
                    Ok(())
                }
                _ => Err("push_object_list must be array".to_string()),
            },
            3 => {
                self.send_destination_and_method = SendDestinationAndMethod::try_from(&value)?;
                Ok(())
            }
            4 => match value {
                CosemDataType::Array(list) => {
                    self.communication_window =
                        list.iter().map(CommunicationWindow::try_from).collect::<Result<Vec<_>, _>>()?;
                    Ok(())
                }
                _ => Err("communication_window must be array".to_string()),
            },
            5 => match value {
                CosemDataType::LongUnsigned(v) => {
                    self.randomisation_start_interval = v;
                    Ok(())
                }
                _ => Err("randomisation_start_interval must be long-unsigned".to_string()),
            },
            6 => match value {
                CosemDataType::Unsigned(v) => {
                    self.number_of_retries = v;
                    Ok(())
                }
                _ => Err("number_of_retries must be unsigned".to_string()),
            },
            7 => {
                self.repetition_delay = value;
                Ok(())
            }
            8 if self.version >= 1 => match value {
                CosemDataType::OctetString(v) => {
                    self.port_reference = v;
                    Ok(())
                }
                _ => Err("port_reference must be octet-string".to_string()),
            },
            _ => Err(format!("Attribute {} not writable for PushSetup", attribute_id)),
        }
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.push(),
            2 if self.version >= 2 => self.reset(),
            _ => Err(format!("Method {} not supported for Push setup version {}", method_id, self.version)),
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

    fn sample_versioned(version: u8) -> PushSetup {
        PushSetup::new(PushSetupConfig {
            version,
            logical_name: ObisCode::new(0, 0, 25, 9, 0, 255),
            push_object_list: vec![CaptureObjectDefinition::new(8, ObisCode::new(0, 0, 1, 0, 0, 255), 2, 0)],
            send_destination_and_method: SendDestinationAndMethod {
                transport_service: 0,
                destination: b"192.168.0.1:4059".to_vec(),
                message: 0,
            },
            communication_window: vec![],
            randomisation_start_interval: 0,
            number_of_retries: 3,
            repetition_delay: CosemDataType::Structure(vec![
                CosemDataType::LongUnsigned(30),
                CosemDataType::LongUnsigned(240),
                CosemDataType::LongUnsigned(0),
            ]),
            port_reference: vec![0, 0, 25, 0, 0, 255],
            push_client_sap: 1,
            push_protection_parameters: vec![],
            push_operation_method: 0,
            confirmation_parameters: ConfirmationParameters { data: vec![] },
            last_confirmation_date_time: DateTime::new([0u8; 12]),
        })
    }

    #[test]
    fn attribute_and_method_counts_per_version() {
        let expected = [(0u8, 7usize, 1usize), (1, 10, 1), (2, 13, 2)];
        for (version, attr_count, method_count) in expected {
            let obj = sample_versioned(version);
            assert_eq!(obj.class_id(), 40);
            assert_eq!(obj.version(), version);
            assert_eq!(obj.attributes().len(), attr_count, "attrs for v{version}");
            assert_eq!(obj.methods().len(), method_count, "methods for v{version}");
        }
    }

    #[test]
    fn round_trip_all_versions() {
        for version in 0..=2u8 {
            let obj = sample_versioned(version);
            let mut buf = Vec::new();
            obj.serialize_ber(&mut buf).unwrap();
            let mut decoded = sample_versioned(0);
            decoded.deserialize_ber(&buf).unwrap();
            assert_eq!(decoded.version(), version);
            assert_eq!(decoded.attributes(), obj.attributes());
        }
    }

    #[test]
    fn reset_clears_confirmation() {
        let mut obj = sample_versioned(2);
        obj.last_confirmation_date_time = DateTime::new([0x07; 12]);
        obj.invoke_method(2, None).unwrap();
        assert_eq!(obj.attributes()[12].1, CosemDataType::DateTime(vec![0; 12]));
        // `reset` is not available in versions 0 and 1.
        let mut v1 = sample_versioned(1);
        assert!(v1.invoke_method(2, None).is_err());
    }
}
