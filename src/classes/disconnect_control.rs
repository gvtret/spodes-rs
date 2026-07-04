use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Values of the `control_state` attribute (IEC 62056-6-2 §4.5.8.2.3).
pub mod control_state {
    /// The output is open, the consumer is disconnected.
    pub const DISCONNECTED: u8 = 0;
    /// The output is closed, the consumer is connected.
    pub const CONNECTED: u8 = 1;
    /// The output is open but ready to be closed (manual reconnection pending).
    pub const READY_FOR_RECONNECTION: u8 = 2;
}

/// Configuration structure used to build a [`DisconnectControl`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DisconnectControlConfig {
    pub logical_name: ObisCode,
    /// Attribute 2: physical output state (true = closed/connected).
    pub output_state: bool,
    /// Attribute 3: control state (see [`control_state`]).
    pub control_state: u8,
    /// Attribute 4: control mode (0..6, IEC 62056-6-2 §4.5.8.2.4).
    pub control_mode: u8,
}

/// `Disconnect control` interface class (class_id = 70, version = 0) per
/// IEC 62056-6-2 §4.5.8. Manages the internal or external disconnect relay
/// (breaker) that connects or disconnects the consumer.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DisconnectControl {
    logical_name: ObisCode,
    output_state: bool,
    control_state: u8,
    control_mode: u8,
}

impl DisconnectControl {
    /// Builds a new [`DisconnectControl`] from its configuration.
    pub fn new(config: DisconnectControlConfig) -> Self {
        DisconnectControl {
            logical_name: config.logical_name,
            output_state: config.output_state,
            control_state: config.control_state,
            control_mode: config.control_mode,
        }
    }

    /// Method 1: `remote_disconnect` — forces the object into the `disconnected`
    /// state if remote disconnection is enabled (control_mode > 0). When
    /// control_mode is 0 the method has no effect (IEC 62056-6-2 §4.5.8.3.1).
    fn remote_disconnect(&mut self) -> Result<CosemDataType, String> {
        if self.control_mode > 0 {
            self.control_state = control_state::DISCONNECTED;
            self.output_state = false;
        }
        Ok(CosemDataType::Null)
    }

    /// Method 2: `remote_reconnect` — forces the object into the
    /// `ready_for_reconnection` state when direct remote reconnection is disabled
    /// (control_mode 1, 3, 5, 6), or directly into the `connected` state when it
    /// is enabled (control_mode 2, 4). When control_mode is 0 the method has no
    /// effect (IEC 62056-6-2 §4.5.8.3.2).
    fn remote_reconnect(&mut self) -> Result<CosemDataType, String> {
        match self.control_mode {
            2 | 4 => {
                self.control_state = control_state::CONNECTED;
                self.output_state = true;
            }
            1 | 3 | 5 | 6 => {
                self.control_state = control_state::READY_FOR_RECONNECTION;
                self.output_state = false;
            }
            _ => {}
        }
        Ok(CosemDataType::Null)
    }
}

impl InterfaceClass for DisconnectControl {
    fn class_id(&self) -> u16 {
        70
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
            (2, CosemDataType::Boolean(self.output_state)),
            (3, CosemDataType::Enum(self.control_state)),
            (4, CosemDataType::Enum(self.control_mode)),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![(1, "remote_disconnect".to_string()), (2, "remote_reconnect".to_string())]
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
        self.output_state = match seq[2] {
            CosemDataType::Boolean(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.control_state = match seq[3] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.control_mode = match seq[4] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, _params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => self.remote_disconnect(),
            2 => self.remote_reconnect(),
            _ => Err(format!("Method {} not supported for Disconnect control", method_id)),
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

    fn sample(control_mode: u8) -> DisconnectControl {
        DisconnectControl::new(DisconnectControlConfig {
            logical_name: ObisCode::new(0, 0, 96, 3, 10, 255),
            output_state: true,
            control_state: control_state::CONNECTED,
            control_mode,
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample(1);
        assert_eq!(obj.class_id(), 70);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 4);
        assert_eq!(obj.methods().len(), 2);
    }

    #[test]
    fn round_trip() {
        let obj = sample(2);
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample(0);
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn disconnect_requires_enabled_mode() {
        // control_mode 0 → method has no effect.
        let mut obj = sample(0);
        obj.invoke_method(1, None).unwrap();
        assert_eq!(obj.attributes()[2].1, CosemDataType::Enum(control_state::CONNECTED));
        // control_mode > 0 → disconnects.
        let mut obj = sample(1);
        obj.invoke_method(1, None).unwrap();
        assert_eq!(obj.attributes()[2].1, CosemDataType::Enum(control_state::DISCONNECTED));
        assert_eq!(obj.attributes()[1].1, CosemDataType::Boolean(false));
    }

    #[test]
    fn reconnect_depends_on_control_mode() {
        // Modes 2/4: direct reconnection → connected.
        let mut obj = sample(2);
        obj.control_state = control_state::DISCONNECTED;
        obj.output_state = false;
        obj.invoke_method(2, None).unwrap();
        assert_eq!(obj.attributes()[2].1, CosemDataType::Enum(control_state::CONNECTED));
        assert_eq!(obj.attributes()[1].1, CosemDataType::Boolean(true));
        // Modes 1/3/5/6: manual reconnection → ready_for_reconnection.
        let mut obj = sample(3);
        obj.control_state = control_state::DISCONNECTED;
        obj.invoke_method(2, None).unwrap();
        assert_eq!(obj.attributes()[2].1, CosemDataType::Enum(control_state::READY_FOR_RECONNECTION));
    }
}
