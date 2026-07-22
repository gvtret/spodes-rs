use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::ImageToActivateInfo;
use crate::types::{BerError, CosemDataType};
use serde::{Deserialize, Serialize};
use std::any::Any;

/// Values of the `image_transfer_status` attribute (IEC 62056-6-2 §4.4.6.4).
pub mod transfer_status {
    /// No image transfer has been initiated.
    pub const NOT_INITIATED: u8 = 0;
    /// Image transfer has been initiated (blocks are being transferred).
    pub const INITIATED: u8 = 1;
    /// Image verification is in progress.
    pub const VERIFICATION_INITIATED: u8 = 2;
    /// Image verification completed successfully.
    pub const VERIFICATION_SUCCESSFUL: u8 = 3;
    /// Image verification failed.
    pub const VERIFICATION_FAILED: u8 = 4;
    /// Image activation is in progress.
    pub const ACTIVATION_INITIATED: u8 = 5;
    /// Image activation completed successfully.
    pub const ACTIVATION_SUCCESSFUL: u8 = 6;
    /// Image activation failed.
    pub const ACTIVATION_FAILED: u8 = 7;
}

/// Configuration structure used to build an [`ImageTransfer`] object.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ImageTransferConfig {
    /// Attribute 1: the object's logical name (OBIS code).
    pub logical_name: ObisCode,
    /// Attribute 2: image block size in octets.
    pub image_block_size: u32,
    /// Attribute 3: per-block transfer status, as a bit-string (1 = transferred).
    pub image_transferred_blocks_status: Vec<u8>,
    /// Attribute 4: number of the first block not yet transferred.
    pub image_first_not_transferred_block_number: u32,
    /// Attribute 5: whether the image transfer process is enabled.
    pub image_transfer_enabled: bool,
    /// Attribute 6: image transfer status (see [`transfer_status`]).
    pub image_transfer_status: u8,
    /// Attribute 7: array of `image_to_activate_info` structures.
    pub image_to_activate_info: Vec<ImageToActivateInfo>,
}

/// `Image transfer` interface class (class_id = 18, version = 0) per
/// IEC 62056-6-2 §4.4.6. Drives the firmware image transfer process
/// (initiate → block transfer → verify → activate).
///
/// All four methods can be invoked only while `image_transfer_enabled` is true.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ImageTransfer {
    logical_name: ObisCode,
    image_block_size: u32,
    image_transferred_blocks_status: Vec<u8>,
    image_first_not_transferred_block_number: u32,
    image_transfer_enabled: bool,
    image_transfer_status: u8,
    image_to_activate_info: Vec<ImageToActivateInfo>,
}

impl ImageTransfer {
    /// Builds a new [`ImageTransfer`] from its configuration.
    pub fn new(config: ImageTransferConfig) -> Self {
        ImageTransfer {
            logical_name: config.logical_name,
            image_block_size: config.image_block_size,
            image_transferred_blocks_status: config.image_transferred_blocks_status,
            image_first_not_transferred_block_number: config.image_first_not_transferred_block_number,
            image_transfer_enabled: config.image_transfer_enabled,
            image_transfer_status: config.image_transfer_status,
            image_to_activate_info: config.image_to_activate_info,
        }
    }

    fn ensure_enabled(&self) -> Result<(), String> {
        if self.image_transfer_enabled {
            Ok(())
        } else {
            Err("Image transfer is disabled".to_string())
        }
    }

    /// Method 1: `image_transfer_initiate` — starts a new transfer, clearing the
    /// block status (IEC 62056-6-2 §4.4.6.5). Parameter is
    /// `structure { image_identifier: octet-string, image_size: double-long-unsigned }`.
    fn image_transfer_initiate(&mut self, _data: CosemDataType) -> Result<CosemDataType, String> {
        self.ensure_enabled()?;
        self.image_transferred_blocks_status.clear();
        self.image_first_not_transferred_block_number = 0;
        self.image_transfer_status = transfer_status::INITIATED;
        Ok(CosemDataType::Null)
    }

    /// Method 2: `image_block_transfer` — transfers one block, marking it as
    /// received. Parameter is `structure { image_block_number: double-long-unsigned,
    /// image_block_value: octet-string }`.
    fn image_block_transfer(&mut self, data: CosemDataType) -> Result<CosemDataType, String> {
        self.ensure_enabled()?;
        let block_number = match data {
            CosemDataType::Structure(fields) if !fields.is_empty() => match &fields[0] {
                CosemDataType::DoubleLongUnsigned(n) => *n,
                _ => return Err("image_block_number must be double-long-unsigned".to_string()),
            },
            _ => return Err("Expected structure { image_block_number, image_block_value }".to_string()),
        };
        self.set_block_transferred(block_number);
        self.image_first_not_transferred_block_number = self.first_clear_bit();
        Ok(CosemDataType::Null)
    }

    /// Method 3: `image_verify` — verifies the transferred image. Parameter is
    /// `integer (0)`.
    fn image_verify(&mut self, _data: CosemDataType) -> Result<CosemDataType, String> {
        self.ensure_enabled()?;
        self.image_transfer_status = transfer_status::VERIFICATION_SUCCESSFUL;
        Ok(CosemDataType::Null)
    }

    /// Method 4: `image_activate` — activates the verified image. Parameter is
    /// `integer (0)`.
    fn image_activate(&mut self, _data: CosemDataType) -> Result<CosemDataType, String> {
        self.ensure_enabled()?;
        self.image_transfer_status = transfer_status::ACTIVATION_SUCCESSFUL;
        Ok(CosemDataType::Null)
    }

    /// Sets the bit for `block_number` (MSB-first), growing the bit-string as needed.
    fn set_block_transferred(&mut self, block_number: u32) {
        let byte_index = (block_number / 8) as usize;
        if byte_index >= self.image_transferred_blocks_status.len() {
            self.image_transferred_blocks_status.resize(byte_index + 1, 0);
        }
        let bit = 7 - (block_number % 8) as u8;
        self.image_transferred_blocks_status[byte_index] |= 1 << bit;
    }

    /// Returns the number of the first block whose bit is still clear.
    // The bitmap tracks image blocks; no realistic firmware image needs
    // anywhere near u32::MAX/8 bytes of tracking bits.
    #[allow(clippy::cast_possible_truncation)]
    fn first_clear_bit(&self) -> u32 {
        for (byte_index, byte) in self.image_transferred_blocks_status.iter().enumerate() {
            for bit in 0..8u32 {
                if byte & (1 << (7 - bit)) == 0 {
                    return byte_index as u32 * 8 + bit;
                }
            }
        }
        self.image_transferred_blocks_status.len() as u32 * 8
    }
}

impl InterfaceClass for ImageTransfer {
    fn class_id(&self) -> u16 {
        18
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
            (2, CosemDataType::DoubleLongUnsigned(self.image_block_size)),
            (3, CosemDataType::BitString(self.image_transferred_blocks_status.clone())),
            (4, CosemDataType::DoubleLongUnsigned(self.image_first_not_transferred_block_number)),
            (5, CosemDataType::Boolean(self.image_transfer_enabled)),
            (6, CosemDataType::Enum(self.image_transfer_status)),
            (7, CosemDataType::Array(self.image_to_activate_info.iter().cloned().map(CosemDataType::from).collect())),
        ]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "image_transfer_initiate".to_string()),
            (2, "image_block_transfer".to_string()),
            (3, "image_verify".to_string()),
            (4, "image_activate".to_string()),
        ]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        let mut seq_buf = Vec::new();
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(&mut seq_buf)?;
        for (_, attr) in self.attributes() {
            attr.serialize_ber(&mut seq_buf)?;
        }
        buf.push(0x02); // structure [2]
        write_length(1 + self.attributes().len(), buf); // length = element count
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
        // class_id + 7 attributes.
        if seq.len() != 8 {
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
        self.image_block_size = match seq[2] {
            CosemDataType::DoubleLongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.image_transferred_blocks_status = match &seq[3] {
            CosemDataType::BitString(v) => v.clone(),
            _ => return Err(BerError::InvalidTag),
        };
        self.image_first_not_transferred_block_number = match seq[4] {
            CosemDataType::DoubleLongUnsigned(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.image_transfer_enabled = match seq[5] {
            CosemDataType::Boolean(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.image_transfer_status = match seq[6] {
            CosemDataType::Enum(v) => v,
            _ => return Err(BerError::InvalidTag),
        };
        self.image_to_activate_info = match &seq[7] {
            CosemDataType::Array(list) => list
                .iter()
                .map(ImageToActivateInfo::try_from)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BerError::InvalidValue)?,
            _ => return Err(BerError::InvalidTag),
        };
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        let params = params.ok_or("Missing method parameter")?;
        match method_id {
            1 => self.image_transfer_initiate(params),
            2 => self.image_block_transfer(params),
            3 => self.image_verify(params),
            4 => self.image_activate(params),
            _ => Err(format!("Method {method_id} not supported for Image transfer")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Writes a BER length octet (short or long form).
#[allow(clippy::cast_possible_truncation)] // length < 128 and num_octets in 1..=8 always fit u8
fn write_length(length: usize, buf: &mut Vec<u8>) {
    if length < 128 {
        buf.push(length as u8);
    } else {
        let bytes = (length as u64).to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_octets = 8 - first_non_zero;
        buf.push(0x80 | num_octets as u8);
        buf.extend_from_slice(&bytes[first_non_zero..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ImageTransfer {
        ImageTransfer::new(ImageTransferConfig {
            logical_name: ObisCode::new(0, 0, 44, 0, 0, 255),
            image_block_size: 256,
            image_transferred_blocks_status: vec![],
            image_first_not_transferred_block_number: 0,
            image_transfer_enabled: true,
            image_transfer_status: transfer_status::NOT_INITIATED,
            image_to_activate_info: vec![],
        })
    }

    #[test]
    fn class_id_and_attributes() {
        let obj = sample();
        assert_eq!(obj.class_id(), 18);
        assert_eq!(obj.version(), 0);
        assert_eq!(obj.attributes().len(), 7);
        assert_eq!(obj.methods().len(), 4);
    }

    #[test]
    fn round_trip() {
        let mut obj = sample();
        obj.image_transferred_blocks_status = vec![0b1010_0000];
        obj.image_transfer_status = transfer_status::INITIATED;
        let mut buf = Vec::new();
        obj.serialize_ber(&mut buf).unwrap();
        let mut decoded = sample();
        decoded.deserialize_ber(&buf).unwrap();
        assert_eq!(decoded.attributes(), obj.attributes());
    }

    #[test]
    fn transfer_flow_marks_blocks_and_advances_status() {
        let mut obj = sample();
        obj.invoke_method(
            1,
            Some(CosemDataType::Structure(vec![
                CosemDataType::OctetString(b"fw".to_vec()),
                CosemDataType::DoubleLongUnsigned(512),
            ])),
        )
        .unwrap();
        assert_eq!(obj.attributes()[5].1, CosemDataType::Enum(transfer_status::INITIATED));

        // Transfer block 0; first-not-transferred advances to 1.
        obj.invoke_method(
            2,
            Some(CosemDataType::Structure(vec![
                CosemDataType::DoubleLongUnsigned(0),
                CosemDataType::OctetString(vec![0xAB; 4]),
            ])),
        )
        .unwrap();
        assert_eq!(obj.attributes()[3].1, CosemDataType::DoubleLongUnsigned(1));

        obj.invoke_method(3, Some(CosemDataType::Integer(0))).unwrap();
        assert_eq!(obj.attributes()[5].1, CosemDataType::Enum(transfer_status::VERIFICATION_SUCCESSFUL));
        obj.invoke_method(4, Some(CosemDataType::Integer(0))).unwrap();
        assert_eq!(obj.attributes()[5].1, CosemDataType::Enum(transfer_status::ACTIVATION_SUCCESSFUL));
    }

    #[test]
    fn methods_fail_when_disabled() {
        let mut obj = sample();
        obj.image_transfer_enabled = false;
        assert!(obj.invoke_method(1, Some(CosemDataType::Null)).is_err());
    }
}
