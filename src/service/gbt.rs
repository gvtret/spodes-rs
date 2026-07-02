//! General block transfer (IEC 62056-5-3, 7.3.13): a transport-independent
//! mechanism that carries any (partial) xDLMS APDU in blocks.
//!
//! ```text
//! E0 | block-control | block-number | block-number-ack | block-data
//!      ^ LB|ST|window   ^ u16           ^ u16 (acked)      ^ A-XDR octet-string
//! ```
//!
//! The block-control octet holds the last-block flag (bit 7), the streaming
//! flag (bit 6) and the window size (bits 5..0).

use super::{push_length, read_length, ServiceError};

/// General-block-transfer APDU tag ([224]).
pub const GENERAL_BLOCK_TRANSFER: u8 = 0xE0;

const LAST_BLOCK: u8 = 0x80;
const STREAMING: u8 = 0x40;
const WINDOW_MASK: u8 = 0x3F;

/// A general-block-transfer APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralBlockTransfer {
    /// Whether this is the last block.
    pub last_block: bool,
    /// Whether streaming is in use.
    pub streaming: bool,
    /// Window size (0..63): the number of blocks that may be sent before an ack.
    pub window: u8,
    /// Number of this block.
    pub block_number: u16,
    /// Number of the last block acknowledged by the peer.
    pub block_number_ack: u16,
    /// This block's fragment of the embedded APDU.
    pub block_data: Vec<u8>,
}

impl GeneralBlockTransfer {
    /// Encodes the general-block-transfer APDU.
    pub fn encode(&self) -> Vec<u8> {
        let block_control = if self.last_block { LAST_BLOCK } else { 0 }
            | if self.streaming { STREAMING } else { 0 }
            | (self.window & WINDOW_MASK);
        let mut buf = vec![GENERAL_BLOCK_TRANSFER, block_control];
        buf.extend_from_slice(&self.block_number.to_be_bytes());
        buf.extend_from_slice(&self.block_number_ack.to_be_bytes());
        push_length(self.block_data.len(), &mut buf);
        buf.extend_from_slice(&self.block_data);
        buf
    }

    /// Decodes a general-block-transfer APDU.
    pub fn decode(bytes: &[u8]) -> Result<GeneralBlockTransfer, ServiceError> {
        if bytes.len() < 6 {
            return Err(ServiceError::Truncated);
        }
        if bytes[0] != GENERAL_BLOCK_TRANSFER {
            return Err(ServiceError::UnexpectedTag(bytes[0]));
        }
        let block_control = bytes[1];
        let block_number = u16::from_be_bytes([bytes[2], bytes[3]]);
        let block_number_ack = u16::from_be_bytes([bytes[4], bytes[5]]);
        let (len, header) = read_length(&bytes[6..])?;
        let start = 6 + header;
        let block_data = bytes.get(start..start + len).ok_or(ServiceError::Truncated)?.to_vec();
        Ok(GeneralBlockTransfer {
            last_block: block_control & LAST_BLOCK != 0,
            streaming: block_control & STREAMING != 0,
            window: block_control & WINDOW_MASK,
            block_number,
            block_number_ack,
            block_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_block_transfer_round_trips() {
        let gbt = GeneralBlockTransfer {
            last_block: false,
            streaming: false,
            window: 1,
            block_number: 1,
            block_number_ack: 0,
            block_data: vec![0xC0, 0x01, 0xC1, 0x00, 0x08],
        };
        let bytes = gbt.encode();
        // E0 01 0001 0000 05 C001C10008.
        assert_eq!(bytes, vec![0xE0, 0x01, 0x00, 0x01, 0x00, 0x00, 0x05, 0xC0, 0x01, 0xC1, 0x00, 0x08]);
        assert_eq!(GeneralBlockTransfer::decode(&bytes).unwrap(), gbt);
    }

    #[test]
    fn last_block_and_streaming_flags_round_trip() {
        let gbt = GeneralBlockTransfer {
            last_block: true,
            streaming: true,
            window: 5,
            block_number: 3,
            block_number_ack: 2,
            block_data: vec![0xAA],
        };
        let bytes = gbt.encode();
        assert_eq!(bytes[1], LAST_BLOCK | STREAMING | 5);
        assert_eq!(GeneralBlockTransfer::decode(&bytes).unwrap(), gbt);
    }

    #[test]
    fn decode_rejects_wrong_tag() {
        assert_eq!(
            GeneralBlockTransfer::decode(&[0xC0, 0x00, 0, 0, 0, 0, 0]),
            Err(ServiceError::UnexpectedTag(0xC0))
        );
    }
}
