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
//!
//! [`send`] and [`receive`] drive this codec over any
//! [`crate::transport::DataLinkLayer`], transparently segmenting an oversized
//! xDLMS APDU into blocks (and reassembling them on the other end) — an
//! alternative to the service-specific WITH-DATABLOCK block transfer that
//! also covers APDU types WITH-DATABLOCK does not, such as DataNotification
//! and EventNotificationRequest.

use super::{push_length, read_length, tag, ServiceError};
use crate::transport::DataLinkLayer;
use std::io;

/// General-block-transfer APDU tag (`[224]`).
pub const GENERAL_BLOCK_TRANSFER: u8 = 0xE0;

const LAST_BLOCK: u8 = 0x80;
const STREAMING: u8 = 0x40;
const WINDOW_MASK: u8 = 0x3F;

/// Octets reserved for the GBT header (tag, control, block numbers, and a
/// worst-case long-form length) when budgeting a block's payload size from
/// an overall frame-size limit.
pub const HEADER_MAX: usize = 8;

/// Default overall block size (including the header) used when a session
/// enables GBT without specifying one explicitly.
pub const DEFAULT_BLOCK_SIZE: usize = 64;

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

/// Returns whether general block transfer applies to this APDU's service
/// (IEC 62056-5-3 §9.3, Table): GET/SET/ACTION requests and responses, plus
/// DataNotification and EventNotificationRequest.
pub fn applies_to_apdu(apdu: &[u8]) -> bool {
    matches!(
        apdu.first(),
        Some(&tag::GET_REQUEST)
            | Some(&tag::GET_RESPONSE)
            | Some(&tag::SET_REQUEST)
            | Some(&tag::SET_RESPONSE)
            | Some(&tag::ACTION_REQUEST)
            | Some(&tag::ACTION_RESPONSE)
            | Some(&tag::DATA_NOTIFICATION)
            | Some(&tag::EVENT_NOTIFICATION_REQUEST)
    )
}

/// Reads one frame from `link` and decodes it as a general-block-transfer
/// APDU.
fn read_block<L: DataLinkLayer>(link: &mut L) -> io::Result<GeneralBlockTransfer> {
    let raw = link.receive_apdu()?;
    Ok(GeneralBlockTransfer::decode(&raw)?)
}

/// Sends an ack-only general-block-transfer frame (no payload): confirms
/// receipt up to `block_number_ack` and grants `window` further blocks.
fn send_ack<L: DataLinkLayer>(link: &mut L, window: u8, block_number_ack: u16) -> io::Result<()> {
    let ack = GeneralBlockTransfer {
        last_block: true,
        streaming: false,
        window: window & WINDOW_MASK,
        block_number: 1,
        block_number_ack,
        block_data: Vec::new(),
    };
    link.send_apdu(&ack.encode())
}

/// Segments `apdu` into general-block-transfer blocks of at most
/// `block_payload_max` octets each and sends them over `link`. In confirmed
/// mode (`window > 0`), waits for an ack-only GBT frame after each window of
/// blocks and retransmits from the first block the peer has not acknowledged
/// if it reports a gap; with `window == 0` (unconfirmed) or `streaming`, no
/// ack is awaited until the caller separately reads a reply.
///
/// `block_payload_max` must be at least 1; a request that already fits
/// within it is still sent as a single-block GBT APDU.
pub fn send<L: DataLinkLayer>(
    link: &mut L,
    apdu: &[u8],
    block_payload_max: usize,
    window: u8,
    streaming: bool,
) -> io::Result<()> {
    let block_payload_max = block_payload_max.max(1);
    let win = window & WINDOW_MASK;
    let mut offset = 0usize;
    let mut block_number: u16 = 1;
    let mut blocks_in_window: u8 = 0;

    while offset < apdu.len() {
        let chunk = (apdu.len() - offset).min(block_payload_max);
        let last = offset + chunk >= apdu.len();

        let block = GeneralBlockTransfer {
            last_block: last,
            streaming,
            window: win,
            block_number,
            block_number_ack: 0,
            block_data: apdu[offset..offset + chunk].to_vec(),
        };
        link.send_apdu(&block.encode())?;

        offset += chunk;
        block_number = block_number.wrapping_add(1);
        blocks_in_window += 1;

        // Confirmed mode: wait for an ack after each window (not after the
        // last block, whose reply is the caller's concern).
        if win > 0 && !last && blocks_in_window >= win {
            let ack = read_block(link)?;
            if !ack.block_data.is_empty() || !ack.last_block || ack.streaming {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "expected an ack-only GBT frame"));
            }
            // The peer reports a gap: retransmit from the first unconfirmed block.
            if ack.block_number_ack.wrapping_add(1) < block_number {
                block_number = ack.block_number_ack.wrapping_add(1);
                offset = (block_number as usize - 1) * block_payload_max;
                if offset >= apdu.len() {
                    offset = 0;
                    block_number = 1;
                }
            }
            blocks_in_window = 0;
        }
    }
    Ok(())
}

/// Reassembles a general-block-transfer sequence starting from `first`, the
/// already-received first frame (typically the result of the caller's own
/// `link.receive_apdu()` used to detect the [`GENERAL_BLOCK_TRANSFER`] tag),
/// reading further blocks from `link` as needed. Handles out-of-order and
/// duplicate blocks by requesting retransmission / acking-and-discarding.
///
/// In confirmed mode (peer window > 0), acks are sent at the same cadence
/// the sender waits on — every `window` accepted blocks — so the two sides
/// stay in lockstep; acking every block regardless of window size would
/// desynchronize a sender that only checks for an ack once per window and
/// trigger spurious retransmits.
///
/// Returns the reassembled plain (or still-ciphered, if the segmented APDU
/// was ciphered) APDU bytes.
pub fn receive<L: DataLinkLayer>(link: &mut L, first: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut block = GeneralBlockTransfer::decode(&first)?;
    let mut acc = Vec::new();
    let mut expected_block: u16 = 1;
    let mut peer_window: u8 = 0;
    let mut blocks_since_ack: u8 = 0;

    loop {
        if block.block_number > expected_block {
            // Gap: request retransmission from `expected_block`.
            let gap = block.block_number - expected_block;
            // The else branch only runs when gap <= WINDOW_MASK, so it always fits u8.
            #[allow(clippy::cast_possible_truncation)]
            let win = if gap > u16::from(WINDOW_MASK) { WINDOW_MASK } else { gap.max(1) as u8 };
            send_ack(link, win, expected_block.saturating_sub(1))?;
            block = read_block(link)?;
            continue;
        }
        if block.block_number < expected_block {
            // Duplicate or late block: ack (if a window is in use) and ignore.
            let win = if block.window > 0 { block.window } else { peer_window };
            if win > 0 {
                send_ack(link, win, block.block_number)?;
            }
            block = read_block(link)?;
            continue;
        }
        if block.window > 0 {
            peer_window = block.window;
        }
        acc.extend_from_slice(&block.block_data);
        if block.last_block {
            return Ok(acc);
        }
        blocks_since_ack += 1;
        if peer_window > 0 && blocks_since_ack >= peer_window {
            send_ack(link, peer_window, expected_block)?;
            blocks_since_ack = 0;
        }
        expected_block = expected_block.wrapping_add(1);
        block = read_block(link)?;
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
        assert_eq!(GeneralBlockTransfer::decode(&[0xC0, 0x00, 0, 0, 0, 0, 0]), Err(ServiceError::UnexpectedTag(0xC0)));
    }

    #[test]
    fn applies_to_apdu_covers_the_documented_tags() {
        for t in [
            tag::GET_REQUEST,
            tag::GET_RESPONSE,
            tag::SET_REQUEST,
            tag::SET_RESPONSE,
            tag::ACTION_REQUEST,
            tag::ACTION_RESPONSE,
            tag::DATA_NOTIFICATION,
            tag::EVENT_NOTIFICATION_REQUEST,
        ] {
            assert!(applies_to_apdu(&[t, 0x00]), "tag 0x{t:02X} should apply");
        }
        assert!(!applies_to_apdu(&[GENERAL_BLOCK_TRANSFER, 0x00]));
        assert!(!applies_to_apdu(&[]));
    }

    // ------------------------------------------------------------------
    // Transport-level send/receive, driven over a scripted DataLinkLayer.
    // ------------------------------------------------------------------

    use crate::transport::DataLinkLayer;
    use std::collections::VecDeque;
    use std::io;

    /// A [`DataLinkLayer`] mock: `receive_apdu` returns pre-programmed frames
    /// in order, `send_apdu` records what was sent.
    #[derive(Default)]
    struct ScriptedLink {
        rx: VecDeque<Vec<u8>>,
        tx: Vec<Vec<u8>>,
    }

    impl DataLinkLayer for ScriptedLink {
        fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
            self.tx.push(apdu.to_vec());
            Ok(())
        }
        fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
            self.rx.pop_front().ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "script exhausted"))
        }
    }

    #[test]
    fn send_unconfirmed_segments_without_waiting_for_acks() {
        let apdu = vec![0xC0, 0x01, 0xC1, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut link = ScriptedLink::default();
        // window = 0: no acks are read (an empty rx queue would panic if `send` tried to).
        send(&mut link, &apdu, 4, 0, false).unwrap();

        assert_eq!(link.tx.len(), 3); // 9 octets / 4-octet blocks = 3 blocks.
        let b1 = GeneralBlockTransfer::decode(&link.tx[0]).unwrap();
        assert_eq!(
            b1,
            GeneralBlockTransfer {
                last_block: false,
                streaming: false,
                window: 0,
                block_number: 1,
                block_number_ack: 0,
                block_data: apdu[0..4].to_vec(),
            }
        );
        let b3 = GeneralBlockTransfer::decode(&link.tx[2]).unwrap();
        assert!(b3.last_block);
        assert_eq!(b3.block_data, apdu[8..9].to_vec());

        // Reassembling the sent blocks recovers the original APDU.
        let mut reassembled = Vec::new();
        for raw in &link.tx {
            reassembled.extend(GeneralBlockTransfer::decode(raw).unwrap().block_data);
        }
        assert_eq!(reassembled, apdu);
    }

    #[test]
    fn send_confirmed_waits_for_ack_each_window() {
        let apdu = vec![0xC0, 0x01, 0xC1, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]; // 3 blocks of 3.
        let mut link = ScriptedLink::default();
        // window = 1: an ack is expected after block 1 and after block 2.
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 1,
                block_data: Vec::new(),
            })
            .encode(),
        );
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 2,
                block_data: Vec::new(),
            })
            .encode(),
        );

        send(&mut link, &apdu, 3, 1, false).unwrap();
        assert_eq!(link.tx.len(), 3);
        assert!(link.rx.is_empty(), "both scripted acks must be consumed");
    }

    #[test]
    fn send_retransmits_from_the_gap_reported_by_the_peer() {
        let apdu = vec![0xC0, 0x01, 0xC1, 0x00, 0x01, 0x02]; // 3 blocks of 2.
        let mut link = ScriptedLink::default();
        // After block 1, the peer reports it never got anything (ack=0):
        // retransmission must restart from block 1.
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 0,
                block_data: Vec::new(),
            })
            .encode(),
        );
        // The retransmitted block 1 is acked properly this time.
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 1,
                block_data: Vec::new(),
            })
            .encode(),
        );
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 2,
                block_data: Vec::new(),
            })
            .encode(),
        );

        send(&mut link, &apdu, 2, 1, false).unwrap();
        // block 1 sent, retransmitted, block 2, block 3 = 4 sends.
        assert_eq!(link.tx.len(), 4);
        let numbers: Vec<u16> =
            link.tx.iter().map(|raw| GeneralBlockTransfer::decode(raw).unwrap().block_number).collect();
        assert_eq!(numbers, vec![1, 1, 2, 3]);
    }

    #[test]
    fn send_rejects_a_reply_that_is_not_an_ack() {
        let apdu = vec![0; 5];
        let mut link = ScriptedLink::default();
        // A frame carrying payload is not a valid ack.
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 1,
                block_data: vec![0xAA],
            })
            .encode(),
        );
        let err = send(&mut link, &apdu, 2, 1, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn receive_reassembles_a_single_block() {
        let first = (GeneralBlockTransfer {
            last_block: true,
            streaming: false,
            window: 0,
            block_number: 1,
            block_number_ack: 0,
            block_data: vec![0xC0, 0x01],
        })
        .encode();
        let mut link = ScriptedLink::default();
        let apdu = receive(&mut link, first).unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01]);
        assert!(link.tx.is_empty(), "no window in use: no ack should be sent");
    }

    #[test]
    fn receive_reassembles_multiple_blocks_and_acks_confirmed_ones() {
        let first = (GeneralBlockTransfer {
            last_block: false,
            streaming: false,
            window: 1,
            block_number: 1,
            block_number_ack: 0,
            block_data: vec![0xC0, 0x01],
        })
        .encode();
        let mut link = ScriptedLink::default();
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 2,
                block_number_ack: 0,
                block_data: vec![0xC1, 0x00],
            })
            .encode(),
        );

        let apdu = receive(&mut link, first).unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01, 0xC1, 0x00]);
        // One ack sent, acknowledging block 1.
        assert_eq!(link.tx.len(), 1);
        let ack = GeneralBlockTransfer::decode(&link.tx[0]).unwrap();
        assert_eq!(ack.block_number_ack, 1);
        assert!(ack.block_data.is_empty());
    }

    #[test]
    fn receive_requests_retransmission_on_a_gap_and_ignores_duplicates() {
        // First frame received is block 2, but block 1 is expected: receive()
        // must ask for a retransmit before it can make progress.
        let first = (GeneralBlockTransfer {
            last_block: true,
            streaming: false,
            window: 1,
            block_number: 2,
            block_number_ack: 0,
            block_data: vec![0xC1, 0x00],
        })
        .encode();
        let mut link = ScriptedLink::default();
        // A duplicate of block 2 arrives before the real block 1 (should be
        // acked and ignored), then block 1 arrives.
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 2,
                block_number_ack: 0,
                block_data: vec![0xC1, 0x00],
            })
            .encode(),
        );
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: false,
                streaming: false,
                window: 1,
                block_number: 1,
                block_number_ack: 0,
                block_data: vec![0xC0, 0x01],
            })
            .encode(),
        );
        // Block 2 again, now expected — completes the transfer.
        link.rx.push_back(
            (GeneralBlockTransfer {
                last_block: true,
                streaming: false,
                window: 1,
                block_number: 2,
                block_number_ack: 0,
                block_data: vec![0xC1, 0x00],
            })
            .encode(),
        );

        let apdu = receive(&mut link, first).unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01, 0xC1, 0x00]);
        assert!(link.rx.is_empty());
    }
}
