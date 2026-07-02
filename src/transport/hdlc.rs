//! The HDLC-based data link layer (IEC 62056-46, ISO/IEC 13239 frame format
//! type 3).
//!
//! This module provides a frame codec — [`HdlcFrame`], [`HdlcAddress`],
//! [`Control`] and the [`fcs16`] check sequence — and, on top of a
//! [`PhysicalTransport`], the [`HdlcLayer`] data-link sub-layer. Because it only
//! needs a byte channel, the same implementation works over a serial line and
//! over TCP.
//!
//! A type-3 frame is laid out as:
//!
//! ```text
//! 7E | format(2) | dest addr(1-4) | src addr(1-4) | control(1) | [HCS(2)] | [information] | FCS(2) | 7E
//! ```
//!
//! The frame format field holds the type (0xA), a segmentation bit and an
//! 11-bit frame length (the octet count between the flags). The HCS is present
//! only when the frame carries an information field; the FCS is always present.
//! Both check sequences are the CRC-16/X.25 defined by [`fcs16`].

use std::io;

use super::{DataLinkLayer, PhysicalTransport};

/// HDLC opening/closing flag.
pub const FLAG: u8 = 0x7E;

/// Computes the HDLC frame/header check sequence (CRC-16/X.25): polynomial
/// 0x1021 reflected (0x8408), initial value 0xFFFF, final one's complement.
/// The result is transmitted low octet first.
pub fn fcs16(data: &[u8]) -> u16 {
    let mut fcs: u16 = 0xFFFF;
    for &byte in data {
        fcs ^= byte as u16;
        for _ in 0..8 {
            if fcs & 1 != 0 {
                fcs = (fcs >> 1) ^ 0x8408;
            } else {
                fcs >>= 1;
            }
        }
    }
    !fcs
}

/// Errors that can occur while decoding an HDLC frame.
#[derive(Debug, PartialEq, Eq)]
pub enum HdlcError {
    /// The buffer did not begin and end with the flag octet.
    MissingFlag,
    /// The frame is shorter than the minimum, or shorter than its length field.
    Truncated,
    /// The frame format type nibble was not 0xA (type 3).
    InvalidFormatType,
    /// The declared frame length did not match the actual length.
    LengthMismatch,
    /// An address field did not terminate within four octets.
    AddressTooLong,
    /// The header check sequence did not match.
    BadHcs,
    /// The frame check sequence did not match.
    BadFcs,
    /// The control field did not encode a known frame type.
    UnknownControl(u8),
}

impl std::fmt::Display for HdlcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for HdlcError {}

impl From<HdlcError> for io::Error {
    fn from(e: HdlcError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

/// An HDLC address (client or server), of 1, 2 or 4 octets. Each octet carries
/// seven address bits and one extension bit (set on the final octet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdlcAddress {
    pub value: u32,
    pub length: u8,
}

impl HdlcAddress {
    /// Creates an address with an explicit octet length (1, 2 or 4).
    pub fn new(value: u32, length: u8) -> Self {
        HdlcAddress { value, length }
    }

    /// Creates a single-octet address (typical for a client address).
    pub fn one_byte(value: u8) -> Self {
        HdlcAddress { value: value as u32, length: 1 }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for i in (0..self.length).rev() {
            let group = ((self.value >> (7 * i)) & 0x7F) as u8;
            let last = i == 0;
            out.push((group << 1) | last as u8);
        }
    }

    fn decode(bytes: &[u8], offset: usize) -> Result<(HdlcAddress, usize), HdlcError> {
        let mut value = 0u32;
        let mut consumed = 0usize;
        loop {
            let idx = offset + consumed;
            let byte = *bytes.get(idx).ok_or(HdlcError::Truncated)?;
            value = (value << 7) | ((byte >> 1) as u32);
            consumed += 1;
            if byte & 1 == 1 {
                break;
            }
            if consumed >= 4 {
                return Err(HdlcError::AddressTooLong);
            }
        }
        Ok((HdlcAddress { value, length: consumed as u8 }, consumed))
    }
}

/// The HDLC control field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Set Normal Response Mode (connection establishment).
    Snrm { poll: bool },
    /// Unnumbered Acknowledge.
    Ua { final_bit: bool },
    /// Disconnect.
    Disc { poll: bool },
    /// Disconnected Mode.
    Dm { final_bit: bool },
    /// Frame Reject.
    Frmr { final_bit: bool },
    /// Unnumbered Information.
    Ui { poll: bool },
    /// Information frame with send/receive sequence numbers.
    Information { send_seq: u8, recv_seq: u8, poll: bool },
    /// Receive Ready (supervisory).
    ReceiveReady { recv_seq: u8, poll_final: bool },
    /// Receive Not Ready (supervisory).
    ReceiveNotReady { recv_seq: u8, poll_final: bool },
}

impl Control {
    fn encode(&self) -> u8 {
        let pf = |b: bool| if b { 0x10 } else { 0x00 };
        match *self {
            Control::Snrm { poll } => 0x83 | pf(poll),
            Control::Ua { final_bit } => 0x63 | pf(final_bit),
            Control::Disc { poll } => 0x43 | pf(poll),
            Control::Dm { final_bit } => 0x0F | pf(final_bit),
            Control::Frmr { final_bit } => 0x87 | pf(final_bit),
            Control::Ui { poll } => 0x03 | pf(poll),
            Control::Information { send_seq, recv_seq, poll } => {
                ((recv_seq & 0x07) << 5) | pf(poll) | ((send_seq & 0x07) << 1)
            }
            Control::ReceiveReady { recv_seq, poll_final } => {
                ((recv_seq & 0x07) << 5) | pf(poll_final) | 0x01
            }
            Control::ReceiveNotReady { recv_seq, poll_final } => {
                ((recv_seq & 0x07) << 5) | pf(poll_final) | 0x05
            }
        }
    }

    fn decode(byte: u8) -> Result<Control, HdlcError> {
        let pf = byte & 0x10 != 0;
        let recv_seq = (byte >> 5) & 0x07;
        if byte & 0x01 == 0 {
            // Information frame.
            return Ok(Control::Information {
                send_seq: (byte >> 1) & 0x07,
                recv_seq,
                poll: pf,
            });
        }
        if byte & 0x03 == 0x01 {
            // Supervisory frame.
            return match byte & 0x0F {
                0x01 => Ok(Control::ReceiveReady { recv_seq, poll_final: pf }),
                0x05 => Ok(Control::ReceiveNotReady { recv_seq, poll_final: pf }),
                _ => Err(HdlcError::UnknownControl(byte)),
            };
        }
        // Unnumbered frame: match with the P/F bit masked out.
        match byte & !0x10 {
            0x83 => Ok(Control::Snrm { poll: pf }),
            0x63 => Ok(Control::Ua { final_bit: pf }),
            0x43 => Ok(Control::Disc { poll: pf }),
            0x0F => Ok(Control::Dm { final_bit: pf }),
            0x87 => Ok(Control::Frmr { final_bit: pf }),
            0x03 => Ok(Control::Ui { poll: pf }),
            _ => Err(HdlcError::UnknownControl(byte)),
        }
    }
}

/// A decoded HDLC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdlcFrame {
    pub destination: HdlcAddress,
    pub source: HdlcAddress,
    pub control: Control,
    /// The information field (may be empty for supervisory/unnumbered frames).
    pub information: Vec<u8>,
    /// The segmentation bit of the frame format field.
    pub segmented: bool,
}

impl HdlcFrame {
    /// Builds a frame without the segmentation bit set.
    pub fn new(destination: HdlcAddress, source: HdlcAddress, control: Control, information: Vec<u8>) -> Self {
        HdlcFrame { destination, source, control, information, segmented: false }
    }

    /// Encodes the frame, including the opening/closing flags, HCS and FCS.
    pub fn encode(&self) -> Vec<u8> {
        // Header: format field (filled in below) + addresses + control.
        let mut header = Vec::new();
        self.destination.encode(&mut header);
        self.source.encode(&mut header);
        header.push(self.control.encode());

        let has_info = !self.information.is_empty();
        // Frame length = format(2) + header + [HCS(2) + info] + FCS(2).
        let length = 2 + header.len() + if has_info { 2 + self.information.len() } else { 0 } + 2;

        let mut framed = Vec::with_capacity(length + 2);
        let seg = if self.segmented { 0x08 } else { 0x00 };
        let format_hi = 0xA0 | seg | ((length >> 8) & 0x07) as u8;
        let format_lo = (length & 0xFF) as u8;

        // Everything the FCS is computed over (format .. end of info).
        let mut checked = Vec::with_capacity(length - 2);
        checked.push(format_hi);
        checked.push(format_lo);
        checked.extend_from_slice(&header);
        if has_info {
            let hcs = fcs16(&checked);
            checked.extend_from_slice(&hcs.to_le_bytes());
            checked.extend_from_slice(&self.information);
        }
        let fcs = fcs16(&checked);

        framed.push(FLAG);
        framed.extend_from_slice(&checked);
        framed.extend_from_slice(&fcs.to_le_bytes());
        framed.push(FLAG);
        framed
    }

    /// Decodes a single frame that begins and ends with a flag octet.
    pub fn decode(frame: &[u8]) -> Result<HdlcFrame, HdlcError> {
        if frame.len() < 2 || frame[0] != FLAG || frame[frame.len() - 1] != FLAG {
            return Err(HdlcError::MissingFlag);
        }
        let body = &frame[1..frame.len() - 1];
        if body.len() < 5 {
            return Err(HdlcError::Truncated);
        }
        if body[0] & 0xF0 != 0xA0 {
            return Err(HdlcError::InvalidFormatType);
        }
        let segmented = body[0] & 0x08 != 0;
        let length = (((body[0] & 0x07) as usize) << 8) | body[1] as usize;
        if length != body.len() {
            return Err(HdlcError::LengthMismatch);
        }

        let (destination, dlen) = HdlcAddress::decode(body, 2)?;
        let (source, slen) = HdlcAddress::decode(body, 2 + dlen)?;
        let control_idx = 2 + dlen + slen;
        let control_byte = *body.get(control_idx).ok_or(HdlcError::Truncated)?;
        let control = Control::decode(control_byte)?;

        let header_len = control_idx + 1;
        let remaining = body.len() - header_len;
        // The trailing 2 octets are always the FCS.
        if remaining < 2 {
            return Err(HdlcError::Truncated);
        }
        let fcs_pos = body.len() - 2;
        let expected_fcs = u16::from_le_bytes([body[fcs_pos], body[fcs_pos + 1]]);
        if fcs16(&body[..fcs_pos]) != expected_fcs {
            return Err(HdlcError::BadFcs);
        }

        let information = if remaining == 2 {
            // No information field, hence no HCS.
            Vec::new()
        } else {
            // HCS(2) directly after the header, then the information field.
            let hcs = u16::from_le_bytes([body[header_len], body[header_len + 1]]);
            if fcs16(&body[..header_len]) != hcs {
                return Err(HdlcError::BadHcs);
            }
            body[header_len + 2..fcs_pos].to_vec()
        };

        Ok(HdlcFrame { destination, source, control, information, segmented })
    }
}

/// The DLMS LLC header prepended to the information field of I/UI frames sent by
/// the client (command).
const LLC_COMMAND: [u8; 3] = [0xE6, 0xE6, 0x00];
/// The DLMS LLC header for frames sent by the server (response).
const LLC_RESPONSE: [u8; 3] = [0xE6, 0xE7, 0x00];

/// The HDLC data-link sub-layer over a physical transport.
///
/// Sends APDUs as information frames (prefixed with the DLMS LLC header) and
/// receives them, maintaining the send/receive sequence numbers. Connection
/// management frames (SNRM/UA/DISC) are available through [`HdlcFrame`] directly.
#[derive(Debug)]
pub struct HdlcLayer<T: PhysicalTransport> {
    transport: T,
    /// Address of the peer this layer sends frames to.
    peer: HdlcAddress,
    /// This station's own address (used as the source address).
    own: HdlcAddress,
    is_client: bool,
    send_seq: u8,
    recv_seq: u8,
}

impl<T: PhysicalTransport> HdlcLayer<T> {
    /// Creates a client-side HDLC layer that talks to the server at `server`
    /// address using the given `client` address.
    pub fn new_client(transport: T, client: HdlcAddress, server: HdlcAddress) -> Self {
        HdlcLayer { transport, peer: server, own: client, is_client: true, send_seq: 0, recv_seq: 0 }
    }

    /// Creates a server-side HDLC layer.
    pub fn new_server(transport: T, server: HdlcAddress, client: HdlcAddress) -> Self {
        HdlcLayer { transport, peer: client, own: server, is_client: false, send_seq: 0, recv_seq: 0 }
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the layer and returns the underlying transport.
    pub fn into_inner(self) -> T {
        self.transport
    }

    fn llc(&self) -> [u8; 3] {
        if self.is_client { LLC_COMMAND } else { LLC_RESPONSE }
    }

    /// Reads one complete frame (from an opening flag to a closing flag) from the
    /// transport.
    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        // Skip to the opening flag.
        let mut byte = [0u8; 1];
        loop {
            read_exact(&mut self.transport, &mut byte)?;
            if byte[0] == FLAG {
                break;
            }
        }
        // Read the 2-octet frame format field to learn the length.
        let mut format = [0u8; 2];
        read_exact(&mut self.transport, &mut format)?;
        if format[0] & 0xF0 != 0xA0 {
            return Err(HdlcError::InvalidFormatType.into());
        }
        let length = (((format[0] & 0x07) as usize) << 8) | format[1] as usize;
        if length < 4 {
            return Err(HdlcError::Truncated.into());
        }
        // `length` counts the format field too; read the rest plus the closing flag.
        let mut rest = vec![0u8; length - 2 + 1];
        read_exact(&mut self.transport, &mut rest)?;
        let mut frame = Vec::with_capacity(length + 2);
        frame.push(FLAG);
        frame.extend_from_slice(&format);
        frame.extend_from_slice(&rest);
        Ok(frame)
    }
}

impl<T: PhysicalTransport> DataLinkLayer for HdlcLayer<T> {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        let mut information = Vec::with_capacity(3 + apdu.len());
        information.extend_from_slice(&self.llc());
        information.extend_from_slice(apdu);
        let control = Control::Information {
            send_seq: self.send_seq,
            recv_seq: self.recv_seq,
            poll: true,
        };
        let frame = HdlcFrame::new(self.peer, self.own, control, information);
        self.transport.send(&frame.encode())?;
        self.send_seq = (self.send_seq + 1) & 0x07;
        Ok(())
    }

    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        let raw = self.read_frame()?;
        let frame = HdlcFrame::decode(&raw)?;
        if let Control::Information { send_seq, .. } = frame.control {
            // Acknowledge the received frame in the next transmission.
            self.recv_seq = (send_seq + 1) & 0x07;
        }
        // Strip the 3-octet LLC header if present.
        let info = &frame.information;
        let apdu = if info.len() >= 3 && info[0] == 0xE6 && (info[1] == 0xE6 || info[1] == 0xE7) {
            info[3..].to_vec()
        } else {
            info.clone()
        };
        Ok(apdu)
    }
}

/// Reads exactly `buf.len()` bytes from `transport`, looping over short reads.
fn read_exact<T: PhysicalTransport>(transport: &mut T, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = transport.receive(&mut buf[filled..])?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "transport closed"));
        }
        filled += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::MemoryTransport;

    #[test]
    fn fcs_residue_is_the_good_fcs_constant() {
        // Recomputing the (complemented) FCS over `data || FCS_le` yields the
        // constant residue 0x0F47 — the one's complement of the classic 0xF0B8
        // "good FCS" magic value (this implementation complements the result).
        let data = [0xA0u8, 0x07, 0x03, 0x21, 0x93];
        let fcs = fcs16(&data);
        let mut with_fcs = data.to_vec();
        with_fcs.extend_from_slice(&fcs.to_le_bytes());
        assert_eq!(fcs16(&with_fcs), 0x0F47);
    }

    #[test]
    fn address_round_trips_for_1_2_4_octets() {
        for (value, length) in [(0x10u32, 1u8), (0x3FFD, 2), (0x0102_0304 & 0x0FFF_FFFF, 4)] {
            let addr = HdlcAddress::new(value, length);
            let mut buf = Vec::new();
            addr.encode(&mut buf);
            assert_eq!(buf.len(), length as usize);
            let (decoded, consumed) = HdlcAddress::decode(&buf, 0).unwrap();
            assert_eq!(consumed, length as usize);
            assert_eq!(decoded, addr);
        }
    }

    #[test]
    fn control_round_trips() {
        let controls = [
            Control::Snrm { poll: true },
            Control::Ua { final_bit: true },
            Control::Disc { poll: true },
            Control::Ui { poll: false },
            Control::Information { send_seq: 3, recv_seq: 5, poll: true },
            Control::ReceiveReady { recv_seq: 2, poll_final: false },
            Control::ReceiveNotReady { recv_seq: 7, poll_final: true },
        ];
        for c in controls {
            assert_eq!(Control::decode(c.encode()).unwrap(), c);
        }
    }

    #[test]
    fn snrm_frame_round_trips() {
        let frame = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Snrm { poll: true },
            Vec::new(),
        );
        let encoded = frame.encode();
        assert_eq!(encoded[0], FLAG);
        assert_eq!(*encoded.last().unwrap(), FLAG);
        let decoded = HdlcFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn information_frame_round_trips_with_hcs() {
        let frame = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xE6, 0xE6, 0x00, 0x60, 0x1D, 0xA1],
        );
        let encoded = frame.encode();
        let decoded = HdlcFrame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_detects_fcs_corruption() {
        let frame = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Ua { final_bit: true },
            Vec::new(),
        );
        let mut encoded = frame.encode();
        let len = encoded.len();
        encoded[len - 2] ^= 0xFF; // corrupt the FCS
        assert_eq!(HdlcFrame::decode(&encoded), Err(HdlcError::BadFcs));
    }

    #[test]
    fn layer_round_trips_apdu_over_transport() {
        let mut client = HdlcLayer::new_client(
            MemoryTransport::new(),
            HdlcAddress::one_byte(0x10),
            HdlcAddress::one_byte(0x03),
        );
        let apdu = vec![0x60, 0x1D, 0xA1, 0x09];
        client.send_apdu(&apdu).unwrap();
        // The loopback transport now holds the encoded frame; read it back.
        let received = client.receive_apdu().unwrap();
        assert_eq!(received, apdu);
    }
}
