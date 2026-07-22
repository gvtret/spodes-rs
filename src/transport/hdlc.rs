//! The HDLC-based data link layer (IEC 62056-46, ISO/IEC 13239 frame format
//! type 3).
//!
//! This module provides a frame codec — [`HdlcFrame`], [`HdlcAddress`],
//! [`Control`] and the [`fcs16`] check sequence — and, on top of a
//! [`crate::transport::PhysicalTransport`], the [`crate::transport::hdlc::HdlcLayer`] data-link sub-layer. Because it only
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
use std::time::Duration;

#[cfg(feature = "tracing")]
use tracing::trace;

use super::{DataLinkLayer, PhysicalTransport};

/// HDLC opening/closing flag.
pub const FLAG: u8 = 0x7E;

/// Computes the HDLC frame/header check sequence (CRC-16/X.25): polynomial
/// 0x1021 reflected (0x8408), initial value 0xFFFF, final one's complement.
/// The result is transmitted low octet first.
pub fn fcs16(data: &[u8]) -> u16 {
    let mut fcs: u16 = 0xFFFF;
    for &byte in data {
        fcs ^= u16::from(byte);
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
        write!(f, "{self:?}")
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
    /// The address value (up to 28 significant bits, seven per octet).
    pub value: u32,
    /// The address length in octets (1, 2 or 4).
    pub length: u8,
}

impl HdlcAddress {
    /// Creates an address with an explicit octet length (1, 2 or 4).
    pub fn new(value: u32, length: u8) -> Self {
        HdlcAddress { value, length }
    }

    /// Creates a single-octet address (typical for a client address).
    pub fn one_byte(value: u8) -> Self {
        HdlcAddress { value: u32::from(value), length: 1 }
    }

    fn encode(self, out: &mut Vec<u8>) {
        for i in (0..self.length).rev() {
            let group = ((self.value >> (7 * i)) & 0x7F) as u8;
            let last = i == 0;
            out.push((group << 1) | u8::from(last));
        }
    }

    fn decode(bytes: &[u8], offset: usize) -> Result<(HdlcAddress, usize), HdlcError> {
        let mut value = 0u32;
        let mut consumed = 0usize;
        loop {
            let idx = offset + consumed;
            let byte = *bytes.get(idx).ok_or(HdlcError::Truncated)?;
            value = (value << 7) | u32::from(byte >> 1);
            consumed += 1;
            if byte & 1 == 1 {
                break;
            }
            if consumed >= 4 {
                return Err(HdlcError::AddressTooLong);
            }
        }
        // consumed is 1..=4: the loop above returns AddressTooLong before it can grow further.
        #[allow(clippy::cast_possible_truncation)]
        let length = consumed as u8;
        Ok((HdlcAddress { value, length }, consumed))
    }
}

/// The HDLC control field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Set Normal Response Mode (connection establishment).
    Snrm {
        /// The poll bit.
        poll: bool,
    },
    /// Unnumbered Acknowledge.
    Ua {
        /// The final bit.
        final_bit: bool,
    },
    /// Disconnect.
    Disc {
        /// The poll bit.
        poll: bool,
    },
    /// Disconnected Mode.
    Dm {
        /// The final bit.
        final_bit: bool,
    },
    /// Frame Reject.
    Frmr {
        /// The final bit.
        final_bit: bool,
    },
    /// Unnumbered Information.
    Ui {
        /// The poll bit.
        poll: bool,
    },
    /// Information frame with send/receive sequence numbers.
    Information {
        /// The send sequence number N(S).
        send_seq: u8,
        /// The receive sequence number N(R).
        recv_seq: u8,
        /// The poll bit.
        poll: bool,
    },
    /// Receive Ready (supervisory).
    ReceiveReady {
        /// The receive sequence number N(R).
        recv_seq: u8,
        /// The poll/final bit.
        poll_final: bool,
    },
    /// Receive Not Ready (supervisory).
    ReceiveNotReady {
        /// The receive sequence number N(R).
        recv_seq: u8,
        /// The poll/final bit.
        poll_final: bool,
    },
}

impl Control {
    fn encode(self) -> u8 {
        let pf = |b: bool| if b { 0x10 } else { 0x00 };
        match self {
            Control::Snrm { poll } => 0x83 | pf(poll),
            Control::Ua { final_bit } => 0x63 | pf(final_bit),
            Control::Disc { poll } => 0x43 | pf(poll),
            Control::Dm { final_bit } => 0x0F | pf(final_bit),
            Control::Frmr { final_bit } => 0x87 | pf(final_bit),
            Control::Ui { poll } => 0x03 | pf(poll),
            Control::Information { send_seq, recv_seq, poll } => {
                ((recv_seq & 0x07) << 5) | pf(poll) | ((send_seq & 0x07) << 1)
            }
            Control::ReceiveReady { recv_seq, poll_final } => ((recv_seq & 0x07) << 5) | pf(poll_final) | 0x01,
            Control::ReceiveNotReady { recv_seq, poll_final } => ((recv_seq & 0x07) << 5) | pf(poll_final) | 0x05,
        }
    }

    fn decode(byte: u8) -> Result<Control, HdlcError> {
        let pf = byte & 0x10 != 0;
        let recv_seq = (byte >> 5) & 0x07;
        if byte & 0x01 == 0 {
            // Information frame.
            return Ok(Control::Information { send_seq: (byte >> 1) & 0x07, recv_seq, poll: pf });
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

/// XID parameters negotiated during the SNRM/UA exchange (IEC 62056-46
/// §6.4.4.4.3.2): the maximum information field length and window size each
/// station uses in each direction.
///
/// Encoded on the wire as the SNRM/UA information field:
/// `81 80 <group-len> 05 02 <max_info_tx:u16> 06 02 <max_info_rx:u16>
/// 07 04 <window_tx:u32> 08 04 <window_rx:u32>` (big-endian values; the
/// window fields are 4 octets on the wire though only small values, 1..7,
/// are meaningful).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XidParams {
    /// Maximum information field length this station will transmit.
    pub max_info_tx: u16,
    /// Maximum information field length this station will receive.
    pub max_info_rx: u16,
    /// Window size (1..7) this station uses when transmitting.
    pub window_tx: u8,
    /// Window size (1..7) this station uses when receiving.
    pub window_rx: u8,
}

impl XidParams {
    /// The client's default ceiling: 1280-octet info fields, window 1.
    pub fn client_default() -> Self {
        XidParams { max_info_tx: 1280, max_info_rx: 1280, window_tx: 1, window_rx: 1 }
    }

    /// The server's default ceiling: 512-octet info fields, window 1.
    pub fn server_default() -> Self {
        XidParams { max_info_tx: 512, max_info_rx: 512, window_tx: 1, window_rx: 1 }
    }

    fn encode(self) -> Vec<u8> {
        let mut params = Vec::new();
        params.push(0x05);
        params.push(0x02);
        params.extend_from_slice(&self.max_info_tx.to_be_bytes());
        params.push(0x06);
        params.push(0x02);
        params.extend_from_slice(&self.max_info_rx.to_be_bytes());
        params.push(0x07);
        params.push(0x04);
        params.extend_from_slice(&u32::from(self.window_tx).to_be_bytes());
        params.push(0x08);
        params.push(0x04);
        params.extend_from_slice(&u32::from(self.window_rx).to_be_bytes());

        // Fixed-shape encoding (4 TLV fields of known width): always 20 bytes.
        #[allow(clippy::cast_possible_truncation)]
        let mut out = vec![0x81, 0x80, params.len() as u8];
        out.extend_from_slice(&params);
        out
    }

    /// Decodes XID parameters from an SNRM/UA information field. Fields not
    /// present (or a field whose value is 0, meaning "no opinion") are left
    /// at 0 so [`Self::negotiate`] treats them as absent.
    fn decode(data: &[u8]) -> XidParams {
        let mut p = XidParams { max_info_tx: 0, max_info_rx: 0, window_tx: 0, window_rx: 0 };
        // Skip the format ID (0x81), group ID (0x80) and group-length octets.
        let mut idx = if data.len() >= 3 && data[0] == 0x81 && data[1] == 0x80 { 3 } else { 0 };
        while idx + 2 <= data.len() {
            let param_id = data[idx];
            let param_len = data[idx + 1] as usize;
            idx += 2;
            let Some(value) = data.get(idx..idx + param_len) else { break };
            match (param_id, value.len()) {
                (0x05, 2) => p.max_info_tx = u16::from_be_bytes([value[0], value[1]]),
                (0x06, 2) => p.max_info_rx = u16::from_be_bytes([value[0], value[1]]),
                // Window sizes are conventionally 1..=7; a peer proposing an
                // out-of-range value is clamped to u8::MAX rather than wrapped,
                // so a bogus large value can't silently alias a small one.
                (0x07, 4) => {
                    p.window_tx =
                        u8::try_from(u32::from_be_bytes([value[0], value[1], value[2], value[3]])).unwrap_or(u8::MAX);
                }
                (0x08, 4) => {
                    p.window_rx =
                        u8::try_from(u32::from_be_bytes([value[0], value[1], value[2], value[3]])).unwrap_or(u8::MAX);
                }
                _ => {}
            }
            idx += param_len;
        }
        p
    }

    /// Tightens `self` (this station's ceiling) against `peer`'s proposal: a
    /// direction is only ever narrowed, and a zero value from the peer (no
    /// opinion / absent) leaves that field unchanged.
    fn negotiate(&mut self, peer: XidParams) {
        if peer.max_info_tx > 0 && peer.max_info_tx < self.max_info_rx {
            self.max_info_rx = peer.max_info_tx;
        }
        if peer.max_info_rx > 0 && peer.max_info_rx < self.max_info_tx {
            self.max_info_tx = peer.max_info_rx;
        }
        if peer.window_tx > 0 && peer.window_tx < self.window_rx {
            self.window_rx = peer.window_tx;
        }
        if peer.window_rx > 0 && peer.window_rx < self.window_tx {
            self.window_tx = peer.window_rx;
        }
    }
}

/// A decoded HDLC frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HdlcFrame {
    /// The destination address.
    pub destination: HdlcAddress,
    /// The source address.
    pub source: HdlcAddress,
    /// The control field.
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
        // Both operands are masked to 3 and 8 bits respectively, so each always fits u8.
        #[allow(clippy::cast_possible_truncation)]
        let format_hi = 0xA0 | seg | ((length >> 8) & 0x07) as u8;
        #[allow(clippy::cast_possible_truncation)]
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

    /// Destination/source addresses when the control field is unknown but the
    /// rest of the header (and FCS) is intact — used to reply with FRMR.
    fn peek_addresses(frame: &[u8]) -> Result<(HdlcAddress, HdlcAddress), HdlcError> {
        if frame.len() < 2 || frame[0] != FLAG || frame[frame.len() - 1] != FLAG {
            return Err(HdlcError::MissingFlag);
        }
        let body = &frame[1..frame.len() - 1];
        if body.len() < 5 || body[0] & 0xF0 != 0xA0 {
            return Err(HdlcError::InvalidFormatType);
        }
        let length = (((body[0] & 0x07) as usize) << 8) | body[1] as usize;
        if length != body.len() {
            return Err(HdlcError::LengthMismatch);
        }
        let fcs_pos = body.len() - 2;
        let expected_fcs = u16::from_le_bytes([body[fcs_pos], body[fcs_pos + 1]]);
        if fcs16(&body[..fcs_pos]) != expected_fcs {
            return Err(HdlcError::BadFcs);
        }
        let (destination, dlen) = HdlcAddress::decode(body, 2)?;
        let (source, _) = HdlcAddress::decode(body, 2 + dlen)?;
        Ok((destination, source))
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
    /// Whether the data link is in NRM (connected) as opposed to NDM.
    connected: bool,
    /// Maximum gap between two octets of the *same* frame (IEC 62056-46
    /// "межсимвольный" timeout) before the read is aborted.
    inter_octet_timeout: Duration,
    /// Maximum time to wait for a *new* frame to start (IEC 62056-46
    /// "межкадровый" / inactivity timeout); `None` waits indefinitely.
    inactivity_timeout: Option<Duration>,
    /// This station's configured XID ceiling, restored at the start of every
    /// SNRM/UA negotiation.
    xid_configured: XidParams,
    /// The XID parameters actually negotiated with the peer (tightened from
    /// `xid_configured` by the last SNRM/UA exchange).
    xid: XidParams,
}

/// How many consecutive undecodable (bad FCS/HCS, malformed) frames are
/// silently dropped before receive gives up (IEC 62056-46 §6.4.4.3: frames
/// with an invalid check sequence are discarded without a response).
const MAX_BAD_FRAMES: usize = 8;

/// IEC 62056-46 / Blue Book inter-octet timeout limits, in milliseconds.
const INTER_OCTET_MIN_MS: u16 = 20;
const INTER_OCTET_MAX_MS: u16 = 6000;
const INTER_OCTET_DEFAULT_MS: u16 = 25;

/// IEC 62056-46 / Blue Book inactivity timeout limit, in seconds (0 disables it).
const INACTIVITY_MAX_S: u16 = 120;

impl<T: PhysicalTransport> HdlcLayer<T> {
    /// Creates a client-side HDLC layer that talks to the server at `server`
    /// address using the given `client` address.
    pub fn new_client(transport: T, client: HdlcAddress, server: HdlcAddress) -> Self {
        HdlcLayer {
            transport,
            peer: server,
            own: client,
            is_client: true,
            send_seq: 0,
            recv_seq: 0,
            connected: false,
            inter_octet_timeout: Duration::from_millis(u64::from(INTER_OCTET_DEFAULT_MS)),
            inactivity_timeout: None,
            xid_configured: XidParams::client_default(),
            xid: XidParams::client_default(),
        }
    }

    /// Creates a server-side HDLC layer.
    pub fn new_server(transport: T, server: HdlcAddress, client: HdlcAddress) -> Self {
        HdlcLayer {
            transport,
            peer: client,
            own: server,
            is_client: false,
            send_seq: 0,
            recv_seq: 0,
            connected: false,
            inter_octet_timeout: Duration::from_millis(u64::from(INTER_OCTET_DEFAULT_MS)),
            inactivity_timeout: None,
            xid_configured: XidParams::server_default(),
            xid: XidParams::server_default(),
        }
    }

    /// Sets the inter-octet timeout (IEC 62056-46 "межсимвольный"): the
    /// maximum gap allowed between two octets of the same frame before the
    /// read is aborted with a [`std::io::ErrorKind::TimedOut`] error.
    /// Clamped to 20..=6000 ms per the standard; defaults to 25 ms.
    ///
    /// Has an effect only if the underlying [`PhysicalTransport`] honours
    /// [`PhysicalTransport::set_read_timeout`].
    pub fn set_inter_octet_timeout_ms(&mut self, ms: u16) {
        self.inter_octet_timeout = Duration::from_millis(u64::from(ms.clamp(INTER_OCTET_MIN_MS, INTER_OCTET_MAX_MS)));
    }

    /// Sets the inactivity timeout (IEC 62056-46 "межкадровый"): the maximum
    /// time to wait for a *new* frame to start before
    /// [`Self::receive_apdu`]-driven reads abort with a
    /// [`std::io::ErrorKind::TimedOut`] error and the link is considered
    /// dropped (see [`Self::is_connected`]). Clamped to 0..=120 s; `0`
    /// disables it (wait indefinitely), which is also the default.
    ///
    /// Has an effect only if the underlying [`PhysicalTransport`] honours
    /// [`PhysicalTransport::set_read_timeout`].
    pub fn set_inactivity_timeout_s(&mut self, seconds: u16) {
        let seconds = seconds.min(INACTIVITY_MAX_S);
        self.inactivity_timeout = if seconds == 0 { None } else { Some(Duration::from_secs(u64::from(seconds))) };
    }

    /// Sets this station's XID ceiling — the ceiling is what SNRM proposes
    /// and what UA's negotiated values are tightened from — and immediately
    /// resets the negotiated [`Self::xid`] to it. Call before [`Self::connect`]
    /// (client) or before the next SNRM is received (server).
    pub fn set_xid_ceiling(&mut self, xid: XidParams) {
        self.xid_configured = xid;
        self.xid = xid;
    }

    /// Returns the XID parameters actually negotiated with the peer (the
    /// ceiling, tightened by the peer's counter-proposal in the last SNRM/UA
    /// exchange). Before the first successful exchange this equals the
    /// configured ceiling.
    pub fn xid(&self) -> XidParams {
        self.xid
    }

    /// Client: establishes the data link (NDM → NRM) with an SNRM/UA
    /// exchange, negotiating XID parameters (IEC 62056-46 §6.4.4.4.3.2 —
    /// see [`Self::set_xid_ceiling`] / [`Self::xid`]) and resetting both
    /// sequence numbers (§6.4.4.2).
    pub fn connect(&mut self) -> io::Result<()> {
        self.xid = self.xid_configured;
        let frame = HdlcFrame::new(self.peer, self.own, Control::Snrm { poll: true }, self.xid_configured.encode());
        self.transport.send(&frame.encode())?;
        let reply = self.read_decoded_frame()?;
        match reply.control {
            Control::Ua { .. } => {
                if !reply.information.is_empty() {
                    self.xid.negotiate(XidParams::decode(&reply.information));
                }
                self.send_seq = 0;
                self.recv_seq = 0;
                self.connected = true;
                Ok(())
            }
            Control::Dm { .. } => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "server answered DM to SNRM")),
            other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected reply to SNRM: {other:?}"))),
        }
    }

    /// Client: releases the data link (NRM → NDM) with a DISC/UA exchange.
    /// A DM answer also completes the release (the peer was already
    /// disconnected).
    pub fn disconnect(&mut self) -> io::Result<()> {
        let frame = HdlcFrame::new(self.peer, self.own, Control::Disc { poll: true }, Vec::new());
        self.transport.send(&frame.encode())?;
        let reply = self.read_decoded_frame()?;
        self.connected = false;
        match reply.control {
            Control::Ua { .. } | Control::Dm { .. } => Ok(()),
            other => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected reply to DISC: {other:?}"))),
        }
    }

    /// Returns whether the data link is connected (NRM).
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Reads frames until one decodes cleanly. Bad FCS/HCS frames are dropped
    /// silently; an unknown control field in NRM is answered with FRMR (W)
    /// (ISO 13239 / Yellow Book HDLC_COMMAND — C++ `OSP_ERR_UNSUPPORTED` path).
    fn read_decoded_frame(&mut self) -> io::Result<HdlcFrame> {
        for _ in 0..MAX_BAD_FRAMES {
            let raw = self.read_frame()?;
            match HdlcFrame::decode(&raw) {
                Ok(frame) => return Ok(frame),
                Err(HdlcError::UnknownControl(_)) if !self.is_client && self.connected => {
                    if let Ok((destination, source)) = HdlcFrame::peek_addresses(&raw) {
                        if destination.value == self.own.value {
                            self.peer = source;
                            self.send_unnumbered(Control::Frmr { final_bit: true })?;
                        }
                    }
                }
                Err(_) => {}
            }
        }
        Err(io::Error::new(io::ErrorKind::InvalidData, "too many undecodable HDLC frames"))
    }

    /// Sends an unnumbered response frame (server side).
    fn send_unnumbered(&mut self, control: Control) -> io::Result<()> {
        self.send_unnumbered_with_info(control, Vec::new())
    }

    /// Sends an unnumbered frame carrying an information field (used for
    /// UA's XID reply to SNRM).
    fn send_unnumbered_with_info(&mut self, control: Control, information: Vec<u8>) -> io::Result<()> {
        let frame = HdlcFrame::new(self.peer, self.own, control, information);
        self.transport.send(&frame.encode())
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
        if self.is_client {
            LLC_COMMAND
        } else {
            LLC_RESPONSE
        }
    }

    /// Reads one complete frame (from an opening flag to a closing flag) from the
    /// transport.
    ///
    /// Waits up to the configured inactivity timeout for the opening flag of
    /// a *new* frame, then up to the (tighter) inter-octet timeout for every
    /// subsequent octet of that same frame.
    ///
    /// An **inter-octet** timeout mid-frame discards the incomplete octets and
    /// keeps waiting for the next frame (C++ `session_recv_frame` parity) —
    /// it is not surfaced as an error. An **inactivity** timeout with an empty
    /// buffer marks the link as NDM and returns
    /// [`std::io::ErrorKind::TimedOut`].
    ///
    /// Both timeouts require the transport to honour
    /// [`PhysicalTransport::set_read_timeout`]; a transport that doesn't
    /// (the default) makes reads block indefinitely as before.
    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        loop {
            // Skip to the opening flag, bounded by the inactivity timeout.
            self.transport.set_read_timeout(self.inactivity_timeout)?;
            let mut byte = [0u8; 1];
            loop {
                match read_exact(&mut self.transport, &mut byte) {
                    Ok(()) => {}
                    Err(e) if is_timeout(&e) => {
                        self.connected = false;
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HDLC inactivity timeout: no frame received",
                        ));
                    }
                    Err(e) => return Err(e),
                }
                if byte[0] == FLAG {
                    break;
                }
            }

            // Frame started: subsequent octets use the inter-octet timeout.
            self.transport.set_read_timeout(Some(self.inter_octet_timeout))?;
            match self.read_frame_body() {
                Ok(frame) => {
                    let _ = self.transport.set_read_timeout(self.inactivity_timeout);
                    return Ok(frame);
                }
                // Incomplete frame: drop it and wait for the next opening flag
                // (C++ clears rx_pending and continues — not an error).
                Err(e) if is_timeout(&e) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        timeout_ms = self.inter_octet_timeout.as_millis() as u64,
                        "HDLC inter-octet timeout, incomplete frame discarded"
                    );
                    let _ = self.transport.set_read_timeout(self.inactivity_timeout);
                }
                // Bad format / truncated mid-frame: resync like C++ buffer shift.
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(error = %e, "HDLC invalid frame discarded, resync");
                    let _ = self.transport.set_read_timeout(self.inactivity_timeout);
                }
                Err(e) => {
                    let _ = self.transport.set_read_timeout(self.inactivity_timeout);
                    return Err(e);
                }
            }
        }
    }

    /// Reads the format field, payload and closing flag of a frame whose
    /// opening flag octet has already been consumed.
    fn read_frame_body(&mut self) -> io::Result<Vec<u8>> {
        let mut format = [0u8; 2];
        read_exact(&mut self.transport, &mut format).map_err(inter_octet_timeout)?;
        if format[0] & 0xF0 != 0xA0 {
            return Err(HdlcError::InvalidFormatType.into());
        }
        let length = (((format[0] & 0x07) as usize) << 8) | format[1] as usize;
        if length < 4 {
            return Err(HdlcError::Truncated.into());
        }
        // `length` counts the format field too; read the rest plus the closing flag.
        let mut rest = vec![0u8; length - 2 + 1];
        read_exact(&mut self.transport, &mut rest).map_err(inter_octet_timeout)?;
        let mut frame = Vec::with_capacity(length + 2);
        frame.push(FLAG);
        frame.extend_from_slice(&format);
        frame.extend_from_slice(&rest);
        Ok(frame)
    }
}

/// Whether `e` is a read timeout (from [`PhysicalTransport::set_read_timeout`]).
fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

/// Relabels a timeout mid-frame as an inter-octet timeout; other errors pass
/// through unchanged.
fn inter_octet_timeout(e: io::Error) -> io::Error {
    if is_timeout(&e) {
        io::Error::new(io::ErrorKind::TimedOut, "HDLC inter-octet timeout: frame aborted")
    } else {
        e
    }
}

impl<T: PhysicalTransport> DataLinkLayer for HdlcLayer<T> {
    /// Frames and sends `apdu`, splitting it into consecutive I-frames (the
    /// format field's segmentation bit set on every frame but the last) when
    /// the LLC-prefixed payload exceeds the negotiated `max_info_tx` (see
    /// [`Self::xid`]) — the mirror of the segmented-frame reassembly already
    /// performed by [`Self::receive_apdu`]. Each segment consumes one N(S)
    /// slot; segments are sent back-to-back without waiting for the peer's
    /// per-segment `RR` (this layer doesn't model true windowed flow
    /// control, and a stray `RR` is harmlessly skipped by the next
    /// `receive_apdu` call regardless).
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        if !self.is_client && !self.connected {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "HDLC link is in NDM"));
        }
        #[cfg(feature = "tracing")]
        trace!(send_seq = self.send_seq, recv_seq = self.recv_seq, apdu_len = apdu.len(), "hdlc send");
        let mut payload = Vec::with_capacity(3 + apdu.len());
        payload.extend_from_slice(&self.llc());
        payload.extend_from_slice(apdu);

        // The LLC prefix makes `payload` at least 3 octets, so this always
        // sends at least one frame.
        let max_info = (self.xid.max_info_tx as usize).max(1);
        let mut offset = 0;
        while offset < payload.len() {
            let chunk = (payload.len() - offset).min(max_info);
            let last = offset + chunk >= payload.len();
            let control = Control::Information { send_seq: self.send_seq, recv_seq: self.recv_seq, poll: true };
            let mut frame = HdlcFrame::new(self.peer, self.own, control, payload[offset..offset + chunk].to_vec());
            frame.segmented = !last;
            self.transport.send(&frame.encode())?;
            self.send_seq = (self.send_seq + 1) & 0x07;
            offset += chunk;
        }
        Ok(())
    }

    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        let mut information = Vec::new();
        loop {
            let frame = self.read_decoded_frame()?;
            // Server: ignore frames not addressed to this station (C++ parity).
            if !self.is_client && frame.destination.value != self.own.value {
                continue;
            }
            match frame.control {
                // ── NDM (server): only SNRM and DISC are meaningful. ──────
                // Everything else (I, UI, RR/RNR, …) is ignored — Yellow Book
                // HDLC_NDMOP / C++ openspodes connect-loop parity.
                Control::Snrm { .. } if !self.is_client && !self.connected => {
                    self.peer = frame.source;
                    self.xid = self.xid_configured;
                    if !frame.information.is_empty() {
                        self.xid.negotiate(XidParams::decode(&frame.information));
                    }
                    self.send_seq = 0;
                    self.recv_seq = 0;
                    self.connected = true;
                    self.send_unnumbered_with_info(Control::Ua { final_bit: true }, self.xid.encode())?;
                }
                Control::Disc { .. } if !self.is_client && !self.connected => {
                    self.peer = frame.source;
                    self.send_unnumbered(Control::Dm { final_bit: true })?;
                }
                _ if !self.is_client && !self.connected => {
                    // NDM: silent drop (I / UI / RR / …).
                }

                // ── NRM (and client): information / UI deliver APDUs. ─────
                Control::Information { send_seq, recv_seq, .. } => {
                    if !self.is_client {
                        self.peer = frame.source;
                        let max_rx = usize::from(self.xid.max_info_rx.max(1));
                        // Info longer than negotiated max_info_rx → FRMR (Y).
                        if frame.information.len() > max_rx {
                            self.send_unnumbered(Control::Frmr { final_bit: true })?;
                            continue;
                        }
                        // Invalid N(R) → FRMR (Z).
                        if recv_seq != self.send_seq {
                            self.send_unnumbered(Control::Frmr { final_bit: true })?;
                            continue;
                        }
                        // Wrong N(S): RR with current N(R), do not advance.
                        if send_seq != self.recv_seq {
                            let rr = Control::ReceiveReady {
                                recv_seq: self.recv_seq,
                                poll_final: true,
                            };
                            self.transport
                                .send(&HdlcFrame::new(self.peer, self.own, rr, Vec::new()).encode())?;
                            continue;
                        }
                    }
                    self.recv_seq = (send_seq + 1) & 0x07;
                    information.extend_from_slice(&frame.information);
                    // A set segmentation bit means more I-frames follow; ask for
                    // the next one with RR and keep reassembling (IEC 62056-46
                    // §6.4.4.4).
                    if frame.segmented {
                        let rr = Control::ReceiveReady { recv_seq: self.recv_seq, poll_final: true };
                        self.transport.send(&HdlcFrame::new(self.peer, self.own, rr, Vec::new()).encode())?;
                        continue;
                    }
                    break;
                }
                Control::Ui { .. } => {
                    information.extend_from_slice(&frame.information);
                    break;
                }
                // Server in NRM: SNRM re-establishes (reset XID / seq / UA).
                Control::Snrm { .. } if !self.is_client => {
                    self.peer = frame.source;
                    self.xid = self.xid_configured;
                    if !frame.information.is_empty() {
                        self.xid.negotiate(XidParams::decode(&frame.information));
                    }
                    self.send_seq = 0;
                    self.recv_seq = 0;
                    self.connected = true;
                    self.send_unnumbered_with_info(Control::Ua { final_bit: true }, self.xid.encode())?;
                }
                // Server in NRM: DISC → UA → NDM.
                Control::Disc { .. } if !self.is_client => {
                    self.peer = frame.source;
                    self.connected = false;
                    self.send_unnumbered(Control::Ua { final_bit: true })?;
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "peer released the data link"));
                }
                // RR/RNR: invalid N(R) → FRMR (Z); otherwise ack and keep waiting.
                Control::ReceiveReady { recv_seq, .. } | Control::ReceiveNotReady { recv_seq, .. } => {
                    if !self.is_client && recv_seq != self.send_seq {
                        self.peer = frame.source;
                        self.send_unnumbered(Control::Frmr { final_bit: true })?;
                    }
                }
                // Unknown / invalid in NRM → FRMR.
                _ => {
                    if !self.is_client {
                        self.peer = frame.source;
                        self.send_unnumbered(Control::Frmr { final_bit: true })?;
                    }
                }
            }
        }
        // Strip the 3-octet LLC header if present.
        let apdu =
            if information.len() >= 3 && information[0] == 0xE6 && (information[1] == 0xE6 || information[1] == 0xE7) {
                information[3..].to_vec()
            } else {
                information
            };
        #[cfg(feature = "tracing")]
        trace!(send_seq = self.send_seq, recv_seq = self.recv_seq, apdu_len = apdu.len(), "hdlc receive");
        Ok(apdu)
    }

    fn client_sap(&self) -> Option<u8> {
        if !self.is_client && self.peer.length == 1 {
            // length == 1 means a single 7-bit address group, always < 128.
            #[allow(clippy::cast_possible_truncation)]
            let sap = self.peer.value as u8;
            Some(sap)
        } else {
            None
        }
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
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        let apdu = vec![0x60, 0x1D, 0xA1, 0x09];
        client.send_apdu(&apdu).unwrap();
        // The loopback transport now holds the encoded frame; read it back.
        let received = client.receive_apdu().unwrap();
        assert_eq!(received, apdu);
    }

    fn server_layer() -> HdlcLayer<MemoryTransport> {
        HdlcLayer::new_server(MemoryTransport::new(), HdlcAddress::one_byte(0x03), HdlcAddress::one_byte(0x10))
    }

    fn client_frame(control: Control, information: Vec<u8>) -> Vec<u8> {
        HdlcFrame::new(HdlcAddress::one_byte(0x03), HdlcAddress::one_byte(0x10), control, information).encode()
    }

    #[test]
    fn connect_performs_snrm_ua_exchange() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        // Pre-feed the server's UA so it is read back after our SNRM.
        let ua = HdlcFrame::new(
            HdlcAddress::one_byte(0x10),
            HdlcAddress::one_byte(0x03),
            Control::Ua { final_bit: true },
            Vec::new(),
        );
        client.transport_mut().feed(&ua.encode());
        client.connect().unwrap();
        assert!(client.is_connected());
    }

    #[test]
    fn server_learns_client_address_from_snrm() {
        let mut server = server_layer();
        let snrm = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x61),
            Control::Snrm { poll: true },
            Vec::new(),
        )
        .encode();
        server.transport_mut().feed(&snrm);
        let info = Control::Information { send_seq: 0, recv_seq: 0, poll: true };
        server.transport_mut().feed(
            &HdlcFrame::new(
                HdlcAddress::one_byte(0x03),
                HdlcAddress::one_byte(0x61),
                info,
                vec![0xE6, 0xE6, 0x00, 0xC0, 0x01, 0xC1],
            )
            .encode(),
        );
        let _ = server.receive_apdu().unwrap();
        let ua_raw = server.read_frame().unwrap();
        let ua = HdlcFrame::decode(&ua_raw).unwrap();
        assert_eq!(ua.destination, HdlcAddress::one_byte(0x61));
    }

    #[test]
    fn server_answers_snrm_with_ua_and_resets_sequences() {
        let mut server = server_layer();
        server.send_seq = 5;
        let info = Control::Information { send_seq: 0, recv_seq: 0, poll: true };
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(info, vec![0xC0, 0x01, 0xC1]));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01, 0xC1]);
        assert!(server.is_connected());
        assert_eq!(server.send_seq, 0);
        // The UA answer is queued in the transport after the consumed frames.
        let raw = server.read_frame().unwrap();
        let ua = HdlcFrame::decode(&raw).unwrap();
        assert!(matches!(ua.control, Control::Ua { .. }));
    }

    #[test]
    fn server_answers_disc_in_ndm_with_dm() {
        let mut server = server_layer();
        // Default peer is 0x10; DISC comes from 0x21 — DM must target the source.
        let disc = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x21),
            Control::Disc { poll: true },
            Vec::new(),
        );
        let info = Control::Information { send_seq: 0, recv_seq: 0, poll: true };
        server.transport_mut().feed(&disc.encode());
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(info, vec![0xC0, 0x01, 0xC1]));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01, 0xC1]);
        let dm = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(dm.control, Control::Dm { .. }));
        assert_eq!(dm.destination, HdlcAddress::one_byte(0x21));
        let ua = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(ua.control, Control::Ua { .. }));
        assert!(server.is_connected());
    }

    #[test]
    fn server_ignores_everything_but_snrm_and_disc_in_ndm() {
        let mut server = server_layer();
        assert!(!server.is_connected());
        // I / UI / RR while in NDM — must produce no wire reply.
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xE6, 0xE6, 0x00, 0x60, 0x36],
        ));
        server
            .transport_mut()
            .feed(&client_frame(Control::Ui { poll: true }, vec![0xAA]));
        server.transport_mut().feed(&client_frame(
            Control::ReceiveReady { recv_seq: 3, poll_final: true },
            Vec::new(),
        ));
        // Then SNRM → UA → NRM and a normal I-frame.
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xE6, 0xE6, 0x00, 0xC0, 0x01],
        ));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01]);
        let ua = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(ua.control, Control::Ua { .. }));
        // Only the UA for SNRM — nothing for the preceding NDM I/UI/RR.
        assert!(server.read_frame().is_err());
    }

    #[test]
    fn server_answers_disc_in_nrm_with_ua_then_stays_in_ndm() {
        let mut server = server_layer();
        server.connected = true;
        server.peer = HdlcAddress::one_byte(0x21);
        server.transport_mut().feed(&client_frame(Control::Disc { poll: true }, Vec::new()));
        let err = server.receive_apdu().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(!server.is_connected());
        let ua = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(ua.control, Control::Ua { .. }));
    }

    #[test]
    fn server_answers_unknown_control_with_frmr() {
        let mut server = server_layer();
        server.connected = true;
        server.peer = HdlcAddress::one_byte(0x21);
        // Control 0xFF is not a valid HDLC command (Gurux "Неизвестная команда").
        let mut unknown = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x21),
            Control::Disc { poll: true },
            Vec::new(),
        )
        .encode();
        // Patch control byte to 0xFF and recompute FCS over format..ctrl.
        unknown[5] = 0xFF;
        let fcs = super::fcs16(&unknown[1..6]);
        unknown[6] = fcs as u8;
        unknown[7] = (fcs >> 8) as u8;

        let info = Control::Information { send_seq: 0, recv_seq: 0, poll: true };
        server.transport_mut().feed(&unknown);
        server.transport_mut().feed(&client_frame(info, vec![0xC0, 0x01]));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01]);
        let frmr = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(frmr.control, Control::Frmr { final_bit: true }));
        assert_eq!(frmr.destination, HdlcAddress::one_byte(0x21));
    }

    #[test]
    fn server_rejects_oversized_i_frame_with_frmr() {
        let mut server = server_layer();
        server.connected = true;
        server.xid.max_info_rx = 16;
        let big = vec![0xAAu8; 64];
        let info = Control::Information { send_seq: 0, recv_seq: 0, poll: true };
        server.transport_mut().feed(&client_frame(info, big));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xC0, 0x01],
        ));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01]);
        let frmr = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(frmr.control, Control::Frmr { .. }));
    }

    #[test]
    fn server_answers_rr_with_bad_nr_with_frmr() {
        let mut server = server_layer();
        server.connected = true;
        server.send_seq = 0;
        let rr = Control::ReceiveReady { recv_seq: 1, poll_final: true };
        server.transport_mut().feed(&client_frame(rr, Vec::new()));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xBB],
        ));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xBB]);
        let frmr = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(frmr.control, Control::Frmr { .. }));
    }

    #[test]
    fn server_answers_wrong_ns_with_rr() {
        let mut server = server_layer();
        server.connected = true;
        server.recv_seq = 0;
        // N(S)=1 while V(R)=0
        let info = Control::Information { send_seq: 1, recv_seq: 0, poll: true };
        server.transport_mut().feed(&client_frame(info, vec![0xE6, 0xE6, 0x00, 0x60]));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xC0],
        ));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0]);
        let rr = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(
            rr.control,
            Control::ReceiveReady {
                recv_seq: 0,
                poll_final: true
            }
        ));
    }

    // ------------------------------------------------------------------
    // State machine: NDM ↔ NRM via SNRM/UA and DISC/UA|DM.
    // ------------------------------------------------------------------

    #[test]
    fn state_ndm_snrm_ua_nrm() {
        let mut server = server_layer();
        assert!(!server.is_connected(), "starts in NDM");
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0x01],
        ));
        assert_eq!(server.receive_apdu().unwrap(), vec![0x01]);
        assert!(server.is_connected(), "NDM --SNRM/UA--> NRM");
        let ua = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(ua.control, Control::Ua { final_bit: true }));
    }

    #[test]
    fn state_nrm_disc_ua_ndm() {
        let mut server = server_layer();
        server.connected = true;
        server.transport_mut().feed(&client_frame(Control::Disc { poll: true }, Vec::new()));
        let err = server.receive_apdu().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(!server.is_connected(), "NRM --DISC/UA--> NDM");
        let ua = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(ua.control, Control::Ua { final_bit: true }));
    }

    #[test]
    fn state_ndm_disc_dm_ndm() {
        let mut server = server_layer();
        assert!(!server.is_connected(), "starts in NDM");
        server.transport_mut().feed(&client_frame(Control::Disc { poll: true }, Vec::new()));
        // Unblock receive_apdu after DM handling with SNRM + I.
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0x01],
        ));
        let _ = server.receive_apdu().unwrap();
        let dm = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(dm.control, Control::Dm { final_bit: true }), "NDM --DISC/DM--> NDM");
        let ua = HdlcFrame::decode(&server.read_frame().unwrap()).unwrap();
        assert!(matches!(ua.control, Control::Ua { .. }));
        assert!(server.is_connected(), "SNRM after DM brings us to NRM");
    }

    #[test]
    fn state_full_cycle_ndm_nrm_ndm_dm() {
        let mut server = server_layer();
        assert!(!server.is_connected());

        // 1) NDM → SNRM → UA → NRM
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xAA],
        ));
        assert_eq!(server.receive_apdu().unwrap(), vec![0xAA]);
        assert!(server.is_connected());
        assert!(matches!(
            HdlcFrame::decode(&server.read_frame().unwrap()).unwrap().control,
            Control::Ua { .. }
        ));

        // 2) NRM → DISC → UA → NDM
        server.transport_mut().feed(&client_frame(Control::Disc { poll: true }, Vec::new()));
        assert_eq!(
            server.receive_apdu().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(!server.is_connected());
        assert!(matches!(
            HdlcFrame::decode(&server.read_frame().unwrap()).unwrap().control,
            Control::Ua { .. }
        ));

        // 3) NDM → DISC → DM → NDM
        server.transport_mut().feed(&client_frame(Control::Disc { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(Control::Snrm { poll: true }, Vec::new()));
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xBB],
        ));
        assert_eq!(server.receive_apdu().unwrap(), vec![0xBB]);
        assert!(matches!(
            HdlcFrame::decode(&server.read_frame().unwrap()).unwrap().control,
            Control::Dm { .. }
        ));
        assert!(matches!(
            HdlcFrame::decode(&server.read_frame().unwrap()).unwrap().control,
            Control::Ua { .. }
        ));
        assert!(server.is_connected());
    }

    #[test]
    fn segmented_information_is_reassembled() {
        let mut server = server_layer();
        server.connected = true;
        let mut first = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xE6, 0xE6, 0x00, 0xC0, 0x01],
        );
        first.segmented = true;
        let second = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Information { send_seq: 1, recv_seq: 0, poll: true },
            vec![0xC1, 0x00, 0x01],
        );
        server.transport_mut().feed(&first.encode());
        server.transport_mut().feed(&second.encode());
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xC0, 0x01, 0xC1, 0x00, 0x01]);
    }

    #[test]
    fn bad_fcs_frames_are_dropped_silently() {
        let mut server = server_layer();
        server.connected = true;
        let mut corrupted = client_frame(Control::Information { send_seq: 0, recv_seq: 0, poll: true }, vec![0xAA]);
        let len = corrupted.len();
        corrupted[len - 2] ^= 0xFF; // corrupt the FCS
        server.transport_mut().feed(&corrupted);
        server
            .transport_mut()
            .feed(&client_frame(Control::Information { send_seq: 1, recv_seq: 0, poll: true }, vec![0xBB]));
        // After bad frame, N(S)=1 is wrong for V(R)=0 → RR, so also feed correct N(S)=0.
        server.transport_mut().feed(&client_frame(
            Control::Information { send_seq: 0, recv_seq: 0, poll: true },
            vec![0xBB],
        ));
        let apdu = server.receive_apdu().unwrap();
        assert_eq!(apdu, vec![0xBB]);
    }

    // ------------------------------------------------------------------
    // Inter-octet / inactivity timeouts.
    // ------------------------------------------------------------------

    #[test]
    fn inter_octet_timeout_ms_clamps_to_standard_range() {
        let mut layer =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        layer.set_inter_octet_timeout_ms(5); // below the 20 ms minimum
        assert_eq!(layer.inter_octet_timeout, Duration::from_millis(20));
        layer.set_inter_octet_timeout_ms(60_000); // above the 6000 ms maximum
        assert_eq!(layer.inter_octet_timeout, Duration::from_millis(6000));
        layer.set_inter_octet_timeout_ms(100);
        assert_eq!(layer.inter_octet_timeout, Duration::from_millis(100));
    }

    #[test]
    fn inactivity_timeout_s_clamps_and_zero_disables() {
        let mut layer =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        assert_eq!(layer.inactivity_timeout, None, "disabled by default");
        layer.set_inactivity_timeout_s(200); // above the 120 s maximum
        assert_eq!(layer.inactivity_timeout, Some(Duration::from_secs(120)));
        layer.set_inactivity_timeout_s(30);
        assert_eq!(layer.inactivity_timeout, Some(Duration::from_secs(30)));
        layer.set_inactivity_timeout_s(0);
        assert_eq!(layer.inactivity_timeout, None, "0 disables it again");
    }

    /// A [`PhysicalTransport`] mock that logs every requested read timeout
    /// and can simulate the peer going silent after a fixed number of
    /// delivered bytes (or immediately, if empty) by returning
    /// [`io::ErrorKind::TimedOut`] instead of blocking forever.
    #[derive(Default)]
    struct TimeoutTransport {
        data: std::collections::VecDeque<u8>,
        set_timeout_log: Vec<Option<Duration>>,
    }

    impl PhysicalTransport for TimeoutTransport {
        fn send(&mut self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() {
                // No more data will ever arrive: a real blocking transport
                // configured with a read timeout would time out here rather
                // than signal EOF.
                return Err(io::Error::new(io::ErrorKind::TimedOut, "simulated timeout"));
            }
            let mut n = 0;
            while n < buf.len() {
                match self.data.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            Ok(n)
        }
        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            self.set_timeout_log.push(timeout);
            Ok(())
        }
    }

    fn timeout_test_layer() -> HdlcLayer<TimeoutTransport> {
        let mut layer = HdlcLayer::new_client(
            TimeoutTransport::default(),
            HdlcAddress::one_byte(0x10),
            HdlcAddress::one_byte(0x03),
        );
        layer.set_inactivity_timeout_s(60);
        layer.set_inter_octet_timeout_ms(30);
        layer
    }

    #[test]
    fn read_frame_switches_from_inactivity_to_inter_octet_timeout() {
        let mut layer = timeout_test_layer();
        let frame = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Ua { final_bit: true },
            Vec::new(),
        )
        .encode();
        layer.transport.data.extend(frame);

        layer.read_frame().expect("full frame is available");

        // Inactivity timeout while waiting for the flag, inter-octet timeout
        // for the rest of the frame, then inactivity restored for the next call.
        assert_eq!(
            layer.transport.set_timeout_log,
            vec![Some(Duration::from_secs(60)), Some(Duration::from_millis(30)), Some(Duration::from_secs(60))]
        );
    }

    #[test]
    fn no_frame_at_all_times_out_as_inactivity_and_disconnects() {
        let mut layer = timeout_test_layer();
        layer.connected = true;
        let err = layer.read_frame().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("inactivity"), "unexpected message: {err}");
        assert!(!layer.is_connected(), "inactivity timeout must drop the connected state");
    }

    #[test]
    fn silence_mid_frame_discards_incomplete_then_inactivity_disconnects() {
        let mut layer = timeout_test_layer();
        layer.connected = true;
        // Only the opening flag and part of the format field arrive; the
        // peer then goes silent. Inter-octet discards the fragment (no error);
        // the next wait uses inactivity and disconnects to NDM.
        layer.transport.data.push_back(FLAG);
        layer.transport.data.push_back(0xA0);

        let err = layer.read_frame().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("inactivity"), "unexpected message: {err}");
        assert!(!layer.is_connected(), "inactivity after inter-octet discard drops to NDM");
        assert!(
            layer
                .transport
                .set_timeout_log
                .iter()
                .any(|t| *t == Some(Duration::from_millis(30))),
            "inter-octet timeout must have been armed for the incomplete frame"
        );
    }

    #[test]
    fn silence_mid_frame_then_next_complete_frame_is_accepted() {
        /// Delivers a partial frame, one inter-octet timeout, then a full UA.
        struct RecoverTransport {
            phase: u8,
            frame: Vec<u8>,
            set_timeout_log: Vec<Option<Duration>>,
        }
        impl PhysicalTransport for RecoverTransport {
            fn send(&mut self, _data: &[u8]) -> io::Result<()> {
                Ok(())
            }
            fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                match self.phase {
                    0 => {
                        // Opening flag only — starts the frame.
                        buf[0] = FLAG;
                        self.phase = 1;
                        Ok(1)
                    }
                    1 => {
                        // One format byte, then silence → inter-octet.
                        buf[0] = 0xA0;
                        self.phase = 2;
                        Ok(1)
                    }
                    2 => {
                        self.phase = 3;
                        Err(io::Error::new(io::ErrorKind::TimedOut, "inter-octet"))
                    }
                    _ => {
                        if self.frame.is_empty() {
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "done"));
                        }
                        let n = buf.len().min(self.frame.len());
                        buf[..n].copy_from_slice(&self.frame[..n]);
                        self.frame.drain(..n);
                        Ok(n)
                    }
                }
            }
            fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
                self.set_timeout_log.push(timeout);
                Ok(())
            }
        }

        let frame = HdlcFrame::new(
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
            Control::Ua { final_bit: true },
            Vec::new(),
        )
        .encode();
        let mut layer = HdlcLayer::new_server(
            RecoverTransport {
                phase: 0,
                frame,
                set_timeout_log: Vec::new(),
            },
            HdlcAddress::one_byte(0x03),
            HdlcAddress::one_byte(0x10),
        );
        layer.set_inactivity_timeout_s(60);
        layer.set_inter_octet_timeout_ms(30);
        layer.connected = true;

        let raw = layer.read_frame().expect("next full frame after inter-octet discard");
        let decoded = HdlcFrame::decode(&raw).unwrap();
        assert!(matches!(decoded.control, Control::Ua { .. }));
        assert!(layer.is_connected(), "inter-octet discard must not drop to NDM");
    }

    // ------------------------------------------------------------------
    // XID negotiation.
    // ------------------------------------------------------------------

    #[test]
    fn xid_params_round_trip_through_wire_encoding() {
        let xid = XidParams { max_info_tx: 1280, max_info_rx: 512, window_tx: 3, window_rx: 1 };
        let encoded = xid.encode();
        assert_eq!(&encoded[..2], &[0x81, 0x80]);
        assert_eq!(XidParams::decode(&encoded), xid);
    }

    #[test]
    fn xid_negotiate_tightens_to_the_smaller_value() {
        let mut mine = XidParams { max_info_tx: 1280, max_info_rx: 1280, window_tx: 3, window_rx: 3 };
        let peer = XidParams { max_info_tx: 200, max_info_rx: 400, window_tx: 1, window_rx: 2 };
        mine.negotiate(peer);
        // My rx is capped by the peer's tx, and vice-versa.
        assert_eq!(mine, XidParams { max_info_tx: 400, max_info_rx: 200, window_tx: 2, window_rx: 1 });
    }

    #[test]
    fn xid_negotiate_ignores_zero_fields_from_peer() {
        let mut mine = XidParams::client_default();
        let peer = XidParams { max_info_tx: 0, max_info_rx: 0, window_tx: 0, window_rx: 0 };
        mine.negotiate(peer);
        assert_eq!(mine, XidParams::client_default(), "an all-zero (absent) proposal changes nothing");
    }

    #[test]
    fn xid_decode_clamps_out_of_range_window_instead_of_wrapping() {
        // window_tx param (tag 0x07, len 4) carrying 300 — out of u8 range.
        let data = [0x81, 0x80, 0x06, 0x07, 0x04, 0x00, 0x00, 0x01, 0x2C];
        let p = XidParams::decode(&data);
        // 300 as u8 would wrap to 44; it must clamp to u8::MAX instead.
        assert_eq!(p.window_tx, u8::MAX);
    }

    #[test]
    fn xid_negotiate_never_widens_the_ceiling() {
        let mut mine = XidParams { max_info_tx: 200, max_info_rx: 200, window_tx: 1, window_rx: 1 };
        let peer = XidParams { max_info_tx: 5000, max_info_rx: 5000, window_tx: 7, window_rx: 7 };
        mine.negotiate(peer);
        assert_eq!(mine, XidParams { max_info_tx: 200, max_info_rx: 200, window_tx: 1, window_rx: 1 });
    }

    #[test]
    fn connect_sends_configured_xid_and_negotiates_the_ua_reply() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        let server_xid = XidParams { max_info_tx: 200, max_info_rx: 300, window_tx: 1, window_rx: 1 };
        let ua = HdlcFrame::new(
            HdlcAddress::one_byte(0x10),
            HdlcAddress::one_byte(0x03),
            Control::Ua { final_bit: true },
            server_xid.encode(),
        );
        client.transport_mut().feed(&ua.encode());
        client.connect().unwrap();

        // Negotiated against the client's 1280/1280/1/1 default: tx capped
        // by the server's rx (300), rx capped by the server's tx (200).
        assert_eq!(client.xid(), XidParams { max_info_tx: 300, max_info_rx: 200, window_tx: 1, window_rx: 1 });

        // The SNRM the client sent carried its configured (unnegotiated)
        // ceiling; nothing has consumed it yet since the UA was pre-fed.
        let mut raw = vec![0u8; 128];
        let n = client.transport_mut().receive(&mut raw).unwrap();
        let sent = HdlcFrame::decode(&raw[..n]).unwrap();
        assert!(matches!(sent.control, Control::Snrm { .. }));
        assert_eq!(XidParams::decode(&sent.information), XidParams::client_default());
    }

    #[test]
    fn server_answers_snrm_with_negotiated_xid() {
        let mut server = server_layer();
        let client_xid = XidParams { max_info_tx: 128, max_info_rx: 128, window_tx: 1, window_rx: 1 };
        let snrm = client_frame(Control::Snrm { poll: true }, client_xid.encode());
        server.transport_mut().feed(&snrm);
        server
            .transport_mut()
            .feed(&client_frame(Control::Information { send_seq: 0, recv_seq: 0, poll: true }, vec![0xC0]));

        server.receive_apdu().unwrap();

        // Negotiated against the server's 512/512/1/1 default.
        assert_eq!(server.xid(), XidParams { max_info_tx: 128, max_info_rx: 128, window_tx: 1, window_rx: 1 });
    }

    #[test]
    fn snrm_without_xid_info_leaves_the_configured_ceiling_untouched() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        let ua = HdlcFrame::new(
            HdlcAddress::one_byte(0x10),
            HdlcAddress::one_byte(0x03),
            Control::Ua { final_bit: true },
            Vec::new(), // no XID info field at all
        );
        client.transport_mut().feed(&ua.encode());
        client.connect().unwrap();
        assert_eq!(client.xid(), XidParams::client_default());
    }

    // ------------------------------------------------------------------
    // Outbound I-frame segmentation.
    // ------------------------------------------------------------------

    #[test]
    fn send_apdu_does_not_segment_when_it_fits_the_ceiling() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        client.send_apdu(&[0xC0, 0x01]).unwrap();
        assert_eq!(client.send_seq, 1, "a single small APDU is sent as exactly one frame");
    }

    #[test]
    fn send_apdu_segments_when_it_exceeds_max_info_tx() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        client.set_xid_ceiling(XidParams { max_info_tx: 10, max_info_rx: 10, window_tx: 1, window_rx: 1 });
        let apdu: Vec<u8> = (0u8..25).collect();
        client.send_apdu(&apdu).unwrap();
        // LLC(3) + 25 = 28 octets, split into 10-octet blocks -> ceil(28/10) = 3 frames,
        // one N(S) slot consumed per frame.
        assert_eq!(client.send_seq, 3);
    }

    #[test]
    fn send_apdu_segments_are_reassembled_correctly_by_a_peer() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        client.set_xid_ceiling(XidParams { max_info_tx: 10, max_info_rx: 10, window_tx: 1, window_rx: 1 });
        let apdu: Vec<u8> = (0u8..25).collect();
        client.send_apdu(&apdu).unwrap();

        // Drain every byte the client produced and feed it into a fresh
        // server's transport, proving send_apdu's segmentation and
        // receive_apdu's reassembly are wire-compatible with each other.
        let mut buf = [0u8; 4096];
        let n = client.transport_mut().receive(&mut buf).unwrap();

        let mut server = server_layer();
        server.connected = true;
        server.transport_mut().feed(&buf[..n]);
        let reassembled = server.receive_apdu().unwrap();
        assert_eq!(reassembled, apdu);
    }

    #[test]
    fn send_apdu_respects_the_negotiated_ceiling_after_connect() {
        let mut client =
            HdlcLayer::new_client(MemoryTransport::new(), HdlcAddress::one_byte(0x10), HdlcAddress::one_byte(0x03));
        let tiny_ceiling = XidParams { max_info_tx: 8, max_info_rx: 8, window_tx: 1, window_rx: 1 };
        let ua = HdlcFrame::new(
            HdlcAddress::one_byte(0x10),
            HdlcAddress::one_byte(0x03),
            Control::Ua { final_bit: true },
            tiny_ceiling.encode(),
        );
        client.transport_mut().feed(&ua.encode());
        client.connect().unwrap();
        assert_eq!(client.xid().max_info_tx, 8);

        let apdu = vec![0xAAu8; 20]; // LLC(3) + 20 = 23 octets -> ceil(23/8) = 3 frames.
        client.send_apdu(&apdu).unwrap();
        assert_eq!(client.send_seq, 3, "send_apdu must use the negotiated ceiling, not the configured default");
    }
}
