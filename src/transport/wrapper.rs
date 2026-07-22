//! The DLMS/COSEM wrapper sub-layer (IEC 62056-47).
//!
//! The wrapper carries an xDLMS APDU over a connection-oriented (TCP) or
//! connectionless (UDP) transport by prefixing it with an 8-octet header:
//!
//! ```text
//! +---------+-------------+------------------+--------+
//! | version | source wPort| destination wPort| length |
//! |  2 oct  |    2 oct    |      2 oct       | 2 oct  |
//! +---------+-------------+------------------+--------+
//! ```
//!
//! All fields are big-endian; `length` is the size of the APDU that follows.
//! The wrapper is defined only over TCP/UDP, so [`Wrapper`] is bounded on
//! [`crate::transport::NetworkTransport`].

use std::io;

#[cfg(feature = "tracing")]
use tracing::trace;

use super::{DataLinkLayer, NetworkTransport, PhysicalTransport};

/// The only defined wrapper protocol version.
pub const WRAPPER_VERSION: u16 = 0x0001;

/// The 8-octet wrapper header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrapperHeader {
    /// Protocol version (always [`WRAPPER_VERSION`]).
    pub version: u16,
    /// Source wPort (the sender's SAP).
    pub source: u16,
    /// Destination wPort (the receiver's SAP).
    pub destination: u16,
    /// Length of the APDU that follows the header.
    pub length: u16,
}

/// Errors that can occur while decoding a wrapper PDU.
#[derive(Debug, PartialEq, Eq)]
pub enum WrapperError {
    /// Fewer than 8 octets were available for the header.
    TooShort,
    /// The version field did not equal [`WRAPPER_VERSION`].
    UnsupportedVersion(u16),
    /// The buffer did not contain `length` octets after the header.
    LengthMismatch {
        /// The length declared in the header.
        declared: usize,
        /// The number of APDU octets actually present.
        actual: usize,
    },
}

impl std::fmt::Display for WrapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapperError::TooShort => write!(f, "wrapper header is shorter than 8 octets"),
            WrapperError::UnsupportedVersion(v) => write!(f, "unsupported wrapper version {v:#06x}"),
            WrapperError::LengthMismatch { declared, actual } => {
                write!(f, "wrapper length mismatch: declared {declared}, actual {actual}")
            }
        }
    }
}

impl std::error::Error for WrapperError {}

impl From<WrapperError> for io::Error {
    fn from(e: WrapperError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }
}

impl WrapperHeader {
    /// Appends the header to `buf` (big-endian).
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.source.to_be_bytes());
        buf.extend_from_slice(&self.destination.to_be_bytes());
        buf.extend_from_slice(&self.length.to_be_bytes());
    }

    /// Parses a header from the first 8 octets of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<WrapperHeader, WrapperError> {
        if bytes.len() < 8 {
            return Err(WrapperError::TooShort);
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != WRAPPER_VERSION {
            return Err(WrapperError::UnsupportedVersion(version));
        }
        Ok(WrapperHeader {
            version,
            source: u16::from_be_bytes([bytes[2], bytes[3]]),
            destination: u16::from_be_bytes([bytes[4], bytes[5]]),
            length: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}

/// Builds a complete wrapper PDU (header + APDU).
pub fn encode(source: u16, destination: u16, apdu: &[u8]) -> Vec<u8> {
    let header = WrapperHeader { version: WRAPPER_VERSION, source, destination, length: apdu.len() as u16 };
    let mut buf = Vec::with_capacity(8 + apdu.len());
    header.encode(&mut buf);
    buf.extend_from_slice(apdu);
    buf
}

/// Parses a complete wrapper PDU, returning the header and the APDU.
pub fn decode(bytes: &[u8]) -> Result<(WrapperHeader, Vec<u8>), WrapperError> {
    let header = WrapperHeader::decode(bytes)?;
    let apdu = &bytes[8..];
    if apdu.len() != header.length as usize {
        return Err(WrapperError::LengthMismatch { declared: header.length as usize, actual: apdu.len() });
    }
    Ok((header, apdu.to_vec()))
}

/// The wrapper data-link sub-layer over a network (TCP/UDP) transport.
#[derive(Debug)]
pub struct Wrapper<T: NetworkTransport> {
    transport: T,
    source: u16,
    destination: u16,
}

impl<T: NetworkTransport> Wrapper<T> {
    /// Creates a wrapper layer that sends from `source` wPort to `destination`
    /// wPort over `transport`.
    pub fn new(transport: T, source: u16, destination: u16) -> Self {
        Wrapper { transport, source, destination }
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the layer and returns the underlying transport.
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: NetworkTransport> DataLinkLayer for Wrapper<T> {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        trace!(source = self.source, dest = self.destination, apdu_len = apdu.len(), "wrapper send");
        let pdu = encode(self.source, self.destination, apdu);
        self.transport.send(&pdu)
    }

    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        let mut header_bytes = [0u8; 8];
        read_exact(&mut self.transport, &mut header_bytes)?;
        let header = WrapperHeader::decode(&header_bytes)?;
        #[cfg(feature = "tracing")]
        trace!(source = header.source, dest = header.destination, apdu_len = header.length, "wrapper receive");
        let mut apdu = vec![0u8; header.length as usize];
        read_exact(&mut self.transport, &mut apdu)?;
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
    fn encode_decode_round_trip() {
        let apdu = vec![0xC0, 0x01, 0x00, 0x08];
        let pdu = encode(0x0001, 0x0010, &apdu);
        // Header: version 0001, source 0001, dest 0010, length 0004.
        assert_eq!(&pdu[..8], &[0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, 0x04]);
        let (header, decoded) = decode(&pdu).unwrap();
        assert_eq!(header.source, 0x0001);
        assert_eq!(header.destination, 0x0010);
        assert_eq!(decoded, apdu);
    }

    #[test]
    fn decode_rejects_bad_version_and_length() {
        assert_eq!(WrapperHeader::decode(&[0u8; 4]), Err(WrapperError::TooShort));
        let bad_version = [0x00, 0x02, 0, 1, 0, 1, 0, 0];
        assert_eq!(WrapperHeader::decode(&bad_version), Err(WrapperError::UnsupportedVersion(2)));
        let short_body = encode(1, 1, &[1, 2, 3]);
        assert!(matches!(decode(&short_body[..8]), Err(WrapperError::LengthMismatch { .. })));
    }

    #[test]
    fn layer_round_trips_over_transport() {
        let mut layer = Wrapper::new(MemoryTransport::new(), 0x0001, 0x0010);
        let apdu = vec![0x61, 0x1F, 0x30, 0x00];
        layer.send_apdu(&apdu).unwrap();
        let received = layer.receive_apdu().unwrap();
        assert_eq!(received, apdu);
    }
}
