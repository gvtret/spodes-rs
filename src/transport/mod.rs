//! Transport layer for the DLMS/COSEM communication profiles.
//!
//! The layer is split into two independent concerns:
//!
//! * [`crate::transport::PhysicalTransport`] — a bidirectional byte channel abstracting the
//!   concrete medium (serial line, TCP connection, UDP socket). It is provided
//!   by the user of the library.
//! * [`crate::transport::DataLinkLayer`] — a framing sub-layer that carries xDLMS APDUs over a
//!   physical transport. Two implementations are provided (added in later
//!   commits): an HDLC layer usable over any medium, and a wrapper layer for
//!   TCP/UDP only.
//!
//! Because the framing sub-layers are generic over the physical transport, the
//! same HDLC implementation works over a serial line and over TCP, while the
//! wrapper sub-layer is bounded on [`crate::transport::NetworkTransport`] so it can only be built
//! over TCP/UDP.

use std::collections::VecDeque;
use std::io;
use std::time::Duration;

pub mod hdlc;
pub mod wrapper;

/// A bidirectional byte channel abstracting the physical medium.
///
/// Framing sub-layers (HDLC, wrapper) are built on top of this trait, so they
/// are independent of whether the underlying medium is a serial line, a TCP
/// connection or a UDP socket.
pub trait PhysicalTransport {
    /// Sends all of `data` over the medium.
    fn send(&mut self, data: &[u8]) -> io::Result<()>;

    /// Receives bytes into `buf`, returning the number of bytes read. A return
    /// value of 0 indicates end of stream.
    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize>;

    /// Sets the maximum time a subsequent [`receive`](Self::receive) call may
    /// block before returning an [`io::ErrorKind::TimedOut`] (or
    /// [`io::ErrorKind::WouldBlock`]) error. `None` waits indefinitely (the
    /// default behaviour, and what every `receive` implementation must do
    /// when this method is never called).
    ///
    /// Used by [`crate::transport::hdlc::HdlcLayer`] to enforce the IEC 62056-46
    /// inter-octet and inactivity timeouts. The default implementation is a
    /// no-op that returns `Ok(())`: a transport that ignores this request
    /// (i.e. keeps blocking indefinitely) makes those timeouts inactive but
    /// otherwise behaves exactly as before this method existed — mirrors
    /// [`std::net::TcpStream::set_read_timeout`], which most network
    /// transports can delegate to directly.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        let _ = timeout;
        Ok(())
    }
}

/// Marker trait for network transports (TCP/UDP).
///
/// The wrapper sub-layer is defined only over TCP/UDP, so it is bounded on this
/// trait. HDLC works over any [`crate::transport::PhysicalTransport`] (serial or network) and does
/// not require it.
pub trait NetworkTransport: PhysicalTransport {}

/// A data link / framing sub-layer that carries xDLMS APDUs.
///
/// Implemented by the HDLC and wrapper sub-layers.
pub trait DataLinkLayer {
    /// Frames and sends one APDU.
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()>;

    /// Receives and de-frames one APDU.
    fn receive_apdu(&mut self) -> io::Result<Vec<u8>>;
}

/// An in-memory loopback transport, primarily for tests: bytes written with
/// [`PhysicalTransport::send`] are read back by [`PhysicalTransport::receive`].
///
/// It implements [`crate::transport::NetworkTransport`], so it can back either framing sub-layer.
#[derive(Debug, Default)]
pub struct MemoryTransport {
    buffer: VecDeque<u8>,
}

impl MemoryTransport {
    /// Creates an empty transport.
    pub fn new() -> Self {
        MemoryTransport { buffer: VecDeque::new() }
    }

    /// Number of bytes currently buffered (sent but not yet received).
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Feeds raw bytes to be returned by subsequent `receive` calls.
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend(data.iter().copied());
    }
}

impl PhysicalTransport for MemoryTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.buffer.extend(data.iter().copied());
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = buf.len().min(self.buffer.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.buffer.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl NetworkTransport for MemoryTransport {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_transport_round_trips_bytes() {
        let mut t = MemoryTransport::new();
        t.send(&[1, 2, 3, 4]).unwrap();
        assert_eq!(t.buffered(), 4);
        let mut buf = [0u8; 2];
        assert_eq!(t.receive(&mut buf).unwrap(), 2);
        assert_eq!(buf, [1, 2]);
        assert_eq!(t.receive(&mut buf).unwrap(), 2);
        assert_eq!(buf, [3, 4]);
        // Empty now.
        assert_eq!(t.receive(&mut buf).unwrap(), 0);
    }
}
