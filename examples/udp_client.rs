//! UDP client example: sends a DLMS/COSEM GET request over UDP using the
//! wrapper sub-layer (IEC 62056-47).
//!
//! Run the server first: `cargo run --example udp_server`
//! Then run this client: `cargo run --example udp_client`
//!
//! The client sends a GET request to port 4065 (standard DLMS/COSEM UDP port)
//! and waits for the response.

use std::io;
use std::net::UdpSocket;

use spodes_rs::obis::ObisCode;
use spodes_rs::service::get::{GetDataResult, GetResponse};
use spodes_rs::session::ClientSession;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::{NetworkTransport, PhysicalTransport};

/// Wraps a `UdpSocket` as a [`PhysicalTransport`].
///
/// Note: UDP is connectionless, so this implementation buffers the last
/// received datagram and returns it in chunks via `receive()`.
struct UdpTransport {
    socket: UdpSocket,
    recv_buf: Vec<u8>,
    recv_pos: usize,
}

impl UdpTransport {
    fn new(socket: UdpSocket) -> Self {
        Self { socket, recv_buf: Vec::new(), recv_pos: 0 }
    }
}

impl NetworkTransport for UdpTransport {}

impl PhysicalTransport for UdpTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        // For UDP wrapper, we need the destination address.
        // In a real implementation, this would be configured.
        // Here we use the connected peer address.
        self.socket.send(data)?;
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If we have buffered data from a previous datagram, return it.
        if self.recv_pos < self.recv_buf.len() {
            let remaining = &self.recv_buf[self.recv_pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.recv_pos += n;
            return Ok(n);
        }

        // Receive a new datagram.
        self.recv_buf.resize(4096, 0);
        let n = self.socket.recv(&mut self.recv_buf)?;
        self.recv_buf.truncate(n);
        self.recv_pos = 0;

        let n = n.min(buf.len());
        buf[..n].copy_from_slice(&self.recv_buf[..n]);
        self.recv_pos = n;
        Ok(n)
    }
}

fn main() -> io::Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4065".into());
    println!("Connecting to {addr}...");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let transport = UdpTransport::new(socket);
    // Client uses source port 1001, destination port 4065 (standard DLMS UDP port).
    let link = Wrapper::new(transport, 1001, 4065);
    let mut session = ClientSession::new(link);

    // GET the value attribute (attribute 2) of a Data object (class_id 1).
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF); // active energy import

    match session.get(1, obis.clone(), 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(value), .. }) => {
            println!("GET {obis} = {value:?}");
        }
        Ok(resp) => println!("Response: {resp:?}"),
        Err(e) => eprintln!("Error: {e}"),
    }

    Ok(())
}
