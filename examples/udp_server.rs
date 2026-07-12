//! UDP server example: listens for DLMS/COSEM requests over UDP and answers
//! GET requests using the wrapper sub-layer (IEC 62056-47).
//!
//! Run with: `cargo run --example udp_server`
//! Then connect with: `cargo run --example udp_client`
//!
//! The server listens on port 4065 (standard DLMS/COSEM UDP port) and serves
//! a single Data object (active energy import).

use std::io;
use std::net::UdpSocket;

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::{DataLinkLayer, NetworkTransport, PhysicalTransport};
use spodes_rs::types::CosemDataType;

struct UdpTransport {
    socket: UdpSocket,
    recv_buf: Vec<u8>,
    recv_pos: usize,
    last_peer: Option<std::net::SocketAddr>,
}

impl UdpTransport {
    fn new(socket: UdpSocket) -> Self {
        Self { socket, recv_buf: Vec::new(), recv_pos: 0, last_peer: None }
    }
}

impl NetworkTransport for UdpTransport {}

impl PhysicalTransport for UdpTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(peer) = self.last_peer {
            self.socket.send_to(data, peer)?;
        }
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.recv_pos < self.recv_buf.len() {
            let remaining = &self.recv_buf[self.recv_pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.recv_pos += n;
            return Ok(n);
        }

        self.recv_buf.resize(4096, 0);
        let (n, peer) = self.socket.recv_from(&mut self.recv_buf)?;
        self.last_peer = Some(peer);
        self.recv_buf.truncate(n);
        self.recv_pos = 0;

        let n = n.min(buf.len());
        buf[..n].copy_from_slice(&self.recv_buf[..n]);
        self.recv_pos = n;
        Ok(n)
    }
}

fn main() -> io::Result<()> {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(4065);

    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    println!("DLMS/COSEM UDP server listening on port {port}");

    let transport = UdpTransport::new(socket);
    // Server uses source port 4065, destination port set from client address.
    let mut link = Wrapper::new(transport, 4065, 0);

    let mut server = RequestDispatcher::new();
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    server.add(Box::new(Data::new(obis, CosemDataType::DoubleLongUnsigned(123_456))));

    loop {
        match link.receive_apdu() {
            Ok(request_apdu) => {
                if let Ok(response) = server.dispatch(&request_apdu) {
                    if let Err(e) = link.send_apdu(&response) {
                        eprintln!("Send error: {e}");
                    }
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::ConnectionReset
                {
                    // Timeout or reset — normal for UDP, continue listening.
                    continue;
                }
                eprintln!("Receive error: {e}");
            }
        }
    }
}
