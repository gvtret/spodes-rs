//! TCP server example using HDLC over TCP (no Wrapper sub-layer).
//!
//! Run: `cargo run --example hdlc_tcp_server`
//! Connect with a client that speaks HDLC frames on the TCP socket.

use std::io;
use std::net::{TcpListener, TcpStream};

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::transport::hdlc::{HdlcAddress, HdlcLayer};
use spodes_rs::transport::{DataLinkLayer, NetworkTransport, PhysicalTransport};
use spodes_rs::types::CosemDataType;

struct TcpTransport(TcpStream);

impl NetworkTransport for TcpTransport {}

impl PhysicalTransport for TcpTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.0.write_all(data)
    }

    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.0.read(buf)
    }
}

fn handle_client(stream: TcpStream) -> io::Result<()> {
    let peer = stream.peer_addr()?;
    println!("Client connected: {peer}");

    let server_addr = HdlcAddress::one_byte(0x01);
    let client_addr = HdlcAddress::one_byte(0x10);
    let mut link = HdlcLayer::new_server(TcpTransport(stream), server_addr, client_addr);

    let mut server = RequestDispatcher::new();
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    server.add(Box::new(Data::new(obis, CosemDataType::DoubleLongUnsigned(42))));

    loop {
        match link.receive_apdu() {
            Ok(request) => {
                if let Ok(response) = server.dispatch(&request) {
                    link.send_apdu(&response)?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(4059);
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("HDLC/TCP server listening on port {port}");
    for stream in listener.incoming().flatten() {
        let _ = handle_client(stream);
    }
    Ok(())
}
