//! TCP server example: listens for DLMS/COSEM connections over TCP and answers
//! GET requests using the wrapper sub-layer (IEC 62056-47).
//!
//! Run with: `cargo run --example tcp_server`
//! Then connect with: `cargo run --example tcp_client`
//!
//! The server listens on port 4059 (standard DLMS/COSEM TCP port) and serves
//! a single Data object (active energy import).

use std::io;
use std::net::{TcpListener, TcpStream};

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::{DataLinkLayer, NetworkTransport, PhysicalTransport};
use spodes_rs::types::CosemDataType;

/// Wraps a `TcpStream` as a [`PhysicalTransport`].
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

    let transport = TcpTransport(stream);
    // Server uses source port 4059, destination port from client.
    let mut link = Wrapper::new(transport, 4059, 0);

    // Build the server-side dispatcher with one Data object.
    let mut server = RequestDispatcher::new();
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF);
    server.add(Box::new(Data::new(obis, CosemDataType::DoubleLongUnsigned(123_456))));

    // Process requests in a loop.
    loop {
        match link.receive_apdu() {
            Ok(request_apdu) => {
                if let Ok(response) = server.dispatch(&request_apdu) {
                    if let Err(e) = link.send_apdu(&response) {
                        eprintln!("Send error: {e}");
                        break;
                    }
                }
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::TimedOut {
                    println!("Client disconnected: {peer}");
                } else {
                    eprintln!("Receive error: {e}");
                }
                break;
            }
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(4059);

    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("DLMS/COSEM TCP server listening on port {port}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream) {
                    eprintln!("Client error: {e}");
                }
            }
            Err(e) => eprintln!("Accept error: {e}"),
        }
    }

    Ok(())
}
