//! TCP client example: connects to a DLMS/COSEM server over TCP and reads a
//! Data object using the wrapper sub-layer (IEC 62056-47).
//!
//! Run the server first: `cargo run --example tcp_server`
//! Then run this client: `cargo run --example tcp_client`
//!
//! The example uses the wrapper framing layer (no HDLC) over a TCP connection
//! to the standard DLMS/COSEM port 4059.

use std::io;
use std::net::TcpStream;

use spodes_rs::obis::ObisCode;
use spodes_rs::service::get::{GetDataResult, GetResponse};
use spodes_rs::session::ClientSession;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::{NetworkTransport, PhysicalTransport};

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

fn main() -> io::Result<()> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4059".into());
    println!("Connecting to {addr}...");

    let stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

    let transport = TcpTransport(stream);
    // Client uses source port 1000, destination port 4059 (standard DLMS port).
    let link = Wrapper::new(transport, 1000, 4059);
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
