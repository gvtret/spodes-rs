//! End-to-end example: a `ClientSession` talking to a `RequestDispatcher`
//! through an in-memory loopback data-link layer.
//!
//! Run with: `cargo run --example client_session`

use std::io;

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::get::{GetDataResult, GetResponse};
use spodes_rs::session::ClientSession;
use spodes_rs::transport::DataLinkLayer;
use spodes_rs::types::CosemDataType;

/// A loopback link: every APDU the client sends is dispatched by a local server
/// and its response is handed back on the next receive.
struct LocalLink {
    server: RequestDispatcher,
    pending: Option<Vec<u8>>,
}

impl DataLinkLayer for LocalLink {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        let response = self.server.dispatch(apdu).expect("dispatch");
        self.pending = Some(response);
        Ok(())
    }

    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.pending.take().expect("a response was produced"))
    }
}

fn main() {
    // Build the server side: a dispatcher holding one Data object.
    let mut server = RequestDispatcher::new();
    let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF); // active energy import
    server.add(Box::new(Data::new(obis.clone(), CosemDataType::DoubleLongUnsigned(123_456))));

    // Drive it from the client side over the loopback link.
    let link = LocalLink { server, pending: None };
    let mut session = ClientSession::new(link);

    // GET the value attribute (attribute 2) of the Data object (class_id 1).
    match session.get(1, obis, 2) {
        Ok(GetResponse::Normal { result: GetDataResult::Data(value), .. }) => {
            println!("GET value = {value:?}");
        }
        other => println!("unexpected response: {other:?}"),
    }
}
