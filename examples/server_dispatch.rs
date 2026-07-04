//! Example: a server-side `RequestDispatcher` answering GET and ACTION request
//! APDUs for a small set of COSEM objects.
//!
//! Run with: `cargo run --example server_dispatch`

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::get::{GetRequest, GetResponse};
use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor};
use spodes_rs::types::CosemDataType;

fn main() {
    // Register two Data objects with the dispatcher.
    let mut server = RequestDispatcher::new();
    let serial = ObisCode::new(0, 0, 96, 1, 0, 0xFF); // device serial number
    let energy = ObisCode::new(1, 0, 1, 8, 0, 0xFF); // active energy import
    server.add(Box::new(Data::new(serial.clone(), CosemDataType::OctetString(b"MTR-0001".to_vec()))));
    server.add(Box::new(Data::new(energy.clone(), CosemDataType::DoubleLongUnsigned(123_456))));

    // A GET-REQUEST-NORMAL for the energy value (class_id 1, attribute 2).
    let request = GetRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(1, true, true),
        attribute: AttributeDescriptor::new(1, energy, 2),
        access_selection: None,
    };

    let response_bytes = server.dispatch(&request.encode().unwrap()).unwrap();
    match GetResponse::decode(&response_bytes).unwrap() {
        GetResponse::Normal { result, .. } => println!("server answered: {result:?}"),
        other => println!("unexpected: {other:?}"),
    }

    // A GET for an object that is not registered yields object-undefined.
    let missing = GetRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(2, true, true),
        attribute: AttributeDescriptor::new(1, ObisCode::new(9, 9, 9, 9, 9, 9), 2),
        access_selection: None,
    };
    let bytes = server.dispatch(&missing.encode().unwrap()).unwrap();
    println!("missing object → {:?}", GetResponse::decode(&bytes).unwrap());
}
