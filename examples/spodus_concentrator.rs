//! End-to-end СПОДУС (СТО 34.01-5.1-013-2023) example: an ИВКЭ concentrator
//! aggregating three meters and giving the head-end both aggregated access and
//! transparent pass-through to an individual meter.
//!
//! Each downstream meter is a СПОДЭС DLMS server built exactly like the
//! `server_dispatch` example on the main branch (a `RequestDispatcher` holding
//! the meter's COSEM objects).
//!
//! Run with: `cargo run --example spodus_concentrator`

use std::io;

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::get::{GetDataResult, GetRequest, GetResponse};
use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor};
use spodes_rs::session::ClientSession;
use spodes_rs::spodus::collect::poll_meter;
use spodes_rs::spodus::meter::{MeterChannel, MeterDescriptor};
use spodes_rs::spodus::node::Concentrator;
use spodes_rs::spodus::proxy::{DirectChannel, MeterProxy};
use spodes_rs::transport::DataLinkLayer;
use spodes_rs::types::CosemDataType;

fn serial_obis() -> ObisCode {
    ObisCode::new(0, 0, 96, 1, 0, 255) // device serial number
}

fn energy_obis() -> ObisCode {
    ObisCode::new(1, 0, 1, 8, 0, 255) // active energy import
}

/// A СПОДЭС meter: a DLMS server exposing a serial number and an energy
/// register — the same meter model as `examples/server_dispatch.rs` on main.
fn spodes_meter(serial: &str, energy: u32) -> RequestDispatcher {
    let mut meter = RequestDispatcher::new();
    meter.add(Box::new(Data::new(serial_obis(), CosemDataType::OctetString(serial.as_bytes().to_vec()))));
    meter.add(Box::new(Data::new(energy_obis(), CosemDataType::DoubleLongUnsigned(energy))));
    meter
}

/// A loopback link: forwards each request APDU to a local meter server.
struct LocalLink {
    server: RequestDispatcher,
    pending: Option<Vec<u8>>,
}

impl DataLinkLayer for LocalLink {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        self.pending = Some(self.server.dispatch(apdu).expect("meter dispatch"));
        Ok(())
    }
    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.pending.take().expect("a meter response"))
    }
}

fn main() {
    // Three meters served by the concentrator (meter_id, energy, direct_id).
    let meters = [("SIT12260001", 100_000u32, 200u16), ("SIT12260002", 200_000, 201), ("SIT12260003", 300_000, 202)];

    // Build the ИВКЭ concentrator: nameplate, meter registry, direct-channel table.
    let mut node = Concentrator::new();
    node.nameplate.serial_number = "IVKE-0001".to_string();
    node.nameplate.spodus_version = "СТО 34.01-5.1-013-2023".to_string();

    let mut links = Vec::new();

    for (serial, energy, direct_id) in meters {
        let meter_id = serial.as_bytes().to_vec();
        node.meters.add(MeterDescriptor {
            meter_id: meter_id.clone(),
            meter_model: b"SiT".to_vec(),
            channels: vec![MeterChannel { id: 1, address: vec![] }],
        });
        node.direct_channels.add(DirectChannel { direct_id, meter_id: meter_id.clone(), channel_id: 1 });

        // Downstream: poll the meter's energy register into the aggregation cache.
        let link = LocalLink { server: spodes_meter(serial, energy), pending: None };
        let mut session = ClientSession::new(link);
        poll_meter(&mut session, &mut node.meters, &meter_id, &[(1, energy_obis(), 2)]);

        // Reclaim the link for the pass-through proxy.
        links.push((meter_id, session.into_inner()));
    }

    // The pass-through proxy uses the concentrator's direct-channel table.
    let mut proxy = MeterProxy::new(node.direct_channels.clone());
    for (meter_id, link) in links {
        proxy.attach(meter_id, link);
    }

    // --- Upstream: the head-end reads aggregated data from the concentrator ---
    let mut dispatcher = node.dispatcher();
    let list = get(&mut dispatcher, 1, spodes_rs::spodus::obis::meter_list(), 2);
    if let GetResponse::Normal { result: GetDataResult::Data(CosemDataType::Array(rows)), .. } = list {
        println!("ИВКЭ serves {} meters", rows.len());
    }
    println!("Aggregated energy (read once, served from cache):");
    for (serial, _, _) in meters {
        let cached = node.meters.cached(serial.as_bytes(), &energy_obis(), 2);
        println!("  {serial}: {cached:?}");
    }

    // --- Pass-through: the head-end reaches meter #2 directly via direct_id 201 ---
    let request = GetRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(1, true, true),
        attribute: AttributeDescriptor::new(1, energy_obis(), 2),
        access_selection: None,
    };
    let response = proxy.forward(201, &request.encode().unwrap()).expect("proxied GET");
    if let GetResponse::Normal { result: GetDataResult::Data(value), .. } = GetResponse::decode(&response).unwrap() {
        println!("Pass-through GET to meter via direct_id 201: {value:?}");
    }
}

/// Sends a GET-REQUEST-NORMAL to a dispatcher and decodes the response.
fn get(dispatcher: &mut RequestDispatcher, class_id: u16, instance: ObisCode, attr: i8) -> GetResponse {
    let request = GetRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(1, true, true),
        attribute: AttributeDescriptor::new(class_id, instance, attr),
        access_selection: None,
    };
    GetResponse::decode(&dispatcher.dispatch(&request.encode().unwrap()).unwrap()).unwrap()
}
