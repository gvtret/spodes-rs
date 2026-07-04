//! Integration test: an ИВКЭ concentrator bound to three СПОДЭС meters.
//!
//! Exercises the full binding — downstream polling/aggregation, upstream
//! head-end reads of the ИВКЭ object catalogue, and transparent pass-through to
//! each meter by its `direct_id`.

use std::io;

use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::service::action::{ActionRequest, ActionResponse};
use spodes_rs::service::get::{GetDataResult, GetRequest, GetResponse};
use spodes_rs::service::{invoke_id_and_priority, AttributeDescriptor, MethodDescriptor};
use spodes_rs::session::ClientSession;
use spodes_rs::spodus::collect::poll_meter;
use spodes_rs::spodus::meter::{MeterChannel, MeterDescriptor};
use spodes_rs::spodus::node::Concentrator;
use spodes_rs::spodus::obis;
use spodes_rs::spodus::proxy::{DirectChannel, MeterProxy};
use spodes_rs::transport::DataLinkLayer;
use spodes_rs::types::CosemDataType;

fn energy_obis() -> ObisCode {
    ObisCode::new(1, 0, 1, 8, 0, 255)
}

/// A СПОДЭС meter server (serial + energy register), as in `server_dispatch`.
fn spodes_meter(serial: &str, energy: u32) -> RequestDispatcher {
    let mut meter = RequestDispatcher::new();
    meter.add(Box::new(Data::new(ObisCode::new(0, 0, 96, 1, 0, 255), CosemDataType::OctetString(serial.into()))));
    meter.add(Box::new(Data::new(energy_obis(), CosemDataType::DoubleLongUnsigned(energy))));
    meter
}

/// Loopback link forwarding each request to a local meter server.
struct LocalLink {
    server: RequestDispatcher,
    pending: Option<Vec<u8>>,
}

impl DataLinkLayer for LocalLink {
    fn send_apdu(&mut self, apdu: &[u8]) -> io::Result<()> {
        self.pending = Some(self.server.dispatch(apdu).expect("dispatch"));
        Ok(())
    }
    fn receive_apdu(&mut self) -> io::Result<Vec<u8>> {
        Ok(self.pending.take().expect("response"))
    }
}

fn get(dispatcher: &mut RequestDispatcher, class_id: u16, instance: ObisCode, attr: i8) -> GetResponse {
    let request = GetRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(1, true, true),
        attribute: AttributeDescriptor::new(class_id, instance, attr),
        access_selection: None,
    };
    GetResponse::decode(&dispatcher.dispatch(&request.encode().unwrap()).unwrap()).unwrap()
}

#[test]
fn ivke_binds_three_meters_end_to_end() {
    let meters = [("SIT12260001", 100_000u32, 200u16), ("RIM33644800", 200_000, 201), ("MIR98450034", 300_000, 202)];

    let mut node = Concentrator::new();
    node.nameplate.serial_number = "IVKE-0001".to_string();

    let mut links = Vec::new();
    for (serial, energy, direct_id) in meters {
        let meter_id = serial.as_bytes().to_vec();
        node.meters.add(MeterDescriptor {
            meter_id: meter_id.clone(),
            meter_model: b"model".to_vec(),
            channels: vec![MeterChannel { id: 1, address: vec![] }],
        });
        node.direct_channels.add(DirectChannel { direct_id, meter_id: meter_id.clone(), channel_id: 1 });

        // Downstream poll into the aggregation cache.
        let mut session = ClientSession::new(LocalLink { server: spodes_meter(serial, energy), pending: None });
        let read = poll_meter(&mut session, &mut node.meters, &meter_id, &[(1, energy_obis(), 2)]);
        assert_eq!(read, 1);
        links.push((meter_id, session.into_inner()));
    }

    // Every meter's energy was aggregated.
    for (serial, energy, _) in meters {
        assert_eq!(
            node.meters.cached(serial.as_bytes(), &energy_obis(), 2),
            Some(&CosemDataType::DoubleLongUnsigned(energy))
        );
    }

    // Upstream: the head-end reads the ИВКЭ catalogue.
    let mut dispatcher = node.dispatcher();
    // Meter list — three meters.
    let GetResponse::Normal { result: GetDataResult::Data(CosemDataType::Array(rows)), .. } =
        get(&mut dispatcher, 1, obis::meter_list(), 2)
    else {
        panic!("meter list");
    };
    assert_eq!(rows.len(), 3);
    // Direct-channel table — three entries.
    let GetResponse::Normal { result: GetDataResult::Data(CosemDataType::Array(dc)), .. } =
        get(&mut dispatcher, 1, obis::direct_channel_table(), 2)
    else {
        panic!("direct channel table");
    };
    assert_eq!(dc.len(), 3);
    // Nameplate serial.
    assert_eq!(
        get(&mut dispatcher, 1, obis::serial_number(), 2),
        GetResponse::Normal {
            invoke_id_and_priority: 0xC1,
            result: GetDataResult::Data(CosemDataType::OctetString(b"IVKE-0001".to_vec())),
        }
    );

    // The full Appendix-A catalogue is served: the passport, meter-interaction
    // and journal profiles are all readable, and a standard object (the Clock)
    // is present.
    for code in [
        obis::nameplate_profile(),
        obis::channel_list(),
        obis::meter_status_table(),
        obis::exchange_status_journal(),
        obis::numeric_meter_journal(),
    ] {
        assert!(matches!(
            get(&mut dispatcher, 7, code, 2),
            GetResponse::Normal { result: GetDataResult::Data(CosemDataType::Array(_)), .. }
        ));
    }
    assert!(matches!(
        get(&mut dispatcher, 8, ObisCode::new(0, 0, 1, 0, 0, 255), 1),
        GetResponse::Normal { result: GetDataResult::Data(_), .. }
    ));

    // Group operation (class 8200): the Table manager reports the meter count.
    let action = ActionRequest::Normal {
        invoke_id_and_priority: invoke_id_and_priority(1, true, true),
        method: MethodDescriptor::new(8200, obis::meter_list(), 3),
        parameters: None,
    };
    let ActionResponse::Normal { return_parameters: Some(GetDataResult::Data(count)), .. } =
        ActionResponse::decode(&dispatcher.dispatch(&action.encode().unwrap()).unwrap()).unwrap()
    else {
        panic!("table manager count");
    };
    assert_eq!(count, CosemDataType::Unsigned(3));

    // Pass-through: reach each meter directly and read its energy.
    let mut proxy = MeterProxy::new(node.direct_channels.clone());
    for (meter_id, link) in links {
        proxy.attach(meter_id, link);
    }
    for (_, energy, direct_id) in meters {
        let request = GetRequest::Normal {
            invoke_id_and_priority: invoke_id_and_priority(1, true, true),
            attribute: AttributeDescriptor::new(1, energy_obis(), 2),
            access_selection: None,
        };
        let response = proxy.forward(direct_id, &request.encode().unwrap()).unwrap();
        let GetResponse::Normal { result: GetDataResult::Data(value), .. } = GetResponse::decode(&response).unwrap()
        else {
            panic!("proxied get");
        };
        assert_eq!(value, CosemDataType::DoubleLongUnsigned(energy));
    }
}
