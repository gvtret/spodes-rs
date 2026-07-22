//! Push listener example — simulates a COSEM server that can be pushed to.
//!
//! Demonstrates how to configure a `Push Setup` object and trigger a push
//! operation. In a real deployment the push data would be sent over the
//! configured transport (TCP, UDP, SMS, …).

use spodes_rs::classes::push_setup::{PushSetup, PushSetupConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::types::attrs::{
    CaptureObjectDefinition, CommunicationWindow, ConfirmationParameters, DateTime, SendDestinationAndMethod,
};
use spodes_rs::types::CosemDataType;

fn main() {
    // 1. Configure the push destination: TCP to 192.168.1.100:4059, A-XDR encoding.
    let send_dest = SendDestinationAndMethod {
        transport_service: 0, // TCP
        destination: b"192.168.1.100:4059".to_vec(),
        message: 2, // A-XDR encoded xDLMS APDU
    };

    // 2. Define a communication window: push is only allowed between 08:00 and 18:00.
    let window = CommunicationWindow {
        begin: DateTime::from_ymdhms(2025, 1, 1, 8, 0, 0),
        end: DateTime::from_ymdhms(2025, 12, 31, 18, 0, 0),
    };

    // 3. The objects whose values will be pushed.
    //    Each entry is { class_id, logical_name, attribute_index, data_index }.
    let push_objects = vec![
        CaptureObjectDefinition::new(3, ObisCode::new(0, 0, 1, 0, 0, 255), 2, 0), // Register class, attr 2
        CaptureObjectDefinition::new(1, ObisCode::new(0, 0, 96, 1, 0, 255), 2, 0), // Data class, attr 2
    ];

    // 4. Build the Push Setup object.
    let config = PushSetupConfig {
        logical_name: ObisCode::new(0, 0, 25, 1, 0, 255),
        version: 0,
        push_object_list: push_objects,
        send_destination_and_method: send_dest,
        communication_window: vec![window],
        randomisation_start_interval: 30,
        number_of_retries: 3,
        repetition_delay: CosemDataType::LongUnsigned(60),
        port_reference: vec![],
        push_client_sap: 0,
        push_protection_parameters: vec![],
        push_operation_method: 0,
        confirmation_parameters: ConfirmationParameters { data: vec![] },
        last_confirmation_date_time: DateTime::new([0u8; 12]),
    };

    let mut push = PushSetup::new(config);

    println!("Push Setup object created:");
    println!("  class_id:    {}", push.class_id());
    println!("  logical_name:{}", push.logical_name());
    println!("  version:     {}", push.version());
    println!("  attributes:  {}", push.attributes().len());

    // 5. Trigger the push operation.
    let result = push.invoke_method(1, Some(CosemDataType::Integer(0)));
    match result {
        Ok(CosemDataType::Null) => println!("Push triggered successfully (transport not implemented yet)."),
        Ok(other) => println!("Push returned unexpected: {other:?}"),
        Err(e) => println!("Push failed: {e}"),
    }

    // 6. Show the serialized representation.
    let mut buf = Vec::new();
    push.serialize_ber(&mut buf).unwrap();
    println!("  serialized: {} bytes", buf.len());
}
