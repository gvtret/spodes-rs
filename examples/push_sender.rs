//! Push sender example — simulates a COSEM client that sends push data.
//!
//! Demonstrates how a client would collect data from multiple COSEM objects
//! and prepare it for push transmission. In a real deployment this would be
//! sent over the configured transport to the push destination.

use spodes_rs::classes::data::Data;
use spodes_rs::classes::register::Register;
use spodes_rs::obis::ObisCode;
use spodes_rs::types::attrs::ScalerUnit;
use spodes_rs::types::CosemDataType;

fn main() {
    // 1. Create some COSEM objects to read values from.
    let total_energy = Register::new(
        ObisCode::new(0, 0, 1, 0, 0, 255),
        CosemDataType::DoubleLongUnsigned(1_234_567),
        ScalerUnit::new(-2, 30), // 0.01 kWh
    );

    let status = Data::new(
        ObisCode::new(0, 0, 96, 1, 0, 255),
        CosemDataType::Unsigned(0), // normal
    );

    // 2. Read the values that will be pushed.
    let energy_value = total_energy.value().clone();
    let status_value = status.value().clone();

    println!("Values to push:");
    println!("  total_energy = {energy_value:?}");
    println!("  status       = {status_value:?}");

    // 3. Build the push data structure.
    //    The push data is a structure with one element per entry in push_object_list.
    let push_data = CosemDataType::Structure(vec![energy_value, status_value]);

    println!("\nPush data payload:");
    println!("  {push_data:?}");

    // 4. Serialize the push data for transmission.
    let mut buf = Vec::new();
    push_data.serialize_ber(&mut buf).unwrap();
    println!("\nSerialized push data: {} bytes", buf.len());
    println!("  hex: {}", hex_string(&buf));

    // 5. In a real implementation, this buffer would be sent over TCP/UDP/SMS
    //    to the destination configured in the Push Setup object.
    println!("\n(In a real deployment, this {}-byte payload would be sent to the push destination)", buf.len());
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}
