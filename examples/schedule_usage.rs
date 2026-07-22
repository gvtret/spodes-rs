use spodes_rs::classes::schedule::{Schedule, ScheduleConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::ScheduleTableEntry;

fn main() {
    // Build the OBIS code for the Schedule object
    let obis = ObisCode::new(0, 0, 10, 101, 0, 255);

    // Build the list of schedule entries
    let entries = vec![ScheduleTableEntry {
        index: 1,
        enable: true,
        script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
        script_selector: 1,
        switch_time: vec![0x10, 0x00, 0x00], // 16:00:00
        validity_window: 0xFFFF,
        exec_weekdays: vec![0x7F], // every day of the week
        exec_specdays: vec![0x00],
        begin_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF],
        end_date: vec![0x07, 0xE5, 0x12, 0x31, 0xFF],
    }];

    // Build the Schedule configuration
    let config = ScheduleConfig { logical_name: obis.clone(), entries, enabled: true };

    // Build the Schedule object
    let schedule = Schedule::new(config);

    // Check the attributes
    println!("Logical Name: {:?}", schedule.logical_name().to_bytes());
    println!("Entries: {:?}", schedule.attributes()[1].1);
    println!("Enabled: {}", schedule.is_enabled());

    // Serialize the object
    let serialized = serialize_object(&schedule).expect("Serialization failed");
    println!("Serialized data: {serialized:?}");

    // Build a new object for deserialization
    let config = ScheduleConfig { logical_name: obis, entries: vec![], enabled: false };
    let mut deserialized = Schedule::new(config);

    // Deserialize the data
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Check the deserialized object
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Entries: {:?}", deserialized.attributes()[1].1);
    println!("Deserialized Enabled: {}", deserialized.is_enabled());
}
