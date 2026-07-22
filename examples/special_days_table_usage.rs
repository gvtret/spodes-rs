use spodes_rs::classes::special_days_table::{SpecialDaysTable, SpecialDaysTableConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::SpecialDayEntry;
use spodes_rs::types::CosemDataType;

fn main() {
    // Build the OBIS code for the SpecialDaysTable object
    let obis = ObisCode::new(0, 0, 11, 102, 0, 255);

    // Build the list of special days
    let entries = vec![SpecialDayEntry {
        index: 1,
        specialday_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF, 0xFF, 0xFF], // 1 January 2025
        day_id: 1,
    }];

    // Build the SpecialDaysTable configuration
    let config = SpecialDaysTableConfig { logical_name: obis.clone(), entries };

    // Build the SpecialDaysTable object
    let mut special_days_table = SpecialDaysTable::new(config);

    // Check the attributes
    println!("Logical Name: {:?}", special_days_table.logical_name().to_bytes());
    println!("Entries: {:?}", special_days_table.attributes()[1].1);

    // Serialize the object
    let serialized = serialize_object(&special_days_table).expect("Serialization failed");
    println!("Serialized data: {serialized:?}");

    // Build a new object for deserialization
    let config = SpecialDaysTableConfig { logical_name: obis, entries: vec![] };
    let mut deserialized = SpecialDaysTable::new(config);

    // Deserialize the data
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Check the deserialized object
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Entries: {:?}", deserialized.attributes()[1].1);

    // Add a new date (25 December 2025)
    let new_date = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(2),                                             // index
        CosemDataType::OctetString(vec![0x07, 0xE5, 0x12, 0x25, 0xFF, 0xFF, 0xFF]), // 25 December 2025
        CosemDataType::Unsigned(2),                                                 // day_id
    ]);
    let result = special_days_table.invoke_method(1, Some(new_date)).expect("Insert method failed");
    println!("Insert result: {result:?}");
    if let CosemDataType::Array(items) = &special_days_table.attributes()[1].1 {
        println!("Entries after insert: {:?}", items.len());
        assert_eq!(items.len(), 2);
    }

    // Delete a date (1 January 2025)
    let delete_data = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::OctetString(vec![0x07, 0xE5, 0x01, 0x01, 0xFF, 0xFF, 0xFF]),
        CosemDataType::Unsigned(1),
    ]);
    let result = special_days_table.invoke_method(2, Some(delete_data)).expect("Delete method failed");
    println!("Delete result: {result:?}");
    if let CosemDataType::Array(items) = &special_days_table.attributes()[1].1 {
        println!("Entries after delete: {:?}", items.len());
        assert_eq!(items.len(), 1);
    }
}
