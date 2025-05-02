use spodes_rs::classes::data::Data;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    let obis = ObisCode::new(0, 0, 96, 1, 0, 255);
    let value = CosemDataType::Integer(42);
    let data = Data::new(obis.clone(), value);

    println!("Data object: {:?}", data);
    println!("Logical name: {}", data.logical_name());
    println!("Class ID: {}", data.class_id());
    println!("Version: {}", data.version());

    let serialized = serialize_object(&data).expect("Serialization failed");
    println!("Serialized data: {:?}", serialized);

    let mut deserialized = Data::new(obis, CosemDataType::Null);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    println!("Deserialized data: {:?}", deserialized);
}
