use spodes_rs::classes::register::Register;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 255);
    let value = CosemDataType::DoubleLong(1000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let mut register = Register::new(obis.clone(), value, scaler_unit);

    println!("Register object: {:?}", register);
    println!("Logical name: {}", register.logical_name());
    println!("Class ID: {}", register.class_id());
    println!("Version: {}", register.version());

    let serialized = serialize_object(&register).expect("Serialization failed");
    println!("Serialized register: {:?}", serialized);

    let mut deserialized = Register::new(obis, CosemDataType::Null, CosemDataType::Null);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    println!("Deserialized register: {:?}", deserialized);

    let reset_result = register
        .invoke_method(1, None)
        .expect("Reset method failed");
    println!("Reset result: {:?}", reset_result);
    println!("Register after reset: {:?}", register);
}
