use spodes_rs::classes::extended_register::ExtendedRegister;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::{DateTime, ScalerUnit};
use spodes_rs::types::CosemDataType;

fn main() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);

    let mut extended_register = ExtendedRegister::new(
        obis.clone(),
        CosemDataType::DoubleLong(2000),
        ScalerUnit::new(0, 0x1B),
        CosemDataType::Unsigned(1),
        DateTime::new([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00]),
    );

    // Выводим начальные атрибуты
    println!("Initial attributes:");
    for (id, value) in extended_register.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Выполняем метод reset
    match extended_register.invoke_method(1, None) {
        Ok(result) => println!("Reset result: {result:?}"),
        Err(e) => println!("Reset failed: {e}"),
    }

    // Выводим атрибуты после reset
    println!("\nAttributes after reset:");
    for (id, value) in extended_register.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Выполняем метод capture
    match extended_register.invoke_method(2, None) {
        Ok(result) => println!("Capture result: {result:?}"),
        Err(e) => println!("Capture failed: {e}"),
    }

    // Выводим атрибуты после capture
    println!("\nAttributes after capture:");
    for (id, value) in extended_register.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Сериализация и десериализация
    let serialized = serialize_object(&extended_register).expect("Serialization failed");
    let mut deserialized = ExtendedRegister::new(
        obis.clone(),
        CosemDataType::Null,
        ScalerUnit::new(0, 0),
        CosemDataType::Null,
        DateTime::new([0u8; 12]),
    );
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Выводим атрибуты после десериализации
    println!("\nAttributes after deserialization:");
    for (id, value) in deserialized.attributes() {
        println!("Attribute {id}: {value:?}");
    }
}
