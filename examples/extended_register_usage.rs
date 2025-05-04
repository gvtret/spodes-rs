use spodes_rs::classes::extended_register::ExtendedRegister;
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    // Создаём OBIS-код для ExtendedRegister
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);

    // Инициализируем ExtendedRegister
    let mut extended_register = ExtendedRegister::new(
        obis.clone(),
        CosemDataType::DoubleLong(2000), // Значение: 2000
        CosemDataType::OctetString(vec![0x00, 0x1B]), // Единица: Wh
        CosemDataType::Unsigned(1), // Статус: действительное измерение
        CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
            0x02, // День недели: вторник
            0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
            0x00, // Сотые доли секунды: 0
            0x00, 0x00, 0x00, // Отклонение от UTC: 0
        ]),
    );

    // Выводим начальные атрибуты
    println!("Initial attributes:");
    for (id, value) in extended_register.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }

    // Выполняем метод reset
    match extended_register.invoke_method(1, None) {
        Ok(result) => println!("Reset result: {:?}", result),
        Err(e) => println!("Reset failed: {}", e),
    }

    // Выводим атрибуты после reset
    println!("\nAttributes after reset:");
    for (id, value) in extended_register.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }

    // Выполняем метод capture
    match extended_register.invoke_method(2, None) {
        Ok(result) => println!("Capture result: {:?}", result),
        Err(e) => println!("Capture failed: {}", e),
    }

    // Выводим атрибуты после capture
    println!("\nAttributes after capture:");
    for (id, value) in extended_register.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }

    // Сериализация и десериализация
    let serialized = serialize_object(&extended_register).expect("Serialization failed");
    let mut deserialized = ExtendedRegister::new(
        obis.clone(),
        CosemDataType::Null,
        CosemDataType::Null,
        CosemDataType::Null,
        CosemDataType::Null,
    );
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Выводим атрибуты после десериализации
    println!("\nAttributes after deserialization:");
    for (id, value) in deserialized.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }
}