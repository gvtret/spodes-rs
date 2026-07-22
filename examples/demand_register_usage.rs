use spodes_rs::classes::demand_register::{DemandRegister, DemandRegisterConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::{DateTime, ScalerUnit};
use spodes_rs::types::CosemDataType;

fn main() {
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);

    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: CosemDataType::DoubleLong(3000),
        last_average_value: CosemDataType::DoubleLong(2500),
        scaler_unit: ScalerUnit::new(0, 0x1B),
        status: CosemDataType::Unsigned(1),
        capture_time: DateTime::new([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00]),
        start_time_current: DateTime::new([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        period: 3600,
        number_of_periods: 24,
    };

    // Создаём объект DemandRegister
    let mut demand_register = DemandRegister::new(config);

    // Выводим начальные атрибуты
    println!("Initial attributes:");
    for (id, value) in demand_register.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Выполняем метод reset
    match demand_register.invoke_method(1, None) {
        Ok(result) => println!("Reset result: {result:?}"),
        Err(e) => println!("Reset failed: {e}"),
    }

    // Выводим атрибуты после reset
    println!("\nAttributes after reset:");
    for (id, value) in demand_register.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Выполняем метод next_period
    match demand_register.invoke_method(2, None) {
        Ok(result) => println!("Next period result: {result:?}"),
        Err(e) => println!("Next period failed: {e}"),
    }

    // Выводим атрибуты после next_period
    println!("\nAttributes after next_period:");
    for (id, value) in demand_register.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Сериализация и десериализация
    let serialized = serialize_object(&demand_register).expect("Serialization failed");
    let config = DemandRegisterConfig {
        logical_name: obis,
        current_average_value: CosemDataType::Null,
        last_average_value: CosemDataType::Null,
        scaler_unit: ScalerUnit::new(0, 0),
        status: CosemDataType::Null,
        capture_time: DateTime::new([0u8; 12]),
        start_time_current: DateTime::new([0u8; 12]),
        period: 0,
        number_of_periods: 0,
    };
    let mut deserialized = DemandRegister::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Выводим атрибуты после десериализации
    println!("\nAttributes after deserialization:");
    for (id, value) in deserialized.attributes() {
        println!("Attribute {id}: {value:?}");
    }
}
