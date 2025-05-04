use spodes_rs::classes::demand_register::{DemandRegister, DemandRegisterConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    // Создаём OBIS-код для DemandRegister
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);

    // Инициализируем конфигурацию DemandRegister
    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: CosemDataType::DoubleLong(3000), // Текущее значение: 3000
        last_average_value: CosemDataType::DoubleLong(2500), // Последнее значение: 2500
        scaler_unit: CosemDataType::OctetString(vec![0x00, 0x1B]), // Единица: Wh
        status: CosemDataType::Unsigned(1), // Статус: действительное измерение
        capture_time: CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
            0x02, // День недели: вторник
            0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
            0x00, // Сотые доли секунды: 0
            0x00, 0x00, 0x00, // Отклонение от UTC: 0
        ]),
        start_time_current: CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
            0x02, // День недели: вторник
            0x10, 0x00, 0x00, // Час: 16, Минуты: 0, Секунды: 0
            0x00, // Сотые доли секунды: 0
            0x00, 0x00, 0x00, // Отклонение от UTC: 0
        ]),
        period: CosemDataType::DoubleLongUnsigned(3600), // Период: 1 час
        number_of_periods: CosemDataType::LongUnsigned(24), // 24 периода в сутки
    };

    // Создаём объект DemandRegister
    let mut demand_register = DemandRegister::new(config);

    // Выводим начальные атрибуты
    println!("Initial attributes:");
    for (id, value) in demand_register.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }

    // Выполняем метод reset
    match demand_register.invoke_method(1, None) {
        Ok(result) => println!("Reset result: {:?}", result),
        Err(e) => println!("Reset failed: {}", e),
    }

    // Выводим атрибуты после reset
    println!("\nAttributes after reset:");
    for (id, value) in demand_register.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }

    // Выполняем метод next_period
    match demand_register.invoke_method(2, None) {
        Ok(result) => println!("Next period result: {:?}", result),
        Err(e) => println!("Next period failed: {}", e),
    }

    // Выводим атрибуты после next_period
    println!("\nAttributes after next_period:");
    for (id, value) in demand_register.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }

    // Сериализация и десериализация
    let serialized = serialize_object(&demand_register).expect("Serialization failed");
    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: CosemDataType::Null,
        last_average_value: CosemDataType::Null,
        scaler_unit: CosemDataType::Null,
        status: CosemDataType::Null,
        capture_time: CosemDataType::Null,
        start_time_current: CosemDataType::Null,
        period: CosemDataType::Null,
        number_of_periods: CosemDataType::Null,
    };
    let mut deserialized = DemandRegister::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Выводим атрибуты после десериализации
    println!("\nAttributes after deserialization:");
    for (id, value) in deserialized.attributes() {
        println!("Attribute {}: {:?}", id, value);
    }
}