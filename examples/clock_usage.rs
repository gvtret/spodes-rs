use spodes_rs::classes::clock::{Clock, ClockConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x25, 0x12, // Час: 16, Минуты: 37, Секунды: 12
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let config = ClockConfig {
        logical_name: obis.clone(),
        time: time.clone(),
        time_zone: CosemDataType::Long(180), // +3 часа от UTC
        status: CosemDataType::Unsigned(1), // Действительное время
        daylight_savings_begin: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_end: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_deviation: CosemDataType::Integer(60), // +1 час
        daylight_savings_enabled: CosemDataType::Boolean(true),
        clock_base: CosemDataType::Unsigned(2), // Внешний источник
    };
    let mut clock = Clock::new(config);
    
    println!("Clock object: {:?}", clock);
    println!("Logical name: {}", clock.logical_name());
    println!("Class ID: {}", clock.class_id());
    println!("Version: {}", clock.version());
    
    let serialized = serialize_object(&clock).expect("Serialization failed");
    println!("Serialized clock: {:?}", serialized);
    
    let config = ClockConfig {
        logical_name: obis.clone(),
        time: CosemDataType::Null,
        time_zone: CosemDataType::Null,
        status: CosemDataType::Null,
        daylight_savings_begin: CosemDataType::Null,
        daylight_savings_end: CosemDataType::Null,
        daylight_savings_deviation: CosemDataType::Null,
        daylight_savings_enabled: CosemDataType::Null,
        clock_base: CosemDataType::Null,
    };
    let mut deserialized = Clock::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    println!("Deserialized clock: {:?}", deserialized);
    
    let result = clock.invoke_method(1, None).expect("Adjust to quarter failed");
    println!("Adjust to quarter result: {:?}", result);
    println!("Clock after adjust to quarter: {:?}", clock);
    
    let new_time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x02, // Год: 2025, Месяц: 5, День: 2
        0x03, // День недели: среда
        0x12, 0x00, 0x00, // Час: 18, Минуты: 0, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let result = clock.invoke_method(3, Some(new_time)).expect("Adjust to preset time failed");
    println!("Adjust to preset time result: {:?}", result);
    println!("Clock after adjust to preset time: {:?}", clock);
}