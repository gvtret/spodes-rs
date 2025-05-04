use spodes_rs::interface::InterfaceClass;
use spodes_rs::classes::schedule::{Schedule, ScheduleConfig};
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    // Создаём OBIS-код для объекта Schedule
    let obis = ObisCode::new(0, 0, 10, 101, 0, 255);

    // Создаём список записей расписания
    // Каждая запись — структура с DateTime и действием (ссылка на ScriptTable)
    let entries = vec![CosemDataType::Structure(vec![
        // DateTime: 2025-05-01 16:00:00
        CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
            0x02,                   // День недели: вторник
            0x10, 0x00, 0x00,      // Час: 16, Минуты: 0, Секунды: 0
            0x00,                   // Сотые доли секунды: 0
            0x00, 0x00, 0x00,      // Отклонение от UTC: 0
        ]),
        // Действие: вызов метода execute объекта ScriptTable
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(9), // class_id: ScriptTable
            CosemDataType::OctetString(vec![0, 0, 10, 100, 0, 255]), // logical_name
            CosemDataType::Integer(1),      // method_index: execute
            CosemDataType::LongUnsigned(1), // parameter: script_identifier
        ]),
    ])];

    // Создаём конфигурацию Schedule
    let config = ScheduleConfig {
        logical_name: obis.clone(),
        entries: entries.clone(),
        enabled: true,
    };

    // Создаём объект Schedule
    let mut schedule = Schedule::new(config);

    // Проверяем атрибуты
    println!("Logical Name: {:?}", schedule.logical_name().to_bytes());
    println!("Entries: {:?}", schedule.attributes()[1].1);
    println!("Enabled: {}", schedule.is_enabled());

    // Сериализуем объект
    let serialized = serialize_object(&schedule).expect("Serialization failed");
    println!("Serialized data: {:?}", serialized);

    // Создаём новый объект для десериализации
    let config = ScheduleConfig {
        logical_name: obis.clone(),
        entries: vec![],
        enabled: false,
    };
    let mut deserialized = Schedule::new(config);

    // Десериализуем данные
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Проверяем десериализованный объект
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Entries: {:?}", deserialized.attributes()[1].1);
    println!("Deserialized Enabled: {}", deserialized.is_enabled());

    // Вызываем метод enable
    let result = schedule.invoke_method(1, None).expect("Enable method failed");
    println!("Enable result: {:?}", result);
    println!("Enabled after enable: {}", schedule.is_enabled());

    // Вызываем метод disable
    let result = schedule.invoke_method(2, None).expect("Disable method failed");
    println!("Disable result: {:?}", result);
    println!("Enabled after disable: {}", schedule.is_enabled());
}