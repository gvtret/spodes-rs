use spodes_rs::classes::schedule::{Schedule, ScheduleConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::ScheduleTableEntry;

fn main() {
    // Создаём OBIS-код для объекта Schedule
    let obis = ObisCode::new(0, 0, 10, 101, 0, 255);

    // Создаём список записей расписания
    let entries = vec![ScheduleTableEntry {
        index: 1,
        enable: true,
        script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
        script_selector: 1,
        switch_time: vec![0x10, 0x00, 0x00], // 16:00:00
        validity_window: 0xFFFF,
        exec_weekdays: vec![0x7F], // все дни недели
        exec_specdays: vec![0x00],
        begin_date: vec![0x07, 0xE5, 0x01, 0x01, 0xFF],
        end_date: vec![0x07, 0xE5, 0x12, 0x31, 0xFF],
    }];

    // Создаём конфигурацию Schedule
    let config = ScheduleConfig { logical_name: obis.clone(), entries: entries.clone(), enabled: true };

    // Создаём объект Schedule
    let schedule = Schedule::new(config);

    // Проверяем атрибуты
    println!("Logical Name: {:?}", schedule.logical_name().to_bytes());
    println!("Entries: {:?}", schedule.attributes()[1].1);
    println!("Enabled: {}", schedule.is_enabled());

    // Сериализуем объект
    let serialized = serialize_object(&schedule).expect("Serialization failed");
    println!("Serialized data: {:?}", serialized);

    // Создаём новый объект для десериализации
    let config = ScheduleConfig { logical_name: obis.clone(), entries: vec![], enabled: false };
    let mut deserialized = Schedule::new(config);

    // Десериализуем данные
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Проверяем десериализованный объект
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Entries: {:?}", deserialized.attributes()[1].1);
    println!("Deserialized Enabled: {}", deserialized.is_enabled());
}
