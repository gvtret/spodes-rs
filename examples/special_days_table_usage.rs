use spodes_rs::classes::special_days_table::{SpecialDaysTable, SpecialDaysTableConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    // Создаём OBIS-код для объекта SpecialDaysTable
    let obis = ObisCode::new(0, 0, 11, 102, 0, 255);

    // Создаём список особых дней
    let entries = vec![CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x01, 0x01, // Год: 2025, Месяц: 1, День: 1
        0x02,                   // День недели: вторник
        0x00, 0x00, 0x00,      // Час: 0, Минуты: 0, Секунды: 0
        0x00,                   // Сотые доли секунды: 0
        0x00, 0x00, 0x00,      // Отклонение от UTC: 0
    ])];

    // Создаём конфигурацию SpecialDaysTable
    let config = SpecialDaysTableConfig {
        logical_name: obis.clone(),
        entries: entries.clone(),
    };

    // Создаём объект SpecialDaysTable
    let mut special_days_table = SpecialDaysTable::new(config);

    // Проверяем атрибуты
    println!("Logical Name: {:?}", special_days_table.logical_name().to_bytes());
    println!("Entries: {:?}", special_days_table.attributes()[1].1);

    // Сериализуем объект
    let serialized = serialize_object(&special_days_table).expect("Serialization failed");
    println!("Serialized data: {:?}", serialized);

    // Создаём новый объект для десериализации
    let config = SpecialDaysTableConfig {
        logical_name: obis.clone(),
        entries: vec![],
    };
    let mut deserialized = SpecialDaysTable::new(config);

    // Десериализуем данные
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Проверяем десериализованный объект
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Entries: {:?}", deserialized.attributes()[1].1);

    // Добавляем новую дату (25 декабря 2025)
    let new_date = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x12, 0x25, // Год: 2025, Месяц: 12, День: 25
        0x04,                   // День недели: четверг
        0x00, 0x00, 0x00,      // Час: 0, Минуты: 0, Секунды: 0
        0x00,                   // Сотые доли секунды: 0
        0x00, 0x00, 0x00,      // Отклонение от UTC: 0
    ]);
    let result = special_days_table
        .invoke_method(1, Some(new_date.clone()))
        .expect("Insert method failed");
    println!("Insert result: {:?}", result);
    if let CosemDataType::Array(entries) = &special_days_table.attributes()[1].1 {
        println!("Entries after insert: {:?}", entries);
        assert_eq!(entries.len(), 2);
    }

    // Удаляем дату (1 января 2025)
    let result = special_days_table
        .invoke_method(2, Some(entries[0].clone()))
        .expect("Delete method failed");
    println!("Delete result: {:?}", result);
    if let CosemDataType::Array(entries) = &special_days_table.attributes()[1].1 {
        println!("Entries after delete: {:?}", entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], new_date);
    }
}