use spodes_rs::interface::InterfaceClass;
use spodes_rs::classes::script_table::{ScriptTable, ScriptTableConfig};
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;

fn main() {
    // Создаём OBIS-код для объекта ScriptTable
    let obis = ObisCode::new(0, 0, 10, 100, 0, 255);

    // Создаём список скриптов
    // Каждый скрипт — структура с идентификатором и действием
    let scripts = vec![CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1), // script_identifier
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(3), // class_id: Register
            CosemDataType::OctetString(vec![1, 0, 1, 8, 0, 255]), // logical_name
            CosemDataType::Integer(1), // method_index: reset
        ]), // action
    ])];

    // Создаём конфигурацию ScriptTable
    let config = ScriptTableConfig {
        logical_name: obis.clone(),
        scripts: scripts.clone(),
    };

    // Создаём объект ScriptTable
    let mut script_table = ScriptTable::new(config);

    // Проверяем атрибуты
    println!("Logical Name: {:?}", script_table.logical_name().to_bytes());
    println!("Scripts: {:?}", script_table.attributes()[1].1);

    // Сериализуем объект
    let serialized = serialize_object(&script_table).expect("Serialization failed");
    println!("Serialized data: {:?}", serialized);

    // Создаём новый объект для десериализации
    let config = ScriptTableConfig {
        logical_name: obis.clone(),
        scripts: vec![],
    };
    let mut deserialized = ScriptTable::new(config);

    // Десериализуем данные
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Проверяем десериализованный объект
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Scripts: {:?}", deserialized.attributes()[1].1);

    // Вызываем метод execute для скрипта с идентификатором 1
    let script_id = CosemDataType::LongUnsigned(1);
    let result = script_table
        .invoke_method(1, Some(script_id))
        .expect("Execute script failed");
    println!("Execute script result: {:?}", result);

    // Проверяем выполнение несуществующего скрипта
    let invalid_script_id = CosemDataType::LongUnsigned(2);
    let result = script_table.invoke_method(1, Some(invalid_script_id));
    match result {
        Ok(_) => println!("Unexpected success for invalid script"),
        Err(e) => println!("Expected error for invalid script: {}", e),
    }
}