use spodes_rs::classes::register_activation::{RegisterActivation, RegisterActivationConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::{ObjectDefinition, RegisterActMask};
use spodes_rs::types::CosemDataType;

fn main() {
    // Создаём OBIS-код для RegisterActivation
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);

    // Инициализируем конфигурацию RegisterActivation
    let config = RegisterActivationConfig {
        logical_name: obis.clone(),
        register_assignment: vec![ObjectDefinition {
            class_id: 3, // Register
            logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
        }],
        mask_list: vec![RegisterActMask {
            mask_name: vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31], // "TARIFF1"
            index_list: vec![1],
        }],
        active_mask: vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31], // "TARIFF1"
    };

    // Создаём объект RegisterActivation
    let mut register_activation = RegisterActivation::new(config);

    // Выводим начальные атрибуты
    println!("Initial attributes:");
    for (id, value) in register_activation.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Добавляем новую маску
    let new_mask = CosemDataType::Structure(vec![
        CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x32]), // mask_name: "TARIFF2"
        CosemDataType::Array(vec![CosemDataType::Unsigned(2)]),                     // register_indices
    ]);
    match register_activation.invoke_method(1, Some(new_mask)) {
        Ok(result) => println!("Add mask result: {result:?}"),
        Err(e) => println!("Add mask failed: {e}"),
    }

    // Выводим атрибуты после добавления маски
    println!("\nAttributes after adding mask:");
    for (id, value) in register_activation.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Удаляем маску "TARIFF1"
    let mask_name = CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]);
    match register_activation.invoke_method(2, Some(mask_name)) {
        Ok(result) => println!("Delete mask result: {result:?}"),
        Err(e) => println!("Delete mask failed: {e}"),
    }

    // Выводим атрибуты после удаления маски
    println!("\nAttributes after deleting mask:");
    for (id, value) in register_activation.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Сериализация и десериализация
    let serialized = serialize_object(&register_activation).expect("Serialization failed");
    let config = RegisterActivationConfig {
        logical_name: obis,
        register_assignment: vec![],
        mask_list: vec![],
        active_mask: vec![],
    };
    let mut deserialized = RegisterActivation::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Выводим атрибуты после десериализации
    println!("\nAttributes after deserialization:");
    for (id, value) in deserialized.attributes() {
        println!("Attribute {id}: {value:?}");
    }
}
