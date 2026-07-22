use spodes_rs::classes::register_activation::{RegisterActivation, RegisterActivationConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::{ObjectDefinition, RegisterActMask};
use spodes_rs::types::CosemDataType;

fn main() {
    // Build the OBIS code for RegisterActivation
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);

    // Initialize the RegisterActivation configuration
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

    // Build the RegisterActivation object
    let mut register_activation = RegisterActivation::new(config);

    // Print the initial attributes
    println!("Initial attributes:");
    for (id, value) in register_activation.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Add a new mask
    let new_mask = CosemDataType::Structure(vec![
        CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x32]), // mask_name: "TARIFF2"
        CosemDataType::Array(vec![CosemDataType::Unsigned(2)]),                     // register_indices
    ]);
    match register_activation.invoke_method(1, Some(new_mask)) {
        Ok(result) => println!("Add mask result: {result:?}"),
        Err(e) => println!("Add mask failed: {e}"),
    }

    // Print the attributes after adding the mask
    println!("\nAttributes after adding mask:");
    for (id, value) in register_activation.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Delete the "TARIFF1" mask
    let mask_name = CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]);
    match register_activation.invoke_method(2, Some(mask_name)) {
        Ok(result) => println!("Delete mask result: {result:?}"),
        Err(e) => println!("Delete mask failed: {e}"),
    }

    // Print the attributes after deleting the mask
    println!("\nAttributes after deleting mask:");
    for (id, value) in register_activation.attributes() {
        println!("Attribute {id}: {value:?}");
    }

    // Serialize and deserialize
    let serialized = serialize_object(&register_activation).expect("Serialization failed");
    let config = RegisterActivationConfig {
        logical_name: obis,
        register_assignment: vec![],
        mask_list: vec![],
        active_mask: vec![],
    };
    let mut deserialized = RegisterActivation::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Print the attributes after deserialization
    println!("\nAttributes after deserialization:");
    for (id, value) in deserialized.attributes() {
        println!("Attribute {id}: {value:?}");
    }
}
