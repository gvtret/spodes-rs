use spodes_rs::classes::script_table::{ScriptTable, ScriptTableConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::{ActionSpecification, Script};
use spodes_rs::types::CosemDataType;

fn main() {
    // Build the OBIS code for the ScriptTable object
    let obis = ObisCode::new(0, 0, 10, 100, 0, 255);

    // Build the list of scripts
    // Each script is a structure with an identifier and an action
    let action = ActionSpecification {
        service_id: 1,
        class_id: 3, // Register
        logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
        index: 1, // method_index: reset
        parameter: CosemDataType::Null,
    };
    let scripts = vec![Script { script_identifier: 1, actions: vec![action] }];

    // Build the ScriptTable configuration
    let config = ScriptTableConfig { logical_name: obis.clone(), scripts };

    // Build the ScriptTable object
    let mut script_table = ScriptTable::new(config);

    // Check the attributes
    println!("Logical Name: {:?}", script_table.logical_name().to_bytes());
    println!("Scripts: {:?}", script_table.attributes()[1].1);

    // Serialize the object
    let serialized = serialize_object(&script_table).expect("Serialization failed");
    println!("Serialized data: {serialized:?}");

    // Build a new object for deserialization
    let config = ScriptTableConfig { logical_name: obis, scripts: vec![] };
    let mut deserialized = ScriptTable::new(config);

    // Deserialize the data
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    // Check the deserialized object
    println!("Deserialized Logical Name: {:?}", deserialized.logical_name().to_bytes());
    println!("Deserialized Scripts: {:?}", deserialized.attributes()[1].1);

    // Invoke the execute method for the script with identifier 1
    let script_id = CosemDataType::LongUnsigned(1);
    let result = script_table.invoke_method(1, Some(script_id)).expect("Execute script failed");
    println!("Execute script result: {result:?}");

    // Check execution of a nonexistent script
    let invalid_script_id = CosemDataType::LongUnsigned(2);
    let result = script_table.invoke_method(1, Some(invalid_script_id));
    match result {
        Ok(_) => println!("Unexpected success for invalid script"),
        Err(e) => println!("Expected error for invalid script: {e}"),
    }
}
