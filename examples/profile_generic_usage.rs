use spodes_rs::classes::data::Data;
use spodes_rs::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;
use std::sync::Arc;

fn main() {
    let profile_obis = ObisCode::new(1, 0, 99, 1, 0, 255);
    let data_obis = ObisCode::new(0, 0, 96, 1, 0, 255);
    let data = Data::new(data_obis.clone(), CosemDataType::Integer(42));
    let capture_objects = vec![(Arc::new(data) as Arc<dyn InterfaceClass + Send + Sync>, 2)];
    let config = ProfileGenericConfig {
        logical_name: profile_obis.clone(),
        buffer: vec![],
        capture_objects,
        capture_period: 3600,
        sort_method: 1,
        sort_object: CosemDataType::Null,
        entries_in_use: 0,
        profile_entries: 100,
    };
    let mut profile = ProfileGeneric::new(config);

    println!("ProfileGeneric object: {:?}", profile);
    println!("Logical name: {}", profile.logical_name());
    println!("Class ID: {}", profile.class_id());
    println!("Version: {}", profile.version());

    let serialized = serialize_object(&profile).expect("Serialization failed");
    println!("Serialized profile: {:?}", serialized);

    let config = ProfileGenericConfig {
        logical_name: profile_obis,
        buffer: vec![],
        capture_objects: vec![],
        capture_period: 0,
        sort_method: 0,
        sort_object: CosemDataType::Null,
        entries_in_use: 0,
        profile_entries: 0,
    };
    let mut deserialized = ProfileGeneric::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    println!("Deserialized profile: {:?}", deserialized);

    let capture_result = profile
        .invoke_method(2, None)
        .expect("Capture method failed");
    println!("Capture result: {:?}", capture_result);
    println!("Profile after capture: {:?}", profile);
}
