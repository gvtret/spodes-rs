use spodes_rs::classes::{data::Data, profile_generic::ProfileGeneric, register::Register};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::{BerError, CosemDataType};
use std::sync::Arc;

#[test]
fn test_data_serialization_deserialization() {
    let obis = ObisCode::new(0, 0, 96, 1, 0, 255);
    let value = CosemDataType::Integer(42);
    let data = Data::new(obis.clone(), value.clone());

    let serialized = serialize_object(&data).expect("Serialization failed");
    let mut deserialized = Data::new(obis, CosemDataType::Null);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), data.logical_name());
    assert_eq!(deserialized.attributes()[1].1, value);
}

#[test]
fn test_register_serialization_deserialization() {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 255);
    let value = CosemDataType::Long64(1000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]); // Пример scaler_unit
    let register = Register::new(obis.clone(), value.clone(), scaler_unit.clone());

    let serialized = serialize_object(&register).expect("Serialization failed");
    let mut deserialized = Register::new(obis, CosemDataType::Null, CosemDataType::Null);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), register.logical_name());
    assert_eq!(deserialized.attributes()[1].1, value);
    assert_eq!(deserialized.attributes()[2].1, scaler_unit);
}

#[test]
fn test_profile_generic_serialization_deserialization() {
    let obis = ObisCode::new(1, 0, 99, 1, 0, 255);
    let buffer = vec![CosemDataType::Structure(vec![
        CosemDataType::Long64(1000),
        CosemDataType::DateTime(vec![0x07, 0xE5, 0x05, 0x01]),
    ])];
    let capture_objects = vec![];
    let capture_period = 3600;
    let sort_method = 1;
    let sort_object = CosemDataType::Null;
    let entries_in_use = 1;
    let profile_entries = 100;

    let profile = ProfileGeneric::new(
        obis.clone(),
        buffer.clone(),
        capture_objects,
        capture_period,
        sort_method,
        sort_object.clone(),
        entries_in_use,
        profile_entries,
    );

    let serialized = serialize_object(&profile).expect("Serialization failed");
    let mut deserialized =
        ProfileGeneric::new(obis, vec![], vec![], 0, 0, CosemDataType::Null, 0, 0);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), profile.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(buffer));
    assert_eq!(
        deserialized.attributes()[3].1,
        CosemDataType::DoubleLongUnsigned(capture_period as u32)
    );
    assert_eq!(
        deserialized.attributes()[4].1,
        CosemDataType::Unsigned(sort_method)
    );
    assert_eq!(deserialized.attributes()[5].1, sort_object);
    assert_eq!(
        deserialized.attributes()[6].1,
        CosemDataType::DoubleLongUnsigned(entries_in_use)
    );
    assert_eq!(
        deserialized.attributes()[7].1,
        CosemDataType::DoubleLongUnsigned(profile_entries)
    );
}

#[test]
fn test_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 255);
    let value = CosemDataType::Long64(1000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let mut register = Register::new(obis, value, scaler_unit);

    let result = register
        .invoke_method(1, None)
        .expect("Reset method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(register.attributes()[1].1, CosemDataType::Long64(0));
}

#[test]
fn test_profile_generic_capture_method() {
    let obis = ObisCode::new(1, 0, 99, 1, 0, 255);
    let data_obis = ObisCode::new(0, 0, 96, 1, 0, 255);
    let data = Data::new(data_obis.clone(), CosemDataType::Integer(42));
    let capture_objects = vec![(Arc::new(data) as Arc<dyn InterfaceClass + Send + Sync>, 2)];
    let mut profile = ProfileGeneric::new(
        obis,
        vec![],
        capture_objects,
        3600,
        1,
        CosemDataType::Null,
        0,
        100,
    );

    let result = profile
        .invoke_method(2, None)
        .expect("Capture method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(
        profile.attributes()[6].1,
        CosemDataType::DoubleLongUnsigned(1)
    );
}
