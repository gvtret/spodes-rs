use spodes_rs::classes::data::Data;
use spodes_rs::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use spodes_rs::classes::register::Register;
use spodes_rs::classes::clock::{Clock, ClockConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::CosemDataType;
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
    let value = CosemDataType::DoubleLong(1000);
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
        CosemDataType::DoubleLong(1000),
        CosemDataType::DateTime(vec![
            0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
            0x02, // День недели: вторник
            0x00, 0x00, 0x00, // Час: 0, Минуты: 0, Секунды: 0
            0x00, // Сотые доли секунды: 0
            0x00, 0x00, 0x00, // Отклонение от UTC: 0
        ]),
    ])];
    let capture_objects = vec![];
    let capture_period = 3600;
    let sort_method = 1;
    let sort_object = CosemDataType::Null;
    let entries_in_use = 1;
    let profile_entries = 100;
    
    let config = ProfileGenericConfig {
        logical_name: obis.clone(),
        buffer: buffer.clone(),
        capture_objects,
        capture_period,
        sort_method,
        sort_object: sort_object.clone(),
        entries_in_use,
        profile_entries,
    };
    let profile = ProfileGeneric::new(config);
    
    let serialized = serialize_object(&profile).expect("Serialization failed");
    let config = ProfileGenericConfig {
        logical_name: obis,
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
    
    assert_eq!(deserialized.logical_name(), profile.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(buffer));
    assert_eq!(deserialized.attributes()[3].1, CosemDataType::DoubleLongUnsigned(capture_period as u32));
    assert_eq!(deserialized.attributes()[4].1, CosemDataType::Unsigned(sort_method));
    assert_eq!(deserialized.attributes()[5].1, sort_object);
    assert_eq!(deserialized.attributes()[6].1, CosemDataType::DoubleLongUnsigned(entries_in_use));
    assert_eq!(deserialized.attributes()[7].1, CosemDataType::DoubleLongUnsigned(profile_entries));
}

#[test]
fn test_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 255);
    let value = CosemDataType::DoubleLong(1000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let mut register = Register::new(obis, value, scaler_unit);
    
    let result = register.invoke_method(1, None).expect("Reset method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(register.attributes()[1].1, CosemDataType::DoubleLong(0));
}

#[test]
fn test_profile_generic_capture_method() {
    let obis = ObisCode::new(1, 0, 99, 1, 0, 255);
    let data_obis = ObisCode::new(0, 0, 96, 1, 0, 255);
    let data = Data::new(data_obis.clone(), CosemDataType::Integer(42));
    let capture_objects = vec![(Arc::new(data) as Arc<dyn InterfaceClass + Send + Sync>, 2)];
    let config = ProfileGenericConfig {
        logical_name: obis,
        buffer: vec![],
        capture_objects,
        capture_period: 3600,
        sort_method: 1,
        sort_object: CosemDataType::Null,
        entries_in_use: 0,
        profile_entries: 100,
    };
    let mut profile = ProfileGeneric::new(config);
    
    let result = profile.invoke_method(2, None).expect("Capture method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(profile.attributes()[6].1, CosemDataType::DoubleLongUnsigned(1));
}

#[test]
fn test_clock_serialization_deserialization() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let time_zone = CosemDataType::Long(180); // +3 часа от UTC
    let status = CosemDataType::Unsigned(1); // Действительное время
    let daylight_savings_begin = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x03, 0x26, // Год: 2025, Месяц: 3, День: 26
        0x00, 0x02, 0x00, 0x00, // Час: 2, Минуты: 0, Секунды: 0
        0x00, 0x00, 0x00, 0x00,
    ]);
    let daylight_savings_end = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x10, 0x29, // Год: 2025, Месяц: 10, День: 29
        0x00, 0x02, 0x00, 0x00, // Час: 2, Минуты: 0, Секунды: 0
        0x00, 0x00, 0x00, 0x00,
    ]);
    let daylight_savings_deviation = CosemDataType::Integer(60); // +1 час
    let daylight_savings_enabled = CosemDataType::Boolean(true);
    let clock_base = CosemDataType::Unsigned(2); // Внешний источник

    let config = ClockConfig {
        logical_name: obis.clone(),
        time: time.clone(),
        time_zone: time_zone.clone(),
        status: status.clone(),
        daylight_savings_begin: daylight_savings_begin.clone(),
        daylight_savings_end: daylight_savings_end.clone(),
        daylight_savings_deviation: daylight_savings_deviation.clone(),
        daylight_savings_enabled: daylight_savings_enabled.clone(),
        clock_base: clock_base.clone(),
    };
    let clock = Clock::new(config);
    
    let serialized = serialize_object(&clock).expect("Serialization failed");
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
    
    assert_eq!(deserialized.logical_name(), clock.logical_name());
    assert_eq!(deserialized.attributes()[1].1, time);
    assert_eq!(deserialized.attributes()[2].1, time_zone);
    assert_eq!(deserialized.attributes()[3].1, status);
    assert_eq!(deserialized.attributes()[4].1, daylight_savings_begin);
    assert_eq!(deserialized.attributes()[5].1, daylight_savings_end);
    assert_eq!(deserialized.attributes()[6].1, daylight_savings_deviation);
    assert_eq!(deserialized.attributes()[7].1, daylight_savings_enabled);
    assert_eq!(deserialized.attributes()[8].1, clock_base);
}

#[test]
fn test_clock_adjust_to_quarter() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x25, 0x12, // Час: 16, Минуты: 37, Секунды: 12
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let config = ClockConfig {
        logical_name: obis,
        time,
        time_zone: CosemDataType::Long(180),
        status: CosemDataType::Unsigned(1),
        daylight_savings_begin: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_end: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_deviation: CosemDataType::Integer(60),
        daylight_savings_enabled: CosemDataType::Boolean(true),
        clock_base: CosemDataType::Unsigned(2),
    };
    let mut clock = Clock::new(config);
    
    let result = clock.invoke_method(1, None).expect("Adjust to quarter failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::DateTime(dt) = &clock.attributes()[1].1 {
        assert_eq!(dt[6], 45); // Минуты: 45 (ближайшая четверть часа)
        assert_eq!(dt[7], 0); // Секунды: 0
        assert_eq!(dt[8], 0); // Сотые доли: 0
    } else {
        panic!("Expected DateTime");
    }
}

#[test]
fn test_clock_adjust_to_minute() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x25, 0x12, // Час: 16, Минуты: 37, Секунды: 12
        0x50, // Сотые доли секунды: 50
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let config = ClockConfig {
        logical_name: obis,
        time,
        time_zone: CosemDataType::Long(180),
        status: CosemDataType::Unsigned(1),
        daylight_savings_begin: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_end: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_deviation: CosemDataType::Integer(60),
        daylight_savings_enabled: CosemDataType::Boolean(true),
        clock_base: CosemDataType::Unsigned(2),
    };
    let mut clock = Clock::new(config);
    
    let result = clock.invoke_method(2, None).expect("Adjust to minute failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::DateTime(dt) = &clock.attributes()[1].1 {
        assert_eq!(dt[6], 37); // Минуты: 37 (без изменений)
        assert_eq!(dt[7], 0); // Секунды: 0
        assert_eq!(dt[8], 0); // Сотые доли: 0
    } else {
        panic!("Expected DateTime");
    }
}

#[test]
fn test_clock_adjust_to_preset_time() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x25, 0x12, // Час: 16, Минуты: 37, Секунды: 12
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let config = ClockConfig {
        logical_name: obis,
        time,
        time_zone: CosemDataType::Long(180),
        status: CosemDataType::Unsigned(1),
        daylight_savings_begin: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_end: CosemDataType::DateTime(vec![0x00; 12]),
        daylight_savings_deviation: CosemDataType::Integer(60),
        daylight_savings_enabled: CosemDataType::Boolean(true),
        clock_base: CosemDataType::Unsigned(2),
    };
    let mut clock = Clock::new(config);
    
    let new_time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x02, // Год: 2025, Месяц: 5, День: 2
        0x03, // День недели: среда
        0x12, 0x00, 0x00, // Час: 18, Минуты: 0, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    
    let result = clock.invoke_method(3, Some(new_time.clone())).expect("Adjust to preset time failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(clock.attributes()[1].1, new_time);
}