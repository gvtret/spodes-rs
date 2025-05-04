use spodes_rs::classes::data::Data;
use spodes_rs::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use spodes_rs::classes::register::Register;
use spodes_rs::classes::clock::{Clock, ClockConfig};
use spodes_rs::classes::extended_register::ExtendedRegister;
use spodes_rs::classes::demand_register::{DemandRegister, DemandRegisterConfig};
use spodes_rs::classes::register_activation::{RegisterActivation, RegisterActivationConfig};
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

#[test]
fn test_extended_register_serialization_deserialization() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);
    let value = CosemDataType::DoubleLong(2000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]); // Пример scaler_unit
    let status = CosemDataType::Unsigned(1); // Статус: действительное измерение
    let capture_time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);

    let extended_register = ExtendedRegister::new(
        obis.clone(),
        value.clone(),
        scaler_unit.clone(),
        status.clone(),
        capture_time.clone(),
    );
    
    let serialized = serialize_object(&extended_register).expect("Serialization failed");
    let mut deserialized = ExtendedRegister::new(
        obis.clone(),
        CosemDataType::Null,
        CosemDataType::Null,
        CosemDataType::Null,
        CosemDataType::Null,
    );
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    
    assert_eq!(deserialized.logical_name(), extended_register.logical_name());
    assert_eq!(deserialized.attributes()[1].1, value);
    assert_eq!(deserialized.attributes()[2].1, scaler_unit);
    assert_eq!(deserialized.attributes()[3].1, status);
    assert_eq!(deserialized.attributes()[4].1, capture_time);
}

#[test]
fn test_extended_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);
    let value = CosemDataType::DoubleLong(2000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let status = CosemDataType::Unsigned(1);
    let capture_time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let mut extended_register = ExtendedRegister::new(obis, value, scaler_unit, status, capture_time);
    
    let result = extended_register.invoke_method(1, None).expect("Reset method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(extended_register.attributes()[1].1, CosemDataType::DoubleLong(0));
    assert_eq!(extended_register.attributes()[3].1, CosemDataType::Null);
    assert_eq!(extended_register.attributes()[4].1, CosemDataType::Null);
}

#[test]
fn test_extended_register_capture_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);
    let value = CosemDataType::DoubleLong(2000);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let status = CosemDataType::Null;
    let capture_time = CosemDataType::Null;
    let mut extended_register = ExtendedRegister::new(obis, value, scaler_unit, status, capture_time);
    
    let result = extended_register.invoke_method(2, None).expect("Capture method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(extended_register.attributes()[3].1, CosemDataType::Unsigned(1));
    if let CosemDataType::DateTime(dt) = &extended_register.attributes()[4].1 {
        assert_eq!(dt, &vec![0x07, 0xE5, 0x05, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    } else {
        panic!("Expected DateTime");
    }
}

#[test]
fn test_demand_register_serialization_deserialization() {
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);
    let current_average_value = CosemDataType::DoubleLong(3000);
    let last_average_value = CosemDataType::DoubleLong(2500);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]); // Пример scaler_unit
    let status = CosemDataType::Unsigned(1); // Статус: действительное измерение
    let capture_time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let start_time_current = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x00, 0x00, // Час: 16, Минуты: 0, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let period = CosemDataType::DoubleLongUnsigned(3600); // 1 час
    let number_of_periods = CosemDataType::LongUnsigned(24); // 24 периода в сутки

    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: current_average_value.clone(),
        last_average_value: last_average_value.clone(),
        scaler_unit: scaler_unit.clone(),
        status: status.clone(),
        capture_time: capture_time.clone(),
        start_time_current: start_time_current.clone(),
        period: period.clone(),
        number_of_periods: number_of_periods.clone(),
    };
    let demand_register = DemandRegister::new(config);
    
    let serialized = serialize_object(&demand_register).expect("Serialization failed");
    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: CosemDataType::Null,
        last_average_value: CosemDataType::Null,
        scaler_unit: CosemDataType::Null,
        status: CosemDataType::Null,
        capture_time: CosemDataType::Null,
        start_time_current: CosemDataType::Null,
        period: CosemDataType::Null,
        number_of_periods: CosemDataType::Null,
    };
    let mut deserialized = DemandRegister::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    
    assert_eq!(deserialized.logical_name(), demand_register.logical_name());
    assert_eq!(deserialized.attributes()[1].1, current_average_value);
    assert_eq!(deserialized.attributes()[2].1, last_average_value);
    assert_eq!(deserialized.attributes()[3].1, scaler_unit);
    assert_eq!(deserialized.attributes()[4].1, status);
    assert_eq!(deserialized.attributes()[5].1, capture_time);
    assert_eq!(deserialized.attributes()[6].1, start_time_current);
    assert_eq!(deserialized.attributes()[7].1, period);
    assert_eq!(deserialized.attributes()[8].1, number_of_periods);
}

#[test]
fn test_demand_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);
    let current_average_value = CosemDataType::DoubleLong(3000);
    let last_average_value = CosemDataType::DoubleLong(2500);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let status = CosemDataType::Unsigned(1);
    let capture_time = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let start_time_current = CosemDataType::DateTime(vec![
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x00, 0x00, // Час: 16, Минуты: 0, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let period = CosemDataType::DoubleLongUnsigned(3600);
    let number_of_periods = CosemDataType::LongUnsigned(24);
    
    let config = DemandRegisterConfig {
        logical_name: obis,
        current_average_value,
        last_average_value,
        scaler_unit,
        status,
        capture_time,
        start_time_current,
        period,
        number_of_periods,
    };
    let mut demand_register = DemandRegister::new(config);
    
    let result = demand_register.invoke_method(1, None).expect("Reset method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(demand_register.attributes()[1].1, CosemDataType::DoubleLong(0));
    assert_eq!(demand_register.attributes()[2].1, CosemDataType::DoubleLong(0));
    assert_eq!(demand_register.attributes()[4].1, CosemDataType::Null);
    assert_eq!(demand_register.attributes()[5].1, CosemDataType::Null);
    assert_eq!(demand_register.attributes()[6].1, CosemDataType::Null);
}

#[test]
fn test_demand_register_next_period_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);
    let current_average_value = CosemDataType::DoubleLong(3000);
    let last_average_value = CosemDataType::DoubleLong(2500);
    let scaler_unit = CosemDataType::OctetString(vec![0x00, 0x1B]);
    let status = CosemDataType::Null;
    let capture_time = CosemDataType::Null;
    let start_time_current = CosemDataType::Null;
    let period = CosemDataType::DoubleLongUnsigned(3600);
    let number_of_periods = CosemDataType::LongUnsigned(24);
    
    let config = DemandRegisterConfig {
        logical_name: obis,
        current_average_value,
        last_average_value,
        scaler_unit,
        status,
        capture_time,
        start_time_current,
        period,
        number_of_periods,
    };
    let mut demand_register = DemandRegister::new(config);
    
    let result = demand_register.invoke_method(2, None).expect("Next period method failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(demand_register.attributes()[1].1, CosemDataType::DoubleLong(0));
    assert_eq!(demand_register.attributes()[2].1, CosemDataType::DoubleLong(3000));
    assert_eq!(demand_register.attributes()[4].1, CosemDataType::Unsigned(1));
    if let CosemDataType::DateTime(dt) = &demand_register.attributes()[5].1 {
        assert_eq!(dt, &vec![0x07, 0xE5, 0x05, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    } else {
        panic!("Expected DateTime for capture_time");
    }
    if let CosemDataType::DateTime(dt) = &demand_register.attributes()[6].1 {
        assert_eq!(dt, &vec![0x07, 0xE5, 0x05, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    } else {
        panic!("Expected DateTime for start_time_current");
    }
}

#[test]
fn test_register_activation_serialization_deserialization() {
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);
    let register_assignment = vec![CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(3), // class_id: Register
        CosemDataType::OctetString(vec![1, 0, 1, 8, 0, 255]), // logical_name
        CosemDataType::Integer(2), // attribute_index
    ])];
    let mask_list = vec![CosemDataType::Structure(vec![
        CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]), // mask_name: "TARIFF1"
        CosemDataType::Array(vec![CosemDataType::Unsigned(1)]), // register_indices
    ])];
    let active_mask = CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]); // "TARIFF1"

    let config = RegisterActivationConfig {
        logical_name: obis.clone(),
        register_assignment: register_assignment.clone(),
        mask_list: mask_list.clone(),
        active_mask: active_mask.clone(),
    };
    let register_activation = RegisterActivation::new(config);
    
    let serialized = serialize_object(&register_activation).expect("Serialization failed");
    let config = RegisterActivationConfig {
        logical_name: obis.clone(),
        register_assignment: vec![],
        mask_list: vec![],
        active_mask: CosemDataType::Null,
    };
    let mut deserialized = RegisterActivation::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");
    
    assert_eq!(deserialized.logical_name(), register_activation.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(register_assignment));
    assert_eq!(deserialized.attributes()[2].1, CosemDataType::Array(mask_list));
    assert_eq!(deserialized.attributes()[3].1, active_mask);
}

#[test]
fn test_register_activation_add_mask() {
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);
    let register_assignment = vec![CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(3), // class_id: Register
        CosemDataType::OctetString(vec![1, 0, 1, 8, 0, 255]), // logical_name
        CosemDataType::Integer(2), // attribute_index
    ])];
    let mask_list = vec![];
    let active_mask = CosemDataType::Null;

    let config = RegisterActivationConfig {
        logical_name: obis,
        register_assignment,
        mask_list,
        active_mask,
    };
    let mut register_activation = RegisterActivation::new(config);
    
    let new_mask = CosemDataType::Structure(vec![
        CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]), // mask_name: "TARIFF1"
        CosemDataType::Array(vec![CosemDataType::Unsigned(1)]), // register_indices
    ]);
    
    let result = register_activation.invoke_method(1, Some(new_mask.clone())).expect("Add mask failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(masks) = &register_activation.attributes()[2].1 {
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0], new_mask);
    } else {
        panic!("Expected Array for mask_list");
    }
}

#[test]
fn test_register_activation_delete_mask() {
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);
    let register_assignment = vec![CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(3), // class_id: Register
        CosemDataType::OctetString(vec![1, 0, 1, 8, 0, 255]), // logical_name
        CosemDataType::Integer(2), // attribute_index
    ])];
    let mask_list = vec![CosemDataType::Structure(vec![
        CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]), // mask_name: "TARIFF1"
        CosemDataType::Array(vec![CosemDataType::Unsigned(1)]), // register_indices
    ])];
    let active_mask = CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]); // "TARIFF1"

    let config = RegisterActivationConfig {
        logical_name: obis,
        register_assignment,
        mask_list,
        active_mask,
    };
    let mut register_activation = RegisterActivation::new(config);
    
    let mask_name = CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]); // "TARIFF1"
    
    let result = register_activation.invoke_method(2, Some(mask_name)).expect("Delete mask failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(masks) = &register_activation.attributes()[2].1 {
        assert_eq!(masks.len(), 0);
    } else {
        panic!("Expected Array for mask_list");
    }
    assert_eq!(register_activation.attributes()[3].1, CosemDataType::Null);
}