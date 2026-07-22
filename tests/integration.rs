use sha1::{Digest, Sha1};
use spodes_rs::classes::association_ln::{
    AssociationLn, AssociationLnConfig, AssociationLnVersion, AuthenticationMechanism,
};
use spodes_rs::classes::clock::{Clock, ClockConfig};
use spodes_rs::classes::data::Data;
use spodes_rs::classes::demand_register::{DemandRegister, DemandRegisterConfig};
use spodes_rs::classes::extended_register::ExtendedRegister;
use spodes_rs::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use spodes_rs::classes::register::Register;
use spodes_rs::classes::register_activation::{RegisterActivation, RegisterActivationConfig};
use spodes_rs::classes::schedule::{Schedule, ScheduleConfig};
use spodes_rs::classes::script_table::{ScriptTable, ScriptTableConfig};
use spodes_rs::classes::special_days_table::{SpecialDaysTable, SpecialDaysTableConfig};
use spodes_rs::interface::InterfaceClass;
use spodes_rs::obis::ObisCode;
use spodes_rs::serialization::{deserialize_object, serialize_object};
use spodes_rs::types::attrs::{
    AccessRight, ActionSpecification, AssociatedPartnersId, ContextName, DateTime, ObjectDefinition, ObjectListElement,
    RegisterActMask, ScalerUnit, ScheduleTableEntry, Script, SortMethod, SpecialDayEntry, XDLMSContextInfo,
};
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
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let register = Register::new(obis.clone(), value.clone(), scaler_unit.clone());

    let serialized = serialize_object(&register).expect("Serialization failed");
    let mut deserialized = Register::new(obis, CosemDataType::Null, ScalerUnit::new(0, 0));
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), register.logical_name());
    assert_eq!(deserialized.attributes()[1].1, value);
    assert_eq!(
        deserialized.attributes()[2].1,
        CosemDataType::Structure(vec![CosemDataType::Integer(0), CosemDataType::Enum(0x1B)])
    );
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
    let sort_method = SortMethod::Fifo;
    let sort_object = None;
    let entries_in_use = 1;
    let profile_entries = 100;

    let config = ProfileGenericConfig {
        logical_name: obis.clone(),
        version: 1,
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
        version: 1,
        buffer: vec![],
        capture_objects: vec![],
        capture_period: 0,
        sort_method: SortMethod::Fifo,
        sort_object: None,
        entries_in_use: 0,
        profile_entries: 0,
    };
    let mut deserialized = ProfileGeneric::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), profile.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(buffer));
    assert_eq!(deserialized.attributes()[3].1, CosemDataType::DoubleLongUnsigned(capture_period));
    assert_eq!(deserialized.attributes()[4].1, CosemDataType::Unsigned(sort_method as u8));
    assert_eq!(deserialized.attributes()[5].1, CosemDataType::Null);
    assert_eq!(deserialized.attributes()[6].1, CosemDataType::DoubleLongUnsigned(entries_in_use));
    assert_eq!(deserialized.attributes()[7].1, CosemDataType::DoubleLongUnsigned(profile_entries));
}

#[test]
fn test_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 0, 255);
    let value = CosemDataType::DoubleLong(1000);
    let scaler_unit = ScalerUnit::new(0, 0x1B);
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
        version: 1,
        buffer: vec![],
        capture_objects,
        capture_period: 3600,
        sort_method: SortMethod::Fifo,
        sort_object: None,
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
    let time = DateTime([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let daylight_savings_begin = DateTime([0x07, 0xE5, 0x03, 0x26, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let daylight_savings_end = DateTime([0x07, 0xE5, 0x10, 0x29, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let config = ClockConfig {
        logical_name: obis.clone(),
        time: time.clone(),
        time_zone: 180,
        status: 1,
        daylight_savings_begin: daylight_savings_begin.clone(),
        daylight_savings_end: daylight_savings_end.clone(),
        daylight_savings_deviation: 60,
        daylight_savings_enabled: true,
        clock_base: 2,
    };
    let clock = Clock::new(config);

    let serialized = serialize_object(&clock).expect("Serialization failed");
    let config = ClockConfig {
        logical_name: obis.clone(),
        time: DateTime([0u8; 12]),
        time_zone: 0,
        status: 0,
        daylight_savings_begin: DateTime([0u8; 12]),
        daylight_savings_end: DateTime([0u8; 12]),
        daylight_savings_deviation: 0,
        daylight_savings_enabled: false,
        clock_base: 0,
    };
    let mut deserialized = Clock::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), clock.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::DateTime(time.0.to_vec()));
    assert_eq!(deserialized.attributes()[2].1, CosemDataType::Long(180));
    assert_eq!(deserialized.attributes()[3].1, CosemDataType::Unsigned(1));
    assert_eq!(deserialized.attributes()[4].1, CosemDataType::DateTime(daylight_savings_begin.0.to_vec()));
    assert_eq!(deserialized.attributes()[5].1, CosemDataType::DateTime(daylight_savings_end.0.to_vec()));
    assert_eq!(deserialized.attributes()[6].1, CosemDataType::Integer(60));
    assert_eq!(deserialized.attributes()[7].1, CosemDataType::Boolean(true));
    assert_eq!(deserialized.attributes()[8].1, CosemDataType::Enum(2));
}

#[test]
fn test_clock_adjust_to_quarter() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = DateTime([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x25, 0x12, 0x00, 0x00, 0x00, 0x00]);
    let config = ClockConfig {
        logical_name: obis,
        time,
        time_zone: 180,
        status: 1,
        daylight_savings_begin: DateTime([0u8; 12]),
        daylight_savings_end: DateTime([0u8; 12]),
        daylight_savings_deviation: 60,
        daylight_savings_enabled: true,
        clock_base: 2,
    };
    let mut clock = Clock::new(config);

    let result = clock.invoke_method(1, None).expect("Adjust to quarter failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::DateTime(dt) = &clock.attributes()[1].1 {
        assert_eq!(dt[6], 45);
        assert_eq!(dt[7], 0);
        assert_eq!(dt[8], 0);
    } else {
        panic!("Expected DateTime");
    }
}

#[test]
fn test_clock_adjust_to_minute() {
    let obis = ObisCode::new(0, 0, 1, 0, 0, 255);
    let time = DateTime([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x25, 0x12, 0x50, 0x00, 0x00, 0x00]);
    let config = ClockConfig {
        logical_name: obis,
        time,
        time_zone: 180,
        status: 1,
        daylight_savings_begin: DateTime([0u8; 12]),
        daylight_savings_end: DateTime([0u8; 12]),
        daylight_savings_deviation: 60,
        daylight_savings_enabled: true,
        clock_base: 2,
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
    let time = DateTime([0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x25, 0x12, 0x00, 0x00, 0x00, 0x00]);
    let config = ClockConfig {
        logical_name: obis,
        time,
        time_zone: 180,
        status: 1,
        daylight_savings_begin: DateTime([0u8; 12]),
        daylight_savings_end: DateTime([0u8; 12]),
        daylight_savings_deviation: 60,
        daylight_savings_enabled: true,
        clock_base: 2,
    };
    let mut clock = Clock::new(config);

    let new_time =
        CosemDataType::DateTime(vec![0x07, 0xE5, 0x05, 0x02, 0x03, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let result = clock.invoke_method(3, Some(new_time.clone())).expect("Adjust to preset time failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(clock.attributes()[1].1, new_time);
}

#[test]
fn test_extended_register_serialization_deserialization() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);
    let value = CosemDataType::DoubleLong(2000);
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let status = CosemDataType::Unsigned(1);
    let capture_time = DateTime::new([
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);

    let extended_register =
        ExtendedRegister::new(obis.clone(), value.clone(), scaler_unit.clone(), status.clone(), capture_time.clone());

    let serialized = serialize_object(&extended_register).expect("Serialization failed");
    let mut deserialized = ExtendedRegister::new(
        obis.clone(),
        CosemDataType::Null,
        ScalerUnit::new(0, 0),
        CosemDataType::Null,
        DateTime::new([0u8; 12]),
    );
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), extended_register.logical_name());
    assert_eq!(deserialized.attributes()[1].1, value);
    assert_eq!(
        deserialized.attributes()[2].1,
        CosemDataType::Structure(vec![CosemDataType::Integer(0), CosemDataType::Enum(0x1B)])
    );
    assert_eq!(deserialized.attributes()[3].1, status);
    assert_eq!(deserialized.attributes()[4].1, CosemDataType::from(capture_time));
}

#[test]
fn test_extended_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);
    let value = CosemDataType::DoubleLong(2000);
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let status = CosemDataType::Unsigned(1);
    let capture_time = DateTime::new([
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
    assert_eq!(extended_register.attributes()[4].1, CosemDataType::DateTime(vec![0u8; 12]));
}

#[test]
fn test_extended_register_capture_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 1, 255);
    let value = CosemDataType::DoubleLong(2000);
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let status = CosemDataType::Null;
    let capture_time = DateTime::new([0u8; 12]);
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
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let status = CosemDataType::Unsigned(1);
    let capture_time = DateTime::new([
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let start_time_current = DateTime::new([
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x00, 0x00, // Час: 16, Минуты: 0, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let period = 3600u32;
    let number_of_periods = 24u16;

    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: current_average_value.clone(),
        last_average_value: last_average_value.clone(),
        scaler_unit: scaler_unit.clone(),
        status: status.clone(),
        capture_time: capture_time.clone(),
        start_time_current: start_time_current.clone(),
        period,
        number_of_periods,
    };
    let demand_register = DemandRegister::new(config);

    let serialized = serialize_object(&demand_register).expect("Serialization failed");
    let config = DemandRegisterConfig {
        logical_name: obis.clone(),
        current_average_value: CosemDataType::Null,
        last_average_value: CosemDataType::Null,
        scaler_unit: ScalerUnit::new(0, 0),
        status: CosemDataType::Null,
        capture_time: DateTime::new([0u8; 12]),
        start_time_current: DateTime::new([0u8; 12]),
        period: 0,
        number_of_periods: 0,
    };
    let mut deserialized = DemandRegister::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), demand_register.logical_name());
    assert_eq!(deserialized.attributes()[1].1, current_average_value);
    assert_eq!(deserialized.attributes()[2].1, last_average_value);
    assert_eq!(
        deserialized.attributes()[3].1,
        CosemDataType::Structure(vec![CosemDataType::Integer(0), CosemDataType::Enum(0x1B)])
    );
    assert_eq!(deserialized.attributes()[4].1, status);
    assert_eq!(deserialized.attributes()[5].1, CosemDataType::from(capture_time));
    assert_eq!(deserialized.attributes()[6].1, CosemDataType::from(start_time_current));
    assert_eq!(deserialized.attributes()[7].1, CosemDataType::DoubleLongUnsigned(period));
    assert_eq!(deserialized.attributes()[8].1, CosemDataType::LongUnsigned(number_of_periods));
}

#[test]
fn test_demand_register_reset_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);
    let current_average_value = CosemDataType::DoubleLong(3000);
    let last_average_value = CosemDataType::DoubleLong(2500);
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let status = CosemDataType::Unsigned(1);
    let capture_time = DateTime::new([
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x30, 0x00, // Час: 16, Минуты: 30, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let start_time_current = DateTime::new([
        0x07, 0xE5, 0x05, 0x01, // Год: 2025, Месяц: 5, День: 1
        0x02, // День недели: вторник
        0x10, 0x00, 0x00, // Час: 16, Минуты: 0, Секунды: 0
        0x00, // Сотые доли секунды: 0
        0x00, 0x00, 0x00, // Отклонение от UTC: 0
    ]);
    let period = 3600u32;
    let number_of_periods = 24u16;

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
    assert_eq!(demand_register.attributes()[5].1, CosemDataType::DateTime(vec![0u8; 12]));
    assert_eq!(demand_register.attributes()[6].1, CosemDataType::DateTime(vec![0u8; 12]));
}

#[test]
fn test_demand_register_next_period_method() {
    let obis = ObisCode::new(1, 0, 1, 8, 2, 255);
    let current_average_value = CosemDataType::DoubleLong(3000);
    let last_average_value = CosemDataType::DoubleLong(2500);
    let scaler_unit = ScalerUnit::new(0, 0x1B);
    let status = CosemDataType::Null;
    let capture_time = DateTime::new([0u8; 12]);
    let start_time_current = DateTime::new([0u8; 12]);
    let period = 3600u32;
    let number_of_periods = 24u16;

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
    let register_assignment = vec![ObjectDefinition {
        class_id: 3, // Register
        logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
    }];
    let mask_list = vec![RegisterActMask {
        mask_name: vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31], // "TARIFF1"
        index_list: vec![1],
    }];
    let active_mask = vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]; // "TARIFF1"

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
        active_mask: vec![],
    };
    let mut deserialized = RegisterActivation::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), register_activation.logical_name());
    assert_eq!(
        deserialized.attributes()[1].1,
        CosemDataType::Array(register_assignment.iter().map(|od| CosemDataType::from(od.clone())).collect(),)
    );
    assert_eq!(
        deserialized.attributes()[2].1,
        CosemDataType::Array(mask_list.iter().map(|m| CosemDataType::from(m.clone())).collect(),)
    );
    assert_eq!(deserialized.attributes()[3].1, CosemDataType::OctetString(active_mask));
}

#[test]
fn test_register_activation_add_mask() {
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);
    let register_assignment = vec![ObjectDefinition {
        class_id: 3, // Register
        logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
    }];
    let mask_list = vec![];
    let active_mask = vec![];

    let config = RegisterActivationConfig { logical_name: obis, register_assignment, mask_list, active_mask };
    let mut register_activation = RegisterActivation::new(config);

    let new_mask = CosemDataType::Structure(vec![
        CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]), // mask_name: "TARIFF1"
        CosemDataType::Array(vec![CosemDataType::Unsigned(1)]),                     // register_indices
    ]);

    let result = register_activation.invoke_method(1, Some(new_mask.clone())).expect("Add mask failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(ref masks) = register_activation.attributes()[2].1 {
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0], new_mask);
    } else {
        panic!("Expected Array for mask_list");
    }
}

#[test]
fn test_register_activation_delete_mask() {
    let obis = ObisCode::new(0, 0, 10, 106, 0, 255);
    let register_assignment = vec![ObjectDefinition {
        class_id: 3, // Register
        logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
    }];
    let mask_list = vec![RegisterActMask {
        mask_name: vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31], // "TARIFF1"
        index_list: vec![1],
    }];
    let active_mask = vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]; // "TARIFF1"

    let config = RegisterActivationConfig { logical_name: obis, register_assignment, mask_list, active_mask };
    let mut register_activation = RegisterActivation::new(config);

    let mask_name = CosemDataType::OctetString(vec![0x54, 0x41, 0x52, 0x49, 0x46, 0x46, 0x31]); // "TARIFF1"

    let result = register_activation.invoke_method(2, Some(mask_name)).expect("Delete mask failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(ref masks) = register_activation.attributes()[2].1 {
        assert_eq!(masks.len(), 0);
    } else {
        panic!("Expected Array for mask_list");
    }
    assert_eq!(register_activation.attributes()[3].1, CosemDataType::OctetString(vec![]));
}

#[test]
fn test_script_table_serialization_deserialization() {
    let obis = ObisCode::new(0, 0, 10, 100, 0, 255);
    let action = ActionSpecification {
        service_id: 1,
        class_id: 3, // Register
        logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
        index: 1, // method_index: reset
        parameter: CosemDataType::Null,
    };
    let scripts = vec![Script { script_identifier: 1, actions: vec![action] }];

    let config = ScriptTableConfig { logical_name: obis.clone(), scripts: scripts.clone() };
    let script_table = ScriptTable::new(config);

    let serialized = serialize_object(&script_table).expect("Serialization failed");
    let config = ScriptTableConfig { logical_name: obis.clone(), scripts: vec![] };
    let mut deserialized = ScriptTable::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), script_table.logical_name());
    let expected_scripts: Vec<CosemDataType> = scripts.into_iter().map(CosemDataType::from).collect();
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(expected_scripts));
}

#[test]
fn test_script_table_execute() {
    let obis = ObisCode::new(0, 0, 10, 100, 0, 255);
    let action = ActionSpecification {
        service_id: 1,
        class_id: 3, // Register
        logical_name: ObisCode::new(1, 0, 1, 8, 0, 255),
        index: 1, // method_index: reset
        parameter: CosemDataType::Null,
    };
    let scripts = vec![Script { script_identifier: 1, actions: vec![action] }];

    let config = ScriptTableConfig { logical_name: obis, scripts };
    let mut script_table = ScriptTable::new(config);

    let script_id = CosemDataType::LongUnsigned(1);
    let result = script_table.invoke_method(1, Some(script_id)).expect("Execute script failed");
    assert_eq!(result, CosemDataType::Null);

    let invalid_script_id = CosemDataType::LongUnsigned(2);
    let result = script_table.invoke_method(1, Some(invalid_script_id));
    assert!(result.is_err());
    if let Err(e) = result {
        assert_eq!(e, "Script with ID 2 not found");
    }
}

#[test]
fn test_schedule_serialization_deserialization() {
    let obis = ObisCode::new(0, 0, 10, 101, 0, 255);
    let entries = vec![ScheduleTableEntry {
        index: 1,
        enable: true,
        script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
        script_selector: 1,
        switch_time: vec![0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        validity_window: 0,
        exec_weekdays: vec![0xFF],
        exec_specdays: vec![],
        begin_date: vec![],
        end_date: vec![],
    }];

    let config = ScheduleConfig { logical_name: obis.clone(), entries: entries.clone(), enabled: true };
    let schedule = Schedule::new(config);

    let serialized = serialize_object(&schedule).expect("Serialization failed");
    let config = ScheduleConfig { logical_name: obis.clone(), entries: vec![], enabled: false };
    let mut deserialized = Schedule::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), schedule.logical_name());
    let expected: Vec<CosemDataType> = entries.into_iter().map(CosemDataType::from).collect();
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(expected));
}

#[test]
fn test_schedule_enable_disable() {
    let obis = ObisCode::new(0, 0, 10, 101, 0, 255);
    let entries = vec![ScheduleTableEntry {
        index: 1,
        enable: true,
        script_logical_name: ObisCode::new(0, 0, 10, 100, 0, 255),
        script_selector: 1,
        switch_time: vec![0x07, 0xE5, 0x05, 0x01, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        validity_window: 0,
        exec_weekdays: vec![0xFF],
        exec_specdays: vec![],
        begin_date: vec![],
        end_date: vec![],
    }];

    let config = ScheduleConfig { logical_name: obis, entries: entries.clone(), enabled: false };
    let mut schedule = Schedule::new(config);

    // Method 1: enable_disable toggles the entry's enable flag by index.
    let result = schedule.invoke_method(1, Some(CosemDataType::Unsigned(0))).expect("enable_disable failed");
    assert_eq!(result, CosemDataType::Null);
    assert!(!schedule.entries()[0].enable);
    schedule.invoke_method(1, Some(CosemDataType::Unsigned(0))).expect("enable_disable failed");
    assert!(schedule.entries()[0].enable);

    // Method 2: insert appends a new entry.
    let mut new_entry = entries[0].clone();
    new_entry.index = 2;
    schedule.invoke_method(2, Some(CosemDataType::from(new_entry))).expect("insert failed");
    assert_eq!(schedule.entries().len(), 2);

    // Method 3: delete removes an entry by index.
    schedule.invoke_method(3, Some(CosemDataType::Unsigned(0))).expect("delete failed");
    assert_eq!(schedule.entries().len(), 1);
    assert_eq!(schedule.entries()[0].index, 2);

    // Out-of-range index is rejected.
    assert!(schedule.invoke_method(3, Some(CosemDataType::Unsigned(5))).is_err());
    // Missing parameter is rejected.
    assert!(schedule.invoke_method(1, None).is_err());
}

#[test]
fn test_special_days_table_serialization_deserialization() {
    let obis = ObisCode::new(0, 0, 11, 102, 0, 255);
    let entries = vec![
        SpecialDayEntry {
            index: 1,
            specialday_date: vec![0x07, 0xE5, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            day_id: 1,
        },
        SpecialDayEntry {
            index: 2,
            specialday_date: vec![0x07, 0xE5, 0x12, 0x25, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            day_id: 2,
        },
    ];

    let config = SpecialDaysTableConfig { logical_name: obis.clone(), entries: entries.clone() };
    let special_days_table = SpecialDaysTable::new(config);

    let serialized = serialize_object(&special_days_table).expect("Serialization failed");
    let config = SpecialDaysTableConfig { logical_name: obis.clone(), entries: vec![] };
    let mut deserialized = SpecialDaysTable::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), special_days_table.logical_name());
    let expected: Vec<CosemDataType> = entries.into_iter().map(CosemDataType::from).collect();
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(expected));
}

#[test]
fn test_special_days_table_insert_method() {
    let obis = ObisCode::new(0, 0, 11, 102, 0, 255);
    let config = SpecialDaysTableConfig { logical_name: obis.clone(), entries: vec![] };
    let mut special_days_table = SpecialDaysTable::new(config);

    let new_date = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::OctetString(vec![0x07, 0xE5, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        CosemDataType::Unsigned(1),
    ]);

    let result = special_days_table.invoke_method(1, Some(new_date.clone())).expect("Insert method failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(entries) = &special_days_table.attributes()[1].1 {
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], new_date);
    } else {
        panic!("Expected Array for entries");
    }

    let result = special_days_table.invoke_method(1, Some(CosemDataType::Integer(42)));
    assert!(result.is_err());

    let invalid_date = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::OctetString(vec![0x07, 0xE5, 0x01, 0x01]),
        CosemDataType::Unsigned(1),
    ]);
    let result = special_days_table.invoke_method(1, Some(invalid_date));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Invalid DateTime length");
}

#[test]
fn test_special_days_table_delete_method() {
    let obis = ObisCode::new(0, 0, 11, 102, 0, 255);
    let date = vec![0x07, 0xE5, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let entry = SpecialDayEntry { index: 1, specialday_date: date.clone(), day_id: 1 };
    let config = SpecialDaysTableConfig { logical_name: obis.clone(), entries: vec![entry] };
    let mut special_days_table = SpecialDaysTable::new(config);

    let delete_param = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::OctetString(date.clone()),
        CosemDataType::Unsigned(1),
    ]);
    let result = special_days_table.invoke_method(2, Some(delete_param.clone())).expect("Delete method failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(entries) = &special_days_table.attributes()[1].1 {
        assert_eq!(entries.len(), 0);
    } else {
        panic!("Expected Array for entries");
    }

    let result = special_days_table.invoke_method(2, Some(delete_param)).expect("Delete non-existent date failed");
    assert_eq!(result, CosemDataType::Null);

    let result = special_days_table.invoke_method(2, Some(CosemDataType::Integer(42)));
    assert!(result.is_err());

    let invalid_date = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::OctetString(vec![0x07, 0xE5, 0x01, 0x01]),
        CosemDataType::Unsigned(1),
    ]);
    let result = special_days_table.invoke_method(2, Some(invalid_date));
    assert!(result.is_ok());
}

#[test]
fn test_association_ln_serialization_deserialization_version0() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let object_list: Vec<ObjectListElement> = vec![];
    let associated_partners_id = AssociatedPartnersId { client_sap: 1, server_sap: 1 };
    let application_context_name = ContextName::OctetString(vec![0x09, 0x06, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]);
    let xdlms_context_info = XDLMSContextInfo {
        conformance: vec![
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        max_receive_pdu_size: 16,
        max_send_pdu_size: 16,
        dlms_version_number: 2,
        quality_of_service: 0,
        cyphering_info: vec![],
    };
    let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let association_status: u8 = 1;

    let config = AssociationLnConfig {
        logical_name: obis.clone(),
        version: AssociationLnVersion::Version0,
        object_list: object_list.clone(),
        associated_partners_id: associated_partners_id.clone(),
        application_context_name: application_context_name.clone(),
        xdlms_context_info: xdlms_context_info.clone(),
        authentication_mechanism: AuthenticationMechanism::Lls,
        secret: secret.clone(),
        association_status,
        security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
        user_list: vec![],
        current_user: None,
    };
    let association_ln = AssociationLn::new(config);

    let serialized = serialize_object(&association_ln).expect("Serialization failed");
    let config = AssociationLnConfig {
        logical_name: obis.clone(),
        version: AssociationLnVersion::Version0,
        object_list: vec![],
        associated_partners_id: AssociatedPartnersId { client_sap: 0, server_sap: 0 },
        application_context_name: ContextName::OctetString(vec![]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![],
            max_receive_pdu_size: 0,
            max_send_pdu_size: 0,
            dlms_version_number: 0,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::Lls,
        secret: vec![],
        association_status: 0,
        security_setup_reference: ObisCode::new(0, 0, 0, 0, 0, 0),
        user_list: vec![],
        current_user: None,
    };
    let mut deserialized = AssociationLn::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), association_ln.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(vec![]));
    assert_eq!(deserialized.attributes()[2].1, CosemDataType::from(associated_partners_id));
    assert_eq!(deserialized.attributes()[3].1, CosemDataType::from(application_context_name));
    assert_eq!(deserialized.attributes()[4].1, CosemDataType::from(xdlms_context_info));
    assert_eq!(
        deserialized.attributes()[5].1,
        CosemDataType::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01])
    );
    assert_eq!(deserialized.attributes()[6].1, CosemDataType::OctetString(secret));
    assert_eq!(deserialized.attributes()[7].1, CosemDataType::Enum(association_status));
}

#[test]
fn test_association_ln_serialization_deserialization_version1() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let object_list: Vec<ObjectListElement> = vec![];
    let associated_partners_id = AssociatedPartnersId { client_sap: 1, server_sap: 1 };
    let application_context_name = ContextName::OctetString(vec![0x09, 0x06, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]);
    let xdlms_context_info = XDLMSContextInfo {
        conformance: vec![
            0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        max_receive_pdu_size: 16,
        max_send_pdu_size: 16,
        dlms_version_number: 2,
        quality_of_service: 0,
        cyphering_info: vec![],
    };
    let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let association_status: u8 = 1;
    let security_setup_reference = ObisCode::new(0, 0, 43, 0, 0, 255);

    let config = AssociationLnConfig {
        logical_name: obis.clone(),
        version: AssociationLnVersion::Version1,
        object_list: object_list.clone(),
        associated_partners_id: associated_partners_id.clone(),
        application_context_name: application_context_name.clone(),
        xdlms_context_info: xdlms_context_info.clone(),
        authentication_mechanism: AuthenticationMechanism::HlsSha1,
        secret: secret.clone(),
        association_status,
        security_setup_reference,
        user_list: vec![],
        current_user: None,
    };
    let association_ln = AssociationLn::new(config);

    let serialized = serialize_object(&association_ln).expect("Serialization failed");
    let config = AssociationLnConfig {
        logical_name: obis.clone(),
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: AssociatedPartnersId { client_sap: 0, server_sap: 0 },
        application_context_name: ContextName::OctetString(vec![]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![],
            max_receive_pdu_size: 0,
            max_send_pdu_size: 0,
            dlms_version_number: 0,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::HlsSha1,
        secret: vec![],
        association_status: 0,
        security_setup_reference: ObisCode::new(0, 0, 0, 0, 0, 0),
        user_list: vec![],
        current_user: None,
    };
    let mut deserialized = AssociationLn::new(config);
    deserialize_object(&mut deserialized, &serialized).expect("Deserialization failed");

    assert_eq!(deserialized.logical_name(), association_ln.logical_name());
    assert_eq!(deserialized.attributes()[1].1, CosemDataType::Array(vec![]));
    assert_eq!(deserialized.attributes()[2].1, CosemDataType::from(associated_partners_id));
    assert_eq!(deserialized.attributes()[3].1, CosemDataType::from(application_context_name));
    assert_eq!(deserialized.attributes()[4].1, CosemDataType::from(xdlms_context_info));
    assert_eq!(
        deserialized.attributes()[5].1,
        CosemDataType::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x04])
    );
    assert_eq!(deserialized.attributes()[6].1, CosemDataType::OctetString(secret));
    assert_eq!(deserialized.attributes()[7].1, CosemDataType::Enum(association_status));
    assert_eq!(deserialized.attributes()[8].1, CosemDataType::OctetString(vec![0, 0, 43, 0, 0, 255]));
}

#[test]
fn test_association_ln_lls_authentication() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let config = AssociationLnConfig {
        logical_name: obis,
        version: AssociationLnVersion::Version0,
        object_list: vec![],
        associated_partners_id: AssociatedPartnersId { client_sap: 1, server_sap: 1 },
        application_context_name: ContextName::OctetString(vec![0x09, 0x06, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![
                0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ],
            max_receive_pdu_size: 16,
            max_send_pdu_size: 16,
            dlms_version_number: 2,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::Lls,
        secret: secret.clone(),
        association_status: 1,
        security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
        user_list: vec![],
        current_user: None,
    };
    let mut association_ln = AssociationLn::new(config);

    let result = association_ln
        .invoke_method(1, Some(CosemDataType::OctetString(secret.clone())))
        .expect("LLS authentication failed");
    assert_eq!(result, CosemDataType::Null);

    let wrong_secret = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = association_ln.invoke_method(1, Some(CosemDataType::OctetString(wrong_secret)));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "LLS authentication failed");
}

#[test]
fn test_association_ln_hls4_sha1_authentication() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    // Pass 1: клиент прислал CtoS; Pass 2: сервер отправил StoC.
    let ctos = vec![0x11, 0x22, 0x33, 0x44];
    let stoc = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let config = AssociationLnConfig {
        logical_name: obis,
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: AssociatedPartnersId { client_sap: 1, server_sap: 1 },
        application_context_name: ContextName::OctetString(vec![0x09, 0x06, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![
                0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ],
            max_receive_pdu_size: 16,
            max_send_pdu_size: 16,
            dlms_version_number: 2,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::HlsSha1,
        secret: secret.clone(),
        association_status: 1,
        security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
        user_list: vec![],
        current_user: None,
    };
    let mut association_ln = AssociationLn::new(config);
    association_ln.set_ctos(ctos.clone());
    association_ln.set_stoc(stoc.clone());

    // Pass 3: клиент присылает f(StoC) = SHA-1(StoC ‖ secret).
    let mut hasher = Sha1::new();
    hasher.update(&stoc);
    hasher.update(&secret);
    let f_stoc = hasher.finalize().to_vec();

    // Pass 4: сервер возвращает f(CtoS) = SHA-1(CtoS ‖ secret).
    let mut hasher = Sha1::new();
    hasher.update(&ctos);
    hasher.update(&secret);
    let expected_f_ctos = hasher.finalize().to_vec();

    let result = association_ln
        .invoke_method(1, Some(CosemDataType::OctetString(f_stoc.clone())))
        .expect("HLS4 SHA1 authentication failed");
    assert_eq!(result, CosemDataType::OctetString(expected_f_ctos));

    // Неверное f(StoC) отклоняется.
    let mut wrong = f_stoc;
    wrong[0] ^= 0xFF;
    assert!(association_ln.invoke_method(1, Some(CosemDataType::OctetString(wrong))).is_err());
}

#[test]
fn test_association_ln_change_hls_secret() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let secret = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let config = AssociationLnConfig {
        logical_name: obis,
        version: AssociationLnVersion::Version0,
        object_list: vec![],
        associated_partners_id: AssociatedPartnersId { client_sap: 1, server_sap: 1 },
        application_context_name: ContextName::OctetString(vec![0x09, 0x06, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![
                0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ],
            max_receive_pdu_size: 16,
            max_send_pdu_size: 16,
            dlms_version_number: 2,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::Lls,
        secret: secret.clone(),
        association_status: 1,
        security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
        user_list: vec![],
        current_user: None,
    };
    let mut association_ln = AssociationLn::new(config);

    let new_secret = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = association_ln
        .invoke_method(2, Some(CosemDataType::OctetString(new_secret.clone())))
        .expect("Change HLS secret failed");
    assert_eq!(result, CosemDataType::Null);
    assert_eq!(association_ln.attributes()[6].1, CosemDataType::OctetString(new_secret));
}

#[test]
fn test_association_ln_add_object() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let config = AssociationLnConfig {
        logical_name: obis,
        version: AssociationLnVersion::Version1,
        object_list: vec![],
        associated_partners_id: AssociatedPartnersId { client_sap: 1, server_sap: 1 },
        application_context_name: ContextName::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![0xFF; 18],
            max_receive_pdu_size: 16,
            max_send_pdu_size: 16,
            dlms_version_number: 2,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::HlsSha1,
        secret: vec![0x01; 16],
        association_status: 1,
        security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
        user_list: vec![],
        current_user: None,
    };
    let mut association_ln = AssociationLn::new(config);

    let element = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),                        // class_id
        CosemDataType::Unsigned(0),                            // version
        CosemDataType::OctetString(vec![0, 0, 96, 1, 0, 255]), // logical_name
        CosemDataType::Structure(vec![
            CosemDataType::Array(vec![]), // attribute_access
            CosemDataType::Array(vec![]), // method_access
        ]), // access_rights
    ]);
    let result = association_ln.invoke_method(3, Some(element.clone())).expect("add_object failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(list) = &association_ln.attributes()[1].1 {
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], element);
    } else {
        panic!("Expected Array for object_list");
    }
}

#[test]
fn test_association_ln_remove_object() {
    let obis = ObisCode::new(0, 0, 40, 0, 0, 255);
    let element = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::Unsigned(0),
        CosemDataType::OctetString(vec![0, 0, 96, 1, 0, 255]),
        CosemDataType::Structure(vec![
            CosemDataType::Array(vec![]), // attribute_access
            CosemDataType::Array(vec![]), // method_access
        ]),
    ]);
    let ole = ObjectListElement {
        class_id: 1,
        version: 0,
        logical_name: ObisCode::new(0, 0, 96, 1, 0, 255),
        access_rights: AccessRight { attribute_access: vec![], method_access: vec![] },
    };
    let config = AssociationLnConfig {
        logical_name: obis,
        version: AssociationLnVersion::Version1,
        object_list: vec![ole],
        associated_partners_id: AssociatedPartnersId { client_sap: 1, server_sap: 1 },
        application_context_name: ContextName::OctetString(vec![0x09, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01]),
        xdlms_context_info: XDLMSContextInfo {
            conformance: vec![0xFF; 18],
            max_receive_pdu_size: 16,
            max_send_pdu_size: 16,
            dlms_version_number: 2,
            quality_of_service: 0,
            cyphering_info: vec![],
        },
        authentication_mechanism: AuthenticationMechanism::HlsSha1,
        secret: vec![0x01; 16],
        association_status: 1,
        security_setup_reference: ObisCode::new(0, 0, 43, 0, 0, 255),
        user_list: vec![],
        current_user: None,
    };
    let mut association_ln = AssociationLn::new(config);

    let result = association_ln.invoke_method(4, Some(element)).expect("remove_object failed");
    assert_eq!(result, CosemDataType::Null);
    if let CosemDataType::Array(list) = &association_ln.attributes()[1].1 {
        assert_eq!(list.len(), 0);
    } else {
        panic!("Expected Array for object_list");
    }

    // Повторное удаление отсутствующего объекта — ошибка.
    let missing = CosemDataType::Structure(vec![
        CosemDataType::LongUnsigned(1),
        CosemDataType::Unsigned(0),
        CosemDataType::OctetString(vec![0, 0, 96, 1, 0, 255]),
        CosemDataType::Array(vec![]),
    ]);
    assert!(association_ln.invoke_method(4, Some(missing)).is_err());
}
