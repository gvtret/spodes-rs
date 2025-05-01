/// Библиотека `spodes-rs` для работы с объектами COSEM (Companion Specification for Energy Metering)
/// в соответствии со стандартами IEC 62056-6-2 и СТО 34.01-5.1-006-2023.
///
/// Предоставляет реализацию интерфейсных классов, типов данных, OBIS-кодов,
/// а также механизмы сериализации/десериализации в формате BER.
pub mod types;

/// Модуль для работы с OBIS-кодами (Object Identification System).
pub mod obis;

/// Модуль, определяющий трейт `InterfaceClass` для интерфейсных классов COSEM.
pub mod interface;

/// Модуль, содержащий реализации интерфейсных классов COSEM (например, `Data`, `Register`).
pub mod classes;

/// Модуль для сериализации и десериализации объектов в формате BER.
pub mod serialization;
