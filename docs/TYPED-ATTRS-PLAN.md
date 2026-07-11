# План: Сильная типизация атрибутов IC

## Цель
Заменить общий `CosemDataType` на сильнотипизированные структуры для каждого IC согласно IEC 62056-6-2.

## Фаза 1: Базовые типы (сейчас)

### 1.1 Создать `src/types/attrs.rs` — типизированные атрибуты
```rust
/// Logical name (OBIS code) — attribute 1 всех IC.
pub type LogicalName = ObisCode;

/// CHOICE тип — любой COSEM тип (для value, status и т.д.)
pub type Choice = CosemDataType;

/// ScalerUnit: structure { scaler: integer, unit: enum }
pub struct ScalerUnit {
    pub scaler: i8,
    pub unit: u8,
}

/// Capture object definition: structure { class_id, logical_name, attribute_index, data_index }
pub struct CaptureObjectDefinition {
    pub class_id: u16,
    pub logical_name: ObisCode,
    pub attribute_index: u8,
    pub data_index: u8,
}
```

### 1.2 Типизированные структуры для основных IC

**Data (class 1):**
```rust
pub struct DataAttrs {
    pub logical_name: LogicalName,  // attr 1: octet-string
    pub value: Choice,              // attr 2: CHOICE (any)
}
```

**Register (class 3):**
```rust
pub struct RegisterAttrs {
    pub logical_name: LogicalName,  // attr 1: octet-string
    pub value: Choice,              // attr 2: CHOICE
    pub scaler_unit: ScalerUnit,    // attr 3: scal_unit_type
}
```

**Clock (class 8):**
```rust
pub struct ClockAttrs {
    pub logical_name: LogicalName,           // attr 1: octet-string
    pub time: DateTime,                      // attr 2: octet-string (date-time)
    pub time_zone: i16,                      // attr 3: long
    pub status: BitString,                   // attr 4: octet-string (bit-string)
    pub daylight_savings_begin: DateTime,    // attr 5: octet-string
    pub daylight_savings_end: DateTime,      // attr 6: octet-string
    pub daylight_savings_deviation: i8,      // attr 7: integer
    pub daylight_savings_enabled: bool,      // attr 8: boolean
    pub clock_base: u8,                      // attr 9: enum
}
```

**Profile generic (class 7):**
```rust
pub struct ProfileGenericAttrs {
    pub logical_name: LogicalName,           // attr 1: octet-string
    pub buffer: Vec<Vec<CosemDataType>>,     // attr 2: array of structures
    pub capture_objects: Vec<CaptureObjectDefinition>, // attr 3: array
    pub capture_period: u32,                 // attr 4: double-long-unsigned
    pub sort_method: u8,                     // attr 5: enum
    pub sort_object: Option<CaptureObjectDefinition>, // attr 6: capture_object_definition
    pub entries_in_use: u32,                 // attr 7: double-long-unsigned
    pub profile_entries: u32,                // attr 8: double-long-unsigned
}
```

## Фаза 2: Обновление InterfaceClass trait

```rust
pub trait InterfaceClass: Any {
    fn class_id(&self) -> u16;
    fn version(&self) -> u8;
    fn logical_name(&self) -> &LogicalName;
    fn attributes(&self) -> Vec<(u8, Choice)>;  // CHOICE для совместимости
    fn methods(&self) -> Vec<(u8, String)>;
    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError>;
    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError>;
    fn set_attribute(&mut self, attribute_id: u8, value: Choice) -> Result<(), String>;
    fn invoke_method(&mut self, method_id: u8, params: Option<Choice>) -> Result<Choice, String>;
    fn as_any(&self) -> &dyn Any;
    
    // Новый метод: возвращает типизированные атрибуты
    fn typed_attributes(&self) -> &dyn Any;  // Для доступа к конкретному типу
}
```

## Фаза 3: Обновление IC (по приоритету)

1. **Data (1)** — базовый, используется везде
2. **Register (3)** — второй по частоте использования
3. **Clock (8)** — сложный, много атрибутов
4. **Profile generic (7)** — сложный, буфер и capture_objects
5. **Association LN (15)** — критичный для ACL
6. **Extended register (4)** — расширение Register
7. **Demand register (5)** — расширение Register
8. Остальные IC...

## Фаза 4: Обновление сервера и клиента

- Сервер: проверка типов при dispatch
- Клиент: получение типизированных ответов
- Тесты: обновление всех тестов

## Риски

1. **Совместимость с BER** — сериализация/десериализация должна остаться совместимой
2. **Обратная совместимость** — старый API через CHOICE должен работать
3. **Объем работ** — 30+ IC, 288 тестов
