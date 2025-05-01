use crate::obis::ObisCode;
use crate::types::{CosemDataType, BerError};
use std::any::Any;

/// Трейт, определяющий общий интерфейс для всех интерфейсных классов COSEM,
/// описанных в IEC 62056-6-2.
///
/// Каждый класс должен предоставлять информацию о своем идентификаторе,
/// версии, логическом имени (OBIS-коде), атрибутах и методах, а также
/// поддерживать сериализацию/десериализацию в формате BER и вызов методов.
pub trait InterfaceClass: Any {
    /// Возвращает идентификатор класса (class_id) согласно IEC 62056-6-2.
    fn class_id(&self) -> u16;

    /// Возвращает версию класса.
    fn version(&self) -> u8;

    /// Возвращает логическое имя объекта (OBIS-код).
    fn logical_name(&self) -> &ObisCode;

    /// Возвращает список атрибутов класса с их идентификаторами и значениями.
    fn attributes(&self) -> Vec<(u8, CosemDataType)>;

    /// Возвращает список методов класса с их идентификаторами и именами.
    fn methods(&self) -> Vec<(u8, String)>;

    /// Сериализует объект в формат BER.
    ///
    /// # Arguments
    /// * `buf` - Буфер для записи сериализованных данных.
    ///
    /// # Returns
    /// * `Ok(())` - Если сериализация прошла успешно.
    /// * `Err(BerError)` - Если произошла ошибка сериализации.
    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError>;

    /// Десериализует объект из данных в формате BER.
    ///
    /// # Arguments
    /// * `data` - Входные данные в формате BER.
    ///
    /// # Returns
    /// * `Ok(())` - Если десериализация прошла успешно.
    /// * `Err(BerError)` - Если произошла ошибка десериализации.
    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError>;

    /// Вызывает метод объекта с указанным идентификатором.
    ///
    /// # Arguments
    /// * `method_id` - Идентификатор метода.
    /// * `params` - Опциональные параметры метода в формате `CosemDataType`.
    ///
    /// # Returns
    /// * `Ok(CosemDataType)` - Результат выполнения метода.
    /// * `Err(String)` - Описание ошибки, если метод не поддерживается.
    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String>;

    /// Возвращает объект как `dyn Any` для динамической диспетчеризации.
    fn as_any(&self) -> &dyn Any;
}