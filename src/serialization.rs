use crate::interface::InterfaceClass;
use crate::types::BerError;

/// Сериализует объект COSEM в формат BER для библиотеки `spodes-rs`.
///
/// # Arguments
/// * `obj` - Объект, реализующий трейт `InterfaceClass`.
///
/// # Returns
/// * `Ok(Vec<u8>)` - Сериализованные данные.
/// * `Err(BerError)` - Если произошла ошибка сериализации.
pub fn serialize_object(obj: &dyn InterfaceClass) -> Result<Vec<u8>, BerError> {
    let mut buf = Vec::new();
    obj.serialize_ber(&mut buf)?;
    Ok(buf)
}

/// Десериализует объект COSEM из данных в формате BER.
///
/// # Arguments
/// * `obj` - Объект, реализующий трейт `InterfaceClass`, для записи десериализованных данных.
/// * `data` - Входные данные в формате BER.
///
/// # Returns
/// * `Ok(())` - Если десериализация прошла успешно.
/// * `Err(BerError)` - Если произошла ошибка десериализации.
pub fn deserialize_object(obj: &mut dyn InterfaceClass, data: &[u8]) -> Result<(), BerError> {
    obj.deserialize_ber(data)
}
