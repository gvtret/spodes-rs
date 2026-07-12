//! BER serialization and deserialization helpers for COSEM interface classes.

use crate::interface::InterfaceClass;
use crate::types::BerError;

/// Serializes a COSEM object into BER.
///
/// # Arguments
/// * `obj` - An object implementing the `InterfaceClass` trait.
///
/// # Returns
/// * `Ok(Vec<u8>)` - The serialized bytes.
/// * `Err(BerError)` - On a serialization error.
pub fn serialize_object(obj: &dyn InterfaceClass) -> Result<Vec<u8>, BerError> {
    let mut buf = Vec::new();
    obj.serialize_ber(&mut buf)?;
    Ok(buf)
}

/// Deserializes a COSEM object from BER data.
///
/// # Arguments
/// * `obj` - An object implementing the `InterfaceClass` trait, into which the
///   deserialized state is written.
/// * `data` - The input BER bytes.
///
/// # Returns
/// * `Ok(())` - On success.
/// * `Err(BerError)` - On a deserialization error.
pub fn deserialize_object(obj: &mut dyn InterfaceClass, data: &[u8]) -> Result<(), BerError> {
    obj.deserialize_ber(data)
}
