use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};
use std::any::Any;

/// The trait shared by every COSEM interface class defined in IEC 62056-6-2.
///
/// Each class exposes its class id, version, logical name (OBIS code),
/// attributes and methods, and supports BER serialization/deserialization and
/// method invocation.
pub trait InterfaceClass: Any {
    /// Returns the class id (`class_id`) as defined in IEC 62056-6-2.
    fn class_id(&self) -> u16;

    /// Returns the class version.
    fn version(&self) -> u8;

    /// Returns the object's logical name (OBIS code).
    fn logical_name(&self) -> &ObisCode;

    /// Returns the class attributes as `(attribute_id, value)` pairs.
    fn attributes(&self) -> Vec<(u8, CosemDataType)>;

    /// Returns the class methods as `(method_id, name)` pairs.
    fn methods(&self) -> Vec<(u8, String)>;

    /// Serializes the object into BER.
    ///
    /// # Arguments
    /// * `buf` - The buffer the serialized bytes are appended to.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(BerError)` - On a serialization error.
    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError>;

    /// Deserializes the object from BER data.
    ///
    /// # Arguments
    /// * `data` - The input BER bytes.
    ///
    /// # Returns
    /// * `Ok(())` - On success.
    /// * `Err(BerError)` - On a deserialization error.
    fn deserialize_ber(&mut self, data: &[u8]) -> Result<(), BerError>;

    /// Writes the value of a writable attribute. The default implementation
    /// rejects the write; classes with writable attributes override it.
    ///
    /// # Arguments
    /// * `attribute_id` - The attribute to write.
    /// * `value` - The new attribute value.
    ///
    /// # Returns
    /// * `Ok(())` - If the attribute was written.
    /// * `Err(String)` - If the attribute is not writable or the value is invalid.
    fn set_attribute(&mut self, attribute_id: u8, value: CosemDataType) -> Result<(), String> {
        let _ = (attribute_id, value);
        Err("attribute is not writable".to_string())
    }

    /// Invokes the object method with the given id.
    ///
    /// # Arguments
    /// * `method_id` - The method id.
    /// * `params` - Optional method parameters as a `CosemDataType`.
    ///
    /// # Returns
    /// * `Ok(CosemDataType)` - The method result.
    /// * `Err(String)` - An error description if the method is not supported.
    fn invoke_method(
        &mut self,
        method_id: u8,
        params: Option<CosemDataType>,
    ) -> Result<CosemDataType, String>;

    /// Returns the object as `dyn Any` for dynamic downcasting.
    fn as_any(&self) -> &dyn Any;
}
