//! Access rights model for DLMS/COSEM (IEC 62056-5-3, 5.3.7).
//!
//! The Association LN object holds an `object_list` that defines the visible
//! COSEM objects and their access rights. Each object entry contains:
//! - `class_id`, `version`, `logical_name` — object identification
//! - `access_rights` — permissions for attributes and methods
//!
//! Access modes per IEC 62056-5-3:
//! - Attribute: no_access(0), read_only(1), write_only(2), read_and_write(3),
//!   authenticated_read_only(4), authenticated_write_only(5), authenticated_read_and_write(6)
//! - Method: no_access(0), access(1), authenticated_access(2)

use crate::types::CosemDataType;

/// Access mode for an attribute (IEC 62056-5-3, 5.3.7.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeAccessMode {
    /// No access to this attribute.
    NoAccess = 0,
    /// Read-only access.
    ReadOnly = 1,
    /// Write-only access.
    WriteOnly = 2,
    /// Read and write access.
    ReadWrite = 3,
    /// Authenticated read-only access.
    AuthenticatedReadOnly = 4,
    /// Authenticated write-only access.
    AuthenticatedWriteOnly = 5,
    /// Authenticated read and write access.
    AuthenticatedReadWrite = 6,
}

impl AttributeAccessMode {
    /// Parses an access mode from its numeric value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NoAccess),
            1 => Some(Self::ReadOnly),
            2 => Some(Self::WriteOnly),
            3 => Some(Self::ReadWrite),
            4 => Some(Self::AuthenticatedReadOnly),
            5 => Some(Self::AuthenticatedWriteOnly),
            6 => Some(Self::AuthenticatedReadWrite),
            _ => None,
        }
    }

    /// Whether this mode allows reading.
    pub fn allows_read(&self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite | Self::AuthenticatedReadOnly | Self::AuthenticatedReadWrite)
    }

    /// Whether this mode allows writing.
    pub fn allows_write(&self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite | Self::AuthenticatedWriteOnly | Self::AuthenticatedReadWrite)
    }

    /// Whether this mode requires authentication.
    pub fn requires_auth(&self) -> bool {
        matches!(self, Self::AuthenticatedReadOnly | Self::AuthenticatedWriteOnly | Self::AuthenticatedReadWrite)
    }
}

/// Access mode for a method (IEC 62056-5-3, 5.3.7.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodAccessMode {
    /// No access to this method.
    NoAccess = 0,
    /// Access allowed.
    Access = 1,
    /// Authenticated access required.
    AuthenticatedAccess = 2,
}

impl MethodAccessMode {
    /// Parses an access mode from its numeric value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::NoAccess),
            1 => Some(Self::Access),
            2 => Some(Self::AuthenticatedAccess),
            _ => None,
        }
    }

    /// Whether this mode allows access.
    pub fn allows_access(&self) -> bool {
        !matches!(self, Self::NoAccess)
    }

    /// Whether this mode requires authentication.
    pub fn requires_auth(&self) -> bool {
        matches!(self, Self::AuthenticatedAccess)
    }
}

/// Access rights for a single attribute (IEC 62056-5-3, 5.3.7.2.2).
#[derive(Debug, Clone)]
pub struct AttributeAccessItem {
    /// The attribute id (1-based).
    pub attribute_id: i8,
    /// The access mode for this attribute.
    pub access_mode: AttributeAccessMode,
    /// Optional access selectors (null-data or array of integer).
    pub access_selectors: Option<Vec<i8>>,
}

/// Access rights for a single method (IEC 62056-5-3, 5.3.7.2.2).
#[derive(Debug, Clone)]
pub struct MethodAccessItem {
    /// The method id (1-based).
    pub method_id: i8,
    /// The access mode for this method.
    pub access_mode: MethodAccessMode,
}

/// Complete access rights for an object (IEC 62056-5-3, 5.3.7.2.2).
#[derive(Debug, Clone)]
pub struct AccessRights {
    /// Access rights for each attribute.
    pub attribute_access: Vec<AttributeAccessItem>,
    /// Access rights for each method.
    pub method_access: Vec<MethodAccessItem>,
}

/// An entry in the Association LN `object_list` (IEC 62056-5-3, 5.3.7.2.2).
#[derive(Debug, Clone)]
pub struct ObjectListEntry {
    /// The class id of the object.
    pub class_id: u16,
    /// The class version.
    pub version: u8,
    /// The logical name (OBIS code) of the object.
    pub logical_name: Vec<u8>, // OBIS as 6 bytes
    /// The access rights for this object.
    pub access_rights: AccessRights,
}

impl ObjectListEntry {
    /// Checks whether a read is allowed for the given attribute.
    pub fn can_read(&self, attribute_id: i8) -> bool {
        self.access_rights.attribute_access.iter()
            .any(|item| item.attribute_id == attribute_id && item.access_mode.allows_read())
    }

    /// Checks whether a write is allowed for the given attribute.
    pub fn can_write(&self, attribute_id: i8) -> bool {
        self.access_rights.attribute_access.iter()
            .any(|item| item.attribute_id == attribute_id && item.access_mode.allows_write())
    }

    /// Checks whether a method call is allowed.
    pub fn can_invoke(&self, method_id: i8) -> bool {
        self.access_rights.method_access.iter()
            .any(|item| item.method_id == method_id && item.access_mode.allows_access())
    }

    /// Checks whether authentication is required for reading.
    pub fn auth_required_read(&self, attribute_id: i8) -> bool {
        self.access_rights.attribute_access.iter()
            .any(|item| item.attribute_id == attribute_id && item.access_mode.requires_auth())
    }

    /// Checks whether authentication is required for writing.
    pub fn auth_required_write(&self, attribute_id: i8) -> bool {
        self.access_rights.attribute_access.iter()
            .any(|item| item.attribute_id == attribute_id && item.access_mode.requires_auth())
    }
}

/// Builds an object_list entry with default read/write access for all attributes.
pub fn full_access_entry(class_id: u16, version: u8, obis: &[u8], attr_count: u8, method_count: u8) -> ObjectListEntry {
    let attribute_access = (1..=attr_count).map(|id| AttributeAccessItem {
        attribute_id: id as i8,
        access_mode: AttributeAccessMode::ReadWrite,
        access_selectors: None,
    }).collect();

    let method_access = (1..=method_count).map(|id| MethodAccessItem {
        method_id: id as i8,
        access_mode: MethodAccessMode::Access,
    }).collect();

    ObjectListEntry {
        class_id,
        version,
        logical_name: obis.to_vec(),
        access_rights: AccessRights { attribute_access, method_access },
    }
}

/// Builds an object_list entry with read-only access for all attributes.
pub fn read_only_entry(class_id: u16, version: u8, obis: &[u8], attr_count: u8, method_count: u8) -> ObjectListEntry {
    let attribute_access = (1..=attr_count).map(|id| AttributeAccessItem {
        attribute_id: id as i8,
        access_mode: AttributeAccessMode::ReadOnly,
        access_selectors: None,
    }).collect();

    let method_access = (1..=method_count).map(|id| MethodAccessItem {
        method_id: id as i8,
        access_mode: MethodAccessMode::NoAccess,
    }).collect();

    ObjectListEntry {
        class_id,
        version,
        logical_name: obis.to_vec(),
        access_rights: AccessRights { attribute_access, method_access },
    }
}
