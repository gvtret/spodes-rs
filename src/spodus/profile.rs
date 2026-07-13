//! Shared builder for the ИВКЭ reference `ProfileGeneric` objects.

use std::sync::Arc;

use crate::classes::data::Data;
use crate::classes::profile_generic::{ProfileGeneric, ProfileGenericConfig};
use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::attrs::SortMethod;
use crate::types::CosemDataType;

/// Builds a СТО-013 reference `ProfileGeneric` (IC 7, v1): each code in
/// `column_codes` becomes a capture-object column marker (`Data` at that code,
/// attribute 2) and `buffer` holds the rows.
pub(crate) fn reference_profile(
    logical_name: ObisCode,
    column_codes: &[ObisCode],
    buffer: Vec<CosemDataType>,
) -> ProfileGeneric {
    let capture_objects = column_codes
        .iter()
        .map(|code| {
            let object: Arc<dyn InterfaceClass + Send + Sync> = Arc::new(Data::new(code.clone(), CosemDataType::Null));
            (object, 2u8)
        })
        .collect();
    let entries_in_use = buffer.len() as u32;
    ProfileGeneric::new(ProfileGenericConfig {
        logical_name,
        version: 1,
        buffer,
        capture_objects,
        capture_period: 0,
        sort_method: SortMethod::Fifo,
        sort_object: None,
        entries_in_use,
        profile_entries: 0,
    })
}
