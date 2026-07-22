//! Table-manager interface class (СТО 34.01-5.1-013-2023, §7.2, class 8200).
//!
//! A СПОДУС-specific class that operates on an `array` attribute as a table of
//! fixed-column rows, one column being a unique key. It provides group
//! operations — add/update, remove, count and selective retrieve — so the
//! head-end can manage a working table (e.g. the meter list `0.0.94.7.128.255`)
//! in a single request. Class 8200, version 0.

use std::any::Any;

use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};

/// The unique-key value of a row structure at `key_index`, if present.
fn key_of(row: &CosemDataType, key_index: usize) -> Option<CosemDataType> {
    match row {
        CosemDataType::Structure(fields) => fields.get(key_index).cloned(),
        _ => None,
    }
}

/// Table-manager object (class 8200, `0.0.94.7.200.255`), managing a working
/// array whose rows are structures with a unique-key column.
#[derive(Clone, Debug)]
pub struct TableManager {
    logical_name: ObisCode,
    /// Index of the unique-key field within each row structure.
    key_index: usize,
    /// The managed working array (rows are structures).
    rows: Vec<CosemDataType>,
}

impl TableManager {
    /// Creates a manager at `logical_name` for a table keyed on field `key_index`.
    pub fn new(logical_name: ObisCode, key_index: usize) -> Self {
        TableManager { logical_name, key_index, rows: Vec::new() }
    }

    /// The managed rows.
    pub fn rows(&self) -> &[CosemDataType] {
        &self.rows
    }

    /// Replaces the managed rows.
    pub fn set_rows(&mut self, rows: Vec<CosemDataType>) {
        self.rows = rows;
    }

    /// Method 1: `add_update_entries` — merge full rows by unique key.
    fn add_update_entries(&mut self, entries: Vec<CosemDataType>) -> Result<CosemDataType, String> {
        let key_index = self.key_index;
        for entry in entries {
            let key = key_of(&entry, key_index).ok_or("entry is not a keyed structure")?;
            match self.rows.iter_mut().find(|r| key_of(r, key_index).as_ref() == Some(&key)) {
                Some(existing) => *existing = entry,
                None => self.rows.push(entry),
            }
        }
        Ok(CosemDataType::Null)
    }

    /// Method 2: `remove_entries` — remove rows by key; empty list clears all.
    fn remove_entries(&mut self, keys: &[CosemDataType]) -> Result<CosemDataType, String> {
        let key_index = self.key_index;
        if keys.is_empty() {
            self.rows.clear();
        } else {
            self.rows.retain(|row| !keys.iter().any(|k| key_of(row, key_index).as_ref() == Some(k)));
        }
        Ok(CosemDataType::Null)
    }

    /// Method 4: `retrieve_entries` — rows matching the keys; empty list = all.
    fn retrieve_entries(&self, keys: &[CosemDataType]) -> CosemDataType {
        let key_index = self.key_index;
        let selected = if keys.is_empty() {
            self.rows.clone()
        } else {
            self.rows
                .iter()
                .filter(|row| keys.iter().any(|k| key_of(row, key_index).as_ref() == Some(k)))
                .cloned()
                .collect()
        };
        CosemDataType::Array(selected)
    }

    /// Extracts the `entries_list` from a method's `{object_obis, entries_list}`
    /// data structure.
    fn entries_list(params: Option<CosemDataType>) -> Result<Vec<CosemDataType>, String> {
        match params {
            Some(CosemDataType::Structure(fields)) => match fields.into_iter().nth(1) {
                Some(CosemDataType::Array(entries)) => Ok(entries),
                _ => Err("entries_list must be an array".to_string()),
            },
            _ => Err("expected a {object_obis, entries_list} structure".to_string()),
        }
    }
}

impl InterfaceClass for TableManager {
    fn class_id(&self) -> u16 {
        8200
    }

    fn version(&self) -> u8 {
        0
    }

    fn logical_name(&self) -> &ObisCode {
        &self.logical_name
    }

    fn attributes(&self) -> Vec<(u8, CosemDataType)> {
        vec![(1, CosemDataType::OctetString(self.logical_name.to_bytes()))]
    }

    fn methods(&self) -> Vec<(u8, String)> {
        vec![
            (1, "add_update_entries".to_string()),
            (2, "remove_entries".to_string()),
            (3, "retrieve_number_of_entries".to_string()),
            (4, "retrieve_entries".to_string()),
        ]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        buf.push(0x02); // structure
        buf.push(0x02); // two elements
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(buf)?;
        CosemDataType::OctetString(self.logical_name.to_bytes()).serialize_ber(buf)
    }

    fn deserialize_ber(&mut self, _data: &[u8]) -> Result<(), BerError> {
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => {
                let entries = Self::entries_list(params)?;
                self.add_update_entries(entries)
            }
            2 => {
                let keys = Self::entries_list(params)?;
                self.remove_entries(&keys)
            }
            3 => {
                // Already clamped to u8::MAX above, so the cast can't truncate.
                #[allow(clippy::cast_possible_truncation)]
                let count = self.rows.len().min(u8::MAX as usize) as u8;
                Ok(CosemDataType::Unsigned(count))
            }
            4 => {
                let keys = Self::entries_list(params)?;
                Ok(self.retrieve_entries(&keys))
            }
            other => Err(format!("method {other} not supported for the Table manager class")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &[u8]) -> CosemDataType {
        CosemDataType::OctetString(id.to_vec())
    }

    fn row(id: &[u8], value: u16) -> CosemDataType {
        CosemDataType::Structure(vec![key(id), CosemDataType::LongUnsigned(value)])
    }

    fn wrap(entries: Vec<CosemDataType>) -> Option<CosemDataType> {
        Some(CosemDataType::Structure(vec![CosemDataType::OctetString(vec![]), CosemDataType::Array(entries)]))
    }

    #[test]
    fn table_manager_group_operations() {
        let mut mgr = TableManager::new(ObisCode::new(0, 0, 94, 7, 200, 255), 0);
        assert_eq!(mgr.class_id(), 8200);

        // add two rows.
        mgr.invoke_method(1, wrap(vec![row(b"A", 1), row(b"B", 2)])).unwrap();
        assert_eq!(mgr.invoke_method(3, None).unwrap(), CosemDataType::Unsigned(2));

        // update A by its unique key.
        mgr.invoke_method(1, wrap(vec![row(b"A", 100)])).unwrap();
        assert_eq!(mgr.invoke_method(3, None).unwrap(), CosemDataType::Unsigned(2));
        let CosemDataType::Array(got) = mgr.invoke_method(4, wrap(vec![key(b"A")])).unwrap() else {
            panic!("array");
        };
        assert_eq!(got, vec![row(b"A", 100)]);

        // remove B; one row left.
        mgr.invoke_method(2, wrap(vec![key(b"B")])).unwrap();
        assert_eq!(mgr.invoke_method(3, None).unwrap(), CosemDataType::Unsigned(1));

        // remove-all with an empty list.
        mgr.invoke_method(2, wrap(vec![])).unwrap();
        assert_eq!(mgr.invoke_method(3, None).unwrap(), CosemDataType::Unsigned(0));
    }
}
