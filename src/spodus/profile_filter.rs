//! Profile-data-filter interface class (СТО 34.01-5.1-013-2023, §7.3, class 8201).
//!
//! A СПОДУС-specific class that extends `Profile generic` (IC 7) with filtered
//! reads: it selects rows of a working profile by range or value-match
//! conditions and projects them to the requested columns, so the head-end can
//! read exactly the rows and columns it needs in one request. Class 8201, v0.
//!
//! The filter data is
//! `{ object_obis, selected_values: array capture_object_definition,
//!    filter_list: array filter_object_definition }`, where each filter is
//! `{ filtering_object, from_value, to_value, entry_values }`. A row passes when
//! it satisfies every filter (range `from..to` inclusive, or membership in
//! `entry_values`).

use std::any::Any;
use std::cmp::Ordering;

use crate::interface::InterfaceClass;
use crate::obis::ObisCode;
use crate::types::{BerError, CosemDataType};

/// Profile-data-filter object (class 8201, `0.0.94.7.201.255`) over a working
/// profile's rows.
#[derive(Clone, Debug)]
pub struct ProfileDataFilter {
    logical_name: ObisCode,
    /// Column OBIS codes of the working profile, in order.
    columns: Vec<ObisCode>,
    /// The working profile rows (structures).
    rows: Vec<CosemDataType>,
}

impl ProfileDataFilter {
    /// Creates a filter at `logical_name` over a profile with the given column
    /// OBIS codes.
    pub fn new(logical_name: ObisCode, columns: Vec<ObisCode>) -> Self {
        ProfileDataFilter { logical_name, columns, rows: Vec::new() }
    }

    /// Replaces the working profile rows.
    pub fn set_rows(&mut self, rows: Vec<CosemDataType>) {
        self.rows = rows;
    }

    /// The working rows.
    pub fn rows(&self) -> &[CosemDataType] {
        &self.rows
    }

    /// Resolves a `capture_object_definition` (field 1 = logical_name) to a
    /// column index.
    fn column_index(&self, capture_object: &CosemDataType) -> Option<usize> {
        let name = match capture_object {
            CosemDataType::Structure(fields) => fields.get(1),
            _ => None,
        }?;
        let CosemDataType::OctetString(bytes) = name else { return None };
        self.columns.iter().position(|c| &c.to_bytes() == bytes)
    }

    /// Whether a row passes all filters.
    fn passes(&self, row: &[CosemDataType], filters: &[CosemDataType]) -> bool {
        filters.iter().all(|filter| self.passes_one(row, filter))
    }

    fn passes_one(&self, row: &[CosemDataType], filter: &CosemDataType) -> bool {
        let CosemDataType::Structure(f) = filter else { return true };
        let Some(index) = f.first().and_then(|o| self.column_index(o)) else { return true };
        let Some(value) = row.get(index) else { return false };
        let from = f.get(1);
        let to = f.get(2);
        let entries = f.get(3);

        // Value-match filter.
        if let Some(CosemDataType::Array(list)) = entries {
            if !list.is_empty() {
                return list.contains(value);
            }
        }
        // Range filter (inclusive; a Null bound is open).
        let lower_ok = matches!(from, None | Some(CosemDataType::Null))
            || matches!(compare(from.unwrap(), value), Some(Ordering::Less | Ordering::Equal));
        let upper_ok = matches!(to, None | Some(CosemDataType::Null))
            || matches!(compare(value, to.unwrap()), Some(Ordering::Less | Ordering::Equal));
        lower_ok && upper_ok
    }

    /// Projects a row to the columns named by `selected_values` (all columns if
    /// the selection is empty).
    fn project(&self, row: &[CosemDataType], selected: &[CosemDataType]) -> CosemDataType {
        if selected.is_empty() {
            return CosemDataType::Structure(row.to_vec());
        }
        let fields = selected.iter().filter_map(|s| self.column_index(s).and_then(|i| row.get(i)).cloned()).collect();
        CosemDataType::Structure(fields)
    }

    /// Applies a filter request, returning the projected matching rows.
    fn filtered(&self, selected: &[CosemDataType], filters: &[CosemDataType]) -> Vec<CosemDataType> {
        self.rows
            .iter()
            .filter_map(|row| match row {
                CosemDataType::Structure(fields) if self.passes(fields, filters) => {
                    Some(self.project(fields, selected))
                }
                _ => None,
            })
            .collect()
    }

    /// Parses `{object_obis, selected_values, filter_list}` into its two arrays.
    fn parse(params: Option<CosemDataType>) -> (Vec<CosemDataType>, Vec<CosemDataType>) {
        let mut selected = Vec::new();
        let mut filters = Vec::new();
        if let Some(CosemDataType::Structure(fields)) = params {
            if let Some(CosemDataType::Array(s)) = fields.get(1) {
                selected = s.clone();
            }
            if let Some(CosemDataType::Array(f)) = fields.get(2) {
                filters = f.clone();
            }
        }
        (selected, filters)
    }
}

/// Compares two COSEM values, if comparable (numeric or byte-lexicographic).
fn compare(a: &CosemDataType, b: &CosemDataType) -> Option<Ordering> {
    if let (Some(x), Some(y)) = (as_int(a), as_int(b)) {
        return Some(x.cmp(&y));
    }
    match (a, b) {
        (CosemDataType::OctetString(x), CosemDataType::OctetString(y))
        | (CosemDataType::DateTime(x), CosemDataType::DateTime(y))
        | (CosemDataType::DateTime(x), CosemDataType::OctetString(y))
        | (CosemDataType::OctetString(x), CosemDataType::DateTime(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

/// The integer value of a numeric COSEM type, if it is one.
fn as_int(v: &CosemDataType) -> Option<i128> {
    Some(match v {
        CosemDataType::Integer(i) => *i as i128,
        CosemDataType::Long(i) => *i as i128,
        CosemDataType::DoubleLong(i) => *i as i128,
        CosemDataType::Unsigned(u) => *u as i128,
        CosemDataType::LongUnsigned(u) => *u as i128,
        CosemDataType::DoubleLongUnsigned(u) => *u as i128,
        CosemDataType::Enum(u) => *u as i128,
        _ => return None,
    })
}

impl InterfaceClass for ProfileDataFilter {
    fn class_id(&self) -> u16 {
        8201
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
            (1, "retrieve_number_of_entries".to_string()),
            (2, "retrieve_entries".to_string()),
            (3, "retrieve_entries_by_row".to_string()),
            (4, "remove_entries".to_string()),
        ]
    }

    fn serialize_ber(&self, buf: &mut Vec<u8>) -> Result<(), BerError> {
        buf.push(0x02);
        buf.push(0x02);
        CosemDataType::LongUnsigned(self.class_id()).serialize_ber(buf)?;
        CosemDataType::OctetString(self.logical_name.to_bytes()).serialize_ber(buf)
    }

    fn deserialize_ber(&mut self, _data: &[u8]) -> Result<(), BerError> {
        Ok(())
    }

    fn invoke_method(&mut self, method_id: u8, params: Option<CosemDataType>) -> Result<CosemDataType, String> {
        match method_id {
            1 => {
                let (_, filters) = Self::parse(params);
                let count = self
                    .rows
                    .iter()
                    .filter(|r| matches!(r, CosemDataType::Structure(f) if self.passes(f, &filters)))
                    .count();
                Ok(CosemDataType::Unsigned(count.min(u8::MAX as usize) as u8))
            }
            // retrieve_entries and retrieve_entries_by_row share the filter+project logic.
            2 | 3 => {
                let (selected, filters) = Self::parse(params);
                Ok(CosemDataType::Array(self.filtered(&selected, &filters)))
            }
            4 => {
                let (_, filters) = Self::parse(params);
                let kept = self
                    .rows
                    .iter()
                    .filter(|row| match row {
                        CosemDataType::Structure(f) => !self.passes(f, &filters),
                        _ => true,
                    })
                    .cloned()
                    .collect();
                self.rows = kept;
                Ok(CosemDataType::Null)
            }
            other => Err(format!("method {other} not supported for the Profile data filter class")),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn columns() -> Vec<ObisCode> {
        vec![ObisCode::new(0, 0, 94, 7, 128, 10), ObisCode::new(1, 0, 1, 8, 0, 255)]
    }

    fn col_def(code: ObisCode) -> CosemDataType {
        CosemDataType::Structure(vec![
            CosemDataType::LongUnsigned(1),
            CosemDataType::OctetString(code.to_bytes()),
            CosemDataType::Integer(2),
            CosemDataType::LongUnsigned(0),
        ])
    }

    fn row(id: &[u8], value: u16) -> CosemDataType {
        CosemDataType::Structure(vec![CosemDataType::OctetString(id.to_vec()), CosemDataType::LongUnsigned(value)])
    }

    fn build() -> ProfileDataFilter {
        let mut f = ProfileDataFilter::new(ObisCode::new(0, 0, 94, 7, 201, 255), columns());
        f.set_rows(vec![row(b"A", 100), row(b"B", 200), row(b"C", 300)]);
        f
    }

    #[test]
    fn value_match_filter_and_projection() {
        let mut filter = build();
        // Select the value column for rows whose meter id is A or C.
        let selected = vec![col_def(ObisCode::new(1, 0, 1, 8, 0, 255))];
        let filters = vec![CosemDataType::Structure(vec![
            col_def(ObisCode::new(0, 0, 94, 7, 128, 10)),
            CosemDataType::Null,
            CosemDataType::Null,
            CosemDataType::Array(vec![
                CosemDataType::OctetString(b"A".to_vec()),
                CosemDataType::OctetString(b"C".to_vec()),
            ]),
        ])];
        let data = Some(CosemDataType::Structure(vec![
            CosemDataType::OctetString(vec![]),
            CosemDataType::Array(selected),
            CosemDataType::Array(filters),
        ]));
        let CosemDataType::Array(rows) = filter.invoke_method(2, data).unwrap() else { panic!("array") };
        assert_eq!(rows.len(), 2);
        // Projected to the single value column.
        assert_eq!(rows[0], CosemDataType::Structure(vec![CosemDataType::LongUnsigned(100)]));
    }

    #[test]
    fn range_filter_and_count() {
        let mut filter = build();
        // Rows whose value column is in [150, 250] → only B (200).
        let filters = vec![CosemDataType::Structure(vec![
            col_def(ObisCode::new(1, 0, 1, 8, 0, 255)),
            CosemDataType::LongUnsigned(150),
            CosemDataType::LongUnsigned(250),
            CosemDataType::Null,
        ])];
        let data = Some(CosemDataType::Structure(vec![
            CosemDataType::OctetString(vec![]),
            CosemDataType::Array(vec![]),
            CosemDataType::Array(filters),
        ]));
        assert_eq!(filter.invoke_method(1, data.clone()).unwrap(), CosemDataType::Unsigned(1));
        let CosemDataType::Array(rows) = filter.invoke_method(2, data).unwrap() else { panic!("array") };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], row(b"B", 200));
    }
}
