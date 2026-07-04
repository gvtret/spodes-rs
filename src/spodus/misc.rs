//! Miscellaneous single-value ИВКЭ objects (СТО 34.01-5.1-013-2023, Appendix A).

use crate::classes::data::Data;
use crate::types::CosemDataType;

use super::obis;

/// The time-difference-with-meters delta object (`0.0.94.7.141.255`, IC 1,
/// unsigned): the tolerated clock skew between the ИВКЭ and its meters.
pub fn time_delta(delta: u8) -> Data {
    Data::new(obis::time_delta(), CosemDataType::Unsigned(delta))
}

/// The discrete-inputs state object (`0.0.96.3.1.255`, IC 1, long-unsigned): the
/// bitmask of the ИВКЭ discrete inputs.
pub fn discrete_inputs(mask: u16) -> Data {
    Data::new(obis::discrete_inputs(), CosemDataType::LongUnsigned(mask))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::InterfaceClass;

    #[test]
    fn misc_objects_have_correct_obis_and_types() {
        let delta = time_delta(5);
        assert_eq!(delta.logical_name(), &obis::time_delta());
        assert_eq!(delta.attributes()[1].1, CosemDataType::Unsigned(5));

        let inputs = discrete_inputs(0x00FF);
        assert_eq!(inputs.logical_name(), &obis::discrete_inputs());
        assert_eq!(inputs.attributes()[1].1, CosemDataType::LongUnsigned(0x00FF));
    }
}
