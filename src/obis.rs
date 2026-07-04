use serde::{Deserialize, Serialize};
use std::fmt;

/// An OBIS code (Object Identification System) used by COSEM to identify
/// objects. It is the six-octet `a.b.c.d.e.f` value group.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ObisCode {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
}

impl ObisCode {
    /// Creates a new OBIS code from its six components.
    ///
    /// # Arguments
    /// * `a`, `b`, `c`, `d`, `e`, `f` - The OBIS code components.
    ///
    /// # Returns
    /// A new `ObisCode`.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        ObisCode { a, b, c, d, e, f }
    }

    /// Returns the OBIS code as a byte vector.
    ///
    /// # Returns
    /// A six-byte vector representing the OBIS code.
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.a, self.b, self.c, self.d, self.e, self.f]
    }
}

impl fmt::Display for ObisCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}-{}.{}.{}.{}.{}",
            self.a, self.b, self.c, self.d, self.e, self.f
        )
    }
}
