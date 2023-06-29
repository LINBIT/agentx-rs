//! Context as defined in [Section 6.1.1](https://datatracker.ietf.org/doc/html/rfc2741#section-6.1.1)
use crate::encodings::OctetString;
use crate::ByteOrder;
use std::io::Error;

/// Context as defined in [Section 6.1.1](https://datatracker.ietf.org/doc/html/rfc2741#section-6.1.1)
///
/// # Examples
///
/// ```
/// # use agentx::{ByteOrder};
/// # use agentx::encodings::{Context,OctetString};
/// # use std::str::FromStr;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///   let ctx = Context(OctetString("mystring".to_string()));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct Context(pub OctetString);

impl Context {
    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Result<Vec<u8>, Error> {
        self.0.to_bytes(bo)
    }

    pub(crate) fn byte_size(&self) -> usize {
        self.0.byte_size()
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        Ok(Context(OctetString::from_bytes(b, bo)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_to_bytes_len() {
        let os = OctetString("rck".to_string());
        let expected_os_len = 4 + 3 + 1;
        let c = Context(os);

        // expect the context has the same length / "is" a OctetString
        assert_eq!(
            c.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            expected_os_len
        );
    }

    #[test]
    fn context_serde() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let expected = Context(OctetString("rckx".to_string()));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = Context::from_bytes(bytes.as_slice(), &bo).unwrap();

            assert_eq!(got, expected);
        }
    }
}
