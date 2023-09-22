//! Octet String as defined in [Section 5.3](https://datatracker.ietf.org/doc/html/rfc2741#section-5.3)

use std::convert::TryFrom;
use std::fmt;
use std::io::{Error, ErrorKind};
use std::mem::size_of;

use crate::{bytes_to_u32, u32_to_bytes, ByteOrder};

/// Octet String as defined in [Section 5.3](https://datatracker.ietf.org/doc/html/rfc2741#section-5.3)
///
/// # Examples
///
/// ```
/// # use agentx::{ByteOrder};
/// # use agentx::encodings::OctetString;
/// # use std::str::FromStr;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///   let os = OctetString("mystring".to_string());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct OctetString(pub String);
// length: u32
// octets: Vec(u8)

impl OctetString {
    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Result<Vec<u8>, Error> {
        let mut content: Vec<u8> = self.0.as_bytes().to_vec();

        let orig_len = content.len();
        while content.len() % 4 != 0 {
            content.push(0);
        }

        let len = u32::try_from(orig_len).map_err(|_| ErrorKind::InvalidData)?;
        let len = u32_to_bytes(len, bo);

        let mut result = Vec::new();
        result.extend(&len);
        result.extend(content);

        Ok(result)
    }

    pub(crate) fn byte_size(&self) -> usize {
        let mut octets_len = self.0.as_bytes().len();
        while octets_len % 4 != 0 {
            octets_len += 1;
        }

        size_of::<u32>() /* length */ + octets_len
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        if b.len() < size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let length = bytes_to_u32(b, bo)?;
        if length == 0 {
            return Ok(OctetString("".to_string()));
        }

        // the length is the the actual string lenght *without* padding
        let b = b
            .get(4..4 + length as usize)
            .ok_or(ErrorKind::InvalidData)?;
        let string = String::from_utf8(b.to_vec()).map_err(|_| ErrorKind::InvalidData)?;

        Ok(OctetString(string))
    }
}

impl fmt::Display for OctetString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_to_bytes_len_manual() {
        let os = OctetString("rck".to_string());
        assert_eq!(
            os.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            4 + 3 /* chars */ + 1 /* padding */
        );

        let os = OctetString("rckx".to_string());
        assert_eq!(
            os.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            4 + 4 /* chars, no padding */
        );

        let os = OctetString("".to_string());
        assert_eq!(
            os.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            4 /* lenght only */
        );
    }

    #[test]
    fn octet_to_bytes_len() {
        let os = OctetString("rck".to_string());
        assert_eq!(
            os.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            os.byte_size()
        );

        let os = OctetString("rckx".to_string());
        assert_eq!(
            os.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            os.byte_size()
        );

        let os = OctetString("".to_string());
        assert_eq!(
            os.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            os.byte_size()
        );
    }

    #[test]
    fn octet_serde() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            // aligned
            let expected = OctetString("rckx".to_string());
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = OctetString::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);

            // not aligned
            let expected = OctetString("rckxy".to_string());
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = OctetString::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);

            // zero
            let expected = OctetString("".to_string());
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = OctetString::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }
}
