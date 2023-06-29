//! OID as defined in [Section 5.1](https://datatracker.ietf.org/doc/html/rfc2741#section-5.1)
//!
//! The standard defines that OIDs are sorted lexicographical, `PartialOrd` and `Ord` are implemented accordingly.

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::str::FromStr;

use crate::{bytes_to_u32, u32_to_bytes, ByteOrder};

/// OID as defined in [Section 5.1](https://datatracker.ietf.org/doc/html/rfc2741#section-5.1)
///
/// # Examples
///
/// ```
/// # use agentx::{ByteOrder};
/// # use agentx::encodings::ID;
/// # use std::str::FromStr;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let expected = ID::from_str("1.2.3.4")?;
/// let v = expected.to_bytes(&ByteOrder::LittleEndian);
/// let got = ID::from_bytes(v.as_slice(), &ByteOrder::LittleEndian)?;
/// assert_eq!(expected, got);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default)]
pub struct ID {
    // number of 4-byte sub-identifier that follow
    // we keep this value as we need it to calulate how much it used in the original byte stream in .byte_size()
    orig_n_subid: u8,
    // if non-zero the first-subidentifier after "internet" (1.3.6.1)
    // prefix: u8,
    /// used in SearchRange to indicate that the specified ID should be included in the results
    pub include: u8,
    // reserved: u8
    /// vector of subids, already normalized!
    sub_ids: Vec<u32>,
}

fn normalize(sub_ids: &[u32], prefix: u8) -> Vec<u32> {
    let mut result = Vec::new();

    if prefix != 0 {
        result = vec![1, 3, 6, 1, prefix as u32];
    }

    result.extend(sub_ids);

    result
}

impl ID {
    /// check for "null Object Identifier"
    pub fn is_null(&self) -> bool {
        self.sub_ids.is_empty()
    }

    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Vec<u8> {
        // it is the job of the constructor to make sure this assumption holds
        // there is no way one could construct an ID manually that would violate the assumption
        let n_subid =
            u8::try_from(self.sub_ids.len()).expect("n_subid lenght checked by constructor");

        // we always normalize IDs, so "prefix" is always 0 in our case
        let mut result = vec![n_subid, 0, self.include, 0];
        for id in &self.sub_ids {
            result.extend(u32_to_bytes(*id, bo));
        }

        result
    }

    pub(crate) fn byte_size(&self) -> usize {
        size_of::<u32>() /* "header" */ + size_of::<u32>() * self.orig_n_subid as usize
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        if b.len() < size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let n_subid = b[0];
        let prefix = b[1];
        let include = b[2];
        // [3] reserved;
        let mut b = b.get(4..).ok_or(ErrorKind::InvalidData)?;

        if b.len() < n_subid as usize * size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let mut sub_ids = Vec::with_capacity(n_subid as usize);
        for _ in 0..n_subid {
            sub_ids.push(bytes_to_u32(b, bo)?);
            b = &b[4..]; // size already checked
        }

        Ok(Self {
            orig_n_subid: n_subid,
            include,
            sub_ids: normalize(&sub_ids, prefix),
        })
    }
}

// to_string() is also use in Ord.cmp(), be careful to not break that. break Debug instead :)
impl fmt::Display for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, id) in self.sub_ids.iter().enumerate() {
            if i > 0 {
                write!(f, ".{}", id)?;
            } else {
                write!(f, "{}", id)?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for ID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)?;
        write!(f, " (include: {})", self.include)
    }
}

impl FromStr for ID {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Ok(Default::default());
        }

        let mut sub_ids = Vec::new();
        for i in input.split('.') {
            let val = i.parse::<u32>().map_err(|_| ErrorKind::InvalidData)?;
            sub_ids.push(val);
        }

        TryFrom::try_from(sub_ids)
    }
}

impl TryFrom<Vec<u32>> for ID {
    type Error = Error;

    fn try_from(value: Vec<u32>) -> Result<Self, Self::Error> {
        let orig_n_subid = u8::try_from(value.len()).map_err(|_| ErrorKind::InvalidData)?;
        Ok(Self {
            orig_n_subid,
            include: 0,
            sub_ids: value,
        })
    }
}

// self.include is used when the ID is part of a SearchRange, but that is just a "flag"
// we do not include it for equality/hash
impl PartialEq for ID {
    fn eq(&self, other: &Self) -> bool {
        self.sub_ids == other.sub_ids
    }
}
impl Eq for ID {}
impl Hash for ID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sub_ids.hash(state);
    }
}
impl PartialOrd for ID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sub_ids.cmp(&other.sub_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn id_new() {
        let id = ID::from_str("1.2.3.4").unwrap();
        let expected = ID {
            orig_n_subid: 4,
            include: 0,
            sub_ids: vec![1, 2, 3, 4],
        };
        assert_eq!(id, expected)
    }

    #[test]
    fn id_to_bytes_len_manual() {
        let id = ID::from_str("1.2.3").unwrap();
        assert_eq!(id.to_bytes(&ByteOrder::LittleEndian).len(), 4 + 3 * 4);
    }

    #[test]
    fn null_id() {
        let id = ID::from_str("").unwrap();
        assert_eq!(id.to_bytes(&ByteOrder::LittleEndian).len(), 4);
    }

    #[test]
    fn id_to_bytes_len() {
        let id = ID::from_str("1.2.3").unwrap();
        assert_eq!(id.to_bytes(&ByteOrder::LittleEndian).len(), id.byte_size());
    }

    #[test]
    fn id_serde() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let expected = ID::from_str("1.2.3.4").unwrap();
            let v = expected.to_bytes(&bo);
            let got = ID::from_bytes(v.as_slice(), &bo).unwrap();
            assert_eq!(expected, got)
        }
    }

    #[test]
    fn id_tryfrom() {
        let expected = ID::from_str("1.2.3").unwrap();
        let got = ID::try_from(vec![1, 2, 3]).unwrap();

        assert_eq!(got, expected);
    }
}
