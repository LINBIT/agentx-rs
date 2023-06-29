//! SearchRange (and SearchRangeList) as defined in [Section 5.2](https://datatracker.ietf.org/doc/html/rfc2741#section-5.2)

use std::io::{Error, ErrorKind};
use std::iter::IntoIterator;

use crate::encodings::ID;
use crate::ByteOrder;

/// SearchRange as defined in [Section 5.2](https://datatracker.ietf.org/doc/html/rfc2741#section-5.2)
///
/// # Examples
///
/// ```
/// # use agentx::{ByteOrder};
/// # use agentx::encodings::{SearchRange,ID};
/// # use std::str::FromStr;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///   let start = ID::from_str("1.2.3.4")?;
///   let end = ID::from_str("1.2.3.8")?;
///   let sr = SearchRange::new(start, end);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct SearchRange {
    /// starting OID
    pub start: ID,
    /// ending OID
    pub end: ID,
}

impl SearchRange {
    /// create SearchRange from starting and ending IDs.
    pub fn new(start: ID, end: ID) -> Self {
        Self { start, end }
    }

    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Vec<u8> {
        let mut result: Vec<u8> = self.start.to_bytes(bo);
        result.extend(self.end.to_bytes(bo));

        result
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        let mut b = b;
        let start = ID::from_bytes(b, bo)?;
        b = b.get(start.byte_size()..).ok_or(ErrorKind::InvalidData)?;
        let end = ID::from_bytes(b, bo)?;

        Ok(SearchRange { start, end })
    }

    pub(crate) fn byte_size(&self) -> usize {
        self.start.byte_size() + self.end.byte_size()
    }
}

/// SearchRangeList as defined in [Section 5.2](https://datatracker.ietf.org/doc/html/rfc2741#section-5.2)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct SearchRangeList(pub Vec<SearchRange>);

impl SearchRangeList {
    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Vec<u8> {
        let mut result = Vec::new();

        for r in &self.0 {
            result.extend(r.to_bytes(bo));
        }

        result
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        let mut b = b;
        let mut ranges = Vec::new();

        while !b.is_empty() {
            let sr = SearchRange::from_bytes(b, bo)?;
            b = b.get(sr.byte_size()..).ok_or(ErrorKind::InvalidData)?;
            ranges.push(sr);
        }

        Ok(SearchRangeList(ranges))
    }

    /// Returns the number of elements in the SearchRangeList, also referred to as its ‘length’.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the SearchRangeList contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl IntoIterator for SearchRangeList {
    type Item = SearchRange;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a SearchRangeList {
    type Item = &'a SearchRange;
    type IntoIter = std::slice::Iter<'a, SearchRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn searchrange_to_bytes_len() {
        let start = ID::from_str("1.2.3.4").unwrap();
        let end = ID::from_str("1.2.3.8").unwrap();
        let expected = start.to_bytes(&ByteOrder::LittleEndian).len()
            + end.to_bytes(&ByteOrder::LittleEndian).len();

        assert_eq!(
            SearchRange::new(start, end)
                .to_bytes(&ByteOrder::LittleEndian)
                .len(),
            expected
        );
    }

    #[test]
    fn searchrange_serde() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let start = ID::from_str("1.2.3.4").unwrap();
            let end = ID::from_str("1.2.3.8").unwrap();
            let expected = SearchRange::new(start, end);
            let bytes = expected.to_bytes(&bo);
            let got = SearchRange::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn searchrangelist_serde() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let mut ranges = Vec::new();

            let start = ID::from_str("1.2.3.4").unwrap();
            let end = ID::from_str("1.2.3.8").unwrap();
            let sr = SearchRange { start, end };
            ranges.push(sr);

            let start = ID::from_str("1.2.7.4").unwrap();
            let end = ID::from_str("1.2.7.8").unwrap();
            let sr = SearchRange { start, end };
            ranges.push(sr);

            let expected = SearchRangeList(ranges);

            let bytes = expected.to_bytes(&bo);

            let got = SearchRangeList::from_bytes(bytes.as_slice(), &bo).unwrap();

            assert_eq!(expected, got);
        }
    }

    #[test]
    fn searchrangelist_intoiter() {
        fn get(srl: &SearchRangeList) -> Vec<SearchRange> {
            let mut srs = Vec::new();
            for i in srl.clone().into_iter() {
                srs.push(i);
            }

            srs
        }
        let expected = vec![
            SearchRange::new(
                ID::from_str("1.2.3").unwrap(),
                ID::from_str("1.2.4").unwrap(),
            ),
            SearchRange::new(
                ID::from_str("1.4.3").unwrap(),
                ID::from_str("1.4.4").unwrap(),
            ),
        ];

        let vbl = SearchRangeList(expected.clone());
        let got = get(&vbl);

        assert_eq!(expected, got);
    }
}
