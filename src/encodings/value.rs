//! Value and VarBind as defined in [Section 5.4](https://datatracker.ietf.org/doc/html/rfc2741#section-5.4)

use std::io::{Error, ErrorKind};
use std::iter::IntoIterator;
use std::mem::size_of;

use crate::encodings::OctetString;
use crate::encodings::ID;
use crate::{
    bytes_to_i32, bytes_to_u16, bytes_to_u32, bytes_to_u64, i32_to_bytes, u16_to_bytes,
    u32_to_bytes, u64_to_bytes, ByteOrder,
};

/// VarBind as defined in [Section 5.4](https://datatracker.ietf.org/doc/html/rfc2741#section-5.4)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct VarBind {
    /// OID name of the VarBind
    pub name: ID,
    /// Value of the VarBind
    pub data: Value,
}

/// Value as defined in [Section 5.4](https://datatracker.ietf.org/doc/html/rfc2741#section-5.4)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub enum Value {
    /// 4 byte (signed) integer type
    Integer(i32),
    /// OctetString
    OctetString(OctetString),
    /// null type (does not contain encoded value)
    #[default]
    Null,
    /// Object identifier
    ObjectIdentifier(ID),
    /// IP address octets need to be orderd most significant to least significant
    IpAddress(OctetString),
    /// 4 byte (unsigned) integer type
    Counter32(u32),
    /// 4 byte (unsigned) integer type
    Gauge32(u32),
    /// 4 byte (signed) integer type
    TimeTicks(i32),
    /// Opaque type consisting of a OctetString
    Opaque(OctetString),
    /// 8 byte (unsigned) integer type
    Counter64(u64),
    /// NoSuchObject (does not contain encoded value)
    NoSuchObject,
    /// NoSuchInstance (does not contain encoded value)
    NoSuchInstance,
    /// EndOfMibView (does not contain encoded value)
    EndOfMibView,
}

impl Value {
    fn byte_size(&self) -> usize {
        // type + reserved + ..;
        size_of::<u32>()
            + match self {
                Self::Integer(_) => size_of::<i32>(),
                Self::OctetString(o) => o.byte_size(),
                Self::Null => 0,
                Self::ObjectIdentifier(i) => i.byte_size(),
                Self::IpAddress(s) => s.byte_size(),
                Self::Counter32(_) => size_of::<u32>(),
                Self::Gauge32(_) => size_of::<u32>(),
                Self::TimeTicks(_) => size_of::<i32>(),
                Self::Opaque(s) => s.byte_size(),
                Self::Counter64(_) => size_of::<u64>(),
                Self::NoSuchObject => 0,
                Self::NoSuchInstance => 0,
                Self::EndOfMibView => 0,
            }
    }
}

impl VarBind {
    /// create a VarBind from an OID and a value
    pub fn new(name: ID, data: Value) -> Self {
        Self { name, data }
    }

    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();

        let (ty, data) = match &self.data {
            Value::Integer(i) => (2, i32_to_bytes(*i, bo).to_vec()),
            Value::OctetString(s) => (4, s.to_bytes(bo)?),
            Value::Null => (5, vec![]),
            Value::ObjectIdentifier(i) => (6, i.to_bytes(bo)),
            Value::IpAddress(a) => (64, a.to_bytes(bo)?),
            Value::Counter32(c) => (65, u32_to_bytes(*c, bo).to_vec()),
            Value::Gauge32(g) => (66, u32_to_bytes(*g, bo).to_vec()),
            Value::TimeTicks(t) => (67, i32_to_bytes(*t, bo).to_vec()),
            Value::Opaque(o) => (68, o.to_bytes(bo)?),
            Value::Counter64(c) => (70, u64_to_bytes(*c, bo).to_vec()),
            Value::NoSuchObject => (128, vec![]),
            Value::NoSuchInstance => (129, vec![]),
            Value::EndOfMibView => (130, vec![]),
        };

        result.extend(u16_to_bytes(ty, bo));
        result.extend([0, 0]); /* reserved */
        result.extend(self.name.to_bytes(bo));
        result.extend(data);

        Ok(result)
    }

    fn byte_size(&self) -> usize {
        self.name.byte_size() + self.data.byte_size()
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        if b.len() < size_of::<u16>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let ty = bytes_to_u16(b, bo)?;
        let mut b = b.get(4..).ok_or(ErrorKind::InvalidData)?; // reserved;

        if b.len() < size_of::<u8>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let n_subids = b[0] as usize;
        let len = 4 /* ID "header" */ + n_subids * size_of::<u32>();
        let sl = b.get(..len).ok_or(ErrorKind::InvalidData)?;
        let name = ID::from_bytes(sl, bo)?;
        b = b.get(len..).ok_or(ErrorKind::InvalidData)?;

        let data = match ty {
            2 => Value::Integer(bytes_to_i32(b, bo)?),
            4 => {
                let os = OctetString::from_bytes(b, bo)?;
                Value::OctetString(os)
            }
            5 => Value::Null,
            6 => Value::ObjectIdentifier(ID::from_bytes(b, bo)?),
            64 => {
                let os = OctetString::from_bytes(b, bo)?;
                Value::IpAddress(os)
            }
            65 => Value::Counter32(bytes_to_u32(b, bo)?),
            66 => Value::Gauge32(bytes_to_u32(b, bo)?),
            67 => Value::TimeTicks(bytes_to_i32(b, bo)?),
            68 => {
                let os = OctetString::from_bytes(b, bo)?;
                Value::Opaque(os)
            }
            70 => Value::Counter64(bytes_to_u64(b, bo)?),
            128 => Value::NoSuchObject,
            129 => Value::NoSuchInstance,
            130 => Value::EndOfMibView,
            _ => return Err(Error::from(ErrorKind::InvalidData)),
        };

        Ok(Self { name, data })
    }
}

/// VarBindList as defined in [Section 5.4](https://datatracker.ietf.org/doc/html/rfc2741#section-5.4)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct VarBindList(pub Vec<VarBind>);

impl VarBindList {
    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();

        for r in &self.0 {
            result.extend(r.to_bytes(bo)?);
        }

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        let mut b = b;
        let mut varbinds = Vec::new();

        while !b.is_empty() {
            let varbind = VarBind::from_bytes(b, bo)?;
            let size = varbind.byte_size();
            varbinds.push(varbind);
            b = b.get(size..).ok_or(ErrorKind::InvalidData)?;
        }

        Ok(Self(varbinds))
    }

    /// Returns the number of elements in the VarBindList, also referred to as its ‘length’.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the VarBindList contains no elements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl IntoIterator for VarBindList {
    type Item = VarBind;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a VarBindList {
    type Item = &'a VarBind;
    type IntoIter = std::slice::Iter<'a, VarBind>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn varbindlist_serde() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let mut varbinds = Vec::new();

            let id1 = ID::from_str("1.2.3").unwrap();
            let id2 = ID::from_str("1.2.3").unwrap();
            let id3 = ID::from_str("1.2.3").unwrap();
            varbinds.push(VarBind::new(id1, Value::Integer(42)));
            varbinds.push(VarBind::new(
                id2,
                Value::OctetString(OctetString("x".to_string())),
            ));
            varbinds.push(VarBind::new(
                id3,
                Value::ObjectIdentifier(ID::from_str("1.2.3.4").unwrap()),
            ));

            let expected = VarBindList(varbinds);
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBindList::from_bytes(bytes.as_slice(), &bo).unwrap();

            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_integer_to_bytes_len_manual() {
        let id = ID::from_str("1.2.3").unwrap();
        let vb = VarBind::new(id, Value::Integer(42));
        assert_eq!(
            vb.to_bytes(&ByteOrder::LittleEndian).unwrap().len(),
            4 /* type + reserved */ + ID::from_str("1.2.3").unwrap().to_bytes(&ByteOrder::LittleEndian).len() + 4 /* data */
        );
    }

    #[test]
    fn varbind_integer_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::Integer(42));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_integer() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::Integer(42));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_serde_octetstring() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::OctetString(OctetString("rck".to_string())));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_octetstring_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::OctetString(OctetString("rck".to_string())));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_null() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::Null);
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_null_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::Null);
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_objectidentifier() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(
                id,
                Value::ObjectIdentifier(ID::from_str("1.2.3.4").unwrap()),
            );
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_objectidentifier_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(
                id,
                Value::ObjectIdentifier(ID::from_str("1.2.3.4").unwrap()),
            );
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_ipaddress() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::IpAddress(OctetString("1234".to_string())));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_ipaddress_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::IpAddress(OctetString("1234".to_string())));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_counter32() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::Counter32(23));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_counter32_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::Counter32(23));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_gauge32() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::Gauge32(2342));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_guage32_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::Gauge32(2342));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_timeticks() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::TimeTicks(2342));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_timeticks_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::TimeTicks(2342));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_counter64() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::Counter64(1));
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_counter64_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::Counter64(1));
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_nosuchobject() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::NoSuchObject);
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_nosuchobject_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::NoSuchObject);
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_nosuchinstance() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::NoSuchInstance);
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_nosuchinstance_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::NoSuchInstance);
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }

    #[test]
    fn varbind_serde_endofmibview() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let expected = VarBind::new(id, Value::EndOfMibView);
            let bytes = expected.to_bytes(&bo).unwrap();
            let got = VarBind::from_bytes(bytes.as_slice(), &bo).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn varbind_endofmibview_to_bytes_len() {
        for bo in vec![ByteOrder::LittleEndian, ByteOrder::BigEndian] {
            let id = ID::from_str("1.2.3").unwrap();
            let vb = VarBind::new(id, Value::EndOfMibView);
            assert_eq!(vb.to_bytes(&bo).unwrap().len(), vb.byte_size());
        }
    }
    #[test]
    fn varbindlist_intoiter() {
        fn get(vbl: &VarBindList) -> Vec<VarBind> {
            let mut vbs = Vec::new();
            for i in vbl.clone().into_iter() {
                vbs.push(i);
            }

            vbs
        }
        let expected = vec![
            VarBind::new(ID::from_str("1.2.3").unwrap(), Value::Integer(23)),
            VarBind::new(ID::from_str("1.2.4").unwrap(), Value::Integer(24)),
        ];

        let vbl = VarBindList(expected.clone());
        let got = get(&vbl);

        assert_eq!(expected, got);
    }
}
