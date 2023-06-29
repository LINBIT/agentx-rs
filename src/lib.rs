#![warn(missing_docs)]

//! AgentX protocol library
//!
//! This library implements all PDU types and encodings according to [RFC2741](https://datatracker.ietf.org/doc/html/rfc2741).
//! It provides Rust idiomatic abstractions wherever possible and allows serialization and deserialization to/from wire compatible bytes.

pub mod encodings;
pub mod pdu;

use std::convert::TryInto;
use std::io::{Error, ErrorKind};

// this looks like a job for the byteorder crate, but unfortunately it does not provide an enum for the different byte order types, LittleEndian and BigEndian are separate enums.
// so let's have our own enum + some native helpers

/// Byte order used when serializing and deserializing data
pub enum ByteOrder {
    /// little endian byte order
    LittleEndian,
    /// big endian byte order
    BigEndian,
    // no NativeEndian as we don't need it in this crate
}

fn u16_to_bytes(from: u16, bo: &ByteOrder) -> [u8; 2] {
    match bo {
        ByteOrder::BigEndian => from.to_be_bytes(),
        ByteOrder::LittleEndian => from.to_le_bytes(),
    }
}

fn bytes_to_u16(from: &[u8], bo: &ByteOrder) -> Result<u16, Error> {
    let from = from.get(0..2).ok_or(ErrorKind::InvalidData)?;
    let from = from.try_into().map_err(|_| ErrorKind::InvalidData)?;
    match bo {
        ByteOrder::BigEndian => Ok(u16::from_be_bytes(from)),
        ByteOrder::LittleEndian => Ok(u16::from_le_bytes(from)),
    }
}

fn u32_to_bytes(from: u32, bo: &ByteOrder) -> [u8; 4] {
    match bo {
        ByteOrder::BigEndian => from.to_be_bytes(),
        ByteOrder::LittleEndian => from.to_le_bytes(),
    }
}

fn bytes_to_u32(from: &[u8], bo: &ByteOrder) -> Result<u32, Error> {
    let from = from.get(0..4).ok_or(ErrorKind::InvalidData)?;
    let from = from.try_into().map_err(|_| ErrorKind::InvalidData)?;
    match bo {
        ByteOrder::BigEndian => Ok(u32::from_be_bytes(from)),
        ByteOrder::LittleEndian => Ok(u32::from_le_bytes(from)),
    }
}

fn u64_to_bytes(from: u64, bo: &ByteOrder) -> [u8; 8] {
    match bo {
        ByteOrder::BigEndian => from.to_be_bytes(),
        ByteOrder::LittleEndian => from.to_le_bytes(),
    }
}

fn bytes_to_u64(from: &[u8], bo: &ByteOrder) -> Result<u64, Error> {
    let from = from.get(0..8).ok_or(ErrorKind::InvalidData)?;
    let from = from.try_into().map_err(|_| ErrorKind::InvalidData)?;
    match bo {
        ByteOrder::BigEndian => Ok(u64::from_be_bytes(from)),
        ByteOrder::LittleEndian => Ok(u64::from_le_bytes(from)),
    }
}

fn i32_to_bytes(from: i32, bo: &ByteOrder) -> [u8; 4] {
    match bo {
        ByteOrder::BigEndian => from.to_be_bytes(),
        ByteOrder::LittleEndian => from.to_le_bytes(),
    }
}

fn bytes_to_i32(from: &[u8], bo: &ByteOrder) -> Result<i32, Error> {
    let from = from.get(0..4).ok_or(ErrorKind::InvalidData)?;
    let from = from.try_into().map_err(|_| ErrorKind::InvalidData)?;
    match bo {
        ByteOrder::BigEndian => Ok(i32::from_be_bytes(from)),
        ByteOrder::LittleEndian => Ok(i32::from_le_bytes(from)),
    }
}
