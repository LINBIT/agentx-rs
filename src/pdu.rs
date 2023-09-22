//! PDU protocol definitions as defined in [Section 6](https://datatracker.ietf.org/doc/html/rfc2741#section-6)
//!
//! Note that Header.payload_length is only calculated when necessary, which is when a struct (e.g., Open PDU) is serialized or deserialized.

use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::time::Duration;

use crate::encodings::{Context, OctetString, SearchRangeList, VarBindList, ID};
use crate::{bytes_to_u16, bytes_to_u32, u16_to_bytes, u32_to_bytes, ByteOrder};

/// PDU Header as defined in [Section 6.1](https://datatracker.ietf.org/doc/html/rfc2741#section-6.1)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, header with a "random" default type does not make sense.
pub struct Header {
    /// Version of the AgentX protocol (currently always 1)
    pub version: u8,
    /// PDU type
    pub ty: Type, // low level u8
    /// flags (INSTANCE_REGISTRATION, NEW_INDEX, ANY_INDEX, NON_DEFAULT_CONTEXT, NON_DEFAULT_CONTEXT), 5-7 reserved
    pub flags: u8,
    // reserved: u8
    /// session ID
    pub session_id: u32,
    /// transaction ID
    pub transaction_id: u32,
    /// packet ID
    pub packet_id: u32,
    /// payload length in bytes excluding the fixed size header (20 bytes). Always 0 or a multiple of 4.
    pub payload_length: u32, // 0 or multiple of 4
}

// bitmask
/// used in the Register PDU
pub const INSTANCE_REGISTRATION: u8 = 0;
/// used in IndexAllocate and IndexDeallocate PDUs.
pub const NEW_INDEX: u8 = 1;
/// used in IndexAllocate and IndexDeallocate PDUs.
pub const ANY_INDEX: u8 = 2;
/// if set a non-default context is used in a PDU
pub const NON_DEFAULT_CONTEXT: u8 = 3;
/// applies to all multi-byte integer values including header fields, if set BigEndian.
pub const NETWORK_BYTE_ORDER: u8 = 4;

fn is_set(flags: u8, mask: u8) -> bool {
    flags & mask == mask
}

const HEADER_SIZE: usize = 20;

fn header_byte_order(flags: u8) -> ByteOrder {
    match is_set(flags, 1 << NETWORK_BYTE_ORDER) {
        true => ByteOrder::BigEndian,
        false => ByteOrder::LittleEndian,
    }
}

fn context_from_bytes(header: &Header, b: &[u8]) -> Result<Option<Context>, Error> {
    let bo = header.byte_order();
    match is_set(header.flags, 1 << NON_DEFAULT_CONTEXT) {
        false => Ok(None),
        true => Ok(Some(Context::from_bytes(b, &bo)?)),
    }
}

impl Header {
    /// create a default Header with a specific Type
    pub fn new(ty: Type) -> Self {
        Self {
            version: 1,
            ty,
            flags: 0,
            session_id: 0,
            transaction_id: 0,
            packet_id: 0,
            payload_length: 0,
        }
    }

    fn byte_order(&self) -> ByteOrder {
        header_byte_order(self.flags)
    }

    /// serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // while there are some PDUs where a Result is not strictly necessary, we still make it a Result for consistency with the PDUs that acutally need a Result
        // IMO Header is a bit special, for obvious reasons it can not fail, and having "expects" does not help. Also Header structs are not really used on their own, they are always embedded in a PDU
        // Header is not a PDU

        let mut result = Vec::with_capacity(HEADER_SIZE);
        result.extend(&[
            self.version,
            self.ty.to_byte(),
            self.flags,
            0, /* reserved */
        ]);

        let bo = self.byte_order();
        result.extend(&u32_to_bytes(self.session_id, &bo));
        result.extend(&u32_to_bytes(self.transaction_id, &bo));
        result.extend(&u32_to_bytes(self.packet_id, &bo));
        result.extend(&u32_to_bytes(self.payload_length, &bo));

        result
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < HEADER_SIZE {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let (version, ty, flags) = (b[0], Type::from_byte(b[1])?, b[2]);
        let bo = header_byte_order(flags);

        let session_id = bytes_to_u32(&b[4..], &bo)?;
        let transaction_id = bytes_to_u32(&b[8..], &bo)?;
        let packet_id = bytes_to_u32(&b[12..], &bo)?;
        let payload_length = bytes_to_u32(&b[16..], &bo)?;

        Ok(Self {
            version,
            ty,
            flags,
            session_id,
            transaction_id,
            packet_id,
            payload_length,
        })
    }

    fn byte_size(&self) -> usize {
        HEADER_SIZE
    }

    fn set_payload_len(&mut self, len: usize) -> Result<(), Error> {
        self.payload_length = u32::try_from(len).map_err(|_| ErrorKind::InvalidData)?;
        Ok(())
    }
}

/// Open PDU as defined in [Section 6.2.1](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.1)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Open {
    /// Header with [Type::Open]
    pub header: Header,
    /// time a master agent should allow to elapse after dispatching a message on a session before it regards the subagent as not responding.
    pub timeout: Duration, // u8
    // reserved: 24 bit
    /// OID that identifies the subagent, can be null ID
    pub id: ID,
    /// DisplayString describing the subagent.
    pub descr: OctetString,
}

impl Default for Open {
    fn default() -> Self {
        Self {
            header: Header::new(Type::Open),
            timeout: Duration::new(0, 0),
            id: ID::default(),
            descr: OctetString::default(),
        }
    }
}

impl Open {
    /// create an Open PDU from an ID and a description
    pub fn new(id: ID, descr: &str) -> Self {
        Open {
            id,
            descr: OctetString(descr.to_string()),
            ..Default::default()
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        let timeout_secs =
            u8::try_from(self.timeout.as_secs()).map_err(|_| ErrorKind::InvalidData)?;

        payload.push(timeout_secs);
        payload.extend(&[0, 0, 0]); // reserved
        payload.extend(self.id.to_bytes(&bo));
        payload.extend(self.descr.to_bytes(&bo)?);

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        if b.len() < size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let timeout = Duration::from_secs(b[0] as u64);
        b = b.get(4..).ok_or(ErrorKind::InvalidData)?;
        //
        let id = ID::from_bytes(b, &bo)?;
        b = b.get(id.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let descr = OctetString::from_bytes(b, &bo)?;

        Ok(Self {
            header,
            timeout,
            id,
            descr,
        })
    }
}

/// Close PDU as defined in [Section 6.2.2](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.2)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Close {
    /// Header with [Type::Close]
    pub header: Header,
    /// reason for close
    pub reason: CloseReason,
    // reserved: 24 bit
}

impl Default for Close {
    fn default() -> Self {
        Self {
            header: Header::new(Type::Close),
            reason: CloseReason::Other,
        }
    }
}

impl Close {
    /// create Close PDU from a CloseReason
    pub fn new(reason: CloseReason) -> Self {
        Self {
            reason,
            ..Default::default()
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        self.header.payload_length = 4; /* 1 reason + 3 reserved */
        result.extend(self.header.to_bytes());
        result.push(self.reason.to_byte());
        result.extend(&[0, 0, 0]); /* reserved */

        Ok(result)
    }

    /// serialize to bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        if b.len() < size_of::<u8>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let reason = CloseReason::from_byte(b[0])?;

        Ok(Self { header, reason })
    }
}

/// Register PDU as defined in [Section 6.2.3](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.3)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, Register without a subtree does not make sense.
pub struct Register {
    /// Header with [Type::Register]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// number of seconds that a master agent should allow to elapse after dispatching a message on a  session before it regards the subagent as not responding. Applies only to messages that concert MIB objects with the subtree. Default is 0 (no override).
    pub timeout: Duration, // u8
    /// value between 1 and 255 used when different sessions register identical or overlapping regions. Defaults to 127.
    pub priority: u8,
    /// range_subid as defined in the standard
    pub range_subid: u8,
    // reserved: 8 bit
    /// OID of the subtree to register
    pub subtree: ID,
    /// upper bound of the sub-identifier's range. Only present if `range_subid` is not 0.
    pub upper_bound: Option<u32>, // present if range_subid non 0
}

impl Register {
    /// create a new Register PDU from a subtree OID
    pub fn new(subtree: ID) -> Self {
        let header = Header::new(Type::Register);

        Self {
            header,
            context: None,
            timeout: Duration::new(0, 0), // default according to spec
            priority: 0,                  // default according to spec
            range_subid: 0,
            subtree,
            upper_bound: None,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        let timeout_secs =
            u8::try_from(self.timeout.as_secs()).map_err(|_| ErrorKind::InvalidData)?;

        payload.extend(&[
            timeout_secs,
            self.priority,
            self.range_subid,
            0, /* reserved */
        ]);

        payload.extend(self.subtree.to_bytes(&bo));

        if let Some(u) = &self.upper_bound {
            payload.extend(&u32_to_bytes(*u, &bo));
        };

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let context = context_from_bytes(&header, b)?;
        if let Some(c) = &context {
            b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
        }

        if b.len() < size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let (timeout, priority, range_subid) = (Duration::from_secs(b[0] as u64), b[1], b[2]);
        b = b.get(4..).ok_or(ErrorKind::InvalidData)?;

        let subtree = ID::from_bytes(b, &bo)?;
        b = b.get(subtree.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let upper_bound = if range_subid != 0 {
            Some(bytes_to_u32(b, &bo)?)
        } else {
            None
        };

        Ok(Self {
            header,
            context,
            timeout,
            priority,
            range_subid,
            subtree,
            upper_bound,
        })
    }
}

/// Unregister PDU as defined in [Section 6.2.4](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.4)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, Unregister without a subtree does not make sense
pub struct Unregister {
    /// Header with [Type::Unregister]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    // reserved: 8 bit
    /// priority at which this region was originally registerd
    pub priority: u8,
    /// indicates a sub-identifier subtree is a range lower bound
    pub range_subid: u8,
    // reserved: 8 bit
    /// previously registered region of the MIG that a subagent no longer wishes to support
    pub subtree: ID,
    /// upper bound of the range sub-identifier. Only present if `range_subid` is not 0.
    pub upper_bound: Option<u32>,
}

impl Unregister {
    /// create a new Unregister PDU from a subtree and a given priority
    pub fn new(subtree: ID, priority: u8) -> Self {
        let header = Header::new(Type::Unregister);

        Self {
            header,
            context: None,
            priority,
            range_subid: 0,
            subtree,
            upper_bound: None,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(&[
            0, /* reserved */
            self.priority,
            self.range_subid,
            0, /* reserved */
        ]);

        payload.extend(self.subtree.to_bytes(&bo));

        if let Some(u) = &self.upper_bound {
            payload.extend(&u32_to_bytes(*u, &bo));
        };

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let context = context_from_bytes(&header, b)?;
        if let Some(c) = &context {
            b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
        }

        if b.len() < size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let (priority, range_subid) = (/* b[0] reserved */ b[1], b[2]);
        b = b.get(4..).ok_or(ErrorKind::InvalidData)?;

        let subtree = ID::from_bytes(b, &bo)?;
        b = b.get(subtree.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let upper_bound = if range_subid != 0 {
            Some(bytes_to_u32(b, &bo)?)
        } else {
            None
        };

        Ok(Self {
            header,
            context,
            priority,
            range_subid,
            subtree,
            upper_bound,
        })
    }
}

/// Get PDU as defined in [Section 6.2.5](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.5)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, Get without a SearchRangeList does not make sense
pub struct Get {
    /// Header with [Type::Get]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// SearchRangeList containing the requested variables for this session.
    pub sr: SearchRangeList,
}

// get alikes:
fn get_alike_from_bytes(b: &[u8]) -> Result<(Header, Option<Context>, SearchRangeList), Error> {
    let header = Header::from_bytes(b)?;
    let bo = header.byte_order();
    let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

    let context = context_from_bytes(&header, b)?;
    if let Some(c) = &context {
        b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
    }

    let sr = SearchRangeList::from_bytes(b, &bo)?;

    Ok((header, context, sr))
}

impl Get {
    /// create a new Get PDU from a SearchRangeList
    pub fn new(sr: SearchRangeList) -> Self {
        let header = Header::new(Type::Get);

        Self {
            header,
            context: None,
            sr,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.sr.to_bytes(&bo));

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (header, context, sr) = get_alike_from_bytes(b)?;

        Ok(Self {
            header,
            context,
            sr,
        })
    }
}

// exact copy of Get (except header type)
/// GetNext PDU as defined in [Section 6.2.6](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.6)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, GetNext without a SearchRangeList does not make sense
pub struct GetNext {
    /// Header with [Type::GetNext]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// SearchRangeList containing the requested variables for this session.
    pub sr: SearchRangeList,
}

impl GetNext {
    /// create a new GetNext PDU from a SearchRangeList
    pub fn new(sr: SearchRangeList) -> Self {
        let header = Header::new(Type::GetNext);

        Self {
            header,
            context: None,
            sr,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.sr.to_bytes(&bo));

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (header, context, sr) = get_alike_from_bytes(b)?;

        Ok(Self {
            header,
            context,
            sr,
        })
    }
}

/// GetBulk PDU as defined in [Section 6.2.7](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.7)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, GetBulk without a SearchRangeList does not make sense
pub struct GetBulk {
    /// Header with [Type::GetBulk]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// the number of variables in the SearchRangeList that are not repeaters
    pub non_repeaters: u16,
    /// the maximum of repetitions requested for repeating variables
    pub max_repetitions: u16,
    /// SearchRangeList containing requested variables for this session.
    pub sr: SearchRangeList,
}

impl GetBulk {
    /// create a new GetBulk PDU from a SearchRangeList
    pub fn new(sr: SearchRangeList) -> Self {
        let header = Header::new(Type::GetBulk);

        Self {
            header,
            context: None,
            non_repeaters: 0,
            max_repetitions: 0,
            sr,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(&u16_to_bytes(self.non_repeaters, &bo));
        payload.extend(&u16_to_bytes(self.max_repetitions, &bo));
        payload.extend(self.sr.to_bytes(&bo));

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let context = context_from_bytes(&header, b)?;
        if let Some(c) = &context {
            b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
        }

        if b.len() < size_of::<u32>() {
            return Err(Error::from(ErrorKind::InvalidData));
        }
        let (non_repeaters, max_repetitions) = (bytes_to_u16(b, &bo)?, bytes_to_u16(&b[2..], &bo)?);
        b = b.get(4..).ok_or(ErrorKind::InvalidData)?;

        let sr = SearchRangeList::from_bytes(b, &bo)?;

        Ok(Self {
            header,
            context,
            non_repeaters,
            max_repetitions,
            sr,
        })
    }
}

/// TestSet PDU as defined in [Section 6.2.8](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.8)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, a TestSet without a VarBindList does not make sense
pub struct TestSet {
    /// Header with [Type::TestSet]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// VarBindList containing the requested VarBinds for this subagent
    pub vb: VarBindList,
}

fn testset_alike_from_bytes(b: &[u8]) -> Result<(Header, Option<Context>, VarBindList), Error> {
    let header = Header::from_bytes(b)?;
    let bo = header.byte_order();
    let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

    let context = context_from_bytes(&header, b)?;
    if let Some(c) = &context {
        b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
    }

    let vb = VarBindList::from_bytes(b, &bo)?;

    Ok((header, context, vb))
}

impl TestSet {
    /// create new TestSet PDU from a VarBindList
    pub fn new(vb: VarBindList) -> Self {
        let header = Header::new(Type::TestSet);

        Self {
            header,
            context: None,
            vb,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.vb.to_bytes(&bo)?);

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (header, context, vb) = testset_alike_from_bytes(b)?;
        Ok(Self {
            header,
            context,
            vb,
        })
    }
}

// same as TestSet
/// Notify PDU as defined in [Section 6.2.10](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.10)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, a Notify without a VarBindList does not make sense
pub struct Notify {
    /// Header with [Type::Notify]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// A VarBindList whose contents define the actual PDU to be sent
    pub vb: VarBindList,
}

impl Notify {
    /// create a new Notify PDU from a VarBindList
    pub fn new(vb: VarBindList) -> Self {
        let header = Header::new(Type::Notify);

        Self {
            header,
            context: None,
            vb,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.vb.to_bytes(&bo)?);

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (header, context, vb) = testset_alike_from_bytes(b)?;
        Ok(Self {
            header,
            context,
            vb,
        })
    }
}

// same as TestSet
/// IndexAllocate PDU as defined in [Section 6.2.12](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.12)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, IndexAllocate without a VarBindList does not make sense
pub struct IndexAllocate {
    /// Header with [Type::IndexAllocate]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// A VarBindList containing the index names and values requested for allocation
    pub vb: VarBindList,
}

impl IndexAllocate {
    /// create a new IndexAllocate PDU from a VarBindList
    pub fn new(vb: VarBindList) -> Self {
        let header = Header::new(Type::IndexAllocate);

        Self {
            header,
            context: None,
            vb,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.vb.to_bytes(&bo)?);

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (header, context, vb) = testset_alike_from_bytes(b)?;
        Ok(Self {
            header,
            context,
            vb,
        })
    }
}

// same as TestSet
/// IndexDeallocate PDU as defined in [Section 6.2.13](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.13)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, IndexDeallocate without a VarBindList does not make sense
pub struct IndexDeallocate {
    /// Header with [Type::IndexDeallocate]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// VarBindList containing the index names and values to be released
    pub vb: VarBindList,
}

impl IndexDeallocate {
    /// create a new IndexDeallocate PDU from a VarBindList
    pub fn new(vb: VarBindList) -> Self {
        let header = Header::new(Type::IndexDeallocate);

        Self {
            header,
            context: None,
            vb,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.vb.to_bytes(&bo)?);

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let (header, context, vb) = testset_alike_from_bytes(b)?;
        Ok(Self {
            header,
            context,
            vb,
        })
    }
}

/// CommitSet PDU as defined in [Section 6.2.9](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.9)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CommitSet {
    /// Header with [Type::CommitSet]
    pub header: Header,
}

impl Default for CommitSet {
    fn default() -> Self {
        Self {
            header: Header::new(Type::CommitSet),
        }
    }
}

impl CommitSet {
    /// create a new CommitSet PDU
    pub fn new() -> Self {
        Self::default()
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.header.to_bytes())
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            header: Header::from_bytes(b)?,
        })
    }
}

// same as CommitSet
/// UndoSet PDU as defined in [Section 6.2.9](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.9)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct UndoSet {
    /// Header with [Type::UndoSet]
    pub header: Header,
}

impl Default for UndoSet {
    fn default() -> Self {
        Self {
            header: Header::new(Type::UndoSet),
        }
    }
}

impl UndoSet {
    /// create new UndoSet PDU
    pub fn new() -> Self {
        Self::default()
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.header.to_bytes())
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            header: Header::from_bytes(b)?,
        })
    }
}

// same as CommitSet
/// CleanupSet PDU as defined in [Section 6.2.9](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.9)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct CleanupSet {
    /// Header with [Type::CleanupSet]
    pub header: Header,
}

impl Default for CleanupSet {
    fn default() -> Self {
        Self {
            header: Header::new(Type::CleanupSet),
        }
    }
}

impl CleanupSet {
    /// create new CleanupSet PDU
    pub fn new() -> Self {
        Self::default()
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.header.to_bytes())
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            header: Header::from_bytes(b)?,
        })
    }
}

/// Ping PDU as defined in [Section 6.2.11](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.11)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Ping {
    /// Header with [Type::Ping]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
}

impl Default for Ping {
    fn default() -> Self {
        Self {
            header: Header::new(Type::Ping),
            context: None,
        }
    }
}

impl Ping {
    /// create a new Ping PDU
    pub fn new() -> Self {
        Self::default()
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let context = context_from_bytes(&header, b)?;

        Ok(Self { header, context })
    }
}

/// AddAgentCaps PDU as defined in [Section 6.2.14](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.14)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, AddAgentCaps without ID does not make sense
pub struct AddAgentCaps {
    /// Header with [Type::AddAgentCaps]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// ID containing the value of an invocation of the AGENT-CAPABILITIES macro, which the master agent exports as a value of sysORID for the indicated context.
    pub id: ID,
    /// OctetString containing a DisplayString to be used as the value of sysORDescr corresponding to the sysORID value above
    pub descr: OctetString,
}

impl AddAgentCaps {
    /// create a new AddAgentCaps PDU from an ID and a description
    pub fn new(id: ID, descr: &str) -> Self {
        let header = Header::new(Type::AddAgentCaps);
        let descr = OctetString(descr.to_string());

        Self {
            header,
            context: None,
            id,
            descr,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.id.to_bytes(&bo));
        payload.extend(self.descr.to_bytes(&bo)?);

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let context = context_from_bytes(&header, b)?;
        if let Some(c) = &context {
            b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
        }

        let id = ID::from_bytes(b, &bo)?;
        b = b.get(id.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let descr = OctetString::from_bytes(b, &bo)?;

        Ok(Self {
            header,
            context,
            id,
            descr,
        })
    }
}

/// RemoveAgentCaps PDU as defined in [Section 6.2.15](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.15)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)] // no Default, RemoveAgentCaps without ID does not make sense
pub struct RemoveAgentCaps {
    /// Header with [Type::RemoveAgentCaps]
    pub header: Header,
    /// optional non-default context
    pub context: Option<Context>,
    /// ID containing the value of sysORID that should no longer be exported
    pub id: ID,
}

impl RemoveAgentCaps {
    /// create new RemoveAgentCaps PDU from an ID
    pub fn new(id: ID) -> Self {
        let header = Header::new(Type::RemoveAgentCaps);

        Self {
            header,
            context: None,
            id,
        }
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        if let Some(c) = &self.context {
            payload.extend(c.0.to_bytes(&bo)?);
        };

        payload.extend(self.id.to_bytes(&bo));

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let context = context_from_bytes(&header, b)?;
        if let Some(c) = &context {
            b = b.get(c.byte_size()..).ok_or(ErrorKind::InvalidData)?;
        }

        let id = ID::from_bytes(b, &bo)?;

        Ok(Self {
            header,
            context,
            id,
        })
    }
}

// for "administrative" PDU types
/// Response PDU as defined in [Section 6.2.16](https://datatracker.ietf.org/doc/html/rfc2741#section-6.2.16)
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Response {
    /// Header with [Type::Response]
    pub header: Header,
    /// sysUptime which is only relevent when sent from master to subagent, otherwise ignored. Value is serialized in 100th of seconds in 32 bit representation, so this wraps around after 497 days
    pub sys_uptime: Duration, // u32
    /// error status
    pub res_error: ResError,
    /// index where the error (if any) of a VarBind occured
    pub res_index: u16,
    /// optional VarBindList, depends on the element of precedure
    pub vb: Option<VarBindList>,
}

// this is a bit boarderline but I think still useful
impl Default for Response {
    fn default() -> Self {
        Self {
            header: Header::new(Type::Response),
            sys_uptime: Duration::new(0, 0),
            res_error: ResError::NoAgentXError,
            res_index: 0,
            vb: None,
        }
    }
}

impl Response {
    /// create new Response PDU
    pub fn new() -> Self {
        Self::default()
    }

    /// create a Response PDU from a Header. This is handy as it copies `session_id`, `transaction_id`, `packet_id` to the header field in the Response PDU.
    /// # Examples
    ///
    /// ```no_run
    /// # use agentx::{ByteOrder};
    /// # use agentx::pdu::{Get, Response};
    /// # use std::str::FromStr;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let bytes = vec![]; // assume we received some actual bytes from a master agent
    /// let get = Get::from_bytes(&bytes)?;
    /// let mut response = Response::from_header(&get.header);
    /// // do some actual work, and fill the rest of response...
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_header(header: &Header) -> Self {
        let mut response = Self::new();
        response.header.session_id = header.session_id;
        response.header.transaction_id = header.transaction_id;
        response.header.packet_id = header.packet_id;

        response
    }

    /// serialize to bytes
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let mut result = Vec::new();
        let mut payload = Vec::new();
        let bo = self.header.byte_order();

        // 100ths of a second...
        let sys_uptime =
            u32::try_from(self.sys_uptime.as_millis() / 10).map_err(|_| ErrorKind::InvalidData)?;
        let sys_uptime = u32_to_bytes(sys_uptime, &bo);
        payload.extend(&sys_uptime);

        payload.extend(&self.res_error.to_bytes(&bo));

        payload.extend(&u16_to_bytes(self.res_index, &bo));

        if let Some(vb) = &self.vb {
            payload.extend(vb.to_bytes(&bo)?);
        }

        self.header.set_payload_len(payload.len())?;
        result.extend(self.header.to_bytes());
        result.extend(payload);

        Ok(result)
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(b)?;
        let bo = header.byte_order();
        let mut b = b.get(header.byte_size()..).ok_or(ErrorKind::InvalidData)?;

        let sys_uptime = bytes_to_u32(b, &bo)?;
        // 100th of a second...
        let sys_uptime = Duration::from_millis((sys_uptime * 10) as u64);
        b = b.get(4..).ok_or(ErrorKind::InvalidData)?;

        let res_error = ResError::from_bytes(b, &bo)?;
        b = b
            .get(res_error.byte_size()..)
            .ok_or(ErrorKind::InvalidData)?;

        let res_index = bytes_to_u16(b, &bo)?;

        let vb = match b.get(2..) {
            None => None,
            Some(b) => Some(VarBindList::from_bytes(b, &bo)?),
        };

        Ok(Self {
            header,
            sys_uptime,
            res_error,
            res_index,
            vb,
        })
    }
}

/// PDU types
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum Type {
    /// Open
    Open,
    /// Close
    Close,
    /// Register
    Register,
    /// Unregister
    Unregister,
    /// Get
    Get,
    /// GetNext
    GetNext,
    /// GetBulk
    GetBulk,
    /// TestSet
    TestSet,
    /// CommitSet
    CommitSet,
    /// UndoSet
    UndoSet,
    /// CleanupSet
    CleanupSet,
    /// Notify
    Notify,
    /// Ping
    Ping,
    /// IndexAllocate
    IndexAllocate,
    /// IndexDeallocate
    IndexDeallocate,
    /// AddAgentCaps
    AddAgentCaps,
    /// RemoveAgentCaps
    RemoveAgentCaps,
    /// Response
    Response,
}

impl Type {
    /// serialize to byte
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Close => 2,
            Self::Register => 3,
            Self::Unregister => 4,
            Self::Get => 5,
            Self::GetNext => 6,
            Self::GetBulk => 7,
            Self::TestSet => 8,
            Self::CommitSet => 9,
            Self::UndoSet => 10,
            Self::CleanupSet => 11,
            Self::Notify => 12,
            Self::Ping => 13,
            Self::IndexAllocate => 14,
            Self::IndexDeallocate => 15,
            Self::AddAgentCaps => 16,
            Self::RemoveAgentCaps => 17,
            Self::Response => 18,
        }
    }

    /// deserialize from byte
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        let ty = match b {
            1 => Self::Open,
            2 => Self::Close,
            3 => Self::Register,
            4 => Self::Unregister,
            5 => Self::Get,
            6 => Self::GetNext,
            7 => Self::GetBulk,
            8 => Self::TestSet,
            9 => Self::CommitSet,
            10 => Self::UndoSet,
            11 => Self::CleanupSet,
            12 => Self::Notify,
            13 => Self::Ping,
            14 => Self::IndexAllocate,
            15 => Self::IndexDeallocate,
            16 => Self::AddAgentCaps,
            17 => Self::RemoveAgentCaps,
            18 => Self::Response,
            _ => return Err(Error::from(ErrorKind::InvalidData)),
        };

        Ok(ty)
    }
}

/// an enumerated value that gives the reason that the master agent or subagent closed the AgentX session.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum CloseReason {
    /// none of the following reasons
    Other,
    /// too many AgentX parse errors from peer
    ParseError,
    /// too many AgentX protocol errors from peer
    ProtocolError,
    /// too many timeouts waiting for peer
    Timeouts,
    /// sending entity is shutting down
    Shutdown,
    /// due to Set operation; this reason code can be used only by the master agent, in response to an SNMP management request.
    ByManager,
}

impl CloseReason {
    /// serialize to byte
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::Other => 1,
            Self::ParseError => 2,
            Self::ProtocolError => 3,
            Self::Timeouts => 4,
            Self::Shutdown => 5,
            Self::ByManager => 6,
        }
    }

    /// deserialize from byte
    pub fn from_byte(b: u8) -> Result<Self, Error> {
        let ty = match b {
            1 => Self::Other,
            2 => Self::ParseError,
            3 => Self::ProtocolError,
            4 => Self::Timeouts,
            5 => Self::Shutdown,
            6 => Self::ByManager,
            _ => return Err(Error::from(ErrorKind::InvalidData)),
        };

        Ok(ty)
    }
}

/// Indicates error status.  Within responses to the set of "administrative" PDU types listed in [Section 6.1](https://datatracker.ietf.org/doc/html/rfc2741#section-6.1), "AgentX PDU Header", values are limited to the following.
/// Within responses to the set of "SNMP request processing" PDU types listed in [Section 6.1](https://datatracker.ietf.org/doc/html/rfc2741#section-6.1) "AgentX PDU Header", values may also include those defined for errors in the SNMPv2 PDU.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ResError {
    /// NoAgentXError
    NoAgentXError,
    /// OpenFailed
    OpenFailed,
    /// NotOpen
    NotOpen,
    /// IndexWrongType
    IndexWrongType,
    /// IndexAlreadyAllocated
    IndexAlreadyAllocated,
    /// IndexNoneAvailable
    IndexNoneAvailable,
    /// IndexNotAllocated
    IndexNotAllocated,
    /// UnsupportedContext
    UnsupportedContext,
    /// DuplicateRegistration
    DuplicateRegistration,
    /// UnknownRegistration
    UnknownRegistration,
    /// UnknownAgentCaps
    UnknownAgentCaps,
    /// ParseError
    ParseError,
    /// RequestDenied
    RequestDenied,
    /// ProcessingError
    ProcessingError,
}

impl ResError {
    /// serialize to bytes
    pub fn to_bytes(&self, bo: &ByteOrder) -> [u8; 2] {
        let val = match self {
            Self::NoAgentXError => 0,
            Self::OpenFailed => 256,
            Self::NotOpen => 257,
            Self::IndexWrongType => 258,
            Self::IndexAlreadyAllocated => 259,
            Self::IndexNoneAvailable => 260,
            Self::IndexNotAllocated => 261,
            Self::UnsupportedContext => 262,
            Self::DuplicateRegistration => 263,
            Self::UnknownRegistration => 264,
            Self::UnknownAgentCaps => 265,
            Self::ParseError => 266,
            Self::RequestDenied => 267,
            Self::ProcessingError => 268,
        };

        u16_to_bytes(val, bo)
    }

    fn byte_size(&self) -> usize {
        2
    }

    /// deserialize from bytes
    pub fn from_bytes(b: &[u8], bo: &ByteOrder) -> Result<Self, Error> {
        let re = match bytes_to_u16(b, bo)? {
            0 => Self::NoAgentXError,
            256 => Self::OpenFailed,
            257 => Self::NotOpen,
            258 => Self::IndexWrongType,
            259 => Self::IndexAlreadyAllocated,
            260 => Self::IndexNoneAvailable,
            261 => Self::IndexNotAllocated,
            262 => Self::UnsupportedContext,
            263 => Self::DuplicateRegistration,
            264 => Self::UnknownRegistration,
            265 => Self::UnknownAgentCaps,
            266 => Self::ParseError,
            267 => Self::RequestDenied,
            268 => Self::ProcessingError,
            _ => return Err(Error::from(ErrorKind::InvalidData)),
        };

        Ok(re)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn header_to_bytes_len() {
        let header = Header::new(Type::Response);
        assert_eq!(header.to_bytes().len(), 20);
    }

    #[test]
    fn open_to_bytes() {
        let mut open = Open::new(ID::from_str("1.2.3").unwrap(), "rck");
        open.header.session_id = 1;
        open.header.transaction_id = 2;
        open.header.packet_id = 3;
        let expected = vec![
            /* header */
            1, 1, 0, 0, /* version, ty, flags, reserved */
            1, 0, 0, 0, /* session */
            2, 0, 0, 0, /* transaction */
            3, 0, 0, 0, /* packet */
            28, 0, 0, 0, /* length */
            /* timeout */
            0, 0, 0, 0, /* timeout, reserved * 3 */
            /* id */
            3, 0, 0, 0, /* n_subid, prefix, include, reserved */
            1, 0, 0, 0, /* subid */
            2, 0, 0, 0, /* subid */
            3, 0, 0, 0, /* subid */
            /* descr */
            3, 0, 0, 0, /* length */
            0x72, 0x63, 0x6B, 0, /* str + padding */
        ];
        assert_eq!(expected, open.to_bytes().unwrap());
    }

    #[test]
    fn open_serde() {
        let mut expected = Open::new(ID::from_str("1.2.3.4").unwrap(), "rck");
        expected.header.session_id = 1;
        expected.header.transaction_id = 2342;
        expected.header.packet_id = 3;

        for bo in vec![0, NETWORK_BYTE_ORDER] {
            if bo > 0 {
                expected.header.flags |= 1 << bo;
            }
            let bytes = expected.to_bytes().unwrap();
            let got = Open::from_bytes(bytes.as_slice()).unwrap();
            assert_eq!(got.header.transaction_id, 2342);

            assert_eq!(got, expected);
        }
    }

    #[test]
    fn close_serde() {
        for flags in vec![0, 1 << NETWORK_BYTE_ORDER] {
            let mut expected = Close::new(CloseReason::ParseError);
            expected.header.flags = flags;
            let bytes = expected.to_bytes().unwrap();
            let got = Close::from_bytes(bytes.as_slice()).unwrap();

            assert_eq!(got, expected);
        }
    }

    #[test]
    fn register_serde() {
        for flags in vec![0, 1 << NETWORK_BYTE_ORDER] {
            let mut expected = Register::new(ID::from_str("1.2.3").unwrap());
            expected.header.flags = flags;
            let bytes = expected.to_bytes().unwrap();
            let got = Register::from_bytes(bytes.as_slice()).unwrap();

            assert_eq!(got.context, None);
            assert_eq!(got.upper_bound, None);

            assert_eq!(got, expected);
        }

        // context
        let mut expected = Register::new(ID::from_str("1.2.3").unwrap());
        expected.context = Some(Context(OctetString("rck".to_string())));
        expected.header.flags = 1 << NON_DEFAULT_CONTEXT;
        let bytes = expected.to_bytes().unwrap();
        let got = Register::from_bytes(bytes.as_slice()).unwrap();

        assert!(got.context.is_some());

        assert_eq!(got, expected);

        // upper_bound
        let mut expected = Register::new(ID::from_str("1.2.3").unwrap());
        expected.range_subid = 2;
        expected.upper_bound = Some(42);
        let bytes = expected.to_bytes().unwrap();
        let got = Register::from_bytes(bytes.as_slice()).unwrap();

        assert_eq!(got.upper_bound, Some(42));

        assert_eq!(got, expected);
    }

    #[test]
    fn unregister_serde() {
        // pretty similar to register, I guess a simple test is good enough
        for flags in vec![0, 1 << NETWORK_BYTE_ORDER] {
            let mut expected = Unregister::new(ID::from_str("1.2.3").unwrap(), 23);
            expected.header.flags = flags;
            let bytes = expected.to_bytes().unwrap();
            let got = Unregister::from_bytes(bytes.as_slice()).unwrap();

            assert_eq!(got.context, None);
            assert_eq!(got.upper_bound, None);

            assert_eq!(got, expected);
        }
    }
}
