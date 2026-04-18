//! TTLV (Tag-Type-Length-Value) encoder/decoder for KMIP.
//!
//! Implements the OASIS KMIP 1.4 binary encoding.
//!
//! Each TTLV item:
//!   Tag:    3 bytes (identifies the field)
//!   Type:   1 byte  (data type)
//!   Length: 4 bytes  (value length in bytes)
//!   Value:  variable (padded to 8-byte alignment)

use std::fmt;

/// KMIP data types.
pub mod item_type {
    pub const STRUCTURE: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const LONG_INTEGER: u8 = 0x03;
    pub const BIG_INTEGER: u8 = 0x04;
    pub const ENUMERATION: u8 = 0x05;
    pub const BOOLEAN: u8 = 0x06;
    pub const TEXT_STRING: u8 = 0x07;
    pub const BYTE_STRING: u8 = 0x08;
    pub const DATE_TIME: u8 = 0x09;
    pub const INTERVAL: u8 = 0x0A;
}

/// A decoded TTLV item.
#[derive(Clone)]
pub struct TtlvItem {
    pub tag: u32,
    pub item_type: u8,
    pub value: TtlvValue,
    pub length: usize,
    pub total_length: usize,
}

/// Possible TTLV values.
#[derive(Clone)]
pub enum TtlvValue {
    Structure(Vec<TtlvItem>),
    Integer(i32),
    LongInteger(i64),
    Enumeration(u32),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(i64),
    Interval(u32),
    BigInteger(Vec<u8>),
    Raw(Vec<u8>),
}

/// TTLV encoding/decoding errors.
#[derive(Debug)]
pub enum TtlvError {
    BufferTooShort,
    InvalidUtf8,
}

impl fmt::Display for TtlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TtlvError::BufferTooShort => write!(f, "TTLV buffer too short for header"),
            TtlvError::InvalidUtf8 => write!(f, "TTLV text string is not valid UTF-8"),
        }
    }
}

impl std::error::Error for TtlvError {}

/// Pad a length to 8-byte alignment.
fn pad_to_8(len: usize) -> usize {
    (len + 7) & !7
}

/// Encode a single TTLV item.
pub fn encode_ttlv(tag: u32, item_type: u8, value: &[u8]) -> Vec<u8> {
    let value_len = value.len();
    let padded = pad_to_8(value_len);
    let mut buf = vec![0u8; 8 + padded];

    // Tag: 3 bytes big-endian
    buf[0] = ((tag >> 16) & 0xFF) as u8;
    buf[1] = ((tag >> 8) & 0xFF) as u8;
    buf[2] = (tag & 0xFF) as u8;

    // Type: 1 byte
    buf[3] = item_type;

    // Length: 4 bytes big-endian
    let len_bytes = (value_len as u32).to_be_bytes();
    buf[4..8].copy_from_slice(&len_bytes);

    // Value + zero padding
    buf[8..8 + value_len].copy_from_slice(value);

    buf
}

/// Encode a Structure containing child TTLV items.
pub fn encode_structure(tag: u32, children: &[Vec<u8>]) -> Vec<u8> {
    let inner: Vec<u8> = children.iter().flat_map(|c| c.iter().copied()).collect();
    encode_ttlv(tag, item_type::STRUCTURE, &inner)
}

/// Encode a 32-bit integer.
pub fn encode_integer(tag: u32, value: i32) -> Vec<u8> {
    encode_ttlv(tag, item_type::INTEGER, &value.to_be_bytes())
}

/// Encode a 64-bit long integer.
pub fn encode_long_integer(tag: u32, value: i64) -> Vec<u8> {
    encode_ttlv(tag, item_type::LONG_INTEGER, &value.to_be_bytes())
}

/// Encode an enumeration (32-bit unsigned).
pub fn encode_enum(tag: u32, value: u32) -> Vec<u8> {
    encode_ttlv(tag, item_type::ENUMERATION, &value.to_be_bytes())
}

/// Encode a boolean.
pub fn encode_boolean(tag: u32, value: bool) -> Vec<u8> {
    let v: i64 = if value { 1 } else { 0 };
    encode_ttlv(tag, item_type::BOOLEAN, &v.to_be_bytes())
}

/// Encode a text string (UTF-8).
pub fn encode_text_string(tag: u32, value: &str) -> Vec<u8> {
    encode_ttlv(tag, item_type::TEXT_STRING, value.as_bytes())
}

/// Encode a byte string (raw bytes).
pub fn encode_byte_string(tag: u32, value: &[u8]) -> Vec<u8> {
    encode_ttlv(tag, item_type::BYTE_STRING, value)
}

/// Encode a DateTime (64-bit POSIX timestamp).
pub fn encode_date_time(tag: u32, timestamp: i64) -> Vec<u8> {
    encode_ttlv(tag, item_type::DATE_TIME, &timestamp.to_be_bytes())
}

/// Decode a TTLV buffer into a parsed item.
pub fn decode_ttlv(buf: &[u8], offset: usize) -> Result<TtlvItem, TtlvError> {
    if buf.len() - offset < 8 {
        return Err(TtlvError::BufferTooShort);
    }

    let tag = ((buf[offset] as u32) << 16)
        | ((buf[offset + 1] as u32) << 8)
        | (buf[offset + 2] as u32);
    let typ = buf[offset + 3];
    let length = u32::from_be_bytes([
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]) as usize;
    let padded = pad_to_8(length);
    let total_length = 8 + padded;
    let value_start = offset + 8;

    let value = match typ {
        item_type::STRUCTURE => {
            let mut children = Vec::new();
            let mut pos = value_start;
            let end = value_start + length;
            while pos < end {
                let child = decode_ttlv(buf, pos)?;
                pos += child.total_length;
                children.push(child);
            }
            TtlvValue::Structure(children)
        }
        item_type::INTEGER => {
            let v = i32::from_be_bytes([
                buf[value_start],
                buf[value_start + 1],
                buf[value_start + 2],
                buf[value_start + 3],
            ]);
            TtlvValue::Integer(v)
        }
        item_type::LONG_INTEGER => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[value_start..value_start + 8]);
            TtlvValue::LongInteger(i64::from_be_bytes(bytes))
        }
        item_type::ENUMERATION => {
            let v = u32::from_be_bytes([
                buf[value_start],
                buf[value_start + 1],
                buf[value_start + 2],
                buf[value_start + 3],
            ]);
            TtlvValue::Enumeration(v)
        }
        item_type::BOOLEAN => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[value_start..value_start + 8]);
            TtlvValue::Boolean(i64::from_be_bytes(bytes) != 0)
        }
        item_type::TEXT_STRING => {
            let s = std::str::from_utf8(&buf[value_start..value_start + length])
                .map_err(|_| TtlvError::InvalidUtf8)?;
            TtlvValue::TextString(s.to_string())
        }
        item_type::BYTE_STRING => {
            TtlvValue::ByteString(buf[value_start..value_start + length].to_vec())
        }
        item_type::DATE_TIME => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[value_start..value_start + 8]);
            TtlvValue::DateTime(i64::from_be_bytes(bytes))
        }
        item_type::BIG_INTEGER => {
            TtlvValue::BigInteger(buf[value_start..value_start + length].to_vec())
        }
        item_type::INTERVAL => {
            let v = u32::from_be_bytes([
                buf[value_start],
                buf[value_start + 1],
                buf[value_start + 2],
                buf[value_start + 3],
            ]);
            TtlvValue::Interval(v)
        }
        _ => {
            TtlvValue::Raw(buf[value_start..value_start + length].to_vec())
        }
    };

    Ok(TtlvItem {
        tag,
        item_type: typ,
        value,
        length,
        total_length,
    })
}

/// Find the first child with a given tag within a decoded structure.
pub fn find_child(item: &TtlvItem, tag: u32) -> Option<&TtlvItem> {
    if let TtlvValue::Structure(ref children) = item.value {
        children.iter().find(|c| c.tag == tag)
    } else {
        None
    }
}

/// Find all children with a given tag within a decoded structure.
pub fn find_children(item: &TtlvItem, tag: u32) -> Vec<&TtlvItem> {
    if let TtlvValue::Structure(ref children) = item.value {
        children.iter().filter(|c| c.tag == tag).collect()
    } else {
        Vec::new()
    }
}

impl TtlvValue {
    /// Get as integer, if the value is an integer.
    pub fn as_integer(&self) -> Option<i32> {
        if let TtlvValue::Integer(v) = self { Some(*v) } else { None }
    }

    /// Get as enumeration, if the value is an enumeration.
    pub fn as_enum(&self) -> Option<u32> {
        if let TtlvValue::Enumeration(v) = self { Some(*v) } else { None }
    }

    /// Get as text string, if the value is a text string.
    pub fn as_text(&self) -> Option<&str> {
        if let TtlvValue::TextString(ref s) = self { Some(s) } else { None }
    }

    /// Get as byte string, if the value is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let TtlvValue::ByteString(ref b) = self { Some(b) } else { None }
    }

    /// Get as boolean, if the value is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        if let TtlvValue::Boolean(v) = self { Some(*v) } else { None }
    }
}
