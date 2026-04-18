//! # cyphera-kmip
//!
//! KMIP client for Rust -- connect to any KMIP-compliant key management server.
//!
//! Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix,
//! HashiCorp Vault Enterprise, and any KMIP 1.4 server.
//!
//! ## Quick Start
//!
//! ```no_run
//! use cyphera_kmip::KmipClient;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = KmipClient::new(
//!     "kmip-server.corp.internal",
//!     5696,
//!     "/path/to/client.pem",
//!     "/path/to/client-key.pem",
//!     Some("/path/to/ca.pem"),
//!     None,
//! )?;
//!
//! let key = client.fetch_key("my-encryption-key")?;
//! client.close();
//! # Ok(())
//! # }
//! ```

pub mod ttlv;
pub mod tags;
pub mod operations;
pub mod client;

pub use client::KmipClient;
pub use operations::{
    build_locate_request, build_get_request, build_create_request,
    parse_response, parse_locate_payload, parse_get_payload, parse_create_payload,
    KmipResponse, LocateResult, GetResult, CreateResult, KmipError,
    PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
pub use tags::*;
pub use ttlv::{
    TtlvItem, TtlvValue, TtlvError,
    encode_ttlv, encode_structure, encode_integer, encode_long_integer,
    encode_enum, encode_boolean, encode_text_string, encode_byte_string,
    encode_date_time, decode_ttlv, find_child, find_children,
    item_type,
};
