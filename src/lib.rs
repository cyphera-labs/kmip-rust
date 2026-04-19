//! # cyphera-kmip
//!
//! KMIP client for Rust -- connect to any KMIP-compliant key management server.
//!
//! Supports all 27 KMIP 1.4 operations: Create, CreateKeyPair, Register,
//! ReKey, DeriveKey, Locate, Check, Get, GetAttributes, GetAttributeList,
//! AddAttribute, ModifyAttribute, DeleteAttribute, ObtainLease, Activate,
//! Revoke, Destroy, Archive, Recover, Query, Poll, DiscoverVersions,
//! Encrypt, Decrypt, Sign, SignatureVerify, and MAC.
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

pub use client::{KmipClient, resolve_algorithm, zero_bytes};
pub use operations::{
    // Request builders
    build_locate_request, build_get_request, build_create_request,
    build_create_key_pair_request, build_register_request,
    build_re_key_request, build_derive_key_request,
    build_check_request, build_get_attributes_request,
    build_get_attribute_list_request, build_add_attribute_request,
    build_modify_attribute_request, build_delete_attribute_request,
    build_obtain_lease_request, build_activate_request,
    build_revoke_request, build_destroy_request,
    build_archive_request, build_recover_request,
    build_query_request, build_poll_request,
    build_discover_versions_request,
    build_encrypt_request, build_decrypt_request,
    build_sign_request, build_signature_verify_request,
    build_mac_request,
    // Response parsers
    parse_response, parse_locate_payload, parse_get_payload,
    parse_create_payload, parse_create_key_pair_payload,
    parse_check_payload, parse_re_key_payload,
    parse_derive_key_payload, parse_encrypt_payload,
    parse_decrypt_payload, parse_sign_payload,
    parse_signature_verify_payload, parse_mac_payload,
    parse_query_payload, parse_discover_versions_payload,
    // Result types
    KmipResponse, LocateResult, GetResult, CreateResult,
    CreateKeyPairResult, CheckResult, ReKeyResult,
    DeriveKeyResult, EncryptResult, DecryptResult,
    SignResult, SignatureVerifyResult, MacResult,
    QueryResult, DiscoverVersionsResult, ProtocolVersionEntry,
    KmipError,
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
