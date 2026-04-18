//! KMIP 1.4 tag, type, and enum constants.
//!
//! Only the subset needed for Locate, Get, Create operations.
//!
//! Reference: OASIS KMIP Specification v1.4
//! <https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html>

/// KMIP tags — 3-byte identifiers for each field.
pub mod tag {
    pub const REQUEST_MESSAGE: u32 = 0x420078;
    pub const RESPONSE_MESSAGE: u32 = 0x42007B;
    pub const REQUEST_HEADER: u32 = 0x420077;
    pub const RESPONSE_HEADER: u32 = 0x42007A;
    pub const PROTOCOL_VERSION: u32 = 0x420069;
    pub const PROTOCOL_VERSION_MAJOR: u32 = 0x42006A;
    pub const PROTOCOL_VERSION_MINOR: u32 = 0x42006B;
    pub const BATCH_COUNT: u32 = 0x42000D;
    pub const BATCH_ITEM: u32 = 0x42000F;
    pub const OPERATION: u32 = 0x42005C;
    pub const REQUEST_PAYLOAD: u32 = 0x420079;
    pub const RESPONSE_PAYLOAD: u32 = 0x42007C;
    pub const RESULT_STATUS: u32 = 0x42007F;
    pub const RESULT_REASON: u32 = 0x420080;
    pub const RESULT_MESSAGE: u32 = 0x420081;

    // Object identification
    pub const UNIQUE_IDENTIFIER: u32 = 0x420094;
    pub const OBJECT_TYPE: u32 = 0x420057;

    // Naming
    pub const NAME: u32 = 0x420053;
    pub const NAME_VALUE: u32 = 0x420055;
    pub const NAME_TYPE: u32 = 0x420054;

    // Attributes (KMIP 1.x style)
    pub const ATTRIBUTE: u32 = 0x420008;
    pub const ATTRIBUTE_NAME: u32 = 0x42000A;
    pub const ATTRIBUTE_VALUE: u32 = 0x42000B;

    // Key structure
    pub const SYMMETRIC_KEY: u32 = 0x42008F;
    pub const KEY_BLOCK: u32 = 0x420040;
    pub const KEY_FORMAT_TYPE: u32 = 0x420042;
    pub const KEY_VALUE: u32 = 0x420045;
    pub const KEY_MATERIAL: u32 = 0x420043;

    // Crypto attributes
    pub const CRYPTOGRAPHIC_ALGORITHM: u32 = 0x420028;
    pub const CRYPTOGRAPHIC_LENGTH: u32 = 0x42002A;
    pub const CRYPTOGRAPHIC_USAGE_MASK: u32 = 0x42002C;

    // Template
    pub const TEMPLATE_ATTRIBUTE: u32 = 0x420091;
}

/// KMIP operation codes.
pub mod operation {
    pub const CREATE: u32 = 0x00000001;
    pub const LOCATE: u32 = 0x00000008;
    pub const GET: u32 = 0x0000000A;
    pub const ACTIVATE: u32 = 0x00000012;
    pub const DESTROY: u32 = 0x00000014;
    pub const CHECK: u32 = 0x0000001C;
}

/// KMIP object types.
pub mod object_type {
    pub const SYMMETRIC_KEY: u32 = 0x00000001;
    pub const PUBLIC_KEY: u32 = 0x00000002;
    pub const PRIVATE_KEY: u32 = 0x00000003;
    pub const CERTIFICATE: u32 = 0x00000006;
    pub const SECRET_DATA: u32 = 0x00000007;
    pub const OPAQUE_DATA: u32 = 0x00000008;
}

/// KMIP result status codes.
pub mod result_status {
    pub const SUCCESS: u32 = 0x00000000;
    pub const OPERATION_FAILED: u32 = 0x00000001;
    pub const OPERATION_PENDING: u32 = 0x00000002;
    pub const OPERATION_UNDONE: u32 = 0x00000003;
}

/// KMIP key format types.
pub mod key_format_type {
    pub const RAW: u32 = 0x00000001;
    pub const OPAQUE: u32 = 0x00000002;
    pub const PKCS1: u32 = 0x00000003;
    pub const PKCS8: u32 = 0x00000004;
    pub const X509: u32 = 0x00000005;
    pub const EC_PRIVATE_KEY: u32 = 0x00000006;
    pub const TRANSPARENT_SYMMETRIC: u32 = 0x00000007;
}

/// Cryptographic algorithms.
pub mod algorithm {
    pub const DES: u32 = 0x00000001;
    pub const TRIPLE_DES: u32 = 0x00000002;
    pub const AES: u32 = 0x00000003;
    pub const RSA: u32 = 0x00000004;
    pub const DSA: u32 = 0x00000005;
    pub const ECDSA: u32 = 0x00000006;
    pub const HMAC_SHA1: u32 = 0x00000007;
    pub const HMAC_SHA256: u32 = 0x00000008;
    pub const HMAC_SHA384: u32 = 0x00000009;
    pub const HMAC_SHA512: u32 = 0x0000000A;
}

/// KMIP name types.
pub mod name_type {
    pub const UNINTERPRETED_TEXT_STRING: u32 = 0x00000001;
    pub const URI: u32 = 0x00000002;
}

/// Cryptographic usage mask (bitmask).
pub mod usage_mask {
    pub const SIGN: u32 = 0x00000001;
    pub const VERIFY: u32 = 0x00000002;
    pub const ENCRYPT: u32 = 0x00000004;
    pub const DECRYPT: u32 = 0x00000008;
    pub const WRAP_KEY: u32 = 0x00000010;
    pub const UNWRAP_KEY: u32 = 0x00000020;
    pub const EXPORT: u32 = 0x00000040;
    pub const DERIVE_KEY: u32 = 0x00000100;
    pub const KEY_AGREEMENT: u32 = 0x00000800;
}
