//! KMIP request/response builders for all 27 KMIP 1.4 operations.
//!
//! Builds KMIP 1.4 request messages and parses response messages.

use crate::tags::*;
use crate::ttlv::*;

/// Protocol version: KMIP 1.4
pub const PROTOCOL_MAJOR: i32 = 1;
pub const PROTOCOL_MINOR: i32 = 4;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Parsed KMIP response.
pub struct KmipResponse {
    pub operation: Option<u32>,
    pub result_status: Option<u32>,
    pub result_reason: Option<u32>,
    pub result_message: Option<String>,
    pub payload: Option<TtlvItem>,
}

/// Parsed Locate response.
pub struct LocateResult {
    pub unique_identifiers: Vec<String>,
}

/// Parsed Get response.
pub struct GetResult {
    pub object_type: Option<u32>,
    pub unique_identifier: Option<String>,
    pub key_material: Option<Vec<u8>>,
}

/// Parsed Create response.
pub struct CreateResult {
    pub object_type: Option<u32>,
    pub unique_identifier: Option<String>,
}

/// Parsed Check response.
pub struct CheckResult {
    pub unique_identifier: Option<String>,
}

/// Parsed ReKey response.
pub struct ReKeyResult {
    pub unique_identifier: Option<String>,
}

/// Parsed Encrypt response.
pub struct EncryptResult {
    pub data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

/// Parsed Decrypt response.
pub struct DecryptResult {
    pub data: Option<Vec<u8>>,
}

/// Parsed Sign response.
pub struct SignResult {
    pub signature_data: Option<Vec<u8>>,
}

/// Parsed SignatureVerify response.
pub struct SignatureVerifyResult {
    pub valid: bool,
}

/// Parsed MAC response.
pub struct MacResult {
    pub mac_data: Option<Vec<u8>>,
}

/// Parsed Query response.
pub struct QueryResult {
    pub operations: Vec<u32>,
    pub object_types: Vec<u32>,
}

/// Parsed DiscoverVersions response.
pub struct DiscoverVersionsResult {
    pub versions: Vec<ProtocolVersionEntry>,
}

/// A protocol version entry (major, minor).
pub struct ProtocolVersionEntry {
    pub major: i32,
    pub minor: i32,
}

/// Parsed DeriveKey response.
pub struct DeriveKeyResult {
    pub unique_identifier: Option<String>,
}

/// Parsed CreateKeyPair response.
pub struct CreateKeyPairResult {
    pub private_key_uid: Option<String>,
    pub public_key_uid: Option<String>,
}

/// KMIP operation error.
#[derive(Debug)]
pub struct KmipError {
    pub message: String,
    pub result_status: Option<u32>,
    pub result_reason: Option<u32>,
}

impl std::fmt::Display for KmipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for KmipError {}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the request header (included in every request).
fn build_request_header(batch_count: i32) -> Vec<u8> {
    encode_structure(tag::REQUEST_HEADER, &[
        encode_structure(tag::PROTOCOL_VERSION, &[
            encode_integer(tag::PROTOCOL_VERSION_MAJOR, PROTOCOL_MAJOR),
            encode_integer(tag::PROTOCOL_VERSION_MINOR, PROTOCOL_MINOR),
        ]),
        encode_integer(tag::BATCH_COUNT, batch_count),
    ])
}

/// Build a request with just a UID in the payload.
fn build_uid_only_request(op: u32, unique_id: &str) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, op),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a request with an empty payload.
fn build_empty_payload_request(op: u32) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, op),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

// ---------------------------------------------------------------------------
// Request builders (all 27 operations)
// ---------------------------------------------------------------------------

/// Build a Locate request -- find keys by name.
pub fn build_locate_request(name: &str) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_structure(tag::ATTRIBUTE, &[
            encode_text_string(tag::ATTRIBUTE_NAME, "Name"),
            encode_structure(tag::ATTRIBUTE_VALUE, &[
                encode_text_string(tag::NAME_VALUE, name),
                encode_enum(tag::NAME_TYPE, name_type::UNINTERPRETED_TEXT_STRING),
            ]),
        ]),
    ]);

    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::LOCATE),
        payload,
    ]);

    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a Get request -- fetch key material by unique ID.
pub fn build_get_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::GET, unique_id)
}

/// Build a Create request -- create a new symmetric key.
pub fn build_create_request(name: &str, algo: u32, length: i32) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_enum(tag::OBJECT_TYPE, object_type::SYMMETRIC_KEY),
        encode_structure(tag::TEMPLATE_ATTRIBUTE, &[
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                encode_enum(tag::ATTRIBUTE_VALUE, algo),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                encode_integer(tag::ATTRIBUTE_VALUE, length),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                encode_integer(tag::ATTRIBUTE_VALUE, (usage_mask::ENCRYPT | usage_mask::DECRYPT) as i32),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Name"),
                encode_structure(tag::ATTRIBUTE_VALUE, &[
                    encode_text_string(tag::NAME_VALUE, name),
                    encode_enum(tag::NAME_TYPE, name_type::UNINTERPRETED_TEXT_STRING),
                ]),
            ]),
        ]),
    ]);

    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::CREATE),
        payload,
    ]);

    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a CreateKeyPair request.
pub fn build_create_key_pair_request(name: &str, algo: u32, length: i32) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_structure(tag::TEMPLATE_ATTRIBUTE, &[
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                encode_enum(tag::ATTRIBUTE_VALUE, algo),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                encode_integer(tag::ATTRIBUTE_VALUE, length),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                encode_integer(tag::ATTRIBUTE_VALUE, (usage_mask::SIGN | usage_mask::VERIFY) as i32),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Name"),
                encode_structure(tag::ATTRIBUTE_VALUE, &[
                    encode_text_string(tag::NAME_VALUE, name),
                    encode_enum(tag::NAME_TYPE, name_type::UNINTERPRETED_TEXT_STRING),
                ]),
            ]),
        ]),
    ]);

    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::CREATE_KEY_PAIR),
        payload,
    ]);

    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a Register request for a symmetric key.
pub fn build_register_request(
    obj_type: u32,
    material: &[u8],
    name: &str,
    algo: u32,
    length: i32,
) -> Vec<u8> {
    let mut payload_children = vec![
        encode_enum(tag::OBJECT_TYPE, obj_type),
        encode_structure(tag::SYMMETRIC_KEY, &[
            encode_structure(tag::KEY_BLOCK, &[
                encode_enum(tag::KEY_FORMAT_TYPE, key_format_type::RAW),
                encode_structure(tag::KEY_VALUE, &[
                    encode_byte_string(tag::KEY_MATERIAL, material),
                ]),
                encode_enum(tag::CRYPTOGRAPHIC_ALGORITHM, algo),
                encode_integer(tag::CRYPTOGRAPHIC_LENGTH, length),
            ]),
        ]),
    ];
    if !name.is_empty() {
        payload_children.push(
            encode_structure(tag::TEMPLATE_ATTRIBUTE, &[
                encode_structure(tag::ATTRIBUTE, &[
                    encode_text_string(tag::ATTRIBUTE_NAME, "Name"),
                    encode_structure(tag::ATTRIBUTE_VALUE, &[
                        encode_text_string(tag::NAME_VALUE, name),
                        encode_enum(tag::NAME_TYPE, name_type::UNINTERPRETED_TEXT_STRING),
                    ]),
                ]),
            ]),
        );
    }

    let payload = encode_structure(tag::REQUEST_PAYLOAD, &payload_children);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::REGISTER),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a ReKey request.
pub fn build_re_key_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::RE_KEY, unique_id)
}

/// Build a DeriveKey request.
pub fn build_derive_key_request(
    unique_id: &str,
    derivation_data: &[u8],
    name: &str,
    length: i32,
) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_structure(tag::DERIVATION_PARAMETERS, &[
            encode_byte_string(tag::DERIVATION_DATA, derivation_data),
        ]),
        encode_structure(tag::TEMPLATE_ATTRIBUTE, &[
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Cryptographic Length"),
                encode_integer(tag::ATTRIBUTE_VALUE, length),
            ]),
            encode_structure(tag::ATTRIBUTE, &[
                encode_text_string(tag::ATTRIBUTE_NAME, "Name"),
                encode_structure(tag::ATTRIBUTE_VALUE, &[
                    encode_text_string(tag::NAME_VALUE, name),
                    encode_enum(tag::NAME_TYPE, name_type::UNINTERPRETED_TEXT_STRING),
                ]),
            ]),
        ]),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::DERIVE_KEY),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a Check request.
pub fn build_check_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::CHECK, unique_id)
}

/// Build a GetAttributes request.
pub fn build_get_attributes_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::GET_ATTRIBUTES, unique_id)
}

/// Build a GetAttributeList request.
pub fn build_get_attribute_list_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::GET_ATTRIBUTE_LIST, unique_id)
}

/// Build an AddAttribute request.
pub fn build_add_attribute_request(unique_id: &str, attr_name: &str, attr_value: &str) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_structure(tag::ATTRIBUTE, &[
            encode_text_string(tag::ATTRIBUTE_NAME, attr_name),
            encode_text_string(tag::ATTRIBUTE_VALUE, attr_value),
        ]),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::ADD_ATTRIBUTE),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a ModifyAttribute request.
pub fn build_modify_attribute_request(unique_id: &str, attr_name: &str, attr_value: &str) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_structure(tag::ATTRIBUTE, &[
            encode_text_string(tag::ATTRIBUTE_NAME, attr_name),
            encode_text_string(tag::ATTRIBUTE_VALUE, attr_value),
        ]),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::MODIFY_ATTRIBUTE),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a DeleteAttribute request.
pub fn build_delete_attribute_request(unique_id: &str, attr_name: &str) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_structure(tag::ATTRIBUTE, &[
            encode_text_string(tag::ATTRIBUTE_NAME, attr_name),
        ]),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::DELETE_ATTRIBUTE),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build an ObtainLease request.
pub fn build_obtain_lease_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::OBTAIN_LEASE, unique_id)
}

/// Build an Activate request.
pub fn build_activate_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::ACTIVATE, unique_id)
}

/// Build a Revoke request with a revocation reason.
pub fn build_revoke_request(unique_id: &str, reason: u32) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_structure(tag::REVOCATION_REASON, &[
            encode_enum(tag::REVOCATION_REASON_CODE, reason),
        ]),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::REVOKE),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a Destroy request.
pub fn build_destroy_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::DESTROY, unique_id)
}

/// Build an Archive request.
pub fn build_archive_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::ARCHIVE, unique_id)
}

/// Build a Recover request.
pub fn build_recover_request(unique_id: &str) -> Vec<u8> {
    build_uid_only_request(operation::RECOVER, unique_id)
}

/// Build a Query request.
pub fn build_query_request() -> Vec<u8> {
    build_empty_payload_request(operation::QUERY)
}

/// Build a Poll request.
pub fn build_poll_request() -> Vec<u8> {
    build_empty_payload_request(operation::POLL)
}

/// Build a DiscoverVersions request.
pub fn build_discover_versions_request() -> Vec<u8> {
    build_empty_payload_request(operation::DISCOVER_VERSIONS)
}

/// Build an Encrypt request.
pub fn build_encrypt_request(unique_id: &str, data: &[u8]) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_byte_string(tag::DATA, data),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::ENCRYPT),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a Decrypt request.
pub fn build_decrypt_request(unique_id: &str, data: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
    let mut payload_children = vec![
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_byte_string(tag::DATA, data),
    ];
    if let Some(n) = nonce {
        if !n.is_empty() {
            payload_children.push(encode_byte_string(tag::IV_COUNTER_NONCE, n));
        }
    }
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &payload_children);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::DECRYPT),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a Sign request.
pub fn build_sign_request(unique_id: &str, data: &[u8]) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_byte_string(tag::DATA, data),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::SIGN),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a SignatureVerify request.
pub fn build_signature_verify_request(unique_id: &str, data: &[u8], signature: &[u8]) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_byte_string(tag::DATA, data),
        encode_byte_string(tag::SIGNATURE_DATA, signature),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::SIGNATURE_VERIFY),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

/// Build a MAC request.
pub fn build_mac_request(unique_id: &str, data: &[u8]) -> Vec<u8> {
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
        encode_byte_string(tag::DATA, data),
    ]);
    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::MAC),
        payload,
    ]);
    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Parse a KMIP response message.
pub fn parse_response(data: &[u8]) -> Result<KmipResponse, Box<dyn std::error::Error>> {
    let msg = decode_ttlv(data, 0)?;
    if msg.tag != tag::RESPONSE_MESSAGE {
        return Err(Box::new(KmipError {
            message: format!(
                "Expected ResponseMessage (0x42007B), got 0x{:06X}",
                msg.tag
            ),
            result_status: None,
            result_reason: None,
        }));
    }

    let batch_item = find_child(&msg, tag::BATCH_ITEM)
        .ok_or_else(|| KmipError {
            message: "No BatchItem in response".to_string(),
            result_status: None,
            result_reason: None,
        })?;

    let op = find_child(batch_item, tag::OPERATION)
        .and_then(|i| i.value.as_enum());
    let status = find_child(batch_item, tag::RESULT_STATUS)
        .and_then(|i| i.value.as_enum());
    let reason = find_child(batch_item, tag::RESULT_REASON)
        .and_then(|i| i.value.as_enum());
    let message = find_child(batch_item, tag::RESULT_MESSAGE)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    let payload = find_child(batch_item, tag::RESPONSE_PAYLOAD).cloned();

    if status != Some(result_status::SUCCESS) {
        let err_msg = message.clone().unwrap_or_else(|| {
            format!("KMIP operation failed (status={:?})", status)
        });
        return Err(Box::new(KmipError {
            message: err_msg,
            result_status: status,
            result_reason: reason,
        }));
    }

    Ok(KmipResponse {
        operation: op,
        result_status: status,
        result_reason: reason,
        result_message: message,
        payload,
    })
}

/// Parse a Locate response payload.
pub fn parse_locate_payload(payload: &TtlvItem) -> LocateResult {
    let ids = find_children(payload, tag::UNIQUE_IDENTIFIER);
    LocateResult {
        unique_identifiers: ids
            .iter()
            .filter_map(|item| item.value.as_text().map(|s| s.to_string()))
            .collect(),
    }
}

/// Parse a Get response payload.
pub fn parse_get_payload(payload: &TtlvItem) -> GetResult {
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    let obj_type = find_child(payload, tag::OBJECT_TYPE)
        .and_then(|i| i.value.as_enum());

    // Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
    let key_material = find_child(payload, tag::SYMMETRIC_KEY)
        .and_then(|sym| find_child(sym, tag::KEY_BLOCK))
        .and_then(|kb| find_child(kb, tag::KEY_VALUE))
        .and_then(|kv| find_child(kv, tag::KEY_MATERIAL))
        .and_then(|km| km.value.as_bytes().map(|b| b.to_vec()));

    GetResult {
        object_type: obj_type,
        unique_identifier: uid,
        key_material,
    }
}

/// Parse a Create response payload.
pub fn parse_create_payload(payload: &TtlvItem) -> CreateResult {
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    let obj_type = find_child(payload, tag::OBJECT_TYPE)
        .and_then(|i| i.value.as_enum());

    CreateResult {
        object_type: obj_type,
        unique_identifier: uid,
    }
}

/// Parse a CreateKeyPair response payload.
pub fn parse_create_key_pair_payload(payload: &TtlvItem) -> CreateKeyPairResult {
    let priv_uid = find_child(payload, tag::PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    let pub_uid = find_child(payload, tag::PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));

    CreateKeyPairResult {
        private_key_uid: priv_uid,
        public_key_uid: pub_uid,
    }
}

/// Parse a Check response payload.
pub fn parse_check_payload(payload: &TtlvItem) -> CheckResult {
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    CheckResult {
        unique_identifier: uid,
    }
}

/// Parse a ReKey response payload.
pub fn parse_re_key_payload(payload: &TtlvItem) -> ReKeyResult {
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    ReKeyResult {
        unique_identifier: uid,
    }
}

/// Parse a DeriveKey response payload.
pub fn parse_derive_key_payload(payload: &TtlvItem) -> DeriveKeyResult {
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER)
        .and_then(|i| i.value.as_text().map(|s| s.to_string()));
    DeriveKeyResult {
        unique_identifier: uid,
    }
}

/// Parse an Encrypt response payload.
pub fn parse_encrypt_payload(payload: &TtlvItem) -> EncryptResult {
    let data = find_child(payload, tag::DATA)
        .and_then(|i| i.value.as_bytes().map(|b| b.to_vec()));
    let nonce = find_child(payload, tag::IV_COUNTER_NONCE)
        .and_then(|i| i.value.as_bytes().map(|b| b.to_vec()));
    EncryptResult { data, nonce }
}

/// Parse a Decrypt response payload.
pub fn parse_decrypt_payload(payload: &TtlvItem) -> DecryptResult {
    let data = find_child(payload, tag::DATA)
        .and_then(|i| i.value.as_bytes().map(|b| b.to_vec()));
    DecryptResult { data }
}

/// Parse a Sign response payload.
pub fn parse_sign_payload(payload: &TtlvItem) -> SignResult {
    let sig = find_child(payload, tag::SIGNATURE_DATA)
        .and_then(|i| i.value.as_bytes().map(|b| b.to_vec()));
    SignResult { signature_data: sig }
}

/// Parse a SignatureVerify response payload.
pub fn parse_signature_verify_payload(payload: &TtlvItem) -> SignatureVerifyResult {
    let valid = find_child(payload, tag::VALIDITY_INDICATOR)
        .and_then(|i| i.value.as_enum())
        .map(|v| v == 0)
        .unwrap_or(false);
    SignatureVerifyResult { valid }
}

/// Parse a MAC response payload.
pub fn parse_mac_payload(payload: &TtlvItem) -> MacResult {
    let mac_data = find_child(payload, tag::MAC_DATA)
        .and_then(|i| i.value.as_bytes().map(|b| b.to_vec()));
    MacResult { mac_data }
}

/// Parse a Query response payload.
pub fn parse_query_payload(payload: &TtlvItem) -> QueryResult {
    let ops = find_children(payload, tag::OPERATION);
    let obj_types = find_children(payload, tag::OBJECT_TYPE);
    QueryResult {
        operations: ops.iter().filter_map(|i| i.value.as_enum()).collect(),
        object_types: obj_types.iter().filter_map(|i| i.value.as_enum()).collect(),
    }
}

/// Parse a DiscoverVersions response payload.
pub fn parse_discover_versions_payload(payload: &TtlvItem) -> DiscoverVersionsResult {
    let versions = find_children(payload, tag::PROTOCOL_VERSION);
    let entries = versions.iter().map(|v| {
        let major = find_child(v, tag::PROTOCOL_VERSION_MAJOR)
            .and_then(|i| i.value.as_integer())
            .unwrap_or(0);
        let minor = find_child(v, tag::PROTOCOL_VERSION_MINOR)
            .and_then(|i| i.value.as_integer())
            .unwrap_or(0);
        ProtocolVersionEntry { major, minor }
    }).collect();
    DiscoverVersionsResult { versions: entries }
}
