//! KMIP request/response builders for Locate, Get, Create operations.
//!
//! Builds KMIP 1.4 request messages and parses response messages.

use crate::tags::*;
use crate::ttlv::*;

/// Protocol version: KMIP 1.4
pub const PROTOCOL_MAJOR: i32 = 1;
pub const PROTOCOL_MINOR: i32 = 4;

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
    let payload = encode_structure(tag::REQUEST_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, unique_id),
    ]);

    let batch_item = encode_structure(tag::BATCH_ITEM, &[
        encode_enum(tag::OPERATION, operation::GET),
        payload,
    ]);

    encode_structure(tag::REQUEST_MESSAGE, &[
        build_request_header(1),
        batch_item,
    ])
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
