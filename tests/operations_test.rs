use cyphera_kmip::ttlv::*;
use cyphera_kmip::tags::*;
use cyphera_kmip::operations::*;

// ── Helper: decode a request message and return the root TtlvItem ───

fn decode_request(data: &[u8]) -> TtlvItem {
    decode_ttlv(data, 0).expect("Failed to decode request")
}

// ── build_locate_request ─────────────────────────────────────────────

#[test]
fn locate_request_is_valid_structure() {
    let req = build_locate_request("test-key");
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    assert_eq!(decoded.item_type, item_type::STRUCTURE);
}

#[test]
fn locate_request_has_protocol_version() {
    let decoded = decode_request(&build_locate_request("test-key"));
    let header = find_child(&decoded, tag::REQUEST_HEADER).unwrap();
    let version = find_child(header, tag::PROTOCOL_VERSION).unwrap();
    let major = find_child(version, tag::PROTOCOL_VERSION_MAJOR).unwrap();
    let minor = find_child(version, tag::PROTOCOL_VERSION_MINOR).unwrap();
    assert_eq!(major.value.as_integer(), Some(PROTOCOL_MAJOR));
    assert_eq!(minor.value.as_integer(), Some(PROTOCOL_MINOR));
}

#[test]
fn locate_request_has_batch_count_1() {
    let decoded = decode_request(&build_locate_request("test-key"));
    let header = find_child(&decoded, tag::REQUEST_HEADER).unwrap();
    let batch_count = find_child(header, tag::BATCH_COUNT).unwrap();
    assert_eq!(batch_count.value.as_integer(), Some(1));
}

#[test]
fn locate_request_has_locate_operation() {
    let decoded = decode_request(&build_locate_request("test-key"));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let op = find_child(batch_item, tag::OPERATION).unwrap();
    assert_eq!(op.value.as_enum(), Some(operation::LOCATE));
}

#[test]
fn locate_request_contains_name_attribute() {
    let decoded = decode_request(&build_locate_request("my-aes-key"));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let attr = find_child(payload, tag::ATTRIBUTE).unwrap();
    let attr_name = find_child(attr, tag::ATTRIBUTE_NAME).unwrap();
    assert_eq!(attr_name.value.as_text(), Some("Name"));

    let attr_value = find_child(attr, tag::ATTRIBUTE_VALUE).unwrap();
    let name_value = find_child(attr_value, tag::NAME_VALUE).unwrap();
    assert_eq!(name_value.value.as_text(), Some("my-aes-key"));

    let name_type_item = find_child(attr_value, tag::NAME_TYPE).unwrap();
    assert_eq!(name_type_item.value.as_enum(), Some(name_type::UNINTERPRETED_TEXT_STRING));
}

// ── build_get_request ────────────────────────────────────────────────

#[test]
fn get_request_is_valid_structure() {
    let req = build_get_request("uid-123");
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    assert_eq!(decoded.item_type, item_type::STRUCTURE);
}

#[test]
fn get_request_has_get_operation() {
    let decoded = decode_request(&build_get_request("uid-123"));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let op = find_child(batch_item, tag::OPERATION).unwrap();
    assert_eq!(op.value.as_enum(), Some(operation::GET));
}

#[test]
fn get_request_contains_unique_identifier() {
    let decoded = decode_request(&build_get_request("uid-abc-def"));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER).unwrap();
    assert_eq!(uid.value.as_text(), Some("uid-abc-def"));
}

#[test]
fn get_request_has_protocol_version() {
    let decoded = decode_request(&build_get_request("uid-123"));
    let header = find_child(&decoded, tag::REQUEST_HEADER).unwrap();
    let version = find_child(header, tag::PROTOCOL_VERSION).unwrap();
    assert!(find_child(version, tag::PROTOCOL_VERSION_MAJOR).is_some());
    assert!(find_child(version, tag::PROTOCOL_VERSION_MINOR).is_some());
}

// ── build_create_request ─────────────────────────────────────────────

#[test]
fn create_request_is_valid_structure() {
    let req = build_create_request("new-key", algorithm::AES, 256);
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    assert_eq!(decoded.item_type, item_type::STRUCTURE);
}

#[test]
fn create_request_has_create_operation() {
    let decoded = decode_request(&build_create_request("new-key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let op = find_child(batch_item, tag::OPERATION).unwrap();
    assert_eq!(op.value.as_enum(), Some(operation::CREATE));
}

#[test]
fn create_request_specifies_symmetric_key_object_type() {
    let decoded = decode_request(&build_create_request("new-key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let obj_type = find_child(payload, tag::OBJECT_TYPE).unwrap();
    assert_eq!(obj_type.value.as_enum(), Some(object_type::SYMMETRIC_KEY));
}

#[test]
fn create_request_has_template_attribute() {
    let decoded = decode_request(&build_create_request("new-key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE);
    assert!(tmpl.is_some());
}

#[test]
fn create_request_contains_algorithm_attribute() {
    let decoded = decode_request(&build_create_request("key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE).unwrap();

    let attrs = find_children(tmpl, tag::ATTRIBUTE);
    let algo_attr = attrs.iter().find(|a| {
        find_child(a, tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text().map(|s| s == "Cryptographic Algorithm"))
            .unwrap_or(false)
    }).expect("Algorithm attribute not found");

    let algo_val = find_child(algo_attr, tag::ATTRIBUTE_VALUE).unwrap();
    assert_eq!(algo_val.value.as_enum(), Some(algorithm::AES));
}

#[test]
fn create_request_contains_length_attribute() {
    let decoded = decode_request(&build_create_request("key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE).unwrap();

    let attrs = find_children(tmpl, tag::ATTRIBUTE);
    let len_attr = attrs.iter().find(|a| {
        find_child(a, tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text().map(|s| s == "Cryptographic Length"))
            .unwrap_or(false)
    }).expect("Length attribute not found");

    let len_val = find_child(len_attr, tag::ATTRIBUTE_VALUE).unwrap();
    assert_eq!(len_val.value.as_integer(), Some(256));
}

#[test]
fn create_request_contains_usage_mask() {
    let decoded = decode_request(&build_create_request("key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE).unwrap();

    let attrs = find_children(tmpl, tag::ATTRIBUTE);
    let mask_attr = attrs.iter().find(|a| {
        find_child(a, tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text().map(|s| s == "Cryptographic Usage Mask"))
            .unwrap_or(false)
    }).expect("Usage Mask attribute not found");

    let mask_val = find_child(mask_attr, tag::ATTRIBUTE_VALUE).unwrap();
    let expected = (usage_mask::ENCRYPT | usage_mask::DECRYPT) as i32;
    assert_eq!(mask_val.value.as_integer(), Some(expected));
}

#[test]
fn create_request_contains_name() {
    let decoded = decode_request(&build_create_request("my-new-key", algorithm::AES, 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE).unwrap();

    let attrs = find_children(tmpl, tag::ATTRIBUTE);
    let name_attr = attrs.iter().find(|a| {
        find_child(a, tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text().map(|s| s == "Name"))
            .unwrap_or(false)
    }).expect("Name attribute not found");

    let name_struct = find_child(name_attr, tag::ATTRIBUTE_VALUE).unwrap();
    let name_value = find_child(name_struct, tag::NAME_VALUE).unwrap();
    assert_eq!(name_value.value.as_text(), Some("my-new-key"));
}

#[test]
fn create_request_custom_algorithm() {
    let decoded = decode_request(&build_create_request("key", algorithm::TRIPLE_DES, 192));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE).unwrap();

    let attrs = find_children(tmpl, tag::ATTRIBUTE);
    let algo_attr = attrs.iter().find(|a| {
        find_child(a, tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text().map(|s| s == "Cryptographic Algorithm"))
            .unwrap_or(false)
    }).unwrap();

    let algo_val = find_child(algo_attr, tag::ATTRIBUTE_VALUE).unwrap();
    assert_eq!(algo_val.value.as_enum(), Some(algorithm::TRIPLE_DES));
}

#[test]
fn create_request_custom_length() {
    let decoded = decode_request(&build_create_request("key", algorithm::AES, 128));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE).unwrap();

    let attrs = find_children(tmpl, tag::ATTRIBUTE);
    let len_attr = attrs.iter().find(|a| {
        find_child(a, tag::ATTRIBUTE_NAME)
            .and_then(|n| n.value.as_text().map(|s| s == "Cryptographic Length"))
            .unwrap_or(false)
    }).unwrap();

    let len_val = find_child(len_attr, tag::ATTRIBUTE_VALUE).unwrap();
    assert_eq!(len_val.value.as_integer(), Some(128));
}

// ── parse_response: success ──────────────────────────────────────────

fn build_success_response(op: u32, payload_children: &[Vec<u8>]) -> Vec<u8> {
    encode_structure(tag::RESPONSE_MESSAGE, &[
        encode_structure(tag::RESPONSE_HEADER, &[
            encode_structure(tag::PROTOCOL_VERSION, &[
                encode_integer(tag::PROTOCOL_VERSION_MAJOR, 1),
                encode_integer(tag::PROTOCOL_VERSION_MINOR, 4),
            ]),
            encode_integer(tag::BATCH_COUNT, 1),
        ]),
        encode_structure(tag::BATCH_ITEM, &[
            encode_enum(tag::OPERATION, op),
            encode_enum(tag::RESULT_STATUS, result_status::SUCCESS),
            encode_structure(tag::RESPONSE_PAYLOAD, payload_children),
        ]),
    ])
}

#[test]
fn parse_response_success() {
    let data = build_success_response(operation::LOCATE, &[]);
    let resp = parse_response(&data).unwrap();
    assert_eq!(resp.result_status, Some(result_status::SUCCESS));
    assert_eq!(resp.operation, Some(operation::LOCATE));
}

#[test]
fn parse_response_failure_returns_error() {
    let data = encode_structure(tag::RESPONSE_MESSAGE, &[
        encode_structure(tag::RESPONSE_HEADER, &[
            encode_structure(tag::PROTOCOL_VERSION, &[
                encode_integer(tag::PROTOCOL_VERSION_MAJOR, 1),
                encode_integer(tag::PROTOCOL_VERSION_MINOR, 4),
            ]),
            encode_integer(tag::BATCH_COUNT, 1),
        ]),
        encode_structure(tag::BATCH_ITEM, &[
            encode_enum(tag::OPERATION, operation::LOCATE),
            encode_enum(tag::RESULT_STATUS, result_status::OPERATION_FAILED),
            encode_text_string(tag::RESULT_MESSAGE, "Object not found"),
        ]),
    ]);
    let result = parse_response(&data);
    match result {
        Err(e) => {
            let err_msg = format!("{}", e);
            assert!(err_msg.contains("Object not found"), "Expected 'Object not found', got: {}", err_msg);
        }
        Ok(_) => panic!("Expected error but got Ok"),
    }
}

#[test]
fn parse_response_wrong_tag_returns_error() {
    // Send a RequestMessage tag instead of ResponseMessage
    let data = encode_structure(tag::REQUEST_MESSAGE, &[
        encode_structure(tag::BATCH_ITEM, &[
            encode_enum(tag::RESULT_STATUS, result_status::SUCCESS),
        ]),
    ]);
    let result = parse_response(&data);
    assert!(result.is_err());
}

// ── parse_locate_payload ─────────────────────────────────────────────

#[test]
fn parse_locate_payload_single_id() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-001"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_locate_payload(&payload);
    assert_eq!(result.unique_identifiers.len(), 1);
    assert_eq!(result.unique_identifiers[0], "uid-001");
}

#[test]
fn parse_locate_payload_multiple_ids() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-001"),
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-002"),
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-003"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_locate_payload(&payload);
    assert_eq!(result.unique_identifiers.len(), 3);
    assert_eq!(result.unique_identifiers[0], "uid-001");
    assert_eq!(result.unique_identifiers[1], "uid-002");
    assert_eq!(result.unique_identifiers[2], "uid-003");
}

#[test]
fn parse_locate_payload_empty() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_locate_payload(&payload);
    assert_eq!(result.unique_identifiers.len(), 0);
}

// ── parse_get_payload ────────────────────────────────────────────────

#[test]
fn parse_get_payload_with_key_material() {
    let key_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_enum(tag::OBJECT_TYPE, object_type::SYMMETRIC_KEY),
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-key-1"),
        encode_structure(tag::SYMMETRIC_KEY, &[
            encode_structure(tag::KEY_BLOCK, &[
                encode_enum(tag::KEY_FORMAT_TYPE, key_format_type::RAW),
                encode_structure(tag::KEY_VALUE, &[
                    encode_byte_string(tag::KEY_MATERIAL, &key_bytes),
                ]),
            ]),
        ]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_get_payload(&payload);
    assert_eq!(result.object_type, Some(object_type::SYMMETRIC_KEY));
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-key-1"));
    assert_eq!(result.key_material, Some(key_bytes));
}

#[test]
fn parse_get_payload_without_key_material() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-no-key"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_get_payload(&payload);
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-no-key"));
    assert!(result.key_material.is_none());
}

// ── parse_create_payload ─────────────────────────────────────────────

#[test]
fn parse_create_payload_fields() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_enum(tag::OBJECT_TYPE, object_type::SYMMETRIC_KEY),
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-created"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_create_payload(&payload);
    assert_eq!(result.object_type, Some(object_type::SYMMETRIC_KEY));
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-created"));
}

#[test]
fn parse_create_payload_missing_fields() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_create_payload(&payload);
    assert!(result.object_type.is_none());
    assert!(result.unique_identifier.is_none());
}

// ── Round-trip: build request -> encode -> decode -> verify ──────────

#[test]
fn round_trip_locate_request() {
    let req = build_locate_request("round-trip-key");
    let decoded = decode_request(&req);
    // Re-encode should produce identical bytes
    // (Verify structural integrity by re-parsing)
    let re_decoded = decode_ttlv(&req, 0).unwrap();
    assert_eq!(re_decoded.tag, decoded.tag);
    assert_eq!(re_decoded.total_length, decoded.total_length);
}

#[test]
fn round_trip_get_request() {
    let req = build_get_request("uid-roundtrip");
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER).unwrap();
    assert_eq!(uid.value.as_text(), Some("uid-roundtrip"));
}

#[test]
fn round_trip_create_request() {
    let req = build_create_request("rt-key", algorithm::AES, 256);
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let op = find_child(batch_item, tag::OPERATION).unwrap();
    assert_eq!(op.value.as_enum(), Some(operation::CREATE));
}

#[test]
fn round_trip_response_parse() {
    let data = build_success_response(operation::GET, &[
        encode_enum(tag::OBJECT_TYPE, object_type::SYMMETRIC_KEY),
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-rt"),
    ]);
    let resp = parse_response(&data).unwrap();
    assert_eq!(resp.operation, Some(operation::GET));
    let payload = resp.payload.unwrap();
    let result = parse_get_payload(&payload);
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-rt"));
}
