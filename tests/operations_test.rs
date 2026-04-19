use cyphera_kmip::ttlv::*;
use cyphera_kmip::tags::*;
use cyphera_kmip::operations::*;

// ── Helper: decode a request message and return the root TtlvItem ───

fn decode_request(data: &[u8]) -> TtlvItem {
    decode_ttlv(data, 0).expect("Failed to decode request")
}

/// Helper: extract operation enum from a decoded request.
fn extract_operation(decoded: &TtlvItem) -> u32 {
    let batch_item = find_child(decoded, tag::BATCH_ITEM).unwrap();
    let op = find_child(batch_item, tag::OPERATION).unwrap();
    op.value.as_enum().unwrap()
}

/// Helper: extract unique identifier from request payload.
fn extract_uid(decoded: &TtlvItem) -> String {
    let batch_item = find_child(decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let uid = find_child(payload, tag::UNIQUE_IDENTIFIER).unwrap();
    uid.value.as_text().unwrap().to_string()
}

/// Helper: build a success response with given op and payload children.
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

// ═══════════════════════════════════════════════════════════════════════
// build_locate_request
// ═══════════════════════════════════════════════════════════════════════

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
    assert_eq!(extract_operation(&decoded), operation::LOCATE);
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

// ═══════════════════════════════════════════════════════════════════════
// build_get_request
// ═══════════════════════════════════════════════════════════════════════

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
    assert_eq!(extract_operation(&decoded), operation::GET);
}

#[test]
fn get_request_contains_unique_identifier() {
    let decoded = decode_request(&build_get_request("uid-abc-def"));
    assert_eq!(extract_uid(&decoded), "uid-abc-def");
}

#[test]
fn get_request_has_protocol_version() {
    let decoded = decode_request(&build_get_request("uid-123"));
    let header = find_child(&decoded, tag::REQUEST_HEADER).unwrap();
    let version = find_child(header, tag::PROTOCOL_VERSION).unwrap();
    assert!(find_child(version, tag::PROTOCOL_VERSION_MAJOR).is_some());
    assert!(find_child(version, tag::PROTOCOL_VERSION_MINOR).is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// build_create_request
// ═══════════════════════════════════════════════════════════════════════

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
    assert_eq!(extract_operation(&decoded), operation::CREATE);
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

// ═══════════════════════════════════════════════════════════════════════
// build_activate_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn activate_request_has_activate_operation() {
    let decoded = decode_request(&build_activate_request("uid-act"));
    assert_eq!(extract_operation(&decoded), operation::ACTIVATE);
}

#[test]
fn activate_request_contains_uid() {
    let decoded = decode_request(&build_activate_request("uid-act"));
    assert_eq!(extract_uid(&decoded), "uid-act");
}

// ═══════════════════════════════════════════════════════════════════════
// build_destroy_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn destroy_request_has_destroy_operation() {
    let decoded = decode_request(&build_destroy_request("uid-del"));
    assert_eq!(extract_operation(&decoded), operation::DESTROY);
}

#[test]
fn destroy_request_contains_uid() {
    let decoded = decode_request(&build_destroy_request("uid-del"));
    assert_eq!(extract_uid(&decoded), "uid-del");
}

// ═══════════════════════════════════════════════════════════════════════
// build_check_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn check_request_has_check_operation() {
    let decoded = decode_request(&build_check_request("uid-chk"));
    assert_eq!(extract_operation(&decoded), operation::CHECK);
}

#[test]
fn check_request_contains_uid() {
    let decoded = decode_request(&build_check_request("uid-chk"));
    assert_eq!(extract_uid(&decoded), "uid-chk");
}

// ═══════════════════════════════════════════════════════════════════════
// build_create_key_pair_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn create_key_pair_request_has_correct_operation() {
    let decoded = decode_request(&build_create_key_pair_request("kp", algorithm::RSA, 2048));
    assert_eq!(extract_operation(&decoded), operation::CREATE_KEY_PAIR);
}

#[test]
fn create_key_pair_request_has_sign_verify_usage_mask() {
    let decoded = decode_request(&build_create_key_pair_request("kp", algorithm::RSA, 2048));
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
    let expected = (usage_mask::SIGN | usage_mask::VERIFY) as i32;
    assert_eq!(mask_val.value.as_integer(), Some(expected));
}

// ═══════════════════════════════════════════════════════════════════════
// build_register_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn register_request_has_register_operation() {
    let decoded = decode_request(&build_register_request(
        object_type::SYMMETRIC_KEY, &[1, 2, 3], "reg-key", algorithm::AES, 128,
    ));
    assert_eq!(extract_operation(&decoded), operation::REGISTER);
}

#[test]
fn register_request_contains_key_material() {
    let material = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let decoded = decode_request(&build_register_request(
        object_type::SYMMETRIC_KEY, &material, "reg-key", algorithm::AES, 128,
    ));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let sym_key = find_child(payload, tag::SYMMETRIC_KEY).unwrap();
    let key_block = find_child(sym_key, tag::KEY_BLOCK).unwrap();
    let key_value = find_child(key_block, tag::KEY_VALUE).unwrap();
    let km = find_child(key_value, tag::KEY_MATERIAL).unwrap();
    assert_eq!(km.value.as_bytes(), Some(material.as_slice()));
}

#[test]
fn register_request_includes_name_when_nonempty() {
    let decoded = decode_request(&build_register_request(
        object_type::SYMMETRIC_KEY, &[1], "my-reg-key", algorithm::AES, 128,
    ));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE);
    assert!(tmpl.is_some());
}

#[test]
fn register_request_omits_name_when_empty() {
    let decoded = decode_request(&build_register_request(
        object_type::SYMMETRIC_KEY, &[1], "", algorithm::AES, 128,
    ));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let tmpl = find_child(payload, tag::TEMPLATE_ATTRIBUTE);
    assert!(tmpl.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// build_re_key_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn re_key_request_has_re_key_operation() {
    let decoded = decode_request(&build_re_key_request("uid-rk"));
    assert_eq!(extract_operation(&decoded), operation::RE_KEY);
}

#[test]
fn re_key_request_contains_uid() {
    let decoded = decode_request(&build_re_key_request("uid-rk"));
    assert_eq!(extract_uid(&decoded), "uid-rk");
}

// ═══════════════════════════════════════════════════════════════════════
// build_derive_key_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn derive_key_request_has_derive_key_operation() {
    let decoded = decode_request(&build_derive_key_request("uid-dk", &[1, 2], "derived", 256));
    assert_eq!(extract_operation(&decoded), operation::DERIVE_KEY);
}

#[test]
fn derive_key_request_contains_derivation_data() {
    let data = vec![0x01, 0x02, 0x03];
    let decoded = decode_request(&build_derive_key_request("uid-dk", &data, "derived", 256));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let params = find_child(payload, tag::DERIVATION_PARAMETERS).unwrap();
    let dd = find_child(params, tag::DERIVATION_DATA).unwrap();
    assert_eq!(dd.value.as_bytes(), Some(data.as_slice()));
}

// ═══════════════════════════════════════════════════════════════════════
// build_get_attributes_request / build_get_attribute_list_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn get_attributes_request_has_correct_operation() {
    let decoded = decode_request(&build_get_attributes_request("uid-ga"));
    assert_eq!(extract_operation(&decoded), operation::GET_ATTRIBUTES);
}

#[test]
fn get_attribute_list_request_has_correct_operation() {
    let decoded = decode_request(&build_get_attribute_list_request("uid-gal"));
    assert_eq!(extract_operation(&decoded), operation::GET_ATTRIBUTE_LIST);
}

// ═══════════════════════════════════════════════════════════════════════
// build_add_attribute_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn add_attribute_request_has_correct_operation() {
    let decoded = decode_request(&build_add_attribute_request("uid-aa", "Contact", "admin@example.com"));
    assert_eq!(extract_operation(&decoded), operation::ADD_ATTRIBUTE);
}

#[test]
fn add_attribute_request_contains_attribute() {
    let decoded = decode_request(&build_add_attribute_request("uid-aa", "Contact", "admin@example.com"));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let attr = find_child(payload, tag::ATTRIBUTE).unwrap();
    let name = find_child(attr, tag::ATTRIBUTE_NAME).unwrap();
    assert_eq!(name.value.as_text(), Some("Contact"));
    let val = find_child(attr, tag::ATTRIBUTE_VALUE).unwrap();
    assert_eq!(val.value.as_text(), Some("admin@example.com"));
}

// ═══════════════════════════════════════════════════════════════════════
// build_modify_attribute_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn modify_attribute_request_has_correct_operation() {
    let decoded = decode_request(&build_modify_attribute_request("uid-ma", "Contact", "new@example.com"));
    assert_eq!(extract_operation(&decoded), operation::MODIFY_ATTRIBUTE);
}

// ═══════════════════════════════════════════════════════════════════════
// build_delete_attribute_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn delete_attribute_request_has_correct_operation() {
    let decoded = decode_request(&build_delete_attribute_request("uid-da", "Contact"));
    assert_eq!(extract_operation(&decoded), operation::DELETE_ATTRIBUTE);
}

#[test]
fn delete_attribute_request_contains_attribute_name() {
    let decoded = decode_request(&build_delete_attribute_request("uid-da", "Contact"));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let attr = find_child(payload, tag::ATTRIBUTE).unwrap();
    let name = find_child(attr, tag::ATTRIBUTE_NAME).unwrap();
    assert_eq!(name.value.as_text(), Some("Contact"));
}

// ═══════════════════════════════════════════════════════════════════════
// build_obtain_lease_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn obtain_lease_request_has_correct_operation() {
    let decoded = decode_request(&build_obtain_lease_request("uid-ol"));
    assert_eq!(extract_operation(&decoded), operation::OBTAIN_LEASE);
}

// ═══════════════════════════════════════════════════════════════════════
// build_revoke_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn revoke_request_has_revoke_operation() {
    let decoded = decode_request(&build_revoke_request("uid-rev", 1));
    assert_eq!(extract_operation(&decoded), operation::REVOKE);
}

#[test]
fn revoke_request_contains_revocation_reason() {
    let decoded = decode_request(&build_revoke_request("uid-rev", 5));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let reason = find_child(payload, tag::REVOCATION_REASON).unwrap();
    let code = find_child(reason, tag::REVOCATION_REASON_CODE).unwrap();
    assert_eq!(code.value.as_enum(), Some(5));
}

// ═══════════════════════════════════════════════════════════════════════
// build_archive_request / build_recover_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn archive_request_has_archive_operation() {
    let decoded = decode_request(&build_archive_request("uid-arc"));
    assert_eq!(extract_operation(&decoded), operation::ARCHIVE);
}

#[test]
fn recover_request_has_recover_operation() {
    let decoded = decode_request(&build_recover_request("uid-rec"));
    assert_eq!(extract_operation(&decoded), operation::RECOVER);
}

// ═══════════════════════════════════════════════════════════════════════
// build_query_request / build_poll_request / build_discover_versions_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn query_request_has_query_operation() {
    let decoded = decode_request(&build_query_request());
    assert_eq!(extract_operation(&decoded), operation::QUERY);
}

#[test]
fn poll_request_has_poll_operation() {
    let decoded = decode_request(&build_poll_request());
    assert_eq!(extract_operation(&decoded), operation::POLL);
}

#[test]
fn discover_versions_request_has_correct_operation() {
    let decoded = decode_request(&build_discover_versions_request());
    assert_eq!(extract_operation(&decoded), operation::DISCOVER_VERSIONS);
}

// ═══════════════════════════════════════════════════════════════════════
// build_encrypt_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn encrypt_request_has_encrypt_operation() {
    let decoded = decode_request(&build_encrypt_request("uid-enc", &[1, 2, 3]));
    assert_eq!(extract_operation(&decoded), operation::ENCRYPT);
}

#[test]
fn encrypt_request_contains_data() {
    let data = vec![0xAA, 0xBB, 0xCC];
    let decoded = decode_request(&build_encrypt_request("uid-enc", &data));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let d = find_child(payload, tag::DATA).unwrap();
    assert_eq!(d.value.as_bytes(), Some(data.as_slice()));
}

// ═══════════════════════════════════════════════════════════════════════
// build_decrypt_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn decrypt_request_has_decrypt_operation() {
    let decoded = decode_request(&build_decrypt_request("uid-dec", &[1], None));
    assert_eq!(extract_operation(&decoded), operation::DECRYPT);
}

#[test]
fn decrypt_request_with_nonce() {
    let nonce = vec![0x01, 0x02, 0x03, 0x04];
    let decoded = decode_request(&build_decrypt_request("uid-dec", &[1], Some(&nonce)));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let iv = find_child(payload, tag::IV_COUNTER_NONCE).unwrap();
    assert_eq!(iv.value.as_bytes(), Some(nonce.as_slice()));
}

#[test]
fn decrypt_request_without_nonce() {
    let decoded = decode_request(&build_decrypt_request("uid-dec", &[1], None));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    assert!(find_child(payload, tag::IV_COUNTER_NONCE).is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// build_sign_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn sign_request_has_sign_operation() {
    let decoded = decode_request(&build_sign_request("uid-sign", &[1, 2]));
    assert_eq!(extract_operation(&decoded), operation::SIGN);
}

// ═══════════════════════════════════════════════════════════════════════
// build_signature_verify_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn signature_verify_request_has_correct_operation() {
    let decoded = decode_request(&build_signature_verify_request("uid-sv", &[1], &[2]));
    assert_eq!(extract_operation(&decoded), operation::SIGNATURE_VERIFY);
}

#[test]
fn signature_verify_request_contains_data_and_signature() {
    let data = vec![0x01];
    let sig = vec![0x02, 0x03];
    let decoded = decode_request(&build_signature_verify_request("uid-sv", &data, &sig));
    let batch_item = find_child(&decoded, tag::BATCH_ITEM).unwrap();
    let payload = find_child(batch_item, tag::REQUEST_PAYLOAD).unwrap();
    let d = find_child(payload, tag::DATA).unwrap();
    assert_eq!(d.value.as_bytes(), Some(data.as_slice()));
    let s = find_child(payload, tag::SIGNATURE_DATA).unwrap();
    assert_eq!(s.value.as_bytes(), Some(sig.as_slice()));
}

// ═══════════════════════════════════════════════════════════════════════
// build_mac_request
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn mac_request_has_mac_operation() {
    let decoded = decode_request(&build_mac_request("uid-mac", &[1, 2]));
    assert_eq!(extract_operation(&decoded), operation::MAC);
}

// ═══════════════════════════════════════════════════════════════════════
// parse_response: success / failure
// ═══════════════════════════════════════════════════════════════════════

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
    let data = encode_structure(tag::REQUEST_MESSAGE, &[
        encode_structure(tag::BATCH_ITEM, &[
            encode_enum(tag::RESULT_STATUS, result_status::SUCCESS),
        ]),
    ]);
    let result = parse_response(&data);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// parse_locate_payload
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
// parse_get_payload
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
// parse_create_payload
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
// parse_create_key_pair_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_create_key_pair_payload_fields() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::PRIVATE_KEY_UNIQUE_IDENTIFIER, "priv-uid"),
        encode_text_string(tag::PUBLIC_KEY_UNIQUE_IDENTIFIER, "pub-uid"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_create_key_pair_payload(&payload);
    assert_eq!(result.private_key_uid.as_deref(), Some("priv-uid"));
    assert_eq!(result.public_key_uid.as_deref(), Some("pub-uid"));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_check_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_check_payload_with_uid() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-checked"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_check_payload(&payload);
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-checked"));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_re_key_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_re_key_payload_with_uid() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-rekeyed"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_re_key_payload(&payload);
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-rekeyed"));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_derive_key_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_derive_key_payload_with_uid() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_text_string(tag::UNIQUE_IDENTIFIER, "uid-derived"),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_derive_key_payload(&payload);
    assert_eq!(result.unique_identifier.as_deref(), Some("uid-derived"));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_encrypt_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_encrypt_payload_with_data_and_nonce() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_byte_string(tag::DATA, &[0xAA, 0xBB]),
        encode_byte_string(tag::IV_COUNTER_NONCE, &[0x01, 0x02, 0x03]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_encrypt_payload(&payload);
    assert_eq!(result.data, Some(vec![0xAA, 0xBB]));
    assert_eq!(result.nonce, Some(vec![0x01, 0x02, 0x03]));
}

#[test]
fn parse_encrypt_payload_data_only() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_byte_string(tag::DATA, &[0xCC]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_encrypt_payload(&payload);
    assert_eq!(result.data, Some(vec![0xCC]));
    assert!(result.nonce.is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// parse_decrypt_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_decrypt_payload_with_data() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_byte_string(tag::DATA, &[0x01, 0x02, 0x03]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_decrypt_payload(&payload);
    assert_eq!(result.data, Some(vec![0x01, 0x02, 0x03]));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_sign_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_sign_payload_with_signature() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_byte_string(tag::SIGNATURE_DATA, &[0xDE, 0xAD]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_sign_payload(&payload);
    assert_eq!(result.signature_data, Some(vec![0xDE, 0xAD]));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_signature_verify_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_signature_verify_payload_valid() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_enum(tag::VALIDITY_INDICATOR, 0), // 0 = valid
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_signature_verify_payload(&payload);
    assert!(result.valid);
}

#[test]
fn parse_signature_verify_payload_invalid() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_enum(tag::VALIDITY_INDICATOR, 1), // 1 = invalid
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_signature_verify_payload(&payload);
    assert!(!result.valid);
}

// ═══════════════════════════════════════════════════════════════════════
// parse_mac_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_mac_payload_with_data() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_byte_string(tag::MAC_DATA, &[0xBE, 0xEF]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_mac_payload(&payload);
    assert_eq!(result.mac_data, Some(vec![0xBE, 0xEF]));
}

// ═══════════════════════════════════════════════════════════════════════
// parse_query_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_query_payload_with_operations_and_types() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_enum(tag::OPERATION, operation::CREATE),
        encode_enum(tag::OPERATION, operation::GET),
        encode_enum(tag::OBJECT_TYPE, object_type::SYMMETRIC_KEY),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_query_payload(&payload);
    assert_eq!(result.operations.len(), 2);
    assert_eq!(result.operations[0], operation::CREATE);
    assert_eq!(result.operations[1], operation::GET);
    assert_eq!(result.object_types.len(), 1);
    assert_eq!(result.object_types[0], object_type::SYMMETRIC_KEY);
}

#[test]
fn parse_query_payload_empty() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_query_payload(&payload);
    assert_eq!(result.operations.len(), 0);
    assert_eq!(result.object_types.len(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// parse_discover_versions_payload
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn parse_discover_versions_payload_with_versions() {
    let payload_data = encode_structure(tag::RESPONSE_PAYLOAD, &[
        encode_structure(tag::PROTOCOL_VERSION, &[
            encode_integer(tag::PROTOCOL_VERSION_MAJOR, 1),
            encode_integer(tag::PROTOCOL_VERSION_MINOR, 4),
        ]),
        encode_structure(tag::PROTOCOL_VERSION, &[
            encode_integer(tag::PROTOCOL_VERSION_MAJOR, 1),
            encode_integer(tag::PROTOCOL_VERSION_MINOR, 3),
        ]),
    ]);
    let payload = decode_ttlv(&payload_data, 0).unwrap();
    let result = parse_discover_versions_payload(&payload);
    assert_eq!(result.versions.len(), 2);
    assert_eq!(result.versions[0].major, 1);
    assert_eq!(result.versions[0].minor, 4);
    assert_eq!(result.versions[1].major, 1);
    assert_eq!(result.versions[1].minor, 3);
}

// ═══════════════════════════════════════════════════════════════════════
// Round-trip tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn round_trip_locate_request() {
    let req = build_locate_request("round-trip-key");
    let decoded = decode_request(&req);
    let re_decoded = decode_ttlv(&req, 0).unwrap();
    assert_eq!(re_decoded.tag, decoded.tag);
    assert_eq!(re_decoded.total_length, decoded.total_length);
}

#[test]
fn round_trip_get_request() {
    let req = build_get_request("uid-roundtrip");
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    assert_eq!(extract_uid(&decoded), "uid-roundtrip");
}

#[test]
fn round_trip_create_request() {
    let req = build_create_request("rt-key", algorithm::AES, 256);
    let decoded = decode_request(&req);
    assert_eq!(decoded.tag, tag::REQUEST_MESSAGE);
    assert_eq!(extract_operation(&decoded), operation::CREATE);
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

#[test]
fn round_trip_encrypt_response() {
    let data = build_success_response(operation::ENCRYPT, &[
        encode_byte_string(tag::DATA, &[0xFF, 0xEE]),
        encode_byte_string(tag::IV_COUNTER_NONCE, &[0x01]),
    ]);
    let resp = parse_response(&data).unwrap();
    assert_eq!(resp.operation, Some(operation::ENCRYPT));
    let payload = resp.payload.unwrap();
    let result = parse_encrypt_payload(&payload);
    assert_eq!(result.data, Some(vec![0xFF, 0xEE]));
    assert_eq!(result.nonce, Some(vec![0x01]));
}

#[test]
fn round_trip_create_key_pair_response() {
    let data = build_success_response(operation::CREATE_KEY_PAIR, &[
        encode_text_string(tag::PRIVATE_KEY_UNIQUE_IDENTIFIER, "priv-1"),
        encode_text_string(tag::PUBLIC_KEY_UNIQUE_IDENTIFIER, "pub-1"),
    ]);
    let resp = parse_response(&data).unwrap();
    assert_eq!(resp.operation, Some(operation::CREATE_KEY_PAIR));
    let payload = resp.payload.unwrap();
    let result = parse_create_key_pair_payload(&payload);
    assert_eq!(result.private_key_uid.as_deref(), Some("priv-1"));
    assert_eq!(result.public_key_uid.as_deref(), Some("pub-1"));
}
