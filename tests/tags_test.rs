use cyphera_kmip::tags::*;

// ── ObjectType values ────────────────────────────────────────────────

#[test]
fn object_type_certificate_is_1() {
    assert_eq!(object_type::CERTIFICATE, 0x00000001);
}

#[test]
fn object_type_symmetric_key_is_2() {
    assert_eq!(object_type::SYMMETRIC_KEY, 0x00000002);
}

#[test]
fn object_type_public_key_is_3() {
    assert_eq!(object_type::PUBLIC_KEY, 0x00000003);
}

#[test]
fn object_type_private_key_is_4() {
    assert_eq!(object_type::PRIVATE_KEY, 0x00000004);
}

#[test]
fn object_type_split_key_is_5() {
    assert_eq!(object_type::SPLIT_KEY, 0x00000005);
}

#[test]
fn object_type_template_is_6() {
    assert_eq!(object_type::TEMPLATE, 0x00000006);
}

#[test]
fn object_type_secret_data_is_7() {
    assert_eq!(object_type::SECRET_DATA, 0x00000007);
}

#[test]
fn object_type_opaque_data_is_8() {
    assert_eq!(object_type::OPAQUE_DATA, 0x00000008);
}

// ── Operation values ─────────────────────────────────────────────────

#[test]
fn operation_create_is_1() {
    assert_eq!(operation::CREATE, 0x00000001);
}

#[test]
fn operation_locate_is_8() {
    assert_eq!(operation::LOCATE, 0x00000008);
}

#[test]
fn operation_get_is_0a() {
    assert_eq!(operation::GET, 0x0000000A);
}

#[test]
fn operation_activate_is_12() {
    assert_eq!(operation::ACTIVATE, 0x00000012);
}

#[test]
fn operation_destroy_is_14() {
    assert_eq!(operation::DESTROY, 0x00000014);
}

#[test]
fn operation_check_is_09() {
    assert_eq!(operation::CHECK, 0x00000009);
}

// ── ResultStatus values ──────────────────────────────────────────────

#[test]
fn result_status_success_is_0() {
    assert_eq!(result_status::SUCCESS, 0x00000000);
}

#[test]
fn result_status_operation_failed_is_1() {
    assert_eq!(result_status::OPERATION_FAILED, 0x00000001);
}

#[test]
fn result_status_operation_pending_is_2() {
    assert_eq!(result_status::OPERATION_PENDING, 0x00000002);
}

#[test]
fn result_status_operation_undone_is_3() {
    assert_eq!(result_status::OPERATION_UNDONE, 0x00000003);
}

// ── Algorithm values ─────────────────────────────────────────────────

#[test]
fn algorithm_des_is_1() {
    assert_eq!(algorithm::DES, 0x00000001);
}

#[test]
fn algorithm_triple_des_is_2() {
    assert_eq!(algorithm::TRIPLE_DES, 0x00000002);
}

#[test]
fn algorithm_aes_is_3() {
    assert_eq!(algorithm::AES, 0x00000003);
}

#[test]
fn algorithm_rsa_is_4() {
    assert_eq!(algorithm::RSA, 0x00000004);
}

#[test]
fn algorithm_hmac_sha256_is_8() {
    assert_eq!(algorithm::HMAC_SHA256, 0x00000008);
}

#[test]
fn algorithm_hmac_sha512_is_a() {
    assert_eq!(algorithm::HMAC_SHA512, 0x0000000A);
}

// ── KeyFormatType values ─────────────────────────────────────────────

#[test]
fn key_format_type_raw_is_1() {
    assert_eq!(key_format_type::RAW, 0x00000001);
}

#[test]
fn key_format_type_pkcs8_is_4() {
    assert_eq!(key_format_type::PKCS8, 0x00000004);
}

#[test]
fn key_format_type_transparent_symmetric_is_7() {
    assert_eq!(key_format_type::TRANSPARENT_SYMMETRIC, 0x00000007);
}

// ── NameType values ──────────────────────────────────────────────────

#[test]
fn name_type_uninterpreted_text_string_is_1() {
    assert_eq!(name_type::UNINTERPRETED_TEXT_STRING, 0x00000001);
}

#[test]
fn name_type_uri_is_2() {
    assert_eq!(name_type::URI, 0x00000002);
}

// ── UsageMask bitmask values ─────────────────────────────────────────

#[test]
fn usage_mask_sign_is_1() {
    assert_eq!(usage_mask::SIGN, 0x00000001);
}

#[test]
fn usage_mask_verify_is_2() {
    assert_eq!(usage_mask::VERIFY, 0x00000002);
}

#[test]
fn usage_mask_encrypt_is_4() {
    assert_eq!(usage_mask::ENCRYPT, 0x00000004);
}

#[test]
fn usage_mask_decrypt_is_8() {
    assert_eq!(usage_mask::DECRYPT, 0x00000008);
}

#[test]
fn usage_mask_wrap_key_is_0x10() {
    assert_eq!(usage_mask::WRAP_KEY, 0x00000010);
}

#[test]
fn usage_mask_unwrap_key_is_0x20() {
    assert_eq!(usage_mask::UNWRAP_KEY, 0x00000020);
}

#[test]
fn usage_mask_export_is_0x40() {
    assert_eq!(usage_mask::EXPORT, 0x00000040);
}

#[test]
fn usage_mask_derive_key_is_0x100() {
    assert_eq!(usage_mask::DERIVE_KEY, 0x00000100);
}

// ── Bitmask combinations ────────────────────────────────────────────

#[test]
fn usage_mask_encrypt_decrypt_combination() {
    let mask = usage_mask::ENCRYPT | usage_mask::DECRYPT;
    assert_eq!(mask, 0x0000000C);
    assert!(mask & usage_mask::ENCRYPT != 0);
    assert!(mask & usage_mask::DECRYPT != 0);
    assert!(mask & usage_mask::SIGN == 0);
}

#[test]
fn usage_mask_all_operations_combination() {
    let mask = usage_mask::SIGN
        | usage_mask::VERIFY
        | usage_mask::ENCRYPT
        | usage_mask::DECRYPT
        | usage_mask::WRAP_KEY
        | usage_mask::UNWRAP_KEY;
    assert_eq!(mask, 0x0000003F);
}

#[test]
fn usage_mask_sign_verify_combination() {
    let mask = usage_mask::SIGN | usage_mask::VERIFY;
    assert_eq!(mask, 0x00000003);
}

// ── Tag values in 0x42XXXX range ─────────────────────────────────────

#[test]
fn tag_request_message_in_42_range() {
    assert_eq!(tag::REQUEST_MESSAGE & 0xFF0000, 0x420000);
}

#[test]
fn tag_response_message_in_42_range() {
    assert_eq!(tag::RESPONSE_MESSAGE & 0xFF0000, 0x420000);
}

#[test]
fn tag_batch_item_in_42_range() {
    assert_eq!(tag::BATCH_ITEM & 0xFF0000, 0x420000);
}

#[test]
fn tag_operation_in_42_range() {
    assert_eq!(tag::OPERATION & 0xFF0000, 0x420000);
}

#[test]
fn tag_unique_identifier_in_42_range() {
    assert_eq!(tag::UNIQUE_IDENTIFIER & 0xFF0000, 0x420000);
}

#[test]
fn all_tags_in_42_range() {
    let tags = [
        tag::REQUEST_MESSAGE, tag::RESPONSE_MESSAGE,
        tag::REQUEST_HEADER, tag::RESPONSE_HEADER,
        tag::PROTOCOL_VERSION, tag::PROTOCOL_VERSION_MAJOR,
        tag::PROTOCOL_VERSION_MINOR, tag::BATCH_COUNT,
        tag::BATCH_ITEM, tag::OPERATION,
        tag::REQUEST_PAYLOAD, tag::RESPONSE_PAYLOAD,
        tag::RESULT_STATUS, tag::RESULT_REASON,
        tag::RESULT_MESSAGE, tag::UNIQUE_IDENTIFIER,
        tag::OBJECT_TYPE, tag::NAME, tag::NAME_VALUE,
        tag::NAME_TYPE, tag::ATTRIBUTE, tag::ATTRIBUTE_NAME,
        tag::ATTRIBUTE_VALUE, tag::SYMMETRIC_KEY,
        tag::KEY_BLOCK, tag::KEY_FORMAT_TYPE,
        tag::KEY_VALUE, tag::KEY_MATERIAL,
        tag::CRYPTOGRAPHIC_ALGORITHM, tag::CRYPTOGRAPHIC_LENGTH,
        tag::CRYPTOGRAPHIC_USAGE_MASK, tag::TEMPLATE_ATTRIBUTE,
    ];
    for &t in &tags {
        assert_eq!(
            t & 0xFF0000,
            0x420000,
            "Tag 0x{:06X} not in 0x42XXXX range",
            t
        );
    }
}

// ── Specific tag values ──────────────────────────────────────────────

#[test]
fn tag_request_message_value() {
    assert_eq!(tag::REQUEST_MESSAGE, 0x420078);
}

#[test]
fn tag_response_message_value() {
    assert_eq!(tag::RESPONSE_MESSAGE, 0x42007B);
}

#[test]
fn tag_protocol_version_value() {
    assert_eq!(tag::PROTOCOL_VERSION, 0x420069);
}

#[test]
fn tag_result_status_value() {
    assert_eq!(tag::RESULT_STATUS, 0x42007F);
}
