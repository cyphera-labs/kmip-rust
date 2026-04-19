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

// ── Operation values (all 27) ───────────────────────────────────────

#[test]
fn operation_create_is_1() {
    assert_eq!(operation::CREATE, 0x00000001);
}

#[test]
fn operation_create_key_pair_is_2() {
    assert_eq!(operation::CREATE_KEY_PAIR, 0x00000002);
}

#[test]
fn operation_register_is_3() {
    assert_eq!(operation::REGISTER, 0x00000003);
}

#[test]
fn operation_re_key_is_4() {
    assert_eq!(operation::RE_KEY, 0x00000004);
}

#[test]
fn operation_derive_key_is_5() {
    assert_eq!(operation::DERIVE_KEY, 0x00000005);
}

#[test]
fn operation_locate_is_8() {
    assert_eq!(operation::LOCATE, 0x00000008);
}

#[test]
fn operation_check_is_09() {
    assert_eq!(operation::CHECK, 0x00000009);
}

#[test]
fn operation_get_is_0a() {
    assert_eq!(operation::GET, 0x0000000A);
}

#[test]
fn operation_get_attributes_is_0b() {
    assert_eq!(operation::GET_ATTRIBUTES, 0x0000000B);
}

#[test]
fn operation_get_attribute_list_is_0c() {
    assert_eq!(operation::GET_ATTRIBUTE_LIST, 0x0000000C);
}

#[test]
fn operation_add_attribute_is_0d() {
    assert_eq!(operation::ADD_ATTRIBUTE, 0x0000000D);
}

#[test]
fn operation_modify_attribute_is_0e() {
    assert_eq!(operation::MODIFY_ATTRIBUTE, 0x0000000E);
}

#[test]
fn operation_delete_attribute_is_0f() {
    assert_eq!(operation::DELETE_ATTRIBUTE, 0x0000000F);
}

#[test]
fn operation_obtain_lease_is_10() {
    assert_eq!(operation::OBTAIN_LEASE, 0x00000010);
}

#[test]
fn operation_activate_is_12() {
    assert_eq!(operation::ACTIVATE, 0x00000012);
}

#[test]
fn operation_revoke_is_13() {
    assert_eq!(operation::REVOKE, 0x00000013);
}

#[test]
fn operation_destroy_is_14() {
    assert_eq!(operation::DESTROY, 0x00000014);
}

#[test]
fn operation_archive_is_15() {
    assert_eq!(operation::ARCHIVE, 0x00000015);
}

#[test]
fn operation_recover_is_16() {
    assert_eq!(operation::RECOVER, 0x00000016);
}

#[test]
fn operation_query_is_18() {
    assert_eq!(operation::QUERY, 0x00000018);
}

#[test]
fn operation_poll_is_1a() {
    assert_eq!(operation::POLL, 0x0000001A);
}

#[test]
fn operation_discover_versions_is_1e() {
    assert_eq!(operation::DISCOVER_VERSIONS, 0x0000001E);
}

#[test]
fn operation_encrypt_is_1f() {
    assert_eq!(operation::ENCRYPT, 0x0000001F);
}

#[test]
fn operation_decrypt_is_20() {
    assert_eq!(operation::DECRYPT, 0x00000020);
}

#[test]
fn operation_sign_is_21() {
    assert_eq!(operation::SIGN, 0x00000021);
}

#[test]
fn operation_signature_verify_is_22() {
    assert_eq!(operation::SIGNATURE_VERIFY, 0x00000022);
}

#[test]
fn operation_mac_is_23() {
    assert_eq!(operation::MAC, 0x00000023);
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
        // New tags
        tag::PRIVATE_KEY_UNIQUE_IDENTIFIER,
        tag::PUBLIC_KEY_UNIQUE_IDENTIFIER,
        tag::PUBLIC_KEY, tag::PRIVATE_KEY,
        tag::CERTIFICATE, tag::CERTIFICATE_TYPE,
        tag::CERTIFICATE_VALUE,
        tag::DATA, tag::IV_COUNTER_NONCE,
        tag::SIGNATURE_DATA, tag::MAC_DATA,
        tag::VALIDITY_INDICATOR,
        tag::REVOCATION_REASON, tag::REVOCATION_REASON_CODE,
        tag::QUERY_FUNCTION, tag::STATE,
        tag::DERIVATION_METHOD, tag::DERIVATION_PARAMETERS,
        tag::DERIVATION_DATA, tag::LEASE_TIME,
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

// ── New tag values ───────────────────────────────────────────────────

#[test]
fn tag_data_value() {
    assert_eq!(tag::DATA, 0x420033);
}

#[test]
fn tag_iv_counter_nonce_value() {
    assert_eq!(tag::IV_COUNTER_NONCE, 0x420047);
}

#[test]
fn tag_signature_data_value() {
    assert_eq!(tag::SIGNATURE_DATA, 0x42004F);
}

#[test]
fn tag_mac_data_value() {
    assert_eq!(tag::MAC_DATA, 0x420051);
}

#[test]
fn tag_validity_indicator_value() {
    assert_eq!(tag::VALIDITY_INDICATOR, 0x420098);
}

#[test]
fn tag_revocation_reason_value() {
    assert_eq!(tag::REVOCATION_REASON, 0x420082);
}

#[test]
fn tag_revocation_reason_code_value() {
    assert_eq!(tag::REVOCATION_REASON_CODE, 0x420083);
}

#[test]
fn tag_derivation_parameters_value() {
    assert_eq!(tag::DERIVATION_PARAMETERS, 0x420032);
}

#[test]
fn tag_derivation_data_value() {
    assert_eq!(tag::DERIVATION_DATA, 0x420030);
}

#[test]
fn tag_lease_time_value() {
    assert_eq!(tag::LEASE_TIME, 0x420049);
}

#[test]
fn tag_private_key_unique_identifier_value() {
    assert_eq!(tag::PRIVATE_KEY_UNIQUE_IDENTIFIER, 0x420066);
}

#[test]
fn tag_public_key_unique_identifier_value() {
    assert_eq!(tag::PUBLIC_KEY_UNIQUE_IDENTIFIER, 0x42006F);
}
