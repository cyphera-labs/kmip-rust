use cyphera_kmip::ttlv::*;

// ── Primitive types: Integer ─────────────────────────────────────────

#[test]
fn encode_decode_integer_positive() {
    let encoded = encode_integer(0x42006A, 42);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x42006A);
    assert_eq!(decoded.item_type, item_type::INTEGER);
    assert_eq!(decoded.value.as_integer(), Some(42));
}

#[test]
fn encode_decode_integer_zero() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 0), 0).unwrap();
    assert_eq!(decoded.value.as_integer(), Some(0));
}

#[test]
fn encode_decode_integer_negative() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, -1), 0).unwrap();
    assert_eq!(decoded.value.as_integer(), Some(-1));
}

#[test]
fn encode_decode_integer_negative_large() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, -999_999), 0).unwrap();
    assert_eq!(decoded.value.as_integer(), Some(-999_999));
}

#[test]
fn encode_decode_integer_max() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, i32::MAX), 0).unwrap();
    assert_eq!(decoded.value.as_integer(), Some(i32::MAX));
}

#[test]
fn encode_decode_integer_min() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, i32::MIN), 0).unwrap();
    assert_eq!(decoded.value.as_integer(), Some(i32::MIN));
}

// ── Primitive types: Long Integer ────────────────────────────────────

#[test]
fn encode_decode_long_integer() {
    let encoded = encode_long_integer(0x420094, 0x0123456789ABCDEF);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420094);
    assert_eq!(decoded.item_type, item_type::LONG_INTEGER);
    if let TtlvValue::LongInteger(v) = decoded.value {
        assert_eq!(v, 0x0123456789ABCDEF);
    } else {
        panic!("Expected LongInteger");
    }
}

#[test]
fn encode_decode_long_integer_zero() {
    let decoded = decode_ttlv(&encode_long_integer(0x420094, 0), 0).unwrap();
    if let TtlvValue::LongInteger(v) = decoded.value {
        assert_eq!(v, 0);
    } else {
        panic!("Expected LongInteger");
    }
}

#[test]
fn encode_decode_long_integer_negative() {
    let decoded = decode_ttlv(&encode_long_integer(0x420094, -1), 0).unwrap();
    if let TtlvValue::LongInteger(v) = decoded.value {
        assert_eq!(v, -1);
    } else {
        panic!("Expected LongInteger");
    }
}

// ── Primitive types: Enumeration ─────────────────────────────────────

#[test]
fn encode_decode_enumeration() {
    let encoded = encode_enum(0x42005C, 0x0000000A);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x42005C);
    assert_eq!(decoded.item_type, item_type::ENUMERATION);
    assert_eq!(decoded.value.as_enum(), Some(0x0000000A));
}

#[test]
fn encode_decode_enumeration_zero() {
    let decoded = decode_ttlv(&encode_enum(0x42005C, 0), 0).unwrap();
    assert_eq!(decoded.value.as_enum(), Some(0));
}

#[test]
fn encode_decode_enumeration_large() {
    let decoded = decode_ttlv(&encode_enum(0x42005C, 0xFFFFFFFF), 0).unwrap();
    assert_eq!(decoded.value.as_enum(), Some(0xFFFFFFFF));
}

// ── Primitive types: Boolean ─────────────────────────────────────────

#[test]
fn encode_decode_boolean_true() {
    let decoded = decode_ttlv(&encode_boolean(0x420008, true), 0).unwrap();
    assert_eq!(decoded.item_type, item_type::BOOLEAN);
    assert_eq!(decoded.value.as_bool(), Some(true));
}

#[test]
fn encode_decode_boolean_false() {
    let decoded = decode_ttlv(&encode_boolean(0x420008, false), 0).unwrap();
    assert_eq!(decoded.item_type, item_type::BOOLEAN);
    assert_eq!(decoded.value.as_bool(), Some(false));
}

// ── Primitive types: Text String ─────────────────────────────────────

#[test]
fn encode_decode_text_string() {
    let encoded = encode_text_string(0x420055, "my-key");
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420055);
    assert_eq!(decoded.item_type, item_type::TEXT_STRING);
    assert_eq!(decoded.value.as_text(), Some("my-key"));
}

#[test]
fn encode_decode_empty_text_string() {
    let decoded = decode_ttlv(&encode_text_string(0x420055, ""), 0).unwrap();
    assert_eq!(decoded.value.as_text(), Some(""));
}

#[test]
fn encode_decode_text_string_exact_8_bytes() {
    // "12345678" is exactly 8 bytes — no padding needed
    let encoded = encode_text_string(0x420055, "12345678");
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.value.as_text(), Some("12345678"));
}

#[test]
fn encode_decode_text_string_unicode_multibyte() {
    let text = "caf\u{00e9}"; // "café" — 5 bytes UTF-8
    let encoded = encode_text_string(0x420055, text);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.value.as_text(), Some(text));
}

#[test]
fn encode_decode_text_string_emoji() {
    let text = "\u{1f512}"; // padlock emoji — 4 bytes UTF-8
    let encoded = encode_text_string(0x420055, text);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.value.as_text(), Some(text));
}

#[test]
fn encode_decode_text_string_cjk() {
    let text = "\u{4e16}\u{754c}"; // "世界" — 6 bytes UTF-8
    let encoded = encode_text_string(0x420055, text);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.value.as_text(), Some(text));
}

// ── Primitive types: Byte String ─────────────────────────────────────

#[test]
fn encode_decode_byte_string() {
    let key = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let encoded = encode_byte_string(0x420043, &key);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420043);
    assert_eq!(decoded.item_type, item_type::BYTE_STRING);
    assert_eq!(decoded.value.as_bytes(), Some(key.as_slice()));
}

#[test]
fn encode_decode_empty_byte_string() {
    let decoded = decode_ttlv(&encode_byte_string(0x420043, &[]), 0).unwrap();
    assert_eq!(decoded.value.as_bytes(), Some([].as_slice()));
}

#[test]
fn encode_decode_byte_string_exact_8_bytes() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let decoded = decode_ttlv(&encode_byte_string(0x420043, &data), 0).unwrap();
    assert_eq!(decoded.value.as_bytes(), Some(data.as_slice()));
}

#[test]
fn encode_decode_byte_string_16_bytes() {
    let data: Vec<u8> = (0..16).collect();
    let decoded = decode_ttlv(&encode_byte_string(0x420043, &data), 0).unwrap();
    assert_eq!(decoded.value.as_bytes(), Some(data.as_slice()));
}

// ── Primitive types: DateTime ────────────────────────────────────────

#[test]
fn encode_decode_date_time() {
    let ts: i64 = 1_700_000_000;
    let decoded = decode_ttlv(&encode_date_time(0x420008, ts), 0).unwrap();
    assert_eq!(decoded.item_type, item_type::DATE_TIME);
    if let TtlvValue::DateTime(v) = decoded.value {
        assert_eq!(v, ts);
    } else {
        panic!("Expected DateTime");
    }
}

// ── Padding ──────────────────────────────────────────────────────────

#[test]
fn integer_total_length_is_16() {
    // Integer: 4 bytes value, padded to 8 -> 8 header + 8 value = 16
    let encoded = encode_integer(0x42006A, 1);
    assert_eq!(encoded.len(), 16);
}

#[test]
fn enum_total_length_is_16() {
    let encoded = encode_enum(0x42005C, 1);
    assert_eq!(encoded.len(), 16);
}

#[test]
fn boolean_total_length_is_16() {
    // Boolean uses 8-byte value (i64) -> 8 header + 8 value = 16
    let encoded = encode_boolean(0x420008, true);
    assert_eq!(encoded.len(), 16);
}

#[test]
fn long_integer_total_length_is_16() {
    let encoded = encode_long_integer(0x420094, 42);
    assert_eq!(encoded.len(), 16);
}

#[test]
fn text_string_5_bytes_padded_to_16() {
    // "hello" = 5 bytes -> pad to 8 -> 8 header + 8 = 16
    let encoded = encode_text_string(0x420055, "hello");
    assert_eq!(encoded.len(), 16);
}

#[test]
fn text_string_9_bytes_padded_to_24() {
    // "123456789" = 9 bytes -> pad to 16 -> 8 header + 16 = 24
    let encoded = encode_text_string(0x420055, "123456789");
    assert_eq!(encoded.len(), 24);
}

#[test]
fn empty_text_string_total_length_is_8() {
    // Empty string: 0 bytes value, padded to 0 -> 8 header + 0 = 8
    let encoded = encode_text_string(0x420055, "");
    assert_eq!(encoded.len(), 8);
}

#[test]
fn byte_string_3_bytes_padded_to_16() {
    let encoded = encode_byte_string(0x420043, &[1, 2, 3]);
    assert_eq!(encoded.len(), 16);
}

#[test]
fn padding_bytes_are_zero() {
    // "hi" = 2 bytes -> padded to 8; bytes [10..16) should be 0
    let encoded = encode_text_string(0x420055, "hi");
    assert_eq!(encoded.len(), 16);
    for &b in &encoded[10..16] {
        assert_eq!(b, 0, "Padding byte should be zero");
    }
}

// ── Structures ───────────────────────────────────────────────────────

#[test]
fn encode_decode_empty_structure() {
    let encoded = encode_structure(0x420069, &[]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420069);
    assert_eq!(decoded.item_type, item_type::STRUCTURE);
    if let TtlvValue::Structure(ref children) = decoded.value {
        assert_eq!(children.len(), 0);
    } else {
        panic!("Expected Structure");
    }
}

#[test]
fn encode_decode_structure_with_children() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 1),
        encode_integer(0x42006B, 4),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420069);
    assert_eq!(decoded.item_type, item_type::STRUCTURE);
    if let TtlvValue::Structure(ref children) = decoded.value {
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].value.as_integer(), Some(1));
        assert_eq!(children[1].value.as_integer(), Some(4));
    } else {
        panic!("Expected Structure");
    }
}

#[test]
fn encode_decode_structure_mixed_types() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 1),
        encode_text_string(0x420055, "test"),
        encode_boolean(0x420008, true),
        encode_enum(0x42005C, 3),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    if let TtlvValue::Structure(ref children) = decoded.value {
        assert_eq!(children.len(), 4);
        assert_eq!(children[0].value.as_integer(), Some(1));
        assert_eq!(children[1].value.as_text(), Some("test"));
        assert_eq!(children[2].value.as_bool(), Some(true));
        assert_eq!(children[3].value.as_enum(), Some(3));
    } else {
        panic!("Expected Structure");
    }
}

#[test]
fn encode_decode_structure_three_levels_deep() {
    let encoded = encode_structure(0x420078, &[
        encode_structure(0x420077, &[
            encode_structure(0x420069, &[
                encode_integer(0x42006A, 1),
                encode_integer(0x42006B, 4),
            ]),
            encode_integer(0x42000D, 1),
        ]),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420078);
    let header = find_child(&decoded, 0x420077).unwrap();
    let version = find_child(header, 0x420069).unwrap();
    let major = find_child(version, 0x42006A).unwrap();
    assert_eq!(major.value.as_integer(), Some(1));
    let minor = find_child(version, 0x42006B).unwrap();
    assert_eq!(minor.value.as_integer(), Some(4));
    let batch = find_child(header, 0x42000D).unwrap();
    assert_eq!(batch.value.as_integer(), Some(1));
}

// ── find_child ───────────────────────────────────────────────────────

#[test]
fn find_child_found() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 1),
        encode_integer(0x42006B, 4),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    let child = find_child(&decoded, 0x42006B).unwrap();
    assert_eq!(child.value.as_integer(), Some(4));
}

#[test]
fn find_child_not_found() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 1),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert!(find_child(&decoded, 0x42FFFF).is_none());
}

#[test]
fn find_child_on_non_structure_returns_none() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    assert!(find_child(&decoded, 0x42006A).is_none());
}

#[test]
fn find_child_returns_first_match() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 100),
        encode_integer(0x42006A, 200),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    let child = find_child(&decoded, 0x42006A).unwrap();
    assert_eq!(child.value.as_integer(), Some(100));
}

// ── find_children ────────────────────────────────────────────────────

#[test]
fn find_children_multiple_matches() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 10),
        encode_integer(0x42006B, 20),
        encode_integer(0x42006A, 30),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    let matches = find_children(&decoded, 0x42006A);
    assert_eq!(matches.len(), 2);
    assert_eq!(matches[0].value.as_integer(), Some(10));
    assert_eq!(matches[1].value.as_integer(), Some(30));
}

#[test]
fn find_children_no_matches() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 1),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    let matches = find_children(&decoded, 0x42FFFF);
    assert_eq!(matches.len(), 0);
}

#[test]
fn find_children_on_non_structure_returns_empty() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    let matches = find_children(&decoded, 0x42006A);
    assert_eq!(matches.len(), 0);
}

// ── Wire format ──────────────────────────────────────────────────────

#[test]
fn wire_format_tag_bytes_big_endian() {
    let encoded = encode_integer(0x42006A, 1);
    assert_eq!(encoded[0], 0x42);
    assert_eq!(encoded[1], 0x00);
    assert_eq!(encoded[2], 0x6A);
}

#[test]
fn wire_format_type_byte_integer() {
    let encoded = encode_integer(0x42006A, 1);
    assert_eq!(encoded[3], item_type::INTEGER);
}

#[test]
fn wire_format_type_byte_enum() {
    let encoded = encode_enum(0x42005C, 1);
    assert_eq!(encoded[3], item_type::ENUMERATION);
}

#[test]
fn wire_format_type_byte_text_string() {
    let encoded = encode_text_string(0x420055, "x");
    assert_eq!(encoded[3], item_type::TEXT_STRING);
}

#[test]
fn wire_format_type_byte_structure() {
    let encoded = encode_structure(0x420069, &[]);
    assert_eq!(encoded[3], item_type::STRUCTURE);
}

#[test]
fn wire_format_length_field_integer() {
    // Integer value is 4 bytes
    let encoded = encode_integer(0x42006A, 1);
    let length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    assert_eq!(length, 4);
}

#[test]
fn wire_format_length_field_long_integer() {
    let encoded = encode_long_integer(0x420094, 1);
    let length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    assert_eq!(length, 8);
}

#[test]
fn wire_format_length_field_boolean() {
    let encoded = encode_boolean(0x420008, true);
    let length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    assert_eq!(length, 8);
}

#[test]
fn wire_format_length_field_text_string() {
    let encoded = encode_text_string(0x420055, "abc");
    let length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    assert_eq!(length, 3); // actual length, not padded
}

#[test]
fn wire_format_length_field_structure() {
    // Structure with one integer child (16 bytes)
    let encoded = encode_structure(0x420069, &[encode_integer(0x42006A, 1)]);
    let length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    assert_eq!(length, 16);
}

// ── Error handling ───────────────────────────────────────────────────

#[test]
fn decode_empty_buffer_returns_error() {
    let result = decode_ttlv(&[], 0);
    assert!(result.is_err());
}

#[test]
fn decode_buffer_too_short_returns_error() {
    let result = decode_ttlv(&[0x42, 0x00, 0x6A, 0x02], 0);
    assert!(result.is_err());
}

#[test]
fn decode_buffer_exactly_7_bytes_returns_error() {
    let result = decode_ttlv(&[0x42, 0x00, 0x6A, 0x02, 0x00, 0x00, 0x00], 0);
    assert!(result.is_err());
}

// ── TtlvValue accessor methods ──────────────────────────────────────

#[test]
fn as_integer_on_non_integer_returns_none() {
    let decoded = decode_ttlv(&encode_text_string(0x420055, "x"), 0).unwrap();
    assert_eq!(decoded.value.as_integer(), None);
}

#[test]
fn as_enum_on_non_enum_returns_none() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    assert_eq!(decoded.value.as_enum(), None);
}

#[test]
fn as_text_on_non_text_returns_none() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    assert_eq!(decoded.value.as_text(), None);
}

#[test]
fn as_bytes_on_non_bytes_returns_none() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    assert_eq!(decoded.value.as_bytes(), None);
}

#[test]
fn as_bool_on_non_bool_returns_none() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    assert_eq!(decoded.value.as_bool(), None);
}

// ── Decode with offset ──────────────────────────────────────────────

#[test]
fn decode_with_nonzero_offset() {
    let item1 = encode_integer(0x42006A, 10);
    let item2 = encode_integer(0x42006B, 20);
    let mut buf = item1.clone();
    buf.extend_from_slice(&item2);

    let decoded = decode_ttlv(&buf, 16).unwrap();
    assert_eq!(decoded.tag, 0x42006B);
    assert_eq!(decoded.value.as_integer(), Some(20));
}

// ── decoded total_length and length fields ──────────────────────────

#[test]
fn decoded_integer_has_correct_lengths() {
    let decoded = decode_ttlv(&encode_integer(0x42006A, 1), 0).unwrap();
    assert_eq!(decoded.length, 4);
    assert_eq!(decoded.total_length, 16);
}

#[test]
fn decoded_text_string_has_correct_length() {
    let decoded = decode_ttlv(&encode_text_string(0x420055, "hello"), 0).unwrap();
    assert_eq!(decoded.length, 5);
    assert_eq!(decoded.total_length, 16);
}

#[test]
fn decoded_structure_has_correct_length() {
    let inner = encode_integer(0x42006A, 1);
    let encoded = encode_structure(0x420069, &[inner]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.length, 16);
    assert_eq!(decoded.total_length, 24);
}

// ── Security hardening tests ────────────────────────────────────────

#[test]
fn rejects_declared_length_exceeding_buffer() {
    // Header claiming 1000 bytes of value, but only 10 bytes provided
    let mut buf = vec![0u8; 18]; // 8 header + 10 body
    buf[0] = 0x42; buf[1] = 0x00; buf[2] = 0x01; // tag = 0x420001
    buf[3] = 0x07; // type = TextString
    buf[4..8].copy_from_slice(&1000u32.to_be_bytes()); // length = 1000
    let result = decode_ttlv(&buf, 0);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("exceeds buffer"), "Expected 'exceeds buffer' in: {}", err_msg);
}

#[test]
fn accepts_declared_length_that_exactly_fits() {
    let encoded = encode_integer(0x420001, 42);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.value.as_integer(), Some(42));
}

#[test]
fn rejects_zero_length_buffer() {
    let result = decode_ttlv(&[], 0);
    assert!(result.is_err());
}

#[test]
fn rejects_structures_nested_deeper_than_32_levels() {
    // Build 33 levels of nesting
    let mut inner = encode_integer(0x420001, 42);
    for _ in 0..33 {
        inner = encode_structure(0x420001, &[inner]);
    }
    let result = decode_ttlv(&inner, 0);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("depth"), "Expected 'depth' in: {}", err_msg);
}

#[test]
fn accepts_structures_nested_exactly_32_levels() {
    // Build 31 wrapping levels (root is depth 0, innermost is depth 31)
    let mut inner = encode_integer(0x420001, 42);
    for _ in 0..31 {
        inner = encode_structure(0x420001, &[inner]);
    }
    let decoded = decode_ttlv(&inner, 0).unwrap();
    assert_eq!(decoded.item_type, item_type::STRUCTURE);
}

#[test]
fn rejects_truncated_header() {
    let buf = vec![0x42, 0x00, 0x01, 0x02];
    let result = decode_ttlv(&buf, 0);
    assert!(result.is_err());
}

#[test]
fn handles_integer_with_wrong_length_safely() {
    // Header: tag=0x420001, type=Integer(0x02), length=3 (should be 4)
    let mut buf = vec![0u8; 16];
    buf[0] = 0x42; buf[1] = 0x00; buf[2] = 0x01;
    buf[3] = 0x02; // type = Integer
    buf[4..8].copy_from_slice(&3u32.to_be_bytes()); // length = 3 (invalid)
    // Should either return Err or handle safely — must not panic
    let _ = decode_ttlv(&buf, 0);
}
