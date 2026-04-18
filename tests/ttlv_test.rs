use cyphera_kmip::ttlv::*;

#[test]
fn encode_decode_integer() {
    let encoded = encode_integer(0x42006A, 1);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x42006A);
    assert_eq!(decoded.item_type, item_type::INTEGER);
    assert_eq!(decoded.value.as_integer(), Some(1));
}

#[test]
fn encode_decode_enumeration() {
    let encoded = encode_enum(0x42005C, 0x0000000A);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x42005C);
    assert_eq!(decoded.item_type, item_type::ENUMERATION);
    assert_eq!(decoded.value.as_enum(), Some(0x0000000A));
}

#[test]
fn encode_decode_text_string() {
    let encoded = encode_text_string(0x420055, "my-key");
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.tag, 0x420055);
    assert_eq!(decoded.item_type, item_type::TEXT_STRING);
    assert_eq!(decoded.value.as_text(), Some("my-key"));
}

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
fn encode_decode_boolean() {
    let encoded = encode_boolean(0x420008, true);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.item_type, item_type::BOOLEAN);
    assert_eq!(decoded.value.as_bool(), Some(true));
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
        panic!("Expected Structure value");
    }
}

#[test]
fn find_child_locates_by_tag() {
    let encoded = encode_structure(0x420069, &[
        encode_integer(0x42006A, 1),
        encode_integer(0x42006B, 4),
    ]);
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    let child = find_child(&decoded, 0x42006B).unwrap();
    assert_eq!(child.value.as_integer(), Some(4));
}

#[test]
fn text_string_padded_to_8_byte_alignment() {
    // "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
    let encoded = encode_text_string(0x420055, "hello");
    assert_eq!(encoded.len(), 16); // 8 header + 8 padded value
}

#[test]
fn empty_text_string() {
    let encoded = encode_text_string(0x420055, "");
    let decoded = decode_ttlv(&encoded, 0).unwrap();
    assert_eq!(decoded.value.as_text(), Some(""));
}

#[test]
fn round_trip_nested_structures() {
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
}
