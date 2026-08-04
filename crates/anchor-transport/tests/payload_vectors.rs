//! Section A — exact known-answer vectors and the full rejection matrix for the
//! canonical anchor log payload.

use tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_LOG_PAYLOAD_PREFIX_V1, AnchorLogPayloadError, AnchorLogPayloadV1,
};

/// The exact 39-byte prefix-plus-colon marker used to build test strings.
fn marker() -> String {
    format!("{ANCHOR_LOG_PAYLOAD_PREFIX_V1}:")
}

#[test]
fn prefix_is_the_frozen_type_identifier() {
    assert_eq!(
        ANCHOR_LOG_PAYLOAD_PREFIX_V1,
        "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1"
    );
    assert_eq!(AnchorLogPayloadV1::exact_encoded_len(), 103);
    assert_eq!(AnchorLogPayloadV1::max_encoded_len(), 103);
}

#[test]
fn known_answer_repeated_byte_digest() {
    let payload = AnchorLogPayloadV1::from_digest(OotleAnchorRecordHashV1::new([0x22; 32]));

    let expected = format!("{}{}", marker(), "22".repeat(32));

    assert_eq!(payload.to_encoded_string(), expected);
    assert_eq!(payload.to_string(), expected);
    assert_eq!(expected.len(), 103);
}

#[test]
fn known_answer_sequential_digest() {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap_or(0);
    }

    let payload = AnchorLogPayloadV1::from_digest(OotleAnchorRecordHashV1::new(bytes));

    let expected = format!(
        "{}000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        marker()
    );

    assert_eq!(payload.to_encoded_string(), expected);
}

#[test]
fn round_trip_recovers_exact_digest() {
    let payload = AnchorLogPayloadV1::from_digest(OotleAnchorRecordHashV1::new([0xab; 32]));
    let encoded = payload.to_encoded_string();

    let Ok(parsed) = AnchorLogPayloadV1::parse(&encoded) else {
        panic!("canonical payload must parse");
    };

    assert_eq!(parsed, payload);
    assert_eq!(parsed.digest(), OotleAnchorRecordHashV1::new([0xab; 32]));
}

#[test]
fn parses_from_str_and_owned_string() {
    let encoded = format!("{}{}", marker(), "0a".repeat(32));

    let parsed_from_ref = AnchorLogPayloadV1::parse(encoded.as_str());
    let parsed_from_fromstr = encoded.parse::<AnchorLogPayloadV1>();
    let parsed_from_owned = AnchorLogPayloadV1::parse(&String::from(encoded.as_str()));

    assert!(parsed_from_ref.is_ok());
    assert_eq!(parsed_from_ref, parsed_from_fromstr);
    assert_eq!(parsed_from_ref, parsed_from_owned);
}

#[test]
fn rejects_empty_input() {
    assert_eq!(
        AnchorLogPayloadV1::parse(""),
        Err(AnchorLogPayloadError::Empty)
    );
}

#[test]
fn rejects_wrong_prefix() {
    let value = format!("WRONG_PREFIX:{}", "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::WrongPrefix)
    );
}

#[test]
fn rejects_alternate_version_prefix() {
    let value = format!("TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2:{}", "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::WrongPrefix)
    );
}

#[test]
fn rejects_missing_colon() {
    let value = format!("{ANCHOR_LOG_PAYLOAD_PREFIX_V1}{}", "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::MissingSeparator)
    );
}

#[test]
fn rejects_extra_colon() {
    let value = format!("{}:{}", marker(), "22".repeat(32).get(1..).unwrap_or(""));

    // The hex region now begins with a colon, which is not a lowercase hex digit.
    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::NonLowercaseHexDigit)
    );
}

#[test]
fn rejects_uppercase_hex() {
    let value = format!("{}{}", marker(), "AA".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::NonLowercaseHexDigit)
    );
}

#[test]
fn rejects_odd_hex_length() {
    let value = format!("{}{}", marker(), "2".repeat(63));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::DigestLength)
    );
}

#[test]
fn rejects_short_and_long_digests() {
    let short = format!("{}{}", marker(), "22".repeat(31));
    let long = format!("{}{}", marker(), "22".repeat(33));

    assert_eq!(
        AnchorLogPayloadV1::parse(&short),
        Err(AnchorLogPayloadError::DigestLength)
    );
    assert_eq!(
        AnchorLogPayloadV1::parse(&long),
        Err(AnchorLogPayloadError::DigestLength)
    );
}

#[test]
fn rejects_non_hex_characters() {
    let value = format!("{}{}", marker(), "zz".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::NonLowercaseHexDigit)
    );
}

#[test]
fn rejects_leading_whitespace() {
    let value = format!(" {}{}", marker(), "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::WrongPrefix)
    );
}

#[test]
fn rejects_trailing_whitespace() {
    let value = format!("{}{} ", marker(), "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::DigestLength)
    );
}

#[test]
fn rejects_embedded_newline() {
    let mut hex = "22".repeat(32);
    hex.replace_range(10..11, "\n");
    let value = format!("{}{hex}", marker());

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::NonLowercaseHexDigit)
    );
}

#[test]
fn rejects_embedded_nul_byte() {
    let mut hex = "22".repeat(32);
    hex.replace_range(0..1, "\0");
    let value = format!("{}{hex}", marker());

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::NonLowercaseHexDigit)
    );
}

#[test]
fn rejects_appended_text_after_valid_payload() {
    let value = format!("{}{}APPENDED", marker(), "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::DigestLength)
    );
}

#[test]
fn rejects_valid_prefix_with_trailing_garbage() {
    let value = format!("{}{}xy", marker(), "22".repeat(32));

    assert_eq!(
        AnchorLogPayloadV1::parse(&value),
        Err(AnchorLogPayloadError::DigestLength)
    );
}
