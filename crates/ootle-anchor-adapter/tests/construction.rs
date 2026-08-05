//! Sections C/D/E/H and Section M(1,4,5,6,7,11,12,14) — anchor log construction,
//! unsigned transaction construction, and inspection evidence.

mod common;

use common::{build_request, payload, valid_request};
use tari_cc_private_ballot_anchor_transport::AnchorLogPayloadV1;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    ANCHOR_EMIT_LOG_LEVEL, AnchorTransactionConstructor, OotleAnchorBuildResultV1,
    PinnedOotleAnchorTransactionConstructor, build_anchor_emit_log,
    build_unsigned_anchor_transaction,
};
use tari_ootle_transaction::{Instruction, UnsignedTransaction};
use tari_template_lib_types::LogLevel;

/// Extracts the message of the single EmitLog instruction, asserting shape.
fn sole_emit_log_message(unsigned: &UnsignedTransaction) -> String {
    match unsigned.instructions() {
        [Instruction::EmitLog { level, message }] => {
            assert_eq!(*level, LogLevel::Info, "anchor log level must be Info");
            let text: &str = message.as_ref();
            text.to_owned()
        }
        other => panic!(
            "expected exactly one EmitLog, got {} instructions",
            other.len()
        ),
    }
}

fn build(request_digest: u8) -> OotleAnchorBuildResultV1 {
    match build_unsigned_anchor_transaction(&build_request(
        "esmeralda",
        "fee-account",
        request_digest,
        1_000,
        None,
    )) {
        Ok(result) => result,
        Err(error) => panic!("construction must succeed, got {error:?}"),
    }
}

#[test]
fn anchor_emit_log_message_is_byte_for_byte_the_payload_and_103_bytes() {
    // Section C: level Info, exact payload bytes, exactly 103 bytes.
    let payload = payload(0x5a);
    let expected = payload.to_encoded_string();
    assert_eq!(expected.len(), 103);
    assert_eq!(AnchorLogPayloadV1::exact_encoded_len(), 103);

    let Ok(Instruction::EmitLog { level, message }) = build_anchor_emit_log(&payload) else {
        panic!("emit log construction must succeed and be an EmitLog");
    };

    assert_eq!(level, ANCHOR_EMIT_LOG_LEVEL);
    assert_eq!(level, LogLevel::Info);

    let message_text: &str = message.as_ref();
    // Byte-for-byte equality with the canonical payload string.
    assert_eq!(message_text.as_bytes(), expected.as_bytes());
    assert_eq!(message_text.len(), 103);
}

#[test]
fn construction_yields_exactly_one_anchor_instruction_at_index_zero() {
    let result = build(0x22);
    let unsigned = result.unsigned_transaction();

    // Exactly one instruction, the anchor EmitLog, no duplicates.
    assert_eq!(unsigned.instructions().len(), 1);
    let message = sole_emit_log_message(unsigned);
    assert_eq!(
        message.as_bytes(),
        payload(0x22).to_encoded_string().as_bytes()
    );

    let evidence = result.evidence();
    assert_eq!(evidence.instruction_count(), 1);
    assert_eq!(evidence.anchor_instruction_index(), 0);
}

#[test]
fn constructed_transaction_has_no_fees_inputs_or_blobs() {
    // Sections D/E and Section M(18): walletd-injected-fee architecture.
    let result = build(0x22);
    let unsigned = result.unsigned_transaction();

    assert!(
        unsigned.fee_instructions().is_empty(),
        "no fee instructions"
    );
    assert!(unsigned.inputs().is_empty(), "no inputs");
    assert!(unsigned.blobs().is_empty(), "no blobs");

    let evidence = result.evidence();
    assert!(!evidence.fee_instructions_present());
    assert_eq!(evidence.input_count(), 0);
    assert_eq!(evidence.blob_count(), 0);
}

#[test]
fn evidence_reports_bound_network_digest_payload_and_schema() {
    // Section E and Section M(11): schema/version and bound context.
    let result = build(0x22);
    let evidence = result.evidence();

    assert_eq!(evidence.network().as_str(), "esmeralda");
    assert_eq!(evidence.ootle_network_byte(), 0x26); // Network::Esmeralda
    assert_eq!(evidence.account().as_str(), "fee-account");
    assert_eq!(evidence.anchor_digest(), common::digest(0x22));
    assert_eq!(
        evidence.anchor_log_payload().to_encoded_string(),
        payload(0x22).to_encoded_string()
    );
    assert_eq!(evidence.unsigned_schema_version(), 1);
    assert_eq!(
        evidence.unsigned_schema_version(),
        result.unsigned_transaction().schema_version()
    );
}

#[test]
fn walletd_preparation_preserves_fee_account_and_max_fee() {
    // Section D: the offline walletd preparation DTO carries the explicit fee
    // account and maximum fee for later walletd injection.
    let request = build_request("esmeralda", "treasury", 0x33, 7_777, Some("client-1"));
    let Ok(result) = build_unsigned_anchor_transaction(&request) else {
        panic!("construction must succeed");
    };
    let preparation = result.walletd_preparation();

    assert_eq!(preparation.network().as_str(), "esmeralda");
    assert_eq!(preparation.fee_account().as_str(), "treasury");
    assert_eq!(preparation.max_fee().value(), 7_777);
    assert_eq!(preparation.anchor_digest(), common::digest(0x33));
    match preparation.client_reference() {
        Some(reference) => assert_eq!(reference.as_str(), "client-1"),
        None => panic!("client reference must be preserved"),
    }
}

#[test]
fn repeated_construction_is_deterministic() {
    // Section M(14): identical requests yield identical fingerprints and evidence.
    let first = build(0x44);
    let second = build(0x44);

    assert_eq!(
        first.evidence().fingerprint().as_bytes(),
        second.evidence().fingerprint().as_bytes()
    );
    assert_eq!(first.evidence(), second.evidence());

    // A different digest yields a different fingerprint.
    let other = build(0x45);
    assert_ne!(
        first.evidence().fingerprint().as_bytes(),
        other.evidence().fingerprint().as_bytes()
    );
}

#[test]
fn constructor_trait_matches_the_free_function() {
    // Section H: the trait implementation is the free construction function.
    let request = valid_request();
    let constructor = PinnedOotleAnchorTransactionConstructor;

    let Ok(via_trait) = constructor.construct(&request) else {
        panic!("trait construction must succeed");
    };
    let Ok(via_function) = build_unsigned_anchor_transaction(&request) else {
        panic!("function construction must succeed");
    };

    assert_eq!(via_trait.evidence(), via_function.evidence());
}
