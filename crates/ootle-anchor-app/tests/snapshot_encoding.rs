//! Snapshot canonical encoding and durable round-trip tests (Slice 4A10
//! §16.1).

// The rejection tests below hand-build malformed CBOR byte sequences and
// deliberately ignore the canonical writer's `Result`. This is the only
// place a writer `Result` is intentionally dropped: it mirrors the existing
// Slice 4A6/4A7 rejection-test convention.
#![allow(unused_must_use)]

mod common;

use tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    SNAPSHOT_HASH_ALGORITHM_ID_V1, SNAPSHOT_RECORD_TYPE_ID_V1, SnapshotFileError, read_snapshot,
    snapshot_digest, write_snapshot_atomic,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleRecoverySnapshot, PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryStateV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdEffectiveStatusV1, WalletdRequestDecisionV1, WalletdSubmissionStateV1,
};
use tari_cc_private_ballot_protocol::CanonicalCborWriter;

use common::*;

fn snap_roundtrip(snapshot: &AnchorLifecycleRecoverySnapshot) -> AnchorLifecycleRecoverySnapshot {
    let path = tmp_path("roundtrip").join(format!("{}.cbor", snapshot.phase().as_str()));
    match write_snapshot_atomic(&path, snapshot) {
        Ok(()) => match read_snapshot(&path) {
            Ok(decoded) => decoded,
            Err(error) => panic!("read failed: {error}"),
        },
        Err(error) => panic!("write failed: {error}"),
    }
}

fn assert_roundtrip_eq(snapshot: AnchorLifecycleRecoverySnapshot) {
    let decoded = snap_roundtrip(&snapshot);
    assert_eq!(decoded, snapshot, "snapshot must round-trip identically");
}

#[test]
fn round_trip_not_prepared() {
    assert_roundtrip_eq(empty_snapshot());
}

#[test]
fn round_trip_prepared() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Prepared,
        WalletdSubmissionStateV1::NotSubmitted,
        None,
        None,
        0,
        1,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Prepared,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_approved() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::NotSubmitted,
        None,
        None,
        0,
        1,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Approved,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_rejected_by_approver() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Rejected,
        WalletdSubmissionStateV1::NotSubmitted,
        None,
        None,
        0,
        1,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::RejectedByApprover,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_submitted() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::SubmittedNotQueried,
        None,
        false,
        1,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_polling_in_progress() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(AnchorReceiptQueryStateV1::ReceiptPending, None, false, 1);
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 1),
        UnifiedAnchorLifecyclePhase::PollingInProgress,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_poll_exhausted_unknown() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(AnchorReceiptQueryStateV1::ReceiptUnknown, None, false, 8);
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 8),
        UnifiedAnchorLifecyclePhase::Unknown,
        Some("POLL_EXHAUSTED"),
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_finalized_accept() {
    assert_roundtrip_eq(known_answer_snapshot());
}

#[test]
fn round_trip_finalized_fee_only() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly,
        Some(AnchorFinalStatusV1::FeeOnlyAccepted),
        false,
        3,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 3),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_finalized_reject() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptFinalizedReject,
        Some(AnchorFinalStatusV1::Rejected),
        false,
        2,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 2),
        UnifiedAnchorLifecyclePhase::FinalizedReject,
        None,
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_finalized_verification_failed() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptVerificationFailed,
        Some(AnchorFinalStatusV1::Rejected),
        false,
        4,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 4),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed,
        Some("ANCHOR_RECEIPT_MISSING_ANCHOR_LOG"),
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn round_trip_finalized_disagreement() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
        Some(AnchorFinalStatusV1::Accepted),
        true,
        2,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 2),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement,
        Some("RECEIPT_AGREEMENT_WRONG_INDEXER_SOURCE"),
    );
    assert_roundtrip_eq(snapshot);
}

#[test]
fn deterministic_encoding() {
    let bytes_a = snapshot_bytes(&known_answer_snapshot());
    let bytes_b = snapshot_bytes(&known_answer_snapshot());
    assert_eq!(bytes_a, bytes_b, "encoding must be deterministic");
}

#[test]
fn field_sensitivity() {
    let bytes_a = snapshot_bytes(&known_answer_snapshot());
    let modified = known_answer_snapshot();
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        1,
        1,
    );
    let receipt = receipt_snapshot(
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
        Some(AnchorFinalStatusV1::Accepted),
        true,
        1,
    );
    let _ = modified; // silence
    let modified = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        vec![receipt],
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    );
    let bytes_b = snapshot_bytes(&modified);
    assert_ne!(bytes_a, bytes_b, "retry-count change must alter encoding");
}

#[test]
fn known_answer_vector() {
    let snapshot = known_answer_snapshot();
    let bytes = snapshot_bytes(&snapshot);
    let digest = match snapshot_digest(&snapshot) {
        Ok(d) => d,
        Err(error) => panic!("digest failed: {error}"),
    };
    // Determinism: the canonical bytes and digest must be reproducible.
    let bytes_again = snapshot_bytes(&snapshot);
    assert_eq!(bytes, bytes_again);
    let digest_again = match snapshot_digest(&snapshot) {
        Ok(d) => d,
        Err(error) => panic!("digest failed: {error}"),
    };
    assert_eq!(digest, digest_again);
    // Pin the exact 32-byte digest (BLAKE3, domain-separated). If any encoded
    // field changes, this assertion fails — that is the known-answer contract.
    let pinned: [u8; 32] = [
        212, 169, 209, 119, 66, 196, 124, 113, 205, 8, 132, 141, 65, 252, 111, 163, 63, 146, 93,
        170, 214, 32, 13, 8, 127, 19, 64, 103, 16, 216, 98, 117,
    ];
    assert_eq!(
        digest, pinned,
        "snapshot digest must match the pinned known-answer vector"
    );
}

#[test]
fn atomic_write_safety() {
    let path = tmp_path("atomic").join("live.cbor");
    let snapshot = known_answer_snapshot();
    match write_snapshot_atomic(&path, &snapshot) {
        Ok(()) => {}
        Err(error) => panic!("first write failed: {error}"),
    }
    let first_bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("first read failed: {error}"),
    };
    // A second write to the same path must replace the file atomically.
    match write_snapshot_atomic(&path, &snapshot) {
        Ok(()) => {}
        Err(error) => panic!("second write failed: {error}"),
    }
    let second_bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("second read failed: {error}"),
    };
    assert_eq!(first_bytes, second_bytes);
    // The deterministic temp path must not linger after a successful rename.
    let tmp = path.with_extension("cbor.tmp");
    assert!(!tmp.exists(), "temp file must not linger after rename");
}

#[test]
fn shape_contains_no_secret_fields() {
    let bytes = snapshot_bytes(&known_answer_snapshot());
    let text = String::from_utf8_lossy(&bytes);
    // The project domain labels legitimately contain the word "ballot"
    // (e.g. "tari-cc-private-ballot/..."), so this scan targets only
    // unmistakably-secret tokens that must never appear in a snapshot.
    for secret in [
        "private_key",
        "mnemonic",
        "seed_phrase",
        "auth_secret",
        "jwt ",
        "nullifier",
        "voter_identity",
        "organizer_identity",
        "seal_signer_secret",
        "registry_key",
    ] {
        assert!(
            !text.to_ascii_lowercase().contains(secret),
            "snapshot must not contain '{secret}'"
        );
    }
}

#[test]
fn reject_wrong_record_type() {
    let body = valid_empty_body();
    let envelope = craft_envelope_raw(
        "BOGUS_RECORD_TYPE",
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &compute_snapshot_digest(&body),
        &body,
    );
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::UnsupportedProtocolVersion) => {}
        other => panic!("expected UnsupportedProtocolVersion, got {other:?}"),
    }
}

#[test]
fn reject_wrong_hash_algorithm() {
    let body = valid_empty_body();
    let envelope = craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        "BOGUS_HASH_ALGORITHM",
        &compute_snapshot_digest(&body),
        &body,
    );
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::UnsupportedHashAlgorithm) => {}
        other => panic!("expected UnsupportedHashAlgorithm, got {other:?}"),
    }
}

#[test]
fn reject_trailing_bytes() {
    let body = valid_empty_body();
    let mut envelope = craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &compute_snapshot_digest(&body),
        &body,
    );
    envelope.push(0xff);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::TrailingCborData) => {}
        other => panic!("expected TrailingCborData, got {other:?}"),
    }
}

#[test]
fn reject_truncation() {
    let body = valid_empty_body();
    let mut envelope = craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &compute_snapshot_digest(&body),
        &body,
    );
    envelope.pop();
    match read_snapshot_raw(&envelope) {
        Err(_) => {}
        Ok(snapshot) => panic!("truncated bytes must not decode, got {snapshot:?}"),
    }
}

#[test]
fn reject_digest_mismatch() {
    let body = valid_empty_body();
    let envelope = craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &[0u8; 32],
        &body,
    );
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::SnapshotDigestMismatch) => {}
        other => panic!("expected SnapshotDigestMismatch, got {other:?}"),
    }
}

#[test]
fn reject_oversized_body() {
    let big = vec![0u8; 70_000];
    let envelope = craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &compute_snapshot_digest(&big),
        &big,
    );
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::ProtocolLimitExceeded) => {}
        other => panic!("expected ProtocolLimitExceeded, got {other:?}"),
    }
}

fn valid_empty_body() -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(6);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(2);
    writer.write_unsigned(8);
    writer.write_unsigned(0);
    let _ = writer.write_text_string("NOT_PREPARED");
    writer.write_array_len(0);
    writer.into_bytes()
}

#[test]
fn reject_unknown_phase() {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(6);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(2);
    writer.write_unsigned(8);
    writer.write_unsigned(0);
    let _ = writer.write_text_string("BOGUS_PHASE");
    writer.write_array_len(0);
    let body = writer.into_bytes();
    let envelope = craft_snapshot_envelope(&body);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::InvalidData) => {}
        other => panic!("expected InvalidData for unknown phase, got {other:?}"),
    }
}

#[test]
fn reject_unknown_decision() {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(6);
    writer.write_array_len(1);
    // walletd snapshot (10 fields) with a bogus decision
    writer.write_array_len(10);
    let _ = writer.write_text_string("anchor-request-001");
    writer.write_unsigned(1);
    // binding (6 fields): network, account, anchor_digest, payload, max_fee, fingerprint
    writer.write_array_len(6);
    let _ = writer.write_text_string("esmeralda");
    let _ = writer.write_text_string("fee-account");
    let _ = writer.write_byte_string(&[0x33; 32]);
    let _ = writer.write_text_string("TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    writer.write_unsigned(1000);
    let _ = writer.write_byte_string(&[0x55; 32]);
    let _ = writer.write_text_string("BOGUS_DECISION");
    let _ = writer.write_text_string("NOT_SUBMITTED");
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_unsigned(0);
    writer.write_unsigned(1);
    writer.write_array_len(0);
    // receipts
    writer.write_array_len(0);
    // submitted (None)
    writer.write_array_len(0);
    // policy
    writer.write_array_len(2);
    writer.write_unsigned(8);
    writer.write_unsigned(0);
    // phase
    let _ = writer.write_text_string("PREPARED");
    // diagnostic
    writer.write_array_len(0);
    let body = writer.into_bytes();
    let envelope = craft_snapshot_envelope(&body);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::InvalidData) => {}
        other => panic!("expected InvalidData for unknown decision, got {other:?}"),
    }
}

#[test]
fn reject_unknown_query_state() {
    // A receipt snapshot requires a submitted handle; build the body with a
    // submitted handle and a receipt whose query-state is bogus.
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(6);
    // walletd snapshots (empty)
    writer.write_array_len(0);
    // receipt snapshots (1)
    writer.write_array_len(1);
    // receipt snapshot (6 fields): query(8), state, final_status, verified, seq, diag
    writer.write_array_len(6);
    // query (8 fields)
    writer.write_array_len(8);
    let _ = writer.write_text_string("anchor-request-001");
    writer.write_unsigned(1);
    let _ = writer.write_text_string(&common::lower_hex_32(TX_BYTE));
    let _ = writer.write_text_string("esmeralda");
    let _ = writer.write_text_string("fee-account");
    let _ = writer.write_byte_string(&[0x33; 32]);
    let _ = writer.write_text_string("TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let _ = writer.write_byte_string(&[0x55; 32]);
    let _ = writer.write_text_string("BOGUS_QUERY_STATE");
    writer.write_array_len(0);
    writer.write_bool(false);
    writer.write_unsigned(1);
    writer.write_array_len(0);
    // submitted handle (Some, 4 fields)
    writer.write_array_len(1);
    writer.write_array_len(4);
    let _ = writer.write_text_string("anchor-request-001");
    writer.write_unsigned(1);
    let _ = writer.write_text_string(&common::lower_hex_32(TX_BYTE));
    // binding (6 fields)
    writer.write_array_len(6);
    let _ = writer.write_text_string("esmeralda");
    let _ = writer.write_text_string("fee-account");
    let _ = writer.write_byte_string(&[0x33; 32]);
    let _ = writer.write_text_string("TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    writer.write_unsigned(1000);
    let _ = writer.write_byte_string(&[0x55; 32]);
    // policy
    writer.write_array_len(2);
    writer.write_unsigned(8);
    writer.write_unsigned(0);
    // phase
    let _ = writer.write_text_string("SUBMITTED");
    // diagnostic
    writer.write_array_len(0);
    let body = writer.into_bytes();
    let envelope = craft_snapshot_envelope(&body);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::InvalidData) => {}
        other => panic!("expected InvalidData for unknown query state, got {other:?}"),
    }
}

#[test]
fn reject_unknown_diagnostic() {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(6);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(2);
    writer.write_unsigned(8);
    writer.write_unsigned(0);
    let _ = writer.write_text_string("NOT_PREPARED");
    // diagnostic (Some, bogus)
    writer.write_array_len(1);
    let _ = writer.write_text_string("BOGUS_DIAGNOSTIC");
    let body = writer.into_bytes();
    let envelope = craft_snapshot_envelope(&body);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::InvalidData) => {}
        other => panic!("expected InvalidData for unknown diagnostic, got {other:?}"),
    }
}

#[test]
fn reject_wrong_body_field_count() {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(5);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(0);
    writer.write_array_len(2);
    writer.write_unsigned(8);
    writer.write_unsigned(0);
    let body = writer.into_bytes();
    let envelope = craft_snapshot_envelope(&body);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::InvalidCbor) => {}
        other => panic!("expected InvalidCbor for wrong body field count, got {other:?}"),
    }
}

#[test]
fn reject_malformed_digest_length() {
    let mut writer = CanonicalCborWriter::new();
    writer.write_array_len(4);
    let _ = writer.write_text_string(SNAPSHOT_RECORD_TYPE_ID_V1);
    let _ = writer.write_text_string(SNAPSHOT_HASH_ALGORITHM_ID_V1);
    // 16-byte digest (wrong length)
    let _ = writer.write_byte_string(&[0u8; 16]);
    let _ = writer.write_byte_string(b"body");
    let bytes = writer.into_bytes();
    match read_snapshot_raw(&bytes) {
        Err(SnapshotFileError::InvalidCbor) => {}
        other => panic!("expected InvalidCbor for malformed digest length, got {other:?}"),
    }
}

#[test]
fn reject_non_canonical_cbor() {
    // Build a body whose policy array uses a non-shortest unsigned encoding
    // (0x18 0x00 = value 0 in the 1-byte form, which is non-canonical because
    // values < 24 must be inline). The canonical reader rejects this.
    let mut body: Vec<u8> = vec![
        0x86, // array(6) body
        0x80, // array(0) walletd snapshots
        0x80, // array(0) receipt snapshots
        0x80, // array(0) submitted (None)
        0x82, // array(2) policy
        0x18, 0x00, // non-canonical unsigned 0
        0x00, // canonical unsigned 0
        0x6c, // text length 12
    ];
    body.extend_from_slice(b"NOT_PREPARED");
    body.push(0x80); // array(0) diagnostic (None)
    let envelope = craft_snapshot_envelope(&body);
    match read_snapshot_raw(&envelope) {
        Err(SnapshotFileError::NonCanonicalCbor) => {}
        other => panic!("expected NonCanonicalCbor, got {other:?}"),
    }
}
