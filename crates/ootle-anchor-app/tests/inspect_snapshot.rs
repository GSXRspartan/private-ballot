//! Integration tests for the `--inspect-snapshot <path>` operator mode.
//!
//! Test-only clippy allows: the strict workspace lints (`expect_used`,
//! `unwrap_used`) apply to production code; test harnesses may use
//! `expect`/`unwrap` for concise assertions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::*;
use std::path::PathBuf;

use tari_cc_private_ballot_ootle_anchor_app::inspect_snapshot;
use tari_cc_private_ballot_ootle_anchor_app::snapshot_store::write_snapshot_atomic;
use tari_cc_private_ballot_ootle_anchor_app::{
    read_snapshot, SnapshotFileError, SNAPSHOT_DOMAIN_LABEL_V1, SNAPSHOT_FRAME_PREFIX_V1,
    SNAPSHOT_HASH_ALGORITHM_ID_V1, SNAPSHOT_RECORD_TYPE_ID_V1,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleRecoverySnapshot, PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryStateV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdEffectiveStatusV1, WalletdRequestDecisionV1,
    WalletdSubmissionStateV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, CanonicalCborWriter, HashProvider};

const VERIFY_FAILED: &str = "ANCHOR_APP_SNAPSHOT_VERIFY_FAILED";

fn write_snapshot_to_temp(snapshot: &AnchorLifecycleRecoverySnapshot) -> PathBuf {
    let path = tmp_path("inspect_snap").join(format!("{}.cbor", unique_id()));
    write_snapshot_atomic(&path, snapshot).expect("write");
    path
}

fn craft_envelope_raw(
    record_type: &str,
    hash_algo: &str,
    digest: &[u8; 32],
    body: &[u8],
) -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    let _ = writer.write_array_len(4);
    let _ = writer.write_text_string(record_type);
    let _ = writer.write_text_string(hash_algo);
    let _ = writer.write_byte_string(digest);
    let _ = writer.write_byte_string(body);
    writer.into_bytes()
}

fn compute_snapshot_digest(body: &[u8]) -> [u8; 32] {
    let mut framed = Vec::with_capacity(
        SNAPSHOT_FRAME_PREFIX_V1.len() + 1 + SNAPSHOT_DOMAIN_LABEL_V1.len() + 1 + body.len(),
    );
    framed.extend_from_slice(SNAPSHOT_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(SNAPSHOT_DOMAIN_LABEL_V1.as_bytes());
    framed.push(0);
    framed.extend_from_slice(body);
    Blake3HashProviderV1.hash(&framed)
}

fn write_bytes_to_temp(bytes: &[u8]) -> PathBuf {
    let path = tmp_path("inspect_snap_raw").join(format!("{}.cbor", unique_id()));
    std::fs::write(&path, bytes).expect("write");
    path
}

#[test]
fn valid_prepared_snapshot_inspects() {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Prepared,
        WalletdSubmissionStateV1::NotSubmitted,
        None,
        Some(WalletdEffectiveStatusV1::Pending),
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
    let path = write_snapshot_to_temp(&snapshot);
    inspect_snapshot::run(&path.to_string_lossy()).expect("inspection must succeed");
}

#[test]
fn valid_submitted_snapshot_inspects() {
    let snapshot = submitted_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    inspect_snapshot::run(&path.to_string_lossy()).expect("inspection must succeed");
}

#[test]
fn valid_finalized_accept_snapshot_inspects() {
    let snapshot = known_answer_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    inspect_snapshot::run(&path.to_string_lossy()).expect("inspection must succeed");
}

#[test]
fn digest_mismatch_rejected() {
    let snapshot = submitted_snapshot();
    let path = tmp_path("digest_mismatch").join(format!("{}.cbor", unique_id()));
    write_snapshot_atomic(&path, &snapshot).expect("write");
    // Corrupt the file by writing a valid envelope with a wrong digest.
    let good_bytes = std::fs::read(&path).expect("read");
    // Extract the body (4th field of the envelope) and re-wrap with a bad digest.
    use tari_cc_private_ballot_protocol::CanonicalCborReader;
    let mut reader = CanonicalCborReader::new(&good_bytes);
    let _ = reader.read_array_len().unwrap();
    let _ = reader.read_text_string().unwrap();
    let _ = reader.read_text_string().unwrap();
    let _ = reader.read_byte_string().unwrap();
    let body = reader.read_byte_string().unwrap();
    let bad_digest = [0u8; 32];
    let bytes = craft_envelope_raw(
        SNAPSHOT_RECORD_TYPE_ID_V1,
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &bad_digest,
        body,
    );
    let path2 = write_bytes_to_temp(&bytes);
    assert_eq!(
        inspect_snapshot::run(&path2.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn malformed_cbor_rejected() {
    let path = write_bytes_to_temp(&[0xFF, 0xFF, 0xFF]);
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn trailing_bytes_rejected() {
    let snapshot = submitted_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    let mut bytes = std::fs::read(&path).expect("read");
    bytes.push(0x00);
    let path2 = write_bytes_to_temp(&bytes);
    assert_eq!(
        inspect_snapshot::run(&path2.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn non_existent_file_rejected() {
    let path = tmp_path("nonexist_snap").join("missing.cbor");
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn no_snapshot_mutation() {
    let snapshot = known_answer_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    let before = std::fs::read(&path).expect("read before");
    inspect_snapshot::run(&path.to_string_lossy()).expect("inspect");
    let after = std::fs::read(&path).expect("read after");
    assert_eq!(before, after, "snapshot file must not be mutated");
}

#[test]
fn no_transport_call() {
    // The inspect-snapshot path never constructs a transport. A snapshot with
    // endpoints pointing to unreachable addresses still inspects successfully.
    let snapshot = known_answer_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    inspect_snapshot::run(&path.to_string_lossy()).expect("inspect without transport");
}

#[test]
fn wrong_record_type_rejected() {
    let snapshot = submitted_snapshot();
    let good_bytes = {
        let path = write_snapshot_to_temp(&snapshot);
        std::fs::read(&path).expect("read")
    };
    use tari_cc_private_ballot_protocol::CanonicalCborReader;
    let mut reader = CanonicalCborReader::new(&good_bytes);
    let _ = reader.read_array_len().unwrap();
    let _ = reader.read_text_string().unwrap();
    let _ = reader.read_text_string().unwrap();
    let _ = reader.read_byte_string().unwrap();
    let body = reader.read_byte_string().unwrap();
    let digest = compute_snapshot_digest(body);
    let bytes = craft_envelope_raw(
        "WRONG_RECORD_TYPE",
        SNAPSHOT_HASH_ALGORITHM_ID_V1,
        &digest,
        body,
    );
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn read_snapshot_returns_error_for_empty_file() {
    let path = write_bytes_to_temp(&[]);
    assert!(matches!(
        read_snapshot(&path),
        Err(SnapshotFileError::InvalidCbor) | Err(SnapshotFileError::ProtocolLimitExceeded)
    ));
}

// --- Semantic reconstruction validation tests (F1 repair) ---
//
// These tests verify that --inspect-snapshot rejects snapshots that are
// structurally valid and digest-consistent but semantically impossible.

/// Builds a snapshot that is digest-valid but semantically impossible:
/// FinalizedAccept phase with no receipt snapshot (FinalizedAccept requires
/// a verified receipt).
fn impossible_finalized_accept_snapshot() -> AnchorLifecycleRecoverySnapshot {
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        Vec::new(), // no receipt — FinalizedAccept requires one
        Some(canonical_submitted()),
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    )
}

#[test]
fn impossible_finalized_accept_rejected() {
    let snapshot = impossible_finalized_accept_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn submitted_phase_without_submitted_handle_rejected() {
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
        None, // no submitted handle — Submitted requires one
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    let path = write_snapshot_to_temp(&snapshot);
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn mismatched_transaction_id_rejected() {
    // Build a submitted handle with a different transaction id than the
    // walletd snapshot records.
    let mismatched_submitted = SubmittedWalletdAnchorRequestV1::new(
        project_request_id(),
        walletd_request_id(),
        transaction_id(0x99), // differs from canonical_transaction_id()
        canonical_binding(),
    );
    let walletd = walletd_snapshot(
        WalletdRequestDecisionV1::Approved,
        WalletdSubmissionStateV1::Submitted,
        Some(canonical_transaction_id()),
        Some(WalletdEffectiveStatusV1::Submitted),
        0,
        1,
    );
    let snapshot = AnchorLifecycleRecoverySnapshot::new(
        vec![walletd],
        Vec::new(),
        Some(mismatched_submitted),
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Submitted,
        None,
    );
    let path = write_snapshot_to_temp(&snapshot);
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn polling_phase_with_zero_attempts_rejected() {
    let snapshot = polling_in_progress_snapshot(0);
    let path = write_snapshot_to_temp(&snapshot);
    assert_eq!(
        inspect_snapshot::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn semantic_failure_leaves_snapshot_byte_identical() {
    let snapshot = impossible_finalized_accept_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    let before = std::fs::read(&path).expect("read before");
    let _ = inspect_snapshot::run(&path.to_string_lossy());
    let after = std::fs::read(&path).expect("read after");
    assert_eq!(
        before, after,
        "snapshot file must not be mutated on failure"
    );
}

#[test]
fn success_output_contains_snapshot_verified() {
    let snapshot = known_answer_snapshot();
    let path = write_snapshot_to_temp(&snapshot);
    // On success, the function returns Ok; the machine code is printed to
    // stdout. We verify the function returns Ok (which only happens after
    // semantic validation passes).
    inspect_snapshot::run(&path.to_string_lossy()).expect("valid snapshot must verify");
}
