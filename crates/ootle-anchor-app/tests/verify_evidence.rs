//! Integration tests for the `--verify-evidence <path>` operator mode.
//!
//! Test-only clippy allows: the strict workspace lints (`expect_used`,
//! `unwrap_used`) apply to production code; test harnesses may use
//! `expect`/`unwrap` for concise assertions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::*;
use std::path::PathBuf;

use tari_cc_private_ballot_ootle_anchor_app::evidence::{
    EVIDENCE_DOMAIN_LABEL_V1, EVIDENCE_FRAME_PREFIX_V1, EVIDENCE_HASH_ALGORITHM_ID_V1,
    EVIDENCE_RECORD_TYPE_ID_V1,
};
use tari_cc_private_ballot_ootle_anchor_app::verify_evidence;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorEvidenceRecordV1, ArchiveProofInputs, EvidenceError, TerminalEvidenceInputs,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborReader, CanonicalCborWriter, HashProvider,
};

const VERIFY_FAILED: &str = "ANCHOR_APP_EVIDENCE_VERIFY_FAILED";

fn sample_evidence() -> AnchorEvidenceRecordV1 {
    let archive = ArchiveProofInputs::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_anchor_digest(),
    );
    let snapshot_digest = [0u8; 32];
    AnchorEvidenceRecordV1::from_terminal_outcome(
        &archive,
        TerminalEvidenceInputs::RejectedByApprover,
        &snapshot_digest,
    )
    .expect("evidence must construct")
}

fn write_evidence_to_temp(record: &AnchorEvidenceRecordV1) -> PathBuf {
    let path = tmp_path("verify_ev").join(format!("{}.cbor", unique_id()));
    std::fs::write(&path, record.canonical_bytes().as_ref()).expect("write");
    path
}

fn craft_envelope(record_type: &str, hash_algo: &str, digest: &[u8], body: &[u8]) -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    let _ = writer.write_array_len(4);
    let _ = writer.write_text_string(record_type);
    let _ = writer.write_text_string(hash_algo);
    let _ = writer.write_byte_string(digest);
    let _ = writer.write_byte_string(body);
    writer.into_bytes()
}

fn extract_body(evidence: &AnchorEvidenceRecordV1) -> Vec<u8> {
    let bytes = evidence.canonical_bytes();
    let mut reader = CanonicalCborReader::new(bytes.as_ref());
    let _ = reader.read_array_len().unwrap();
    let _ = reader.read_text_string().unwrap();
    let _ = reader.read_text_string().unwrap();
    let _ = reader.read_byte_string().unwrap();
    reader.read_byte_string().unwrap().to_vec()
}

fn write_bytes_to_temp(bytes: &[u8]) -> PathBuf {
    let path = tmp_path("verify_ev_raw").join(format!("{}.cbor", unique_id()));
    std::fs::write(&path, bytes).expect("write");
    path
}

#[test]
fn valid_evidence_verifies() {
    let evidence = sample_evidence();
    let path = write_evidence_to_temp(&evidence);
    verify_evidence::run(&path.to_string_lossy()).expect("verification must succeed");
}

#[test]
fn wrong_version_rejected() {
    let evidence = sample_evidence();
    let body = extract_body(&evidence);
    let digest = evidence.digest();
    let bytes = craft_envelope(
        "WRONG_RECORD_TYPE",
        EVIDENCE_HASH_ALGORITHM_ID_V1,
        &digest,
        &body,
    );
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn wrong_hash_algorithm_rejected() {
    let evidence = sample_evidence();
    let body = extract_body(&evidence);
    let digest = evidence.digest();
    let bytes = craft_envelope(
        EVIDENCE_RECORD_TYPE_ID_V1,
        "WRONG_HASH_ALGO",
        &digest,
        &body,
    );
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn digest_mismatch_rejected() {
    let evidence = sample_evidence();
    let body = extract_body(&evidence);
    let bad_digest = [0u8; 32];
    let bytes = craft_envelope(
        EVIDENCE_RECORD_TYPE_ID_V1,
        EVIDENCE_HASH_ALGORITHM_ID_V1,
        &bad_digest,
        &body,
    );
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn altered_body_rejected() {
    let evidence = sample_evidence();
    let mut body = extract_body(&evidence);
    body[0] ^= 0xFF;
    let digest = evidence.digest();
    let bytes = craft_envelope(
        EVIDENCE_RECORD_TYPE_ID_V1,
        EVIDENCE_HASH_ALGORITHM_ID_V1,
        &digest,
        &body,
    );
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn trailing_bytes_rejected() {
    let evidence = sample_evidence();
    let mut bytes = evidence.canonical_bytes().to_vec();
    bytes.push(0x00);
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn oversized_input_rejected() {
    let evidence = sample_evidence();
    let mut bytes = evidence.canonical_bytes().to_vec();
    bytes.extend_from_slice(&vec![0u8; 9_000]);
    let path = write_bytes_to_temp(&bytes);
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn non_existent_file_rejected() {
    let path = tmp_path("nonexist").join("missing.cbor");
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

#[test]
fn no_file_mutation() {
    let evidence = sample_evidence();
    let path = write_evidence_to_temp(&evidence);
    let before = std::fs::read(&path).expect("read before");
    verify_evidence::run(&path.to_string_lossy()).expect("verify");
    let after = std::fs::read(&path).expect("read after");
    assert_eq!(before, after, "evidence file must not be mutated");
}

#[test]
fn from_canonical_bytes_rejects_malformed_transaction_id_with_valid_digest() {
    // Build evidence with a valid transaction ID, then corrupt the transaction
    // ID text in the body to be non-hex. The body digest is recomputed so the
    // envelope verifies, forcing rejection to reach the transaction-ID
    // validator rather than merely failing on a digest mismatch.
    let archive = ArchiveProofInputs::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_anchor_digest(),
    );
    let snapshot_digest = [0u8; 32];
    let evidence = AnchorEvidenceRecordV1::from_terminal_outcome(
        &archive,
        TerminalEvidenceInputs::FeeOnly {
            transaction_id: canonical_transaction_id(),
            ledger_position: None,
        },
        &snapshot_digest,
    )
    .expect("evidence");

    let mut body = extract_body(&evidence);

    // The transaction ID is encoded as a CBOR text string in the body (field
    // 6). Find its hex pattern and corrupt it with a control character so the
    // AnchorTransactionId validator rejects it (the validator rejects control
    // characters, not non-hex).
    let tx_hex = canonical_transaction_id().as_str().as_bytes().to_vec();
    if let Some(pos) = body
        .windows(tx_hex.len())
        .position(|w| w == tx_hex.as_slice())
    {
        // Replace the first character with a newline (control character).
        body[pos] = b'\n';
    } else {
        panic!("transaction ID hex pattern not found in body");
    }

    // Recompute the body digest with the correct evidence domain framing.
    let recomputed_digest = compute_evidence_body_digest(&body);
    let bytes = craft_envelope(
        EVIDENCE_RECORD_TYPE_ID_V1,
        EVIDENCE_HASH_ALGORITHM_ID_V1,
        &recomputed_digest,
        &body,
    );
    assert!(matches!(
        AnchorEvidenceRecordV1::from_canonical_bytes(&bytes),
        Err(EvidenceError::InvalidData)
    ));
}

/// Computes the evidence body digest using the same domain framing as the
/// production encoder, so a test envelope can carry a correctly recomputed
/// digest.
fn compute_evidence_body_digest(body: &[u8]) -> [u8; 32] {
    let mut framed = Vec::with_capacity(
        EVIDENCE_FRAME_PREFIX_V1.len() + 1 + EVIDENCE_DOMAIN_LABEL_V1.len() + 1 + body.len(),
    );
    framed.extend_from_slice(EVIDENCE_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(EVIDENCE_DOMAIN_LABEL_V1.as_bytes());
    framed.push(0);
    framed.extend_from_slice(body);
    Blake3HashProviderV1.hash(&framed)
}

// --- F5: metadata size check before read ---

#[test]
fn oversized_file_rejected_before_read() {
    // Write a file larger than MAX_EVIDENCE_FILE_BYTES. The verifier should
    // reject it via metadata without allocating the full file.
    let path = tmp_path("oversized").join("big.evidence");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // MAX_EVIDENCE_FILE_BYTES is 8192; write 9000 bytes.
    std::fs::write(&path, vec![0u8; 9_000]).expect("write oversized file");
    assert_eq!(
        verify_evidence::run(&path.to_string_lossy()),
        Err(VERIFY_FAILED.to_owned())
    );
}

// --- F6: single-line human_review_summary ---

#[test]
fn human_review_summary_is_sanitized_to_single_line() {
    // The raw summary contains an embedded newline. The sanitize function
    // must collapse it to a single physical line with no control characters.
    let evidence = sample_evidence();
    let raw = evidence.human_review_summary();
    assert!(
        raw.contains('\n'),
        "raw summary must contain a newline (the pre-sanitization state)"
    );
    let sanitized = verify_evidence::sanitize_single_line(&raw);
    assert!(
        !sanitized.contains('\n') && !sanitized.contains('\r'),
        "sanitized summary must not contain newlines"
    );
    assert!(
        !sanitized.chars().any(|c| c.is_control()),
        "sanitized summary must not contain control characters"
    );
}
