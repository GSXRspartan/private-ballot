//! E.1 regression: evidence decode-and-verify round trip.
//!
//! Tests that `AnchorEvidenceRecordV1::from_canonical_bytes` correctly decodes
//! canonical evidence, verifies the embedded body digest, and rejects trailing
//! bytes, wrong versions, wrong hash algorithms, malformed digests, and altered
//! bodies.

mod common;

use common::*;
use tari_cc_private_ballot_ootle_anchor_app::evidence::{
    EVIDENCE_HASH_ALGORITHM_ID_V1, EVIDENCE_RECORD_TYPE_ID_V1,
};
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorEvidenceRecordV1, ArchiveProofInputs, EvidenceError, TerminalEvidenceInputs,
};
use tari_cc_private_ballot_protocol::{CanonicalCborReader, CanonicalCborWriter};

fn sample_evidence() -> AnchorEvidenceRecordV1 {
    let archive = ArchiveProofInputs::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_anchor_digest(),
    );
    let snapshot_digest = [0u8; 32];
    match AnchorEvidenceRecordV1::from_terminal_outcome(
        &archive,
        TerminalEvidenceInputs::RejectedByApprover,
        &snapshot_digest,
    ) {
        Ok(evidence) => evidence,
        Err(e) => panic!("evidence must construct: {e:?}"),
    }
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
    let _ = reader
        .read_array_len()
        .unwrap_or_else(|e| panic!("reader: {e:?}"));
    let _ = reader
        .read_text_string()
        .unwrap_or_else(|e| panic!("reader: {e:?}"));
    let _ = reader
        .read_text_string()
        .unwrap_or_else(|e| panic!("reader: {e:?}"));
    let _ = reader
        .read_byte_string()
        .unwrap_or_else(|e| panic!("reader: {e:?}"));
    reader
        .read_byte_string()
        .unwrap_or_else(|e| panic!("reader: {e:?}"))
        .to_vec()
}

#[test]
fn round_trip_succeeds() {
    let evidence = sample_evidence();
    let bytes = evidence.canonical_bytes();
    let decoded = match AnchorEvidenceRecordV1::from_canonical_bytes(&bytes) {
        Ok(d) => d,
        Err(e) => panic!("round trip must succeed: {e:?}"),
    };
    assert_eq!(decoded, evidence);
    assert_eq!(decoded.canonical_bytes().as_ref(), bytes.as_ref());
}

#[test]
fn reject_trailing_bytes() {
    let evidence = sample_evidence();
    let mut bytes = evidence.canonical_bytes().to_vec();
    bytes.push(0x00);
    assert!(matches!(
        AnchorEvidenceRecordV1::from_canonical_bytes(&bytes),
        Err(EvidenceError::InvalidData)
    ));
}

#[test]
fn reject_wrong_version() {
    let evidence = sample_evidence();
    let body = extract_body(&evidence);
    let digest = evidence.digest();
    let bytes = craft_envelope(
        "WRONG_RECORD_TYPE",
        EVIDENCE_HASH_ALGORITHM_ID_V1,
        &digest,
        &body,
    );
    assert!(matches!(
        AnchorEvidenceRecordV1::from_canonical_bytes(&bytes),
        Err(EvidenceError::InvalidData)
    ));
}

#[test]
fn reject_wrong_hash_algorithm() {
    let evidence = sample_evidence();
    let body = extract_body(&evidence);
    let digest = evidence.digest();
    let bytes = craft_envelope(
        EVIDENCE_RECORD_TYPE_ID_V1,
        "WRONG_HASH_ALGO",
        &digest,
        &body,
    );
    assert!(matches!(
        AnchorEvidenceRecordV1::from_canonical_bytes(&bytes),
        Err(EvidenceError::InvalidData)
    ));
}

#[test]
fn reject_malformed_digest() {
    let evidence = sample_evidence();
    let body = extract_body(&evidence);
    let short_digest = [0u8; 31];
    let bytes = craft_envelope(
        EVIDENCE_RECORD_TYPE_ID_V1,
        EVIDENCE_HASH_ALGORITHM_ID_V1,
        &short_digest,
        &body,
    );
    assert!(matches!(
        AnchorEvidenceRecordV1::from_canonical_bytes(&bytes),
        Err(EvidenceError::InvalidData)
    ));
}

#[test]
fn reject_altered_body() {
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
    assert!(matches!(
        AnchorEvidenceRecordV1::from_canonical_bytes(&bytes),
        Err(EvidenceError::InvalidData)
    ));
}
