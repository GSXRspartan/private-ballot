#![forbid(unsafe_code)]

//! Shared invariants for the standalone cargo-fuzz targets.

use tari_cc_private_ballot_archive::ArchiveManifestV1;
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotPackageV1, CandidateDefinition, CandidateId,
    CandidateSet, ElectionManifestV1,
};
use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES,
    test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;

fn input_is_bounded(data: &[u8]) -> bool {
    data.len() <= MAX_CANONICAL_OBJECT_BYTES
}

fn candidate(identifier: &[u8], display_name: &str) -> Option<CandidateDefinition> {
    let id = CandidateId::new(identifier.to_vec()).ok()?;
    CandidateDefinition::new(id, display_name.to_owned()).ok()
}

/// Returns the fixed candidate context used by payload and package targets.
pub fn approval_context() -> Option<(CandidateSet, ApprovalLimits)> {
    let candidates = CandidateSet::new(vec![
        candidate(b"approve", "Approve")?,
        candidate(b"defer", "Defer")?,
        candidate(b"reject", "Reject")?,
    ])
    .ok()?;

    let limits = ApprovalLimits::new(1, 2, true).ok()?;

    Some((candidates, limits))
}

/// Exercises the public deterministic-CBOR primitive reader and writer.
pub fn fuzz_canonical_cbor_reader(data: &[u8]) {
    let Some((&operation, encoded)) = data.split_first() else {
        return;
    };

    if !input_is_bounded(encoded) {
        return;
    }

    let mut reader = CanonicalCborReader::new(encoded);
    let mut writer = CanonicalCborWriter::new();

    let parsed = match operation % 5 {
        0 => match reader.read_unsigned() {
            Ok(value) => {
                writer.write_unsigned(value);
                Ok(())
            }
            Err(error) => Err(error),
        },
        1 => match reader.read_byte_string() {
            Ok(value) => writer.write_byte_string(value),
            Err(error) => Err(error),
        },
        2 => match reader.read_text_string() {
            Ok(value) => writer.write_text_string(value),
            Err(error) => Err(error),
        },
        3 => match reader.read_array_len() {
            Ok(value) => writer.write_array_len(value),
            Err(error) => Err(error),
        },
        _ => match reader.read_map_len() {
            Ok(value) => writer.write_map_len(value),
            Err(error) => Err(error),
        },
    };

    if parsed.is_err() || reader.finish().is_err() {
        return;
    }

    assert_eq!(writer.into_bytes(), encoded);
}

/// Fuzzes registry canonical decoding, re-encoding, and commitment determinism.
pub fn fuzz_registry_snapshot(data: &[u8]) {
    if !input_is_bounded(data) {
        return;
    }

    let Ok(first) = RegistrySnapshot::from_canonical_cbor(data) else {
        return;
    };

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("a decoded registry snapshot must re-encode");
    };

    assert_eq!(first_bytes, data);

    let Ok(second) = RegistrySnapshot::from_canonical_cbor(&first_bytes) else {
        panic!("re-encoded registry snapshot must decode");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second registry snapshot must re-encode");
    };

    assert_eq!(second_bytes, first_bytes);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_commitment) = first.canonical_commitment(&provider) else {
        panic!("decoded registry snapshot must have a commitment");
    };

    let Ok(second_commitment) = second.canonical_commitment(&provider) else {
        panic!("second registry snapshot must have a commitment");
    };

    assert_eq!(first_commitment, second_commitment);
}

/// Fuzzes candidate-set canonical decoding, re-encoding, and commitment determinism.
pub fn fuzz_candidate_set(data: &[u8]) {
    if !input_is_bounded(data) {
        return;
    }

    let Ok(first) = CandidateSet::from_canonical_cbor(data) else {
        return;
    };

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("a decoded candidate set must re-encode");
    };

    assert_eq!(first_bytes, data);

    let Ok(second) = CandidateSet::from_canonical_cbor(&first_bytes) else {
        panic!("re-encoded candidate set must decode");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second candidate set must re-encode");
    };

    assert_eq!(second_bytes, first_bytes);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_commitment) = first.canonical_commitment(&provider) else {
        panic!("decoded candidate set must have a commitment");
    };

    let Ok(second_commitment) = second.canonical_commitment(&provider) else {
        panic!("second candidate set must have a commitment");
    };

    assert_eq!(first_commitment, second_commitment);
}

/// Fuzzes approval-payload canonical decoding with fixed candidate context.
pub fn fuzz_approval_ballot_payload(data: &[u8]) {
    if !input_is_bounded(data) {
        return;
    }

    let Some((candidates, limits)) = approval_context() else {
        panic!("fixed approval context must remain valid");
    };

    let Ok(first) = ApprovalBallotPayload::from_canonical_cbor(data, &candidates, limits) else {
        return;
    };

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("a decoded approval payload must re-encode");
    };

    assert_eq!(first_bytes, data);

    let Ok(second) = ApprovalBallotPayload::from_canonical_cbor(&first_bytes, &candidates, limits)
    else {
        panic!("re-encoded approval payload must decode");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second approval payload must re-encode");
    };

    assert_eq!(second_bytes, first_bytes);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_hash) = first.canonical_hash(&provider) else {
        panic!("decoded approval payload must have a canonical hash");
    };

    let Ok(second_hash) = second.canonical_hash(&provider) else {
        panic!("second approval payload must have a canonical hash");
    };

    assert_eq!(first_hash, second_hash);
}

/// Fuzzes election-manifest canonical decoding and hash determinism.
pub fn fuzz_election_manifest(data: &[u8]) {
    if !input_is_bounded(data) {
        return;
    }

    let Ok(first) = ElectionManifestV1::from_canonical_cbor(data) else {
        return;
    };

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("a decoded election manifest must re-encode");
    };

    assert_eq!(first_bytes, data);

    let Ok(second) = ElectionManifestV1::from_canonical_cbor(&first_bytes) else {
        panic!("re-encoded election manifest must decode");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second election manifest must re-encode");
    };

    assert_eq!(second_bytes, first_bytes);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_hash) = first.canonical_hash(&provider) else {
        panic!("decoded election manifest must have a canonical hash");
    };

    let Ok(second_hash) = second.canonical_hash(&provider) else {
        panic!("second election manifest must have a canonical hash");
    };

    assert_eq!(first_hash, second_hash);
}

/// Fuzzes ballot-package canonical decoding with fixed candidate context.
pub fn fuzz_ballot_package(data: &[u8]) {
    if !input_is_bounded(data) {
        return;
    }

    let Some((candidates, limits)) = approval_context() else {
        panic!("fixed approval context must remain valid");
    };

    let Ok(first) = BallotPackageV1::from_canonical_cbor(data, &candidates, limits) else {
        return;
    };

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("a decoded ballot package must re-encode");
    };

    assert_eq!(first_bytes, data);

    let Ok(second) = BallotPackageV1::from_canonical_cbor(&first_bytes, &candidates, limits) else {
        panic!("re-encoded ballot package must decode");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second ballot package must re-encode");
    };

    assert_eq!(second_bytes, first_bytes);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_hash) = first.canonical_hash(&provider) else {
        panic!("decoded ballot package must have a canonical hash");
    };

    let Ok(second_hash) = second.canonical_hash(&provider) else {
        panic!("second ballot package must have a canonical hash");
    };

    assert_eq!(first_hash, second_hash);
}

/// Fuzzes archive-manifest canonical decoding and hash determinism.
pub fn fuzz_archive_manifest(data: &[u8]) {
    if !input_is_bounded(data) {
        return;
    }

    let Ok(first) = ArchiveManifestV1::from_canonical_cbor(data) else {
        return;
    };

    let Ok(first_bytes) = first.to_canonical_cbor() else {
        panic!("a decoded archive manifest must re-encode");
    };

    assert_eq!(first_bytes, data);

    let Ok(second) = ArchiveManifestV1::from_canonical_cbor(&first_bytes) else {
        panic!("re-encoded archive manifest must decode");
    };

    let Ok(second_bytes) = second.to_canonical_cbor() else {
        panic!("second archive manifest must re-encode");
    };

    assert_eq!(second_bytes, first_bytes);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_hash) = first.canonical_hash(&provider) else {
        panic!("decoded archive manifest must have a canonical hash");
    };

    let Ok(second_hash) = second.canonical_hash(&provider) else {
        panic!("second archive manifest must have a canonical hash");
    };

    assert_eq!(first_hash, second_hash);
}
