//! Production BLAKE3 provider coverage across protocol artifact consumers.

use tari_cc_private_ballot_archive::{
    ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
    CandidateDefinition, CandidateId, CandidateSet, ElectionId, ElectionManifestV1,
    ElectionManifestV1Input,
};
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, Blake3HashProviderV1, CanonicalCborWriter, HashProvider,
    PROTOCOL_VERSION_V1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;

#[test]
fn production_provider_hashes_all_major_protocol_artifacts() {
    let provider = Blake3HashProviderV1;
    let registry = registry();
    let candidates = candidates();

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("production registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("production candidate commitment must be derivable");
    };
    let Ok(election_id) = ElectionId::new(b"production-hash-integration".to_vec()) else {
        panic!("test election identifier must be valid");
    };
    let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
        panic!("test approval limits must be valid");
    };
    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: "TARI_TRIPTYCH_PROTOTYPE_V1".to_owned(),
        approval_limits: limits,
        governance_source_revision: "production-hash-vector-1".to_owned(),
    }) else {
        panic!("production test manifest must be valid");
    };
    let Ok(payload) =
        ApprovalBallotPayload::new(vec![candidate_id(b"candidate-a")], &candidates, limits)
    else {
        panic!("production test payload must be valid");
    };

    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("production manifest hash must be derivable");
    };
    let Ok(payload_hash) = payload.canonical_hash(&provider) else {
        panic!("production payload hash must be derivable");
    };
    let Ok(scope) = manifest.canonical_scope(&provider) else {
        panic!("production election scope must be derivable");
    };
    let Ok(path) = ArchivePathV1::new("ballots/00000001.cbor".to_owned()) else {
        panic!("production archive path must be valid");
    };
    let file = ArchiveFileEntryV1::for_bytes(path, &provider, b"canonical archive file");
    let Ok(catalog) = ArchiveFileCatalogV1::new(vec![file.clone()]) else {
        panic!("production archive catalog must be valid");
    };
    let Ok(archive) = ArchiveManifestV1::for_provider(manifest_hash, catalog, &provider) else {
        panic!("production archive manifest must be valid");
    };
    let Ok(archive_hash) = archive.canonical_hash(&provider) else {
        panic!("production archive hash must be derivable");
    };

    assert_eq!(provider.algorithm_id(), BLAKE3_256_HASH_ALGORITHM_ID_V1);
    assert_eq!(archive.hash_algorithm_id(), BLAKE3_256_HASH_ALGORITHM_ID_V1);
    assert_ne!(registry_commitment.as_bytes(), &[0_u8; 32]);
    assert_ne!(candidate_set_commitment.as_bytes(), &[0_u8; 32]);
    assert_ne!(manifest_hash.as_bytes(), &[0_u8; 32]);
    assert_ne!(payload_hash.as_bytes(), &[0_u8; 32]);
    assert_ne!(scope.as_bytes(), &[0_u8; 32]);
    assert_ne!(file.digest().as_bytes(), &[0_u8; 32]);
    assert_ne!(archive_hash.as_bytes(), &[0_u8; 32]);
    assert!(
        file.verify_bytes(&provider, b"canonical archive file")
            .is_ok()
    );
    assert!(archive.verify_hash(&provider, archive_hash).is_ok());
}

fn registry() -> RegistrySnapshot {
    let mut writer = CanonicalCborWriter::new();

    assert!(writer.write_array_len(1).is_ok());
    assert!(
        writer
            .write_byte_string(b"production-governance-key")
            .is_ok()
    );

    let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
        panic!("production registry fixture must be valid");
    };

    registry
}

fn candidates() -> CandidateSet {
    let Ok(first) =
        CandidateDefinition::new(candidate_id(b"candidate-a"), "Candidate A".to_owned())
    else {
        panic!("first production candidate must be valid");
    };
    let Ok(second) =
        CandidateDefinition::new(candidate_id(b"candidate-b"), "Candidate B".to_owned())
    else {
        panic!("second production candidate must be valid");
    };
    let Ok(candidates) = CandidateSet::new(vec![first, second]) else {
        panic!("production candidate set must be valid");
    };

    candidates
}

fn candidate_id(bytes: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(bytes.to_vec()) else {
        panic!("production candidate identifier must be valid");
    };

    id
}
