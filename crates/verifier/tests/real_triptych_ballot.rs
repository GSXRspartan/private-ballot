//! Verifier-level integration coverage for the real Tari Triptych prototype.
//!
//! These tests exercise only project-owned public APIs:
//!
//! registry snapshot -> manifest and payload -> reconstructed proof statement ->
//! registry-bound prover/verifier -> verified ballot -> lifecycle ledger.
//!
//! This remains prototype-only cryptography and does not authorize binding
//! elections, key persistence, CLI secret handling, or Ootle deployment.

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    RISTRETTO_COMPRESSED_POINT_BYTES, TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1,
    prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_protocol::{
    CanonicalCborWriter, PROTOCOL_VERSION_V1, ProtocolError, ValidationCode,
    test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, ingest_approval_ballot_package_v1,
    reconstruct_approval_proof_statement, verify_approval_proof,
};

const RISTRETTO_BASEPOINT_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

const SECRET_SCALAR_ONE_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn real_triptych_ballot_verifies_through_the_application_boundary() {
    let fixture = fixture(b"integration-election-a");
    let payload = payload(&fixture.candidates, b"candidate-a");
    let package = package_for_payload(&fixture, &payload);
    let Ok(package_bytes) = package.to_canonical_cbor() else {
        panic!("real Triptych package must encode canonically");
    };
    let provider = TestOnlyDeterministicHasher;
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("registry-bound Triptych verifier must be constructible");
    };
    let lifecycle = open_lifecycle(&fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    assert!(
        ingest_approval_ballot_package_v1(
            &package_bytes,
            &fixture.manifest,
            &fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &verifier,
        )
        .is_ok()
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.accepted_ballots()[0].payload(), &payload);
}

#[test]
fn bound_ingestion_rejects_a_proof_copied_to_another_election() {
    let first_fixture = fixture(b"integration-copy-source");
    let second_fixture = fixture(b"integration-copy-target");
    let payload = payload(&first_fixture.candidates, b"candidate-a");
    let first_package = package_for_payload(&first_fixture, &payload);
    let provider = TestOnlyDeterministicHasher;
    let Ok(target_manifest_hash) = second_fixture.manifest.canonical_hash(&provider) else {
        panic!("target manifest hash must be derivable");
    };
    let Ok(copied_package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: target_manifest_hash,
        proof_suite_id: second_fixture.manifest.proof_suite_id().to_owned(),
        proof: first_package.proof().to_vec(),
        payload: first_package.payload().clone(),
    }) else {
        panic!("copied-proof package must remain structurally valid");
    };
    let Ok(package_bytes) = copied_package.to_canonical_cbor() else {
        panic!("copied-proof package must encode canonically");
    };
    let Ok(verifier) =
        build_tari_triptych_verifier_from_registry_v1(&second_fixture.registry, &provider)
    else {
        panic!("target registry verifier must be constructible");
    };
    let lifecycle = open_lifecycle(&second_fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    assert!(
        ingest_approval_ballot_package_v1(
            &package_bytes,
            &second_fixture.manifest,
            &second_fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &verifier,
        )
        .is_err()
    );
    assert!(ledger.is_empty());
}

#[test]
fn bound_ingestion_rejects_a_proof_when_the_manifest_registry_changes() {
    let fixture = fixture(b"integration-registry-source");
    let payload = payload(&fixture.candidates, b"candidate-a");
    let first_package = package_for_payload(&fixture, &payload);
    let provider = TestOnlyDeterministicHasher;
    let Ok(candidate_set_commitment) = fixture.candidates.canonical_commitment(&provider) else {
        panic!("candidate commitment must be derivable");
    };
    let Ok(election_id) = ElectionId::new(b"integration-registry-target".to_vec()) else {
        panic!("target election ID must be valid");
    };
    let Ok(modified_manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: tari_cc_private_ballot_protocol::RegistryCommitment::new([9_u8; 32]),
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "integration-registry-target".to_owned(),
    }) else {
        panic!("modified-registry manifest must be valid");
    };
    let Ok(modified_manifest_hash) = modified_manifest.canonical_hash(&provider) else {
        panic!("modified-registry manifest hash must be derivable");
    };
    let Ok(copied_package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: modified_manifest_hash,
        proof_suite_id: modified_manifest.proof_suite_id().to_owned(),
        proof: first_package.proof().to_vec(),
        payload: first_package.payload().clone(),
    }) else {
        panic!("modified-registry package must remain structurally valid");
    };
    let Ok(package_bytes) = copied_package.to_canonical_cbor() else {
        panic!("modified-registry package must encode canonically");
    };
    let Ok(original_verifier) =
        build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("source registry verifier must be constructible");
    };
    let lifecycle = open_lifecycle(&modified_manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    assert!(
        ingest_approval_ballot_package_v1(
            &package_bytes,
            &modified_manifest,
            &fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &original_verifier,
        )
        .is_err()
    );
    assert!(ledger.is_empty());
}

#[test]
fn proof_for_one_ballot_is_rejected_for_another_ballot() {
    let fixture = fixture(b"integration-election-b");
    let first_payload = payload(&fixture.candidates, b"candidate-a");
    let second_payload = payload(&fixture.candidates, b"candidate-b");
    let provider = TestOnlyDeterministicHasher;

    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("registry-bound Triptych verifier must be constructible");
    };
    let Ok(first_statement) =
        reconstruct_approval_proof_statement(&fixture.manifest, &first_payload, &provider)
    else {
        panic!("first application proof statement must be reconstructible");
    };
    let secret = secret_key();
    let Ok(first_proof) = prove_tari_triptych_prototype_v1(&first_statement, &verifier, &secret)
    else {
        panic!("first application proof must be constructible");
    };

    assert!(
        verify_approval_proof(
            &fixture.manifest,
            &second_payload,
            &first_proof,
            &provider,
            &verifier,
        )
        .is_err()
    );
}

#[test]
fn same_voter_in_one_election_has_one_nullifier_and_second_ballot_is_rejected() {
    let fixture = fixture(b"integration-election-c");
    let first_payload = payload(&fixture.candidates, b"candidate-a");
    let second_payload = payload(&fixture.candidates, b"candidate-b");

    let Ok(first_verified) = prove_and_verify(&fixture, &first_payload) else {
        panic!("first real Triptych ballot must verify");
    };
    let Ok(second_verified) = prove_and_verify(&fixture, &second_payload) else {
        panic!("second real Triptych ballot must verify cryptographically");
    };

    assert_eq!(
        first_verified.nullifier().as_bytes(),
        second_verified.nullifier().as_bytes(),
    );

    let lifecycle = open_lifecycle(&fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    assert!(ledger.accept_verified(&lifecycle, first_verified).is_ok());

    let duplicate = ledger.accept_verified(&lifecycle, second_verified);

    assert!(matches!(
        duplicate,
        Err(error) if error.code() == ValidationCode::DuplicateNullifier
    ));
    assert_eq!(ledger.len(), 1);
    assert_eq!(ledger.accepted_ballots()[0].payload(), &first_payload,);
}

#[test]
fn same_voter_in_different_elections_has_different_nullifiers() {
    let first_fixture = fixture(b"integration-election-d1");
    let second_fixture = fixture(b"integration-election-d2");
    let first_payload = payload(&first_fixture.candidates, b"candidate-a");
    let second_payload = payload(&second_fixture.candidates, b"candidate-a");

    let Ok(first_verified) = prove_and_verify(&first_fixture, &first_payload) else {
        panic!("first-election real Triptych ballot must verify");
    };
    let Ok(second_verified) = prove_and_verify(&second_fixture, &second_payload) else {
        panic!("second-election real Triptych ballot must verify");
    };

    assert_ne!(
        first_verified.nullifier().as_bytes(),
        second_verified.nullifier().as_bytes(),
    );
    assert_ne!(
        first_verified.statement().election_scope(),
        second_verified.statement().election_scope(),
    );
}

#[test]
fn real_triptych_package_round_trip_preserves_exact_bytes_and_verifies() {
    let fixture = fixture(b"package-election-a");
    let payload = payload(&fixture.candidates, b"candidate-a");
    let package = package_for_payload(&fixture, &payload);
    let provider = TestOnlyDeterministicHasher;

    let Ok(original_hash) = package.canonical_hash(&provider) else {
        panic!("real Triptych package hash must be derivable");
    };
    let Ok(encoded) = package.to_canonical_cbor() else {
        panic!("real Triptych package must encode canonically");
    };
    let Ok(decoded) =
        BallotPackageV1::from_canonical_cbor(&encoded, &fixture.candidates, approval_limits())
    else {
        panic!("real Triptych package must decode canonically");
    };
    let Ok(reencoded) = decoded.to_canonical_cbor() else {
        panic!("decoded real Triptych package must re-encode");
    };
    let Ok(decoded_hash) = decoded.canonical_hash(&provider) else {
        panic!("decoded real Triptych package hash must be derivable");
    };

    assert_eq!(reencoded, encoded);
    assert_eq!(decoded_hash, original_hash);
    assert_eq!(decoded.manifest_hash(), package.manifest_hash());
    assert_eq!(decoded.proof_suite_id(), package.proof_suite_id());
    assert_eq!(decoded.proof(), package.proof());
    assert_eq!(decoded.payload(), package.payload());

    let Ok(verified) = verify_decoded_package(&fixture, &decoded) else {
        panic!("decoded real Triptych package must verify");
    };
    let lifecycle = open_lifecycle(&fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    assert!(ledger.accept_verified(&lifecycle, verified).is_ok());
    assert_eq!(ledger.len(), 1);
}

#[test]
fn package_with_real_proof_and_changed_payload_is_rejected_after_round_trip() {
    let fixture = fixture(b"package-election-b");
    let first_payload = payload(&fixture.candidates, b"candidate-a");
    let second_payload = payload(&fixture.candidates, b"candidate-b");
    let first_package = package_for_payload(&fixture, &first_payload);

    let Ok(changed_package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: first_package.manifest_hash(),
        proof_suite_id: first_package.proof_suite_id().to_owned(),
        proof: first_package.proof().to_vec(),
        payload: second_payload,
    }) else {
        panic!("structurally valid changed-payload package must be constructible");
    };
    let Ok(encoded) = changed_package.to_canonical_cbor() else {
        panic!("changed-payload package must encode canonically");
    };
    let Ok(decoded) =
        BallotPackageV1::from_canonical_cbor(&encoded, &fixture.candidates, approval_limits())
    else {
        panic!("changed-payload package must decode canonically");
    };

    assert!(verify_decoded_package(&fixture, &decoded).is_err());
}

#[test]
fn independently_round_tripped_packages_derive_one_election_nullifier() {
    let fixture = fixture(b"package-election-c");
    let first_payload = payload(&fixture.candidates, b"candidate-a");
    let second_payload = payload(&fixture.candidates, b"candidate-b");
    let first_package = round_trip_package(&fixture, package_for_payload(&fixture, &first_payload));
    let second_package =
        round_trip_package(&fixture, package_for_payload(&fixture, &second_payload));

    let Ok(first_verified) = verify_decoded_package(&fixture, &first_package) else {
        panic!("first round-tripped real Triptych package must verify");
    };
    let Ok(second_verified) = verify_decoded_package(&fixture, &second_package) else {
        panic!("second round-tripped real Triptych package must verify");
    };

    assert_eq!(
        first_verified.nullifier().as_bytes(),
        second_verified.nullifier().as_bytes(),
    );

    let lifecycle = open_lifecycle(&fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    assert!(ledger.accept_verified(&lifecycle, first_verified).is_ok());

    let duplicate = ledger.accept_verified(&lifecycle, second_verified);

    assert!(matches!(
        duplicate,
        Err(error) if error.code() == ValidationCode::DuplicateNullifier
    ));
    assert_eq!(ledger.len(), 1);
}

struct Fixture {
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
}

fn fixture(election_id_bytes: &[u8]) -> Fixture {
    let provider = TestOnlyDeterministicHasher;
    let registry = registry();
    let candidates = candidate_set();

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("test registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("test candidate-set commitment must be derivable");
    };
    let Ok(election_id) = ElectionId::new(election_id_bytes.to_vec()) else {
        panic!("test election ID must be valid");
    };
    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "integration-revision-1".to_owned(),
    }) else {
        panic!("real Triptych integration manifest must be valid");
    };

    Fixture {
        registry,
        candidates,
        manifest,
    }
}

fn package_for_payload(fixture: &Fixture, payload: &ApprovalBallotPayload) -> BallotPackageV1 {
    let provider = TestOnlyDeterministicHasher;
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("registry-bound Triptych verifier must be constructible");
    };
    let Ok(statement) = reconstruct_approval_proof_statement(&fixture.manifest, payload, &provider)
    else {
        panic!("package proof statement must be reconstructible");
    };
    let secret = secret_key();
    let Ok(proof) = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) else {
        panic!("real Triptych package proof must be constructible");
    };
    let Ok(manifest_hash) = fixture.manifest.canonical_hash(&provider) else {
        panic!("package manifest hash must be derivable");
    };
    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        proof,
        payload: payload.clone(),
    }) else {
        panic!("real Triptych ballot package must be valid");
    };

    package
}

fn round_trip_package(fixture: &Fixture, package: BallotPackageV1) -> BallotPackageV1 {
    let Ok(encoded) = package.to_canonical_cbor() else {
        panic!("real Triptych package must encode canonically");
    };
    let Ok(decoded) =
        BallotPackageV1::from_canonical_cbor(&encoded, &fixture.candidates, approval_limits())
    else {
        panic!("real Triptych package must decode canonically");
    };
    let Ok(reencoded) = decoded.to_canonical_cbor() else {
        panic!("decoded real Triptych package must re-encode");
    };

    assert_eq!(reencoded, encoded);

    decoded
}

fn verify_decoded_package(
    fixture: &Fixture,
    package: &BallotPackageV1,
) -> Result<VerifiedApprovalBallotV1, ProtocolError> {
    let provider = TestOnlyDeterministicHasher;
    let manifest_hash = fixture.manifest.canonical_hash(&provider)?;

    assert_eq!(package.manifest_hash(), manifest_hash);
    assert_eq!(package.proof_suite_id(), fixture.manifest.proof_suite_id(),);

    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)?;

    verify_approval_proof(
        &fixture.manifest,
        package.payload(),
        package.proof(),
        &provider,
        &verifier,
    )
}

fn prove_and_verify(
    fixture: &Fixture,
    payload: &ApprovalBallotPayload,
) -> Result<VerifiedApprovalBallotV1, ProtocolError> {
    let provider = TestOnlyDeterministicHasher;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)?;
    let statement = reconstruct_approval_proof_statement(&fixture.manifest, payload, &provider)?;
    let secret = secret_key();
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret)?;

    verify_approval_proof(&fixture.manifest, payload, &proof, &provider, &verifier)
}

fn registry() -> RegistrySnapshot {
    let mut writer = CanonicalCborWriter::new();

    assert!(writer.write_array_len(1).is_ok());
    assert!(writer.write_byte_string(&RISTRETTO_BASEPOINT_BYTES).is_ok());

    let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
        panic!("single-member canonical registry must be valid");
    };

    registry
}

fn secret_key() -> TariTriptychSecretKeyV1 {
    let Ok(secret) = TariTriptychSecretKeyV1::from_canonical_bytes(SECRET_SCALAR_ONE_BYTES) else {
        panic!("scalar one must be a canonical nonzero Triptych secret");
    };

    secret
}

fn candidate_set() -> CandidateSet {
    let Ok(first) =
        CandidateDefinition::new(candidate_id(b"candidate-a"), "Candidate A".to_owned())
    else {
        panic!("first candidate must be valid");
    };
    let Ok(second) =
        CandidateDefinition::new(candidate_id(b"candidate-b"), "Candidate B".to_owned())
    else {
        panic!("second candidate must be valid");
    };
    let Ok(candidates) = CandidateSet::new(vec![first, second]) else {
        panic!("candidate set must be valid");
    };

    candidates
}

fn payload(candidates: &CandidateSet, selected_candidate: &[u8]) -> ApprovalBallotPayload {
    let Ok(payload) = ApprovalBallotPayload::new(
        vec![candidate_id(selected_candidate)],
        candidates,
        approval_limits(),
    ) else {
        panic!("approval payload must be valid");
    };

    payload
}

fn candidate_id(bytes: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(bytes.to_vec()) else {
        panic!("candidate ID must be valid");
    };

    id
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
        panic!("approval limits must be valid");
    };

    limits
}

fn open_lifecycle(manifest: &ElectionManifestV1) -> ElectionLifecycleV1 {
    let provider = TestOnlyDeterministicHasher;
    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("manifest hash must be derivable");
    };
    let mut lifecycle = ElectionLifecycleV1::new();

    assert!(
        lifecycle
            .freeze(manifest_hash, manifest.registry_commitment())
            .is_ok()
    );
    assert!(lifecycle.open().is_ok());

    lifecycle
}
