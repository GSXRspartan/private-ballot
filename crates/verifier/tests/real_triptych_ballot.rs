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
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input, ElectionManifestV2,
    ElectionManifestV2Input,
};
use tari_cc_private_ballot_crypto::{
    RISTRETTO_COMPRESSED_POINT_BYTES, TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES,
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychProofEnvelopeV1, TariTriptychSecretKeyV1,
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
    reconstruct_approval_proof_statement, verify_approval_ballot_packages_batch_v1,
    verify_approval_proof,
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
fn batch_verification_matches_individual_ingestion_outcomes() {
    let fixture = fixture(b"integration-batch-parity");
    let provider = TestOnlyDeterministicHasher;
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("registry-bound Triptych verifier must be constructible");
    };

    let payload_a = payload(&fixture.candidates, b"candidate-a");
    let payload_b = payload(&fixture.candidates, b"candidate-b");
    let valid_a = encode(&package_for_payload(&fixture, &payload_a));
    let valid_b = encode(&package_for_payload(&fixture, &payload_b));

    // Appended bytes: fails canonical decode (before any crypto).
    let mut trailing = valid_a.clone();
    trailing.push(0x5a);

    // A valid proof declared against the wrong payload: parses, but the proof
    // does not authenticate the reconstructed statement (crypto-invalid).
    let first_package = package_for_payload(&fixture, &payload_a);
    let Ok(changed_payload_package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: first_package.manifest_hash(),
        proof_suite_id: first_package.proof_suite_id().to_owned(),
        proof: first_package.proof().to_vec(),
        payload: payload_b.clone(),
    }) else {
        panic!("changed-payload package must be structurally valid");
    };
    let changed_payload = encode(&changed_payload_package);

    let packages = [
        valid_a.as_slice(),
        trailing.as_slice(),
        valid_b.as_slice(),
        changed_payload.as_slice(),
    ];

    let batch = verify_approval_ballot_packages_batch_v1(
        &packages,
        &fixture.manifest,
        &fixture.candidates,
        &provider,
        &verifier,
    );
    assert_eq!(batch.len(), packages.len());

    // Reference: each package driven individually through the unchanged
    // ingestion path into a FRESH open ledger. Ok/rejection-code must match the
    // batch result exactly. A bad neighbour never suppresses a valid ballot.
    for (index, package_bytes) in packages.iter().enumerate() {
        let lifecycle = open_lifecycle(&fixture.manifest);
        let mut ledger = BallotAcceptanceLedger::new();
        let individual = ingest_approval_ballot_package_v1(
            package_bytes,
            &fixture.manifest,
            &fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &verifier,
        );

        match (&batch[index], &individual) {
            (Ok(_), Ok(())) => {}
            (Err(batched), Err(single)) => assert_eq!(
                batched.code(),
                single.code(),
                "batch and individual rejection codes must match for package {index}",
            ),
            _ => panic!("batch and individual ingestion disagreed for package {index}"),
        }
    }

    assert!(batch[0].is_ok(), "first valid package must batch-verify");
    assert!(batch[2].is_ok(), "second valid package must batch-verify");
    assert!(batch[1].is_err(), "malformed package must be rejected");
    assert!(batch[3].is_err(), "crypto-invalid package must be rejected");
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
fn appended_bytes_are_rejected_without_consuming_a_real_triptych_nullifier() {
    let fixture = fixture(b"trailing-byte-rejection");
    let ballot_payload = payload(&fixture.candidates, b"candidate-a");
    let package = package_for_payload(&fixture, &ballot_payload);
    let Ok(package_bytes) = package.to_canonical_cbor() else {
        panic!("real Triptych package must encode canonically");
    };
    let Ok(decoded_package) = BallotPackageV1::from_canonical_cbor(
        &package_bytes,
        &fixture.candidates,
        approval_limits(),
    ) else {
        panic!("canonical real Triptych package must decode");
    };
    let Ok(reencoded_package) = decoded_package.to_canonical_cbor() else {
        panic!("decoded real Triptych package must re-encode");
    };

    assert_eq!(reencoded_package, package_bytes);

    let Ok(canonical_payload_bytes) = ballot_payload.to_canonical_cbor() else {
        panic!("real Triptych payload must encode canonically");
    };
    let package_suffixes = [
        ("one zero byte", vec![0_u8]),
        ("one nonzero byte", vec![0xa5_u8]),
        (
            "eight arbitrary bytes",
            vec![0x10_u8, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87],
        ),
        ("thirty-two arbitrary bytes", vec![0x5a_u8; 32]),
        ("canonical approval payload bytes", canonical_payload_bytes),
    ];

    for (label, suffix) in package_suffixes {
        let mut mutated_package_bytes = package_bytes.clone();
        mutated_package_bytes.extend_from_slice(&suffix);

        assert_ne!(
            mutated_package_bytes, package_bytes,
            "{label} must alter the canonical ballot package bytes"
        );

        for repetition in 0..3 {
            assert!(
                matches!(
                    BallotPackageV1::from_canonical_cbor(
                        &mutated_package_bytes,
                        &fixture.candidates,
                        approval_limits(),
                    ),
                    Err(error) if error.code() == ValidationCode::TrailingCborData
                ),
                "{label} was not rejected by canonical package decoding on repetition {repetition}"
            );
        }

        assert_rejected_package_does_not_consume_nullifier(
            &fixture,
            &package_bytes,
            &mutated_package_bytes,
            ValidationCode::TrailingCborData,
            label,
        );
    }

    let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(package.proof()) else {
        panic!("real Triptych proof envelope must decode");
    };
    let original_inner_proof = envelope.triptych_proof_bytes().to_vec();
    let other_payload = payload(&fixture.candidates, b"candidate-b");
    let other_package = package_for_payload(&fixture, &other_payload);
    let Ok(other_envelope) = TariTriptychProofEnvelopeV1::from_bytes(other_package.proof()) else {
        panic!("second real Triptych proof envelope must decode");
    };
    let Some(serialized_a) = other_envelope.triptych_proof_bytes().get(8..40) else {
        panic!("Triptych proof must contain its first serialized point");
    };
    let other_envelope_bytes = other_envelope.to_bytes();
    let Some(version_and_linking_tag) =
        other_envelope_bytes.get(..TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES)
    else {
        panic!("Triptych proof envelope must contain its fixed header");
    };
    let proof_suffixes = [
        ("one zero byte", vec![0_u8]),
        ("one nonzero byte", vec![0xa5_u8]),
        (
            "eight arbitrary bytes",
            vec![0x10_u8, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87],
        ),
        ("thirty-two arbitrary bytes", vec![0x5a_u8; 32]),
        (
            "a serialized point copied from another valid proof",
            serialized_a.to_vec(),
        ),
        (
            "another envelope version and linking-tag header",
            version_and_linking_tag.to_vec(),
        ),
        ("another complete valid envelope", other_envelope_bytes),
    ];

    for (label, suffix) in proof_suffixes {
        let mut mutated_inner_proof = original_inner_proof.clone();
        mutated_inner_proof.extend_from_slice(&suffix);
        let Ok(mutated_envelope) =
            TariTriptychProofEnvelopeV1::new(*envelope.linking_tag_bytes(), mutated_inner_proof)
        else {
            panic!("appended inner proof bytes must remain structurally encodable");
        };
        let Ok(mutated_package) = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: package.protocol_version(),
            manifest_hash: package.manifest_hash(),
            proof_suite_id: package.proof_suite_id().to_owned(),
            proof: mutated_envelope.to_bytes(),
            payload: package.payload().clone(),
        }) else {
            panic!("package containing an appended proof envelope must remain canonical");
        };
        let Ok(mutated_package_bytes) = mutated_package.to_canonical_cbor() else {
            panic!("package containing an appended proof envelope must encode canonically");
        };
        let Ok(decoded_mutated_package) = BallotPackageV1::from_canonical_cbor(
            &mutated_package_bytes,
            &fixture.candidates,
            approval_limits(),
        ) else {
            panic!("canonical package with an appended proof envelope must decode");
        };

        for repetition in 0..3 {
            assert!(
                matches!(
                    verify_decoded_package(&fixture, &decoded_mutated_package),
                    Err(error) if error.code() == ValidationCode::MalformedProof
                ),
                "{label} was not rejected by proof verification on repetition {repetition}"
            );
        }

        assert_rejected_package_does_not_consume_nullifier(
            &fixture,
            &package_bytes,
            &mutated_package_bytes,
            ValidationCode::MalformedProof,
            label,
        );
    }
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

#[test]
fn real_triptych_v2_question_binds_the_complete_proof_chain() {
    let fixture = v2_fixture(
        b"real-triptych-v2-question",
        "Should the V2 Triptych integration question pass?",
    );
    let changed_question = v2_fixture(
        b"real-triptych-v2-question",
        "Should the changed V2 Triptych integration question pass?",
    );
    let payload = payload(&fixture.candidates, b"candidate-a");
    let provider = TestOnlyDeterministicHasher;

    let Ok(first_manifest_hash) = fixture.manifest.canonical_hash(&provider) else {
        panic!("V2 manifest hash must be derivable");
    };
    let Ok(changed_manifest_hash) = changed_question.manifest.canonical_hash(&provider) else {
        panic!("changed V2 manifest hash must be derivable");
    };
    let Ok(first_scope) = fixture.manifest.canonical_scope(&provider) else {
        panic!("V2 election scope must be derivable");
    };
    let Ok(changed_scope) = changed_question.manifest.canonical_scope(&provider) else {
        panic!("changed V2 election scope must be derivable");
    };

    assert_ne!(first_manifest_hash, changed_manifest_hash);
    assert_ne!(first_scope, changed_scope);

    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("registry-bound Triptych verifier must be constructible");
    };
    let Ok(statement) =
        reconstruct_approval_proof_statement(&fixture.manifest, &payload, &provider)
    else {
        panic!("V2 proof statement must be reconstructible");
    };
    let secret = secret_key();
    let Ok(proof) = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) else {
        panic!("V2 real Triptych proof must be constructible");
    };
    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash: first_manifest_hash,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        proof: proof.clone(),
        payload: payload.clone(),
    }) else {
        panic!("V2 real Triptych package must be structurally valid");
    };

    assert_eq!(package.manifest_hash(), first_manifest_hash);
    assert!(
        verify_approval_proof(&fixture.manifest, &payload, &proof, &provider, &verifier).is_ok()
    );
    assert!(
        verify_approval_proof(
            &changed_question.manifest,
            &payload,
            &proof,
            &provider,
            &verifier,
        )
        .is_err()
    );
}

struct Fixture {
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
}

struct V2Fixture {
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest: ElectionManifestV2,
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

fn v2_fixture(election_id_bytes: &[u8], proposal_question: &str) -> V2Fixture {
    let provider = TestOnlyDeterministicHasher;
    let registry = registry();
    let candidates = candidate_set();

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("test V2 registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("test V2 candidate-set commitment must be derivable");
    };
    let Ok(election_id) = ElectionId::new(election_id_bytes.to_vec()) else {
        panic!("test V2 election ID must be valid");
    };
    let Ok(manifest) = ElectionManifestV2::new(ElectionManifestV2Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "integration-revision-1".to_owned(),
        proposal_question: proposal_question.to_owned(),
    }) else {
        panic!("real Triptych V2 integration manifest must be valid");
    };

    V2Fixture {
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

fn encode(package: &BallotPackageV1) -> Vec<u8> {
    let Ok(bytes) = package.to_canonical_cbor() else {
        panic!("real Triptych package must encode canonically");
    };

    bytes
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

fn assert_rejected_package_does_not_consume_nullifier(
    fixture: &Fixture,
    original_package_bytes: &[u8],
    rejected_package_bytes: &[u8],
    expected_code: ValidationCode,
    label: &str,
) {
    let provider = TestOnlyDeterministicHasher;
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)
    else {
        panic!("registry-bound Triptych verifier must be constructible");
    };
    let lifecycle = open_lifecycle(&fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    for repetition in 0..3 {
        assert!(
            matches!(
                ingest_approval_ballot_package_v1(
                    rejected_package_bytes,
                    &fixture.manifest,
                    &fixture.candidates,
                    &lifecycle,
                    &mut ledger,
                    &provider,
                    &verifier,
                ),
                Err(error) if error.code() == expected_code
            ),
            "{label} was not rejected by manifest-bound ingestion on repetition {repetition}"
        );
        assert!(
            ledger.is_empty(),
            "{label} must not mutate the acceptance ledger before rejection"
        );
    }

    assert!(
        ingest_approval_ballot_package_v1(
            original_package_bytes,
            &fixture.manifest,
            &fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &verifier,
        )
        .is_ok(),
        "the original package must remain acceptable after {label}"
    );
    assert_eq!(ledger.len(), 1);

    assert!(matches!(
        ingest_approval_ballot_package_v1(
            original_package_bytes,
            &fixture.manifest,
            &fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &verifier,
        ),
        Err(error) if error.code() == ValidationCode::DuplicateNullifier
    ));
    assert_eq!(ledger.len(), 1);
}
