//! Real Tari Triptych package replay through the metadata-minimized archive model.
//!
//! The test exercises only project-owned public APIs and exact canonical package
//! bytes. It remains prototype-only and does not authorize binding elections,
//! secret-key persistence, or deployment.

use tari_cc_private_ballot_archive::{
    BallotDecisionOutcomeV1, BallotPackageDigestV1, VerificationTranscriptV1,
};
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
    CanonicalCborWriter, HashDomain, PROTOCOL_VERSION_V1, ProtocolError, ValidationCode,
    hash_domain_separated, test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, build_tari_triptych_verifier_from_registry_v1,
    ingest_approval_ballot_package_v1, reconstruct_approval_proof_statement,
};

const RISTRETTO_BASEPOINT_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

const SECRET_SCALAR_ONE_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn real_triptych_packages_replay_to_complete_transcript_and_first_valid_tally() {
    let fixture = fixture(b"archive-replay-election");
    let first_payload = payload(&fixture.candidates, b"candidate-a");
    let duplicate_payload = payload(&fixture.candidates, b"candidate-b");
    let first_package = package_for_payload(&fixture, &first_payload);
    let duplicate_package = package_for_payload(&fixture, &duplicate_payload);

    let first_bytes = package_bytes(&fixture, &first_package);
    let duplicate_bytes = package_bytes(&fixture, &duplicate_package);
    let tampered_bytes = tampered_package_bytes(&fixture, &first_package);
    let packages = vec![first_bytes, duplicate_bytes, tampered_bytes];

    assert_ne!(
        raw_package_digest(&packages[0]),
        raw_package_digest(&packages[2]),
    );

    let Ok((first_transcript, first_tally)) = replay_packages(&fixture, &packages) else {
        panic!("first real Triptych archive replay must succeed");
    };
    let Ok((second_transcript, second_tally)) = replay_packages(&fixture, &packages) else {
        panic!("second real Triptych archive replay must succeed");
    };

    assert_eq!(second_transcript, first_transcript);
    assert_eq!(second_tally, first_tally);
    assert_eq!(first_transcript.submissions().len(), 3);
    assert_eq!(first_transcript.decisions().len(), 3);
    assert_eq!(first_transcript.accepted_count(), 1);
    assert_eq!(first_transcript.rejected_count(), 2);
    assert!(first_transcript.validate_complete().is_ok());

    assert!(matches!(
        first_transcript.decisions()[0].outcome(),
        BallotDecisionOutcomeV1::Accepted
    ));
    assert!(matches!(
        first_transcript.decisions()[1].outcome(),
        BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier)
    ));
    assert!(matches!(
        first_transcript.decisions()[2].outcome(),
        BallotDecisionOutcomeV1::Rejected(code)
            if code != ValidationCode::DuplicateNullifier
    ));

    for (index, (submission, bytes)) in first_transcript
        .submissions()
        .iter()
        .zip(&packages)
        .enumerate()
    {
        let Ok(expected_sequence) = u64::try_from(index) else {
            panic!("test submission index must fit in u64");
        };

        assert_eq!(submission.sequence().value(), expected_sequence);
        assert_eq!(submission.package_digest(), raw_package_digest(bytes));
        assert!(submission.received_before_close());
    }

    assert_eq!(first_tally.accepted_ballots(), 1);
    assert_eq!(first_tally.abstentions(), 0);

    let counts: Vec<(&[u8], u64)> = first_tally
        .counts()
        .iter()
        .map(|count| (count.candidate_id().as_bytes(), count.approvals()))
        .collect();

    assert_eq!(
        counts,
        vec![
            (b"candidate-a".as_slice(), 1),
            (b"candidate-b".as_slice(), 0),
        ]
    );
    assert!(matches!(
        first_tally.leading_result(),
        LeadingResult::SingleLeader {
            candidate_id,
            approvals: 1,
        } if candidate_id.as_bytes() == b"candidate-a"
    ));
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
        governance_source_revision: "archive-replay-integration-revision-1".to_owned(),
    }) else {
        panic!("real Triptych archive-replay manifest must be valid");
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
        panic!("archive-replay proof statement must be reconstructible");
    };
    let secret = secret_key();
    let Ok(proof) = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) else {
        panic!("real Triptych archive-replay proof must be constructible");
    };
    let Ok(manifest_hash) = fixture.manifest.canonical_hash(&provider) else {
        panic!("archive-replay manifest hash must be derivable");
    };
    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        proof,
        payload: payload.clone(),
    }) else {
        panic!("real Triptych archive-replay package must be valid");
    };

    package
}

fn package_bytes(fixture: &Fixture, package: &BallotPackageV1) -> Vec<u8> {
    let provider = TestOnlyDeterministicHasher;
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
    let Ok(canonical_hash) = package.canonical_hash(&provider) else {
        panic!("real Triptych package hash must be derivable");
    };

    assert_eq!(reencoded, encoded);
    assert_eq!(raw_package_digest(&encoded).as_bytes(), &canonical_hash);

    encoded
}

fn tampered_package_bytes(fixture: &Fixture, package: &BallotPackageV1) -> Vec<u8> {
    let mut tampered_proof = package.proof().to_vec();

    let Some(version_byte) = tampered_proof.first_mut() else {
        panic!("real Triptych proof envelope must not be empty");
    };

    *version_byte ^= 0x01;

    let Ok(tampered) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: package.protocol_version(),
        manifest_hash: package.manifest_hash(),
        proof_suite_id: package.proof_suite_id().to_owned(),
        proof: tampered_proof,
        payload: package.payload().clone(),
    }) else {
        panic!("structurally valid proof-tampered package must be constructible");
    };

    package_bytes(fixture, &tampered)
}

fn replay_packages(
    fixture: &Fixture,
    packages: &[Vec<u8>],
) -> Result<(VerificationTranscriptV1, ApprovalTally), ProtocolError> {
    let provider = TestOnlyDeterministicHasher;
    let manifest_hash = fixture.manifest.canonical_hash(&provider)?;
    let lifecycle = open_lifecycle(&fixture.manifest)?;
    let mut transcript = VerificationTranscriptV1::new(manifest_hash);
    let mut ledger = BallotAcceptanceLedger::new();
    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)?;

    for bytes in packages {
        let digest = raw_package_digest(bytes);
        let sequence = transcript.record_submission(digest, true)?;
        let outcome = match ingest_approval_ballot_package_v1(
            bytes,
            &fixture.manifest,
            &fixture.candidates,
            &lifecycle,
            &mut ledger,
            &provider,
            &verifier,
        ) {
            Ok(()) => BallotDecisionOutcomeV1::Accepted,
            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
        };

        transcript.record_decision(sequence, digest, outcome)?;
    }

    transcript.validate_complete()?;

    let accepted_payloads = ledger
        .accepted_ballots()
        .iter()
        .map(|ballot| ballot.payload());
    let tally = ApprovalTally::from_ballots(&fixture.candidates, accepted_payloads)?;

    Ok((transcript, tally))
}

fn raw_package_digest(bytes: &[u8]) -> BallotPackageDigestV1 {
    let provider = TestOnlyDeterministicHasher;

    BallotPackageDigestV1::new(hash_domain_separated(
        &provider,
        HashDomain::BallotPackageV1,
        bytes,
    ))
}

fn open_lifecycle(manifest: &ElectionManifestV1) -> Result<ElectionLifecycleV1, ProtocolError> {
    let provider = TestOnlyDeterministicHasher;
    let manifest_hash = manifest.canonical_hash(&provider)?;
    let mut lifecycle = ElectionLifecycleV1::new();

    lifecycle.freeze(manifest_hash, manifest.registry_commitment())?;
    lifecycle.open()?;

    Ok(lifecycle)
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
