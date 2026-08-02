//! Multi-member real Tari Triptych coverage through package replay and tally.
//!
//! This test uses only project-owned public APIs and fixed canonical key
//! fixtures. It demonstrates mechanism coverage for registered non-first
//! members, not a proof of anonymity or production suitability.

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
    BallotAcceptanceLedger, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
    verify_approval_proof,
};

const PUBLIC_KEY_ONE_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

const PUBLIC_KEY_TWO_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c, 0xea, 0x23,
    0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c, 0x73, 0xa3, 0xb9, 0x19,
];

const PUBLIC_KEY_THREE_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0x94, 0x74, 0x1f, 0x5d, 0x5d, 0x52, 0x75, 0x5e, 0xce, 0x4f, 0x23, 0xf0, 0x44, 0xee, 0x27, 0xd5,
    0xd1, 0xea, 0x1e, 0x2b, 0xd1, 0x96, 0xb4, 0x62, 0x16, 0x6b, 0x16, 0x15, 0x2a, 0x9d, 0x02, 0x59,
];

const PUBLIC_KEY_FOUR_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0xda, 0x80, 0x86, 0x27, 0x73, 0x35, 0x8b, 0x46, 0x6f, 0xfa, 0xdf, 0xe0, 0xb3, 0x29, 0x3a, 0xb3,
    0xd9, 0xfd, 0x53, 0xc5, 0xea, 0x6c, 0x95, 0x53, 0x58, 0xf5, 0x68, 0x32, 0x2d, 0xaf, 0x6a, 0x57,
];

const PUBLIC_KEY_FIVE_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0xe8, 0x82, 0xb1, 0x31, 0x01, 0x6b, 0x52, 0xc1, 0xd3, 0x33, 0x70, 0x80, 0x18, 0x7c, 0xf7, 0x68,
    0x42, 0x3e, 0xfc, 0xcb, 0xb5, 0x17, 0xbb, 0x49, 0x5a, 0xb8, 0x12, 0xc4, 0x16, 0x0f, 0xf4, 0x4e,
];

#[test]
fn four_member_non_first_signers_replay_once_each_and_reject_duplicate() {
    let fixture = fixture(b"multi-member-archive-election");
    let registry_keys = canonical_registry_keys();

    assert_eq!(registry_keys.len(), 4);
    assert_eq!(registry_keys[2], PUBLIC_KEY_FOUR_BYTES);
    assert_eq!(registry_keys[3], PUBLIC_KEY_ONE_BYTES);
    assert!(!registry_keys.contains(&PUBLIC_KEY_FIVE_BYTES));
    assert_eq!(fixture.registry.entries().len(), 4);

    let candidate_a = payload(&fixture.candidates, b"candidate-a");
    let candidate_b = payload(&fixture.candidates, b"candidate-b");

    let Ok(first_package) = package_for_secret(&fixture, &candidate_a, scalar_bytes(4)) else {
        panic!("registered fourth-scalar voter must construct a package");
    };
    let Ok(second_package) = package_for_secret(&fixture, &candidate_b, scalar_bytes(1)) else {
        panic!("registered first-scalar voter must construct a package");
    };
    let Ok(duplicate_package) = package_for_secret(&fixture, &candidate_b, scalar_bytes(4)) else {
        panic!("same registered voter must construct a second package");
    };

    let outsider = package_for_secret(&fixture, &candidate_a, scalar_bytes(5));

    assert!(matches!(
        outsider,
        Err(error) if error.code() == ValidationCode::InvalidData
    ));

    let first_bytes = package_bytes(&fixture, &first_package);
    let second_bytes = package_bytes(&fixture, &second_package);
    let duplicate_bytes = package_bytes(&fixture, &duplicate_package);

    let Ok(first_verified) = verify_package_bytes(&fixture, &first_bytes) else {
        panic!("first registered voter package must verify");
    };
    let Ok(second_verified) = verify_package_bytes(&fixture, &second_bytes) else {
        panic!("second registered voter package must verify");
    };
    let Ok(duplicate_verified) = verify_package_bytes(&fixture, &duplicate_bytes) else {
        panic!("same-voter second package must verify cryptographically");
    };

    assert_eq!(
        first_verified.nullifier().as_bytes(),
        duplicate_verified.nullifier().as_bytes(),
    );
    assert_ne!(
        first_verified.nullifier().as_bytes(),
        second_verified.nullifier().as_bytes(),
    );

    let packages = vec![first_bytes, second_bytes, duplicate_bytes];

    let Ok((first_transcript, first_tally)) = replay_packages(&fixture, &packages) else {
        panic!("first multi-member replay must succeed");
    };
    let Ok((second_transcript, second_tally)) = replay_packages(&fixture, &packages) else {
        panic!("second multi-member replay must succeed");
    };

    assert_eq!(second_transcript, first_transcript);
    assert_eq!(second_tally, first_tally);
    assert_eq!(first_transcript.submissions().len(), 3);
    assert_eq!(first_transcript.decisions().len(), 3);
    assert_eq!(first_transcript.accepted_count(), 2);
    assert_eq!(first_transcript.rejected_count(), 1);
    assert!(first_transcript.validate_complete().is_ok());

    assert!(matches!(
        first_transcript.decisions()[0].outcome(),
        BallotDecisionOutcomeV1::Accepted
    ));
    assert!(matches!(
        first_transcript.decisions()[1].outcome(),
        BallotDecisionOutcomeV1::Accepted
    ));
    assert!(matches!(
        first_transcript.decisions()[2].outcome(),
        BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier)
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

    assert_eq!(first_tally.accepted_ballots(), 2);
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
            (b"candidate-b".as_slice(), 1),
        ]
    );

    match first_tally.leading_result() {
        LeadingResult::Tie {
            candidate_ids,
            approvals,
        } => {
            assert_eq!(approvals, 1);
            assert_eq!(candidate_ids.len(), 2);
            assert_eq!(candidate_ids[0].as_bytes(), b"candidate-a");
            assert_eq!(candidate_ids[1].as_bytes(), b"candidate-b");
        }
        other => panic!("expected a one-vote tie, got {other:?}"),
    }
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
        panic!("multi-member registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("candidate-set commitment must be derivable");
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
        governance_source_revision: "multi-member-integration-revision-1".to_owned(),
    }) else {
        panic!("multi-member real Triptych manifest must be valid");
    };

    Fixture {
        registry,
        candidates,
        manifest,
    }
}

fn package_for_secret(
    fixture: &Fixture,
    payload: &ApprovalBallotPayload,
    secret_bytes: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> Result<BallotPackageV1, ProtocolError> {
    let provider = TestOnlyDeterministicHasher;
    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)?;
    let statement = reconstruct_approval_proof_statement(&fixture.manifest, payload, &provider)?;
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(secret_bytes)?;
    let proof = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret)?;
    let manifest_hash = fixture.manifest.canonical_hash(&provider)?;

    BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        proof,
        payload: payload.clone(),
    })
}

fn package_bytes(fixture: &Fixture, package: &BallotPackageV1) -> Vec<u8> {
    let provider = TestOnlyDeterministicHasher;
    let Ok(encoded) = package.to_canonical_cbor() else {
        panic!("multi-member package must encode canonically");
    };
    let Ok(decoded) =
        BallotPackageV1::from_canonical_cbor(&encoded, &fixture.candidates, approval_limits())
    else {
        panic!("multi-member package must decode canonically");
    };
    let Ok(reencoded) = decoded.to_canonical_cbor() else {
        panic!("decoded multi-member package must re-encode");
    };
    let Ok(canonical_hash) = package.canonical_hash(&provider) else {
        panic!("multi-member package hash must be derivable");
    };

    assert_eq!(reencoded, encoded);
    assert_eq!(raw_package_digest(&encoded).as_bytes(), &canonical_hash);

    encoded
}

fn verify_package_bytes(
    fixture: &Fixture,
    bytes: &[u8],
) -> Result<VerifiedApprovalBallotV1, ProtocolError> {
    let provider = TestOnlyDeterministicHasher;
    let package =
        BallotPackageV1::from_canonical_cbor(bytes, &fixture.candidates, approval_limits())?;
    let manifest_hash = fixture.manifest.canonical_hash(&provider)?;

    if package.manifest_hash() != manifest_hash {
        return Err(ProtocolError::new(
            ValidationCode::WrongManifestHash,
            "multi-member package manifest hash does not match the frozen manifest",
        ));
    }

    if package.proof_suite_id() != fixture.manifest.proof_suite_id() {
        return Err(ProtocolError::new(
            ValidationCode::UnsupportedProofSuite,
            "multi-member package proof suite does not match the frozen manifest",
        ));
    }

    let verifier = build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider)?;

    verify_approval_proof(
        &fixture.manifest,
        package.payload(),
        package.proof(),
        &provider,
        &verifier,
    )
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

    for bytes in packages {
        let digest = raw_package_digest(bytes);
        let sequence = transcript.record_submission(digest, true)?;
        let outcome = match verify_package_bytes(fixture, bytes) {
            Ok(verified) => match ledger.accept_verified(&lifecycle, verified) {
                Ok(()) => BallotDecisionOutcomeV1::Accepted,
                Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
            },
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

fn canonical_registry_keys() -> Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]> {
    let mut keys = vec![
        PUBLIC_KEY_ONE_BYTES,
        PUBLIC_KEY_TWO_BYTES,
        PUBLIC_KEY_THREE_BYTES,
        PUBLIC_KEY_FOUR_BYTES,
    ];
    keys.sort_unstable();
    keys
}

fn registry() -> RegistrySnapshot {
    let keys = canonical_registry_keys();
    let mut writer = CanonicalCborWriter::new();

    assert!(writer.write_array_len(keys.len()).is_ok());

    for key in keys {
        assert!(writer.write_byte_string(&key).is_ok());
    }

    let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
        panic!("four-member canonical registry must be valid");
    };

    registry
}

fn scalar_bytes(value: u8) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
    let mut bytes = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
    bytes[0] = value;
    bytes
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
