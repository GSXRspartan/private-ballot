//! Governance-scale real Tari Triptych regressions.
//!
//! These tests cover the accepted maximum Council size of seven and the
//! proposed Core Contributor bootstrap threshold of eleven. They use fixed,
//! probe-verified Ristretto public keys and project-owned public APIs only.
//! This is mechanism and capacity coverage, not a proof of anonymity or
//! production suitability.

use std::time::Instant;

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
use tari_cc_private_ballot_tally::ApprovalTally;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
    verify_approval_proof,
};

const PUBLIC_KEYS: [[u8; RISTRETTO_COMPRESSED_POINT_BYTES]; 12] = [
    [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ],
    [
        0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c, 0xea,
        0x23, 0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c, 0x73, 0xa3,
        0xb9, 0x19,
    ],
    [
        0x94, 0x74, 0x1f, 0x5d, 0x5d, 0x52, 0x75, 0x5e, 0xce, 0x4f, 0x23, 0xf0, 0x44, 0xee, 0x27,
        0xd5, 0xd1, 0xea, 0x1e, 0x2b, 0xd1, 0x96, 0xb4, 0x62, 0x16, 0x6b, 0x16, 0x15, 0x2a, 0x9d,
        0x02, 0x59,
    ],
    [
        0xda, 0x80, 0x86, 0x27, 0x73, 0x35, 0x8b, 0x46, 0x6f, 0xfa, 0xdf, 0xe0, 0xb3, 0x29, 0x3a,
        0xb3, 0xd9, 0xfd, 0x53, 0xc5, 0xea, 0x6c, 0x95, 0x53, 0x58, 0xf5, 0x68, 0x32, 0x2d, 0xaf,
        0x6a, 0x57,
    ],
    [
        0xe8, 0x82, 0xb1, 0x31, 0x01, 0x6b, 0x52, 0xc1, 0xd3, 0x33, 0x70, 0x80, 0x18, 0x7c, 0xf7,
        0x68, 0x42, 0x3e, 0xfc, 0xcb, 0xb5, 0x17, 0xbb, 0x49, 0x5a, 0xb8, 0x12, 0xc4, 0x16, 0x0f,
        0xf4, 0x4e,
    ],
    [
        0xf6, 0x47, 0x46, 0xd3, 0xc9, 0x2b, 0x13, 0x05, 0x0e, 0xd8, 0xd8, 0x02, 0x36, 0xa7, 0xf0,
        0x00, 0x7c, 0x3b, 0x3f, 0x96, 0x2f, 0x5b, 0xa7, 0x93, 0xd1, 0x9a, 0x60, 0x1e, 0xbb, 0x1d,
        0xf4, 0x03,
    ],
    [
        0x44, 0xf5, 0x35, 0x20, 0x92, 0x6e, 0xc8, 0x1f, 0xbd, 0x5a, 0x38, 0x78, 0x45, 0xbe, 0xb7,
        0xdf, 0x85, 0xa9, 0x6a, 0x24, 0xec, 0xe1, 0x87, 0x38, 0xbd, 0xcf, 0xa6, 0xa7, 0x82, 0x2a,
        0x17, 0x6d,
    ],
    [
        0x90, 0x32, 0x93, 0xd8, 0xf2, 0x28, 0x7e, 0xbe, 0x10, 0xe2, 0x37, 0x4d, 0xc1, 0xa5, 0x3e,
        0x0b, 0xc8, 0x87, 0xe5, 0x92, 0x69, 0x9f, 0x02, 0xd0, 0x77, 0xd5, 0x26, 0x3c, 0xdd, 0x55,
        0x60, 0x1c,
    ],
    [
        0x02, 0x62, 0x2a, 0xce, 0x8f, 0x73, 0x03, 0xa3, 0x1c, 0xaf, 0xc6, 0x3f, 0x8f, 0xc4, 0x8f,
        0xdc, 0x16, 0xe1, 0xc8, 0xc8, 0xd2, 0x34, 0xb2, 0xf0, 0xd6, 0x68, 0x52, 0x82, 0xa9, 0x07,
        0x60, 0x31,
    ],
    [
        0x20, 0x70, 0x6f, 0xd7, 0x88, 0xb2, 0x72, 0x0a, 0x1e, 0xd2, 0xa5, 0xda, 0xd4, 0x95, 0x2b,
        0x01, 0xf4, 0x13, 0xbc, 0xf0, 0xe7, 0x56, 0x4d, 0xe8, 0xcd, 0xc8, 0x16, 0x68, 0x9e, 0x2d,
        0xb9, 0x5f,
    ],
    [
        0xbc, 0xe8, 0x3f, 0x8b, 0xa5, 0xdd, 0x2f, 0xa5, 0x72, 0x86, 0x4c, 0x24, 0xba, 0x18, 0x10,
        0xf9, 0x52, 0x2b, 0xc6, 0x00, 0x4a, 0xfe, 0x95, 0x87, 0x7a, 0xc7, 0x32, 0x41, 0xca, 0xfd,
        0xab, 0x42,
    ],
    [
        0xe4, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30, 0x99, 0xca, 0x20, 0x8c, 0x67, 0xad, 0xaf,
        0xca, 0xfa, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde, 0x60, 0x26, 0xe3, 0xca, 0x8f, 0xf8,
        0x44, 0x60,
    ],
];

#[test]
fn seven_member_council_registry_accepts_every_registered_voter_once() {
    let result = run_governance_case(7, false);

    assert_eq!(result.accepted, 7);
    assert_eq!(result.rejected, 0);
    assert_eq!(result.tally_total, 7);
    assert!(result.proof_bytes > 0);
    assert!(result.package_bytes > result.proof_bytes);
}

#[test]
fn eleven_member_cc_registry_accepts_every_voter_and_rejects_one_duplicate() {
    let result = run_governance_case(11, true);

    assert_eq!(result.accepted, 11);
    assert_eq!(result.rejected, 1);
    assert_eq!(result.tally_total, 11);
    assert!(result.proof_bytes > 0);
    assert!(result.package_bytes > result.proof_bytes);
}

struct CaseResult {
    accepted: usize,
    rejected: usize,
    tally_total: u64,
    proof_bytes: usize,
    package_bytes: usize,
}

struct Fixture {
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
}

fn run_governance_case(members: usize, include_duplicate: bool) -> CaseResult {
    let fixture = fixture(members);
    let prove_started = Instant::now();
    let mut packages = Vec::new();
    let mut proof_bytes = 0_usize;
    let mut package_bytes_total = 0_usize;

    for scalar in 1..=members {
        let candidate = if scalar % 2 == 0 {
            b"candidate-b".as_slice()
        } else {
            b"candidate-a".as_slice()
        };
        let ballot = payload(&fixture.candidates, candidate);
        let Ok(member_scalar) = u8::try_from(scalar) else {
            panic!("member scalar must fit in u8");
        };
        let Ok(package) = package_for_secret(&fixture, &ballot, scalar_bytes(member_scalar)) else {
            panic!("registered governance voter must construct a package");
        };

        proof_bytes += package.proof().len();

        let encoded = package_bytes(&fixture, &package);
        package_bytes_total += encoded.len();
        packages.push(encoded);
    }

    if include_duplicate {
        let duplicate_payload = payload(&fixture.candidates, b"candidate-b");
        let Ok(duplicate_package) =
            package_for_secret(&fixture, &duplicate_payload, scalar_bytes(1))
        else {
            panic!("registered voter must construct a duplicate package");
        };

        proof_bytes += duplicate_package.proof().len();

        let encoded = package_bytes(&fixture, &duplicate_package);
        package_bytes_total += encoded.len();
        packages.push(encoded);
    }

    let outsider_payload = payload(&fixture.candidates, b"candidate-a");
    let outsider = package_for_secret(&fixture, &outsider_payload, scalar_bytes(12));

    assert!(matches!(
        outsider,
        Err(error) if error.code() == ValidationCode::InvalidData
    ));

    let prove_elapsed = prove_started.elapsed();
    let replay_started = Instant::now();
    let Ok((transcript, tally)) = replay_packages(&fixture, &packages) else {
        panic!("governance-scale replay must succeed");
    };
    let replay_elapsed = replay_started.elapsed();

    assert!(transcript.validate_complete().is_ok());
    assert_eq!(transcript.accepted_count(), members);
    assert_eq!(transcript.rejected_count(), usize::from(include_duplicate),);

    if include_duplicate {
        let Some(last) = transcript.decisions().last() else {
            panic!("duplicate decision must exist");
        };

        assert!(matches!(
            last.outcome(),
            BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier)
        ));
    }

    let tally_total = tally
        .counts()
        .iter()
        .map(|count| count.approvals())
        .sum::<u64>();

    println!(
        "governance_scale members={members} padded_capacity={} prove_ms={} replay_ms={} \
         proof_bytes={} package_bytes={} accepted={} rejected={}",
        members.next_power_of_two(),
        prove_elapsed.as_millis(),
        replay_elapsed.as_millis(),
        proof_bytes,
        package_bytes_total,
        transcript.accepted_count(),
        transcript.rejected_count(),
    );

    CaseResult {
        accepted: transcript.accepted_count(),
        rejected: transcript.rejected_count(),
        tally_total,
        proof_bytes,
        package_bytes: package_bytes_total,
    }
}

fn fixture(members: usize) -> Fixture {
    let provider = TestOnlyDeterministicHasher;
    let registry = registry(members);
    let candidates = candidate_set();

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("governance registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("candidate-set commitment must be derivable");
    };
    let election_id_bytes = format!("governance-scale-{members}");
    let Ok(election_id) = ElectionId::new(election_id_bytes.into_bytes()) else {
        panic!("governance election ID must be valid");
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
        governance_source_revision: format!("governance-scale-{members}-revision-1"),
    }) else {
        panic!("governance-scale manifest must be valid");
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
        panic!("governance package must encode canonically");
    };
    let Ok(decoded) =
        BallotPackageV1::from_canonical_cbor(&encoded, &fixture.candidates, approval_limits())
    else {
        panic!("governance package must decode canonically");
    };
    let Ok(reencoded) = decoded.to_canonical_cbor() else {
        panic!("decoded governance package must re-encode");
    };
    let Ok(canonical_hash) = package.canonical_hash(&provider) else {
        panic!("governance package hash must be derivable");
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
            "governance package manifest hash does not match the frozen manifest",
        ));
    }

    if package.proof_suite_id() != fixture.manifest.proof_suite_id() {
        return Err(ProtocolError::new(
            ValidationCode::UnsupportedProofSuite,
            "governance package proof suite does not match the frozen manifest",
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

fn registry(members: usize) -> RegistrySnapshot {
    assert!(matches!(members, 7 | 11));

    let mut keys = PUBLIC_KEYS[..members].to_vec();
    keys.sort_unstable();

    let mut writer = CanonicalCborWriter::new();

    assert!(writer.write_array_len(keys.len()).is_ok());

    for key in keys {
        assert!(writer.write_byte_string(&key).is_ok());
    }

    let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
        panic!("governance-scale canonical registry must be valid");
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
