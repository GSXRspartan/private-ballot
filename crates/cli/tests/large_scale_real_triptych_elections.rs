//! Complete large-scale real Tari Triptych election tests.
//!
//! Runs 128, 250, and three independent 256-voter elections with
//! real proofs, duplicate rejection, outsider rejection, replay,
//! mixed tallies, and release-mode performance metrics.

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

const FIXTURE_KEY_COUNT: usize = 2_048;
const FIXTURE_KEYS: &[u8; FIXTURE_KEY_COUNT * RISTRETTO_COMPRESSED_POINT_BYTES] =
    include_bytes!("fixtures/triptych_large_election_keys_2048.bin");

#[test]
#[ignore = "manual complete 128/250/256-voter Triptych elections"]
fn manual_large_scale_real_triptych_elections_pass() {
    let case_128 = run_large_election_case(128, 0, 1);
    assert_case(&case_128, 128);

    let case_250 = run_large_election_case(250, 300, 2);
    assert_case(&case_250, 250);

    let case_256_a = run_large_election_case(256, 600, 3);
    let case_256_b = run_large_election_case(256, 900, 4);
    let case_256_c = run_large_election_case(256, 1_200, 5);

    assert_case(&case_256_a, 256);
    assert_case(&case_256_b, 256);
    assert_case(&case_256_c, 256);

    assert_ne!(case_256_a.first_nullifier, case_256_b.first_nullifier);
    assert_ne!(case_256_a.first_nullifier, case_256_c.first_nullifier);
    assert_ne!(case_256_b.first_nullifier, case_256_c.first_nullifier);

    assert_eq!(case_256_a.tally_total, case_256_b.tally_total);
    assert_eq!(case_256_a.tally_total, case_256_c.tally_total);
}

fn assert_case(result: &CaseResult, members: usize) {
    assert_eq!(result.accepted, members);
    assert_eq!(result.rejected, 1);

    let Ok(expected_total) = u64::try_from(members) else {
        panic!("large-election member count must fit in u64");
    };

    assert_eq!(result.tally_total, expected_total);
    assert!(result.proof_bytes > 0);
    assert!(result.package_bytes > result.proof_bytes);
}

struct CaseResult {
    accepted: usize,
    rejected: usize,
    tally_total: u64,
    proof_bytes: usize,
    package_bytes: usize,
    first_nullifier: Vec<u8>,
}

struct Fixture {
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
}

fn run_large_election_case(members: usize, key_offset: usize, election_run: usize) -> CaseResult {
    let fixture = fixture(members, key_offset, election_run);
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
        let member_scalar = key_offset + scalar;
        let Ok(package) = package_for_secret(&fixture, &ballot, scalar_bytes(member_scalar)) else {
            panic!("registered governance voter must construct a package");
        };

        proof_bytes += package.proof().len();

        let encoded = package_bytes(&fixture, &package);
        package_bytes_total += encoded.len();
        packages.push(encoded);
    }

    {
        let duplicate_payload = payload(&fixture.candidates, b"candidate-b");
        let Ok(duplicate_package) =
            package_for_secret(&fixture, &duplicate_payload, scalar_bytes(key_offset + 1))
        else {
            panic!("registered voter must construct a duplicate package");
        };

        proof_bytes += duplicate_package.proof().len();

        let encoded = package_bytes(&fixture, &duplicate_package);
        package_bytes_total += encoded.len();
        packages.push(encoded);
    }

    let outsider_payload = payload(&fixture.candidates, b"candidate-a");
    let outsider = package_for_secret(
        &fixture,
        &outsider_payload,
        scalar_bytes(key_offset + members + 1),
    );

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
    assert_eq!(transcript.rejected_count(), 1,);

    {
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

    let Some(first_nullifier) = first_verified_nullifier(&fixture, &packages) else {
        panic!("first verified nullifier must exist");
    };

    CaseResult {
        accepted: transcript.accepted_count(),
        rejected: transcript.rejected_count(),
        tally_total,
        proof_bytes,
        package_bytes: package_bytes_total,
        first_nullifier,
    }
}

fn fixture(members: usize, key_offset: usize, election_run: usize) -> Fixture {
    let provider = TestOnlyDeterministicHasher;
    let registry = registry(members, key_offset);
    let candidates = candidate_set();

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("governance registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("candidate-set commitment must be derivable");
    };
    let election_id_bytes = format!("large-election-{members}-run-{election_run}");
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
        governance_source_revision: format!("large-election-{members}-run-{election_run}"),
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

fn registry(members: usize, key_offset: usize) -> RegistrySnapshot {
    assert!(matches!(members, 128 | 250 | 256));
    assert!(key_offset + members <= FIXTURE_KEY_COUNT);

    let mut keys = FIXTURE_KEYS
        .chunks_exact(RISTRETTO_COMPRESSED_POINT_BYTES)
        .skip(key_offset)
        .take(members)
        .map(|key| key.to_vec())
        .collect::<Vec<_>>();
    keys.sort_unstable();

    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(keys.len()).is_ok());

    for key in keys {
        assert!(writer.write_byte_string(&key).is_ok());
    }

    let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
        panic!("large-election canonical registry must be valid");
    };

    registry
}

fn scalar_bytes(value: usize) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
    let Ok(value) = u64::try_from(value) else {
        panic!("fixture scalar must fit in u64");
    };

    let mut bytes = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn first_verified_nullifier(election: &Fixture, packages: &[Vec<u8>]) -> Option<Vec<u8>> {
    for bytes in packages {
        if let Ok(verified) = verify_package_bytes(election, bytes) {
            return Some(verified.nullifier().as_bytes().to_vec());
        }
    }

    None
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
