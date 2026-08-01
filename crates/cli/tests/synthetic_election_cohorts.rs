use tari_cc_private_ballot_archive::{
    BallotDecisionOutcomeV1, BallotPackageDigestV1, VerificationTranscriptV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
    CandidateDefinition, CandidateId, CandidateSet, ElectionId, ElectionLifecycleV1,
    ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::test_only_verifier::TestOnlyProofVerifierV1;
use tari_cc_private_ballot_protocol::{
    ManifestHash, PROTOCOL_VERSION_V1, RegistryCommitment, TEST_ONLY_SUITE_ID, ValidationCode,
    test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, reconstruct_approval_proof_statement, verify_approval_proof,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CohortSummary {
    accepted_ballots: usize,
    duplicate_rejections: usize,
    abstentions: u64,
    counts: Vec<(Vec<u8>, u64)>,
    leading_result: LeadingResult,
    accepted_nullifiers: Vec<Vec<u8>>,
}

fn candidate_id(index: usize) -> CandidateId {
    let value = format!("candidate-{index:03}").into_bytes();

    let Ok(id) = CandidateId::new(value) else {
        panic!("synthetic candidate identifier must be valid");
    };

    id
}

fn candidate_set(candidate_count: usize) -> CandidateSet {
    let mut candidates = Vec::with_capacity(candidate_count);

    for index in (0..candidate_count).rev() {
        let id = candidate_id(index);
        let name = format!("Synthetic Candidate {index:03}");

        let Ok(candidate) = CandidateDefinition::new(id, name) else {
            panic!("synthetic candidate definition must be valid");
        };

        candidates.push(candidate);
    }

    let Ok(candidates) = CandidateSet::new(candidates) else {
        panic!("synthetic candidate set must be valid");
    };

    candidates
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 2, true) else {
        panic!("synthetic approval limits must be valid");
    };

    limits
}

fn manifest(candidates: &CandidateSet) -> ElectionManifestV1 {
    let provider = TestOnlyDeterministicHasher;

    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("synthetic candidate-set commitment must succeed");
    };

    let Ok(election_id) = ElectionId::new(b"synthetic-election-cohort-v1".to_vec()) else {
        panic!("synthetic election identifier must be valid");
    };

    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: RegistryCommitment::new([7_u8; 32]),
        candidate_set_commitment,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "synthetic-cohort-revision-1".to_owned(),
    }) else {
        panic!("synthetic election manifest must be valid");
    };

    manifest
}

fn open_lifecycle(manifest: &ElectionManifestV1) -> ElectionLifecycleV1 {
    let provider = TestOnlyDeterministicHasher;

    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("synthetic manifest hash must succeed");
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

fn selection_indices(voter_index: usize, candidate_count: usize) -> Vec<usize> {
    if voter_index.is_multiple_of(11) {
        return Vec::new();
    }

    let first = voter_index % candidate_count;

    if !voter_index.is_multiple_of(5) {
        return vec![first];
    }

    let mut second = (voter_index.wrapping_mul(3).wrapping_add(1)) % candidate_count;

    if second == first {
        second = (second + 1) % candidate_count;
    }

    vec![first, second]
}

fn payload(candidates: &CandidateSet, selection_indices: &[usize]) -> ApprovalBallotPayload {
    let selections = selection_indices
        .iter()
        .copied()
        .map(candidate_id)
        .collect();

    let Ok(payload) = ApprovalBallotPayload::new(selections, candidates, approval_limits()) else {
        panic!("synthetic approval payload must be valid");
    };

    payload
}

fn nullifier(voter_index: usize) -> Vec<u8> {
    format!("synthetic-nullifier-{voter_index:08}").into_bytes()
}

fn verified_ballot(
    manifest: &ElectionManifestV1,
    payload: &ApprovalBallotPayload,
    nullifier: Vec<u8>,
) -> tari_cc_private_ballot_verifier::VerifiedApprovalBallotV1 {
    let provider = TestOnlyDeterministicHasher;

    let Ok(statement) = reconstruct_approval_proof_statement(manifest, payload, &provider) else {
        panic!("synthetic proof statement must be valid");
    };

    let Ok(proof) = TestOnlyProofVerifierV1::proof_for(&statement) else {
        panic!("synthetic test-only proof must be constructible");
    };

    let Ok(verifier) = TestOnlyProofVerifierV1::new(nullifier) else {
        panic!("synthetic test verifier must be valid");
    };

    let Ok(ballot) = verify_approval_proof(manifest, payload, &proof, &provider, &verifier) else {
        panic!("synthetic test-only proof must verify");
    };

    ballot
}

fn assert_leading_result(result: &LeadingResult, expected_counts: &[u64]) {
    let Some(maximum) = expected_counts.iter().copied().max() else {
        panic!("synthetic candidate counts must not be empty");
    };

    if maximum == 0 {
        assert_eq!(result, &LeadingResult::NoApprovals);
        return;
    }

    let expected_leaders: Vec<CandidateId> = expected_counts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, approvals)| *approvals == maximum)
        .map(|(index, _)| candidate_id(index))
        .collect();

    if expected_leaders.len() == 1 {
        assert_eq!(
            result,
            &LeadingResult::SingleLeader {
                candidate_id: expected_leaders[0].clone(),
                approvals: maximum,
            }
        );
        return;
    }

    assert_eq!(
        result,
        &LeadingResult::Tie {
            candidate_ids: expected_leaders,
            approvals: maximum,
        }
    );
}

fn run_cohort(voter_count: usize, candidate_count: usize) -> CohortSummary {
    assert!(voter_count > 0);
    assert!(candidate_count >= 2);

    let candidates = candidate_set(candidate_count);
    let manifest = manifest(&candidates);
    let lifecycle = open_lifecycle(&manifest);
    let mut ledger = BallotAcceptanceLedger::new();
    let mut expected_counts = vec![0_u64; candidate_count];
    let mut expected_abstentions = 0_u64;
    let mut duplicate_rejections = 0_usize;

    for voter_index in 0..voter_count {
        let indices = selection_indices(voter_index, candidate_count);
        let ballot_payload = payload(&candidates, &indices);

        if indices.is_empty() {
            let Some(next) = expected_abstentions.checked_add(1) else {
                panic!("synthetic abstention count overflowed");
            };
            expected_abstentions = next;
        }

        for index in indices.iter().copied() {
            let Some(next) = expected_counts[index].checked_add(1) else {
                panic!("synthetic approval count overflowed");
            };
            expected_counts[index] = next;
        }

        let voter_nullifier = nullifier(voter_index);
        let ballot = verified_ballot(&manifest, &ballot_payload, voter_nullifier.clone());

        assert!(ledger.accept_verified(&lifecycle, ballot).is_ok());

        if voter_index.is_multiple_of(17) {
            let alternate_index = (voter_index + 1) % candidate_count;
            let alternate_payload = payload(&candidates, &[alternate_index]);
            let duplicate = verified_ballot(&manifest, &alternate_payload, voter_nullifier);

            let result = ledger.accept_verified(&lifecycle, duplicate);

            assert!(matches!(
                result,
                Err(error) if error.code() == ValidationCode::DuplicateNullifier
            ));

            duplicate_rejections += 1;
        }
    }

    assert_eq!(ledger.len(), voter_count);

    let accepted_payloads = ledger
        .accepted_ballots()
        .iter()
        .map(|ballot| ballot.payload());

    let Ok(tally) = ApprovalTally::from_ballots(&candidates, accepted_payloads) else {
        panic!("synthetic accepted ballots must tally");
    };

    let Ok(voter_count_u64) = u64::try_from(voter_count) else {
        panic!("synthetic voter count must fit in u64");
    };

    assert_eq!(tally.accepted_ballots(), voter_count_u64);
    assert_eq!(tally.abstentions(), expected_abstentions);
    assert_eq!(tally.counts().len(), candidate_count);

    for (index, count) in tally.counts().iter().enumerate() {
        assert_eq!(count.candidate_id(), &candidate_id(index));
        assert_eq!(count.approvals(), expected_counts[index]);
    }

    let leading_result = tally.leading_result();
    assert_leading_result(&leading_result, &expected_counts);

    let counts = tally
        .counts()
        .iter()
        .map(|count| (count.candidate_id().as_bytes().to_vec(), count.approvals()))
        .collect();

    let accepted_nullifiers = ledger
        .accepted_ballots()
        .iter()
        .map(|ballot| ballot.election_scoped_nullifier().to_vec())
        .collect();

    CohortSummary {
        accepted_ballots: ledger.len(),
        duplicate_rejections,
        abstentions: tally.abstentions(),
        counts,
        leading_result,
        accepted_nullifiers,
    }
}

fn package_digest(index: usize) -> BallotPackageDigestV1 {
    let Ok(value) = u64::try_from(index) else {
        panic!("synthetic replay index must fit in u64");
    };

    let mut bytes = [0_u8; 32];
    bytes[0..8].copy_from_slice(&value.to_be_bytes());
    bytes[8..16].copy_from_slice(&value.rotate_left(13).to_be_bytes());
    bytes[16..24].copy_from_slice(&value.wrapping_mul(17).to_be_bytes());
    bytes[24..32].copy_from_slice(&value.wrapping_add(0x5a5a).to_be_bytes());

    BallotPackageDigestV1::new(bytes)
}

fn replay_transcript(submission_count: usize) -> VerificationTranscriptV1 {
    let mut transcript = VerificationTranscriptV1::new(ManifestHash::new([9_u8; 32]));

    let mut records = Vec::with_capacity(submission_count);

    for index in 0..submission_count {
        let digest = package_digest(index);
        let received_before_close = !index.is_multiple_of(13);

        let Ok(sequence) = transcript.record_submission(digest, received_before_close) else {
            panic!("synthetic replay submission must be recorded");
        };

        records.push((sequence, digest, received_before_close));
    }

    for (index, (sequence, digest, received_before_close)) in records.into_iter().enumerate() {
        let outcome = if !received_before_close {
            BallotDecisionOutcomeV1::Rejected(ValidationCode::ElectionNotOpen)
        } else if index.is_multiple_of(5) {
            BallotDecisionOutcomeV1::Rejected(ValidationCode::MalformedProof)
        } else {
            BallotDecisionOutcomeV1::Accepted
        };

        assert!(
            transcript
                .record_decision(sequence, digest, outcome)
                .is_ok()
        );
    }

    transcript
}

#[test]
fn small_medium_and_large_cohorts_preserve_exact_acceptance_and_tallies() {
    let cases = [(32_usize, 3_usize), (257, 7), (1_024, 11)];

    for (voter_count, candidate_count) in cases {
        let summary = run_cohort(voter_count, candidate_count);

        assert_eq!(summary.accepted_ballots, voter_count);
        assert_eq!(summary.duplicate_rejections, ((voter_count - 1) / 17) + 1);
        assert_eq!(summary.counts.len(), candidate_count);
        assert_eq!(summary.accepted_nullifiers.len(), voter_count);
    }
}

#[test]
fn repeated_synthetic_cohort_runs_are_identical() {
    let first = run_cohort(513, 9);
    let second = run_cohort(513, 9);

    assert_eq!(first, second);
}

#[test]
fn large_replay_transcript_is_complete_ordered_and_deterministic() {
    const SUBMISSION_COUNT: usize = 4_096;

    let first = replay_transcript(SUBMISSION_COUNT);
    let second = replay_transcript(SUBMISSION_COUNT);

    assert_eq!(first, second);
    assert_eq!(first.submissions().len(), SUBMISSION_COUNT);
    assert_eq!(first.decisions().len(), SUBMISSION_COUNT);
    assert!(first.validate_complete().is_ok());

    for (index, submission) in first.submissions().iter().enumerate() {
        let Ok(expected_sequence) = u64::try_from(index) else {
            panic!("synthetic replay index must fit in u64");
        };

        assert_eq!(submission.sequence().value(), expected_sequence);
        assert_eq!(submission.package_digest(), package_digest(index));
        assert_eq!(
            submission.received_before_close(),
            !index.is_multiple_of(13)
        );
    }

    let expected_rejected = (0..SUBMISSION_COUNT)
        .filter(|index| (*index).is_multiple_of(13) || (*index).is_multiple_of(5))
        .count();

    assert_eq!(first.rejected_count(), expected_rejected);
    assert_eq!(first.accepted_count(), SUBMISSION_COUNT - expected_rejected);
}
