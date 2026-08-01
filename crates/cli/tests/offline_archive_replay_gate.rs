use std::collections::BTreeMap;

use tari_cc_private_ballot_archive::{
    ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
    BallotDecisionOutcomeV1, BallotPackageDigestV1, VerificationTranscriptV1,
};
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::test_only_verifier::TestOnlyProofVerifierV1;
use tari_cc_private_ballot_protocol::{
    HashDomain, PROTOCOL_VERSION_V1, RegistryCommitment, TEST_ONLY_SUITE_ID, ValidationCode,
    hash_domain_separated, test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, reconstruct_approval_proof_statement, verify_approval_proof,
};

const ELECTION_MANIFEST_PATH: &str = "election-manifest.cbor";
const CANDIDATE_SET_PATH: &str = "candidate-set.cbor";
const VERIFICATION_POLICY_PATH: &str = "verification-policy.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofMode {
    Valid,
    CorruptStatementTranscript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArchivedSubmission {
    path: String,
    bytes: Vec<u8>,
    received_before_close: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElectionFixture {
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
    submissions: Vec<ArchivedSubmission>,
}

#[derive(Debug, PartialEq, Eq)]
struct ReplayResult {
    transcript: VerificationTranscriptV1,
    tally: ApprovalTally,
}

fn candidate_id(value: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(value.to_vec()) else {
        panic!("test option identifier must be valid");
    };

    id
}

fn candidate(value: &[u8], display_name: &str) -> CandidateDefinition {
    let Ok(candidate) = CandidateDefinition::new(candidate_id(value), display_name.to_owned())
    else {
        panic!("test governance option must be valid");
    };

    candidate
}

fn candidate_set() -> CandidateSet {
    let Ok(candidates) = CandidateSet::new(vec![
        candidate(b"reject", "Reject"),
        candidate(b"approve", "Approve"),
        candidate(b"defer", "Defer"),
    ]) else {
        panic!("test governance options must be valid");
    };

    candidates
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 1, true) else {
        panic!("test approval limits must be valid");
    };

    limits
}

fn election_manifest(
    candidates: &CandidateSet,
    provider: &TestOnlyDeterministicHasher,
) -> ElectionManifestV1 {
    let Ok(election_id) = ElectionId::new(b"council-governance-topic-0001".to_vec()) else {
        panic!("test election identifier must be valid");
    };

    let Ok(candidate_set_commitment) = candidates.canonical_commitment(provider) else {
        panic!("test candidate-set commitment must succeed");
    };

    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: RegistryCommitment::new([41_u8; 32]),
        candidate_set_commitment,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "council-and-cc-roster-revision-1".to_owned(),
    }) else {
        panic!("test election manifest must be valid");
    };

    manifest
}

fn payload(candidates: &CandidateSet, selection: Option<&[u8]>) -> ApprovalBallotPayload {
    let selections = selection
        .map(|value| vec![candidate_id(value)])
        .unwrap_or_default();

    let Ok(payload) = ApprovalBallotPayload::new(selections, candidates, approval_limits()) else {
        panic!("test approval payload must be valid");
    };

    payload
}

fn canonical_package_bytes(
    manifest: &ElectionManifestV1,
    candidates: &CandidateSet,
    selection: Option<&[u8]>,
    nullifier: &[u8],
    proof_mode: ProofMode,
    provider: &TestOnlyDeterministicHasher,
) -> Vec<u8> {
    let payload = payload(candidates, selection);

    let Ok(statement) = reconstruct_approval_proof_statement(manifest, &payload, provider) else {
        panic!("test proof statement reconstruction must succeed");
    };

    let Ok(mut proof) = TestOnlyProofVerifierV1::proof_for_with_nullifier(&statement, nullifier)
    else {
        panic!("self-contained test proof construction must succeed");
    };

    if proof_mode == ProofMode::CorruptStatementTranscript {
        let Some(last) = proof.last_mut() else {
            panic!("test proof must contain a statement transcript");
        };

        *last ^= 0x01;
    }

    let Ok(manifest_hash) = manifest.canonical_hash(provider) else {
        panic!("test manifest hash must succeed");
    };

    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: TEST_ONLY_SUITE_ID.to_owned(),
        proof,
        payload,
    }) else {
        panic!("test ballot package must be valid");
    };

    let Ok(bytes) = package.to_canonical_cbor() else {
        panic!("test ballot package encoding must succeed");
    };

    bytes
}

fn submission_path(index: usize) -> String {
    format!("submissions/{index:08}.cbor")
}

fn archived_submission(
    index: usize,
    manifest: &ElectionManifestV1,
    candidates: &CandidateSet,
    selection: Option<&[u8]>,
    nullifier: &[u8],
    proof_mode: ProofMode,
    received_before_close: bool,
) -> ArchivedSubmission {
    let provider = TestOnlyDeterministicHasher;

    ArchivedSubmission {
        path: submission_path(index),
        bytes: canonical_package_bytes(
            manifest, candidates, selection, nullifier, proof_mode, &provider,
        ),
        received_before_close,
    }
}

fn fixture(last_selection: &[u8]) -> ElectionFixture {
    let provider = TestOnlyDeterministicHasher;
    let candidates = candidate_set();
    let manifest = election_manifest(&candidates, &provider);

    let mut submissions = vec![
        archived_submission(
            0,
            &manifest,
            &candidates,
            Some(b"approve"),
            b"nullifier-alpha",
            ProofMode::Valid,
            true,
        ),
        archived_submission(
            1,
            &manifest,
            &candidates,
            Some(b"reject"),
            b"nullifier-beta",
            ProofMode::Valid,
            true,
        ),
        archived_submission(
            2,
            &manifest,
            &candidates,
            Some(b"defer"),
            b"nullifier-alpha",
            ProofMode::Valid,
            true,
        ),
        archived_submission(
            3,
            &manifest,
            &candidates,
            Some(b"approve"),
            b"nullifier-malformed",
            ProofMode::CorruptStatementTranscript,
            true,
        ),
        archived_submission(
            4,
            &manifest,
            &candidates,
            Some(b"reject"),
            b"nullifier-late",
            ProofMode::Valid,
            false,
        ),
        archived_submission(
            5,
            &manifest,
            &candidates,
            None,
            b"nullifier-abstain",
            ProofMode::Valid,
            true,
        ),
        archived_submission(
            6,
            &manifest,
            &candidates,
            Some(last_selection),
            b"nullifier-gamma",
            ProofMode::Valid,
            true,
        ),
    ];

    submissions.reverse();

    ElectionFixture {
        candidates,
        manifest,
        submissions,
    }
}

fn sorted_submissions(submissions: &[ArchivedSubmission]) -> Vec<ArchivedSubmission> {
    let mut sorted = submissions.to_vec();

    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    sorted
}

fn archive_path(value: &str) -> ArchivePathV1 {
    let Ok(path) = ArchivePathV1::new(value.to_owned()) else {
        panic!("test archive path must be valid");
    };

    path
}

fn file_map(fixture: &ElectionFixture) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();

    let Ok(manifest_bytes) = fixture.manifest.to_canonical_cbor() else {
        panic!("test election manifest encoding must succeed");
    };

    let Ok(candidate_bytes) = fixture.candidates.to_canonical_cbor() else {
        panic!("test candidate-set encoding must succeed");
    };

    files.insert(ELECTION_MANIFEST_PATH.to_owned(), manifest_bytes);
    files.insert(CANDIDATE_SET_PATH.to_owned(), candidate_bytes);
    files.insert(
        VERIFICATION_POLICY_PATH.to_owned(),
        b"FIRST_VALID_BALLOT_COUNTS;PUBLIC_APPROVAL;TEST_ONLY_PROOF_SUITE".to_vec(),
    );

    for submission in &fixture.submissions {
        let previous = files.insert(submission.path.clone(), submission.bytes.clone());

        assert!(
            previous.is_none(),
            "test archive fixture contained a duplicate path"
        );
    }

    files
}

fn archive_manifest(
    fixture: &ElectionFixture,
    files: &BTreeMap<String, Vec<u8>>,
) -> ArchiveManifestV1 {
    let provider = TestOnlyDeterministicHasher;

    let Ok(election_manifest_hash) = fixture.manifest.canonical_hash(&provider) else {
        panic!("test election manifest hash must succeed");
    };

    let entries = files
        .iter()
        .rev()
        .map(|(path, bytes)| ArchiveFileEntryV1::for_bytes(archive_path(path), &provider, bytes))
        .collect();

    let Ok(catalog) = ArchiveFileCatalogV1::new(entries) else {
        panic!("test archive file catalog must be valid");
    };

    let Ok(manifest) = ArchiveManifestV1::for_provider(election_manifest_hash, catalog, &provider)
    else {
        panic!("test archive manifest must be valid");
    };

    manifest
}

fn verify_all_files(manifest: &ArchiveManifestV1, files: &BTreeMap<String, Vec<u8>>) {
    let provider = TestOnlyDeterministicHasher;

    assert_eq!(manifest.files().len(), files.len());

    for entry in manifest.files().entries() {
        let Some(bytes) = files.get(entry.path().as_str()) else {
            panic!("archive manifest referenced an unavailable test file");
        };

        assert!(entry.verify_bytes(&provider, bytes).is_ok());
    }
}

fn raw_package_digest(bytes: &[u8]) -> BallotPackageDigestV1 {
    let provider = TestOnlyDeterministicHasher;

    BallotPackageDigestV1::new(hash_domain_separated(
        &provider,
        HashDomain::BallotPackageV1,
        bytes,
    ))
}

fn replay(submissions: &[ArchivedSubmission], files: &BTreeMap<String, Vec<u8>>) -> ReplayResult {
    let provider = TestOnlyDeterministicHasher;

    let Some(manifest_bytes) = files.get(ELECTION_MANIFEST_PATH) else {
        panic!("archive must contain the election manifest");
    };

    let Some(candidate_bytes) = files.get(CANDIDATE_SET_PATH) else {
        panic!("archive must contain the candidate set");
    };

    let Ok(manifest) = ElectionManifestV1::from_canonical_cbor(manifest_bytes) else {
        panic!("archived election manifest must decode");
    };

    let Ok(candidates) = CandidateSet::from_canonical_cbor(candidate_bytes) else {
        panic!("archived candidate set must decode");
    };

    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("archived candidate-set commitment must succeed");
    };

    assert_eq!(
        candidate_set_commitment,
        manifest.candidate_set_commitment()
    );

    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("archived election manifest hash must succeed");
    };

    let mut lifecycle = ElectionLifecycleV1::new();

    assert!(
        lifecycle
            .freeze(manifest_hash, manifest.registry_commitment())
            .is_ok()
    );

    assert!(lifecycle.open().is_ok());

    let verifier = TestOnlyProofVerifierV1::replay();
    let mut ledger = BallotAcceptanceLedger::new();
    let mut transcript = VerificationTranscriptV1::new(manifest_hash);

    for submission in sorted_submissions(submissions) {
        let Some(bytes) = files.get(&submission.path) else {
            panic!("archive must contain every submitted ballot package");
        };

        let digest = raw_package_digest(bytes);

        let Ok(sequence) = transcript.record_submission(digest, submission.received_before_close)
        else {
            panic!("archived submission must be recordable");
        };

        let outcome = match BallotPackageV1::from_canonical_cbor(
            bytes,
            &candidates,
            manifest.approval_limits(),
        ) {
            Ok(package) => {
                let Ok(canonical_hash) = package.canonical_hash(&provider) else {
                    panic!("decoded package hash must succeed");
                };

                assert_eq!(digest, BallotPackageDigestV1::new(canonical_hash));

                if !submission.received_before_close {
                    BallotDecisionOutcomeV1::Rejected(ValidationCode::ElectionNotOpen)
                } else if let Err(error) =
                    package.validate_manifest_binding(manifest_hash, manifest.proof_suite_id())
                {
                    BallotDecisionOutcomeV1::Rejected(error.code())
                } else {
                    match verify_approval_proof(
                        &manifest,
                        package.payload(),
                        package.proof(),
                        &provider,
                        &verifier,
                    ) {
                        Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
                        Ok(verified) => match ledger.accept_verified(&lifecycle, verified) {
                            Ok(()) => BallotDecisionOutcomeV1::Accepted,
                            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
                        },
                    }
                }
            }
            Err(error) => BallotDecisionOutcomeV1::Rejected(error.code()),
        };

        assert!(
            transcript
                .record_decision(sequence, digest, outcome)
                .is_ok()
        );
    }

    assert!(transcript.validate_complete().is_ok());

    let Ok(tally) = ApprovalTally::from_ballots(
        &candidates,
        ledger
            .accepted_ballots()
            .iter()
            .map(|ballot| ballot.payload()),
    ) else {
        panic!("replayed accepted ballots must tally");
    };

    ReplayResult { transcript, tally }
}

fn tally_counts(tally: &ApprovalTally) -> Vec<(Vec<u8>, u64)> {
    tally
        .counts()
        .iter()
        .map(|count| (count.candidate_id().as_bytes().to_vec(), count.approvals()))
        .collect()
}

#[test]
fn canonical_ballot_packages_replay_to_same_transcript_and_tally() {
    let first_fixture = fixture(b"approve");
    let mut second_fixture = first_fixture.clone();

    second_fixture.submissions.rotate_left(3);

    let first_files = file_map(&first_fixture);
    let second_files = file_map(&second_fixture);

    assert_eq!(first_files, second_files);

    let first_archive_manifest = archive_manifest(&first_fixture, &first_files);

    let second_archive_manifest = archive_manifest(&second_fixture, &second_files);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_archive_bytes) = first_archive_manifest.to_canonical_cbor() else {
        panic!("first archive-manifest encoding must succeed");
    };

    let Ok(second_archive_bytes) = second_archive_manifest.to_canonical_cbor() else {
        panic!("second archive-manifest encoding must succeed");
    };

    assert_eq!(first_archive_bytes, second_archive_bytes);

    let Ok(decoded_archive_manifest) = ArchiveManifestV1::from_canonical_cbor(&first_archive_bytes)
    else {
        panic!("archive manifest must decode on a clean replay path");
    };

    assert_eq!(decoded_archive_manifest, first_archive_manifest);

    let Ok(first_archive_hash) = first_archive_manifest.canonical_hash(&provider) else {
        panic!("first archive hash must succeed");
    };

    let Ok(second_archive_hash) = second_archive_manifest.canonical_hash(&provider) else {
        panic!("second archive hash must succeed");
    };

    assert_eq!(first_archive_hash, second_archive_hash);

    assert!(
        decoded_archive_manifest
            .verify_hash(&provider, first_archive_hash)
            .is_ok()
    );

    verify_all_files(&decoded_archive_manifest, &first_files);

    let first_replay = replay(&first_fixture.submissions, &first_files);
    let second_replay = replay(&second_fixture.submissions, &second_files);

    assert_eq!(first_replay, second_replay);
    assert_eq!(first_replay.transcript.submissions().len(), 7);
    assert_eq!(first_replay.transcript.decisions().len(), 7);
    assert_eq!(first_replay.transcript.accepted_count(), 4);
    assert_eq!(first_replay.transcript.rejected_count(), 3);

    let outcomes: Vec<BallotDecisionOutcomeV1> = first_replay
        .transcript
        .decisions()
        .iter()
        .map(|decision| decision.outcome())
        .collect();

    assert_eq!(
        outcomes,
        vec![
            BallotDecisionOutcomeV1::Accepted,
            BallotDecisionOutcomeV1::Accepted,
            BallotDecisionOutcomeV1::Rejected(ValidationCode::DuplicateNullifier,),
            BallotDecisionOutcomeV1::Rejected(ValidationCode::InvalidData,),
            BallotDecisionOutcomeV1::Rejected(ValidationCode::ElectionNotOpen,),
            BallotDecisionOutcomeV1::Accepted,
            BallotDecisionOutcomeV1::Accepted,
        ]
    );

    assert_eq!(first_replay.tally.accepted_ballots(), 4);
    assert_eq!(first_replay.tally.abstentions(), 1);
    assert_eq!(
        tally_counts(&first_replay.tally),
        vec![
            (b"approve".to_vec(), 2),
            (b"defer".to_vec(), 0),
            (b"reject".to_vec(), 1),
        ]
    );

    assert!(matches!(
        first_replay.tally.leading_result(),
        LeadingResult::SingleLeader {
            candidate_id,
            approvals: 2,
        } if candidate_id.as_bytes() == b"approve"
    ));
}

#[test]
fn tampered_canonical_ballot_package_is_rejected_before_replay() {
    let fixture = fixture(b"approve");
    let files = file_map(&fixture);
    let manifest = archive_manifest(&fixture, &files);
    let provider = TestOnlyDeterministicHasher;
    let target_path = submission_path(1);

    let Some(entry) = manifest
        .files()
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == target_path)
    else {
        panic!("target submission entry must exist");
    };

    let Some(original_bytes) = files.get(&target_path) else {
        panic!("target submission bytes must exist");
    };

    assert!(entry.verify_bytes(&provider, original_bytes).is_ok());

    let mut tampered = original_bytes.clone();
    tampered[0] ^= 0x01;

    assert!(matches!(
        entry.verify_bytes(&provider, &tampered),
        Err(error)
            if error.code()
                == ValidationCode::ArchiveFileDigestMismatch
    ));
}

#[test]
fn changed_canonical_ballot_package_changes_archive_replay_and_tally() {
    let baseline_fixture = fixture(b"approve");
    let changed_fixture = fixture(b"reject");

    let baseline_files = file_map(&baseline_fixture);
    let changed_files = file_map(&changed_fixture);

    let baseline_archive_manifest = archive_manifest(&baseline_fixture, &baseline_files);

    let changed_archive_manifest = archive_manifest(&changed_fixture, &changed_files);

    let provider = TestOnlyDeterministicHasher;

    let Ok(baseline_archive_hash) = baseline_archive_manifest.canonical_hash(&provider) else {
        panic!("baseline archive hash must succeed");
    };

    let Ok(changed_archive_hash) = changed_archive_manifest.canonical_hash(&provider) else {
        panic!("changed archive hash must succeed");
    };

    assert_ne!(baseline_files, changed_files);
    assert_ne!(baseline_archive_manifest, changed_archive_manifest);
    assert_ne!(baseline_archive_hash, changed_archive_hash);

    let baseline_replay = replay(&baseline_fixture.submissions, &baseline_files);

    let changed_replay = replay(&changed_fixture.submissions, &changed_files);

    assert_ne!(baseline_replay.transcript, changed_replay.transcript);
    assert_ne!(baseline_replay.tally, changed_replay.tally);

    assert_eq!(baseline_replay.transcript.accepted_count(), 4);
    assert_eq!(changed_replay.transcript.accepted_count(), 4);
    assert_eq!(baseline_replay.transcript.rejected_count(), 3);
    assert_eq!(changed_replay.transcript.rejected_count(), 3);

    assert_eq!(
        tally_counts(&baseline_replay.tally),
        vec![
            (b"approve".to_vec(), 2),
            (b"defer".to_vec(), 0),
            (b"reject".to_vec(), 1),
        ]
    );

    assert_eq!(
        tally_counts(&changed_replay.tally),
        vec![
            (b"approve".to_vec(), 1),
            (b"defer".to_vec(), 0),
            (b"reject".to_vec(), 2),
        ]
    );

    assert!(matches!(
        changed_replay.tally.leading_result(),
        LeadingResult::SingleLeader {
            candidate_id,
            approvals: 2,
        } if candidate_id.as_bytes() == b"reject"
    ));
}
