use std::collections::BTreeMap;

use tari_cc_private_ballot_archive::{
    ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
    BallotDecisionOutcomeV1, BallotPackageDigestV1, VerificationTranscriptV1,
};
use tari_cc_private_ballot_protocol::{
    HashDomain, ManifestHash, ValidationCode, hash_domain_separated,
    test_only::TestOnlyDeterministicHasher,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArchivedSubmission {
    path: String,
    bytes: Vec<u8>,
    received_before_close: bool,
    outcome: BallotDecisionOutcomeV1,
}

fn submission_path(index: usize) -> String {
    format!("submissions/{index:08}.bin")
}

fn submission_bytes(index: usize) -> Vec<u8> {
    let Ok(index_u64) = u64::try_from(index) else {
        panic!("test submission index must fit in u64");
    };

    let mut bytes = b"TEST_ONLY_ARCHIVED_BALLOT_PACKAGE_V1".to_vec();
    bytes.extend_from_slice(&index_u64.to_be_bytes());
    bytes.extend_from_slice(&index_u64.rotate_left(17).to_be_bytes());
    bytes.extend_from_slice(&index_u64.wrapping_mul(31).to_be_bytes());
    bytes
}

fn submission_outcome(index: usize, received_before_close: bool) -> BallotDecisionOutcomeV1 {
    if !received_before_close {
        return BallotDecisionOutcomeV1::Rejected(ValidationCode::ElectionNotOpen);
    }

    if index.is_multiple_of(17) {
        return BallotDecisionOutcomeV1::Rejected(ValidationCode::MalformedProof);
    }

    BallotDecisionOutcomeV1::Accepted
}

fn fixture(submission_count: usize) -> Vec<ArchivedSubmission> {
    let mut submissions = Vec::with_capacity(submission_count);

    for index in 0..submission_count {
        let received_before_close = !index.is_multiple_of(13);

        submissions.push(ArchivedSubmission {
            path: submission_path(index),
            bytes: submission_bytes(index),
            received_before_close,
            outcome: submission_outcome(index, received_before_close),
        });
    }

    submissions.reverse();
    submissions
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

fn file_map(submissions: &[ArchivedSubmission]) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();

    files.insert(
        "election-manifest.cbor".to_owned(),
        b"TEST_ONLY_ELECTION_MANIFEST_BYTES_V1".to_vec(),
    );

    files.insert(
        "verification-policy.txt".to_owned(),
        b"TEST_ONLY_POLICY_FIRST_VALID_BALLOT_COUNTS".to_vec(),
    );

    for submission in submissions {
        let previous = files.insert(submission.path.clone(), submission.bytes.clone());

        assert!(
            previous.is_none(),
            "test archive fixture contained a duplicate path"
        );
    }

    files
}

fn archive_manifest(
    election_manifest_hash: ManifestHash,
    files: &BTreeMap<String, Vec<u8>>,
) -> ArchiveManifestV1 {
    let provider = TestOnlyDeterministicHasher;

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

fn package_digest(bytes: &[u8]) -> BallotPackageDigestV1 {
    let provider = TestOnlyDeterministicHasher;

    BallotPackageDigestV1::new(hash_domain_separated(
        &provider,
        HashDomain::BallotPackageV1,
        bytes,
    ))
}

fn replay(
    election_manifest_hash: ManifestHash,
    submissions: &[ArchivedSubmission],
) -> VerificationTranscriptV1 {
    let sorted = sorted_submissions(submissions);
    let mut transcript = VerificationTranscriptV1::new(election_manifest_hash);
    let mut decisions = Vec::with_capacity(sorted.len());

    for submission in &sorted {
        let digest = package_digest(&submission.bytes);

        let Ok(sequence) = transcript.record_submission(digest, submission.received_before_close)
        else {
            panic!("test archived submission must be recordable");
        };

        decisions.push((sequence, digest, submission.outcome));
    }

    for (sequence, digest, outcome) in decisions {
        assert!(
            transcript
                .record_decision(sequence, digest, outcome)
                .is_ok()
        );
    }

    assert!(transcript.validate_complete().is_ok());
    transcript
}

#[test]
fn complete_archive_integrity_and_replay_model_are_deterministic() {
    const SUBMISSION_COUNT: usize = 257;

    let election_manifest_hash = ManifestHash::new([7_u8; 32]);
    let first_submissions = fixture(SUBMISSION_COUNT);
    let mut second_submissions = first_submissions.clone();

    second_submissions.rotate_left(73);

    let first_files = file_map(&first_submissions);
    let second_files = file_map(&second_submissions);

    assert_eq!(first_files, second_files);

    let first_manifest = archive_manifest(election_manifest_hash, &first_files);

    let second_manifest = archive_manifest(election_manifest_hash, &second_files);

    let provider = TestOnlyDeterministicHasher;

    let Ok(first_manifest_bytes) = first_manifest.to_canonical_cbor() else {
        panic!("first archive-manifest encoding must succeed");
    };

    let Ok(second_manifest_bytes) = second_manifest.to_canonical_cbor() else {
        panic!("second archive-manifest encoding must succeed");
    };

    assert_eq!(first_manifest_bytes, second_manifest_bytes);

    let Ok(decoded_manifest) = ArchiveManifestV1::from_canonical_cbor(&first_manifest_bytes) else {
        panic!("archive manifest must decode on a clean replay path");
    };

    assert_eq!(decoded_manifest, first_manifest);

    let Ok(first_archive_hash) = first_manifest.canonical_hash(&provider) else {
        panic!("first archive hash must succeed");
    };

    let Ok(second_archive_hash) = second_manifest.canonical_hash(&provider) else {
        panic!("second archive hash must succeed");
    };

    assert_eq!(first_archive_hash, second_archive_hash);

    assert!(
        decoded_manifest
            .verify_hash(&provider, first_archive_hash)
            .is_ok()
    );

    verify_all_files(&decoded_manifest, &first_files);

    let first_replay = replay(election_manifest_hash, &first_submissions);

    let second_replay = replay(election_manifest_hash, &second_submissions);

    assert_eq!(first_replay, second_replay);
    assert_eq!(first_replay.submissions().len(), SUBMISSION_COUNT);
    assert_eq!(first_replay.decisions().len(), SUBMISSION_COUNT);

    let expected_rejected = (0..SUBMISSION_COUNT)
        .filter(|index| index.is_multiple_of(13) || index.is_multiple_of(17))
        .count();

    assert_eq!(first_replay.rejected_count(), expected_rejected);
    assert_eq!(
        first_replay.accepted_count(),
        SUBMISSION_COUNT - expected_rejected
    );

    let sorted = sorted_submissions(&first_submissions);

    for (index, (submission, archived)) in
        first_replay.submissions().iter().zip(&sorted).enumerate()
    {
        let Ok(expected_sequence) = u64::try_from(index) else {
            panic!("test replay index must fit in u64");
        };

        assert_eq!(submission.sequence().value(), expected_sequence);
        assert_eq!(submission.package_digest(), package_digest(&archived.bytes));
        assert_eq!(
            submission.received_before_close(),
            archived.received_before_close
        );
    }
}

#[test]
fn tampered_archived_submission_is_rejected_before_replay() {
    let election_manifest_hash = ManifestHash::new([8_u8; 32]);
    let submissions = fixture(32);
    let files = file_map(&submissions);
    let manifest = archive_manifest(election_manifest_hash, &files);
    let provider = TestOnlyDeterministicHasher;
    let target_path = submission_path(7);

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

    let result = entry.verify_bytes(&provider, &tampered);

    assert!(matches!(
        result,
        Err(error)
            if error.code()
                == ValidationCode::ArchiveFileDigestMismatch
    ));
}

#[test]
fn changed_submission_bytes_change_archive_and_replay_commitments() {
    let election_manifest_hash = ManifestHash::new([9_u8; 32]);
    let baseline_submissions = fixture(64);
    let mut changed_submissions = baseline_submissions.clone();

    let Some(changed) = changed_submissions
        .iter_mut()
        .find(|submission| submission.path == submission_path(23))
    else {
        panic!("changed submission must exist");
    };

    changed.bytes.push(0xff);

    let baseline_files = file_map(&baseline_submissions);
    let changed_files = file_map(&changed_submissions);

    let baseline_manifest = archive_manifest(election_manifest_hash, &baseline_files);

    let changed_manifest = archive_manifest(election_manifest_hash, &changed_files);

    let provider = TestOnlyDeterministicHasher;

    let Ok(baseline_archive_hash) = baseline_manifest.canonical_hash(&provider) else {
        panic!("baseline archive hash must succeed");
    };

    let Ok(changed_archive_hash) = changed_manifest.canonical_hash(&provider) else {
        panic!("changed archive hash must succeed");
    };

    assert_ne!(baseline_manifest, changed_manifest);
    assert_ne!(baseline_archive_hash, changed_archive_hash);

    let baseline_replay = replay(election_manifest_hash, &baseline_submissions);

    let changed_replay = replay(election_manifest_hash, &changed_submissions);

    assert_ne!(baseline_replay, changed_replay);
    assert_eq!(
        baseline_replay.accepted_count(),
        changed_replay.accepted_count()
    );
    assert_eq!(
        baseline_replay.rejected_count(),
        changed_replay.rejected_count()
    );
}
