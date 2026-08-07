//! Archive writer tests (required cases 20-26).

mod common;

use tari_cc_private_ballot_gui_core::archive_writer::{
    submission_archive_path, write_archive_directory_v1,
};
use tari_cc_private_ballot_gui_core::{GuiElectionSessionV1, verify_archive_directory_v1};

use common::{TestDir, open_session, triptych_package_bytes};

fn session_with_ballots() -> GuiElectionSessionV1 {
    let mut session = open_session();
    intake_canonical_packages(&mut session);
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    session
}

/// The canonical package byte set, built once per call. Triptych proofs use
/// fresh OS randomness by design, so callers needing identical bytes across
/// two sessions must build once and share.
fn canonical_packages() -> Vec<Vec<u8>> {
    vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-b"]), // duplicate, still archived
    ]
}

fn intake_canonical_packages(session: &mut GuiElectionSessionV1) {
    for package in &canonical_packages() {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }
}

fn intake_packages(session: &mut GuiElectionSessionV1, packages: &[Vec<u8>]) {
    for package in packages {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
}

#[test]
fn archive_layout_is_deterministic() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-layout");
    let target = dir.join("archive");

    let result = match write_archive_directory_v1(&session, &target) {
        Ok(result) => result,
        Err(error) => panic!("archive write must succeed: {error}"),
    };

    let paths: Vec<&str> = result.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "candidate-set.cbor",
            "election-manifest.cbor",
            submission_archive_path(0).as_str(),
            submission_archive_path(1).as_str(),
            submission_archive_path(2).as_str(),
            "voter-registry.cbor",
        ]
    );
    assert_eq!(result.archive_manifest_path, "archive-manifest.cbor");
    assert_eq!(result.archive_hash_hex.len(), 64);
    assert_eq!(result.election_manifest_hash_hex.len(), 64);
    assert!(target.join("archive-manifest.cbor").is_file());
    for file in &result.files {
        assert!(target.join(&file.path).is_file(), "missing {}", file.path);
        assert_eq!(file.digest_hex.len(), 64);
        assert!(file.bytes > 0);
    }
}

#[test]
fn identical_package_bytes_produce_identical_archives() {
    // Proofs carry fresh randomness, so determinism is asserted over identical
    // canonical package bytes ingested into two independent sessions.
    let packages = canonical_packages();
    let mut first = open_session();
    intake_packages(&mut first, &packages);
    let mut second = open_session();
    intake_packages(&mut second, &packages);
    let dir = TestDir::new("archive-determinism");

    let first_result = match write_archive_directory_v1(&first, &dir.join("first")) {
        Ok(result) => result,
        Err(_) => panic!("first write must succeed"),
    };
    let second_result = match write_archive_directory_v1(&second, &dir.join("second")) {
        Ok(result) => result,
        Err(_) => panic!("second write must succeed"),
    };

    assert_eq!(
        first_result.archive_hash_hex,
        second_result.archive_hash_hex
    );
    assert_eq!(first_result.files, second_result.files);

    // Byte-identical content, including the archive manifest file itself.
    for file in &first_result.files {
        let left = std::fs::read(dir.join("first").join(&file.path));
        let right = std::fs::read(dir.join("second").join(&file.path));
        assert_eq!(left.ok(), right.ok());
    }
    let left = std::fs::read(dir.join("first").join("archive-manifest.cbor"));
    let right = std::fs::read(dir.join("second").join("archive-manifest.cbor"));
    assert_eq!(left.ok(), right.ok());
}

#[test]
fn non_empty_target_directory_is_rejected_without_overwrite() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-collision");
    let target = dir.join("archive");
    assert!(std::fs::create_dir(&target).is_ok());
    let sentinel = target.join("pre-existing.txt");
    assert!(std::fs::write(&sentinel, b"do not touch").is_ok());

    let error = match write_archive_directory_v1(&session, &target) {
        Ok(_) => panic!("non-empty target must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_ARCHIVE_TARGET_NOT_EMPTY");

    // The pre-existing content is untouched and nothing was written.
    let contents = std::fs::read(&sentinel);
    assert_eq!(contents.ok(), Some(b"do not touch".to_vec()));
    let entry_count = match std::fs::read_dir(&target) {
        Ok(entries) => entries.count(),
        Err(_) => panic!("target dir must be readable"),
    };
    assert_eq!(entry_count, 1);
}

#[test]
fn file_target_is_rejected() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-file-target");
    let target = dir.join("not-a-dir");
    assert!(std::fs::write(&target, b"file").is_ok());

    let error = match write_archive_directory_v1(&session, &target) {
        Ok(_) => panic!("file target must be rejected"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_ARCHIVE_TARGET_INVALID");
}

#[test]
fn zero_ballot_archive_writes_and_verifies() {
    let mut session = open_session();
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let dir = TestDir::new("archive-zero-ballots");
    let target = dir.join("archive");

    let result = match write_archive_directory_v1(&session, &target) {
        Ok(result) => result,
        Err(error) => panic!("zero-ballot write must succeed: {error}"),
    };
    assert_eq!(result.files.len(), 3);

    let verification = match verify_archive_directory_v1(&target) {
        Ok(verification) => verification,
        Err(error) => panic!("zero-ballot archive must verify: {error}"),
    };
    assert!(
        verification.verified,
        "failure: {:?}",
        verification.failure_code
    );
    assert_eq!(verification.ballot_package_count, 0);
    assert_eq!(verification.accepted_count, 0);
}
