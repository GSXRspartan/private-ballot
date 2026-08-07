//! Full offline archive replay verifier tests (required cases 27-38).

mod common;

use tari_cc_private_ballot_gui_core::archive_writer::write_archive_directory_v1;
use tari_cc_private_ballot_gui_core::{GuiElectionSessionV1, verify_archive_directory_v1};

use common::{TestDir, open_session, triptych_package_bytes};

fn closed_session_with_ballots() -> GuiElectionSessionV1 {
    let mut session = open_session();
    let packages = vec![
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b", b"candidate-c"]),
        triptych_package_bytes(0, &[b"candidate-b"]), // duplicate nullifier
        triptych_package_bytes(2, &[b"candidate-c"]),
    ];
    for package in &packages {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    session
}

fn write_test_archive(dir: &TestDir) -> (GuiElectionSessionV1, std::path::PathBuf) {
    let session = closed_session_with_ballots();
    let target = dir.join("archive");
    if let Err(error) = write_archive_directory_v1(&session, &target) {
        panic!("archive write must succeed: {error}");
    }
    (session, target)
}

fn flip_first_byte(path: &std::path::Path) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => panic!("target file must be readable"),
    };
    let Some(first) = bytes.first() else {
        panic!("target file must not be empty");
    };
    let mut tampered = bytes.clone();
    tampered[0] = first ^ 0x01;
    assert!(std::fs::write(path, tampered).is_ok());
}

#[test]
fn valid_archive_verifies_completely() {
    let dir = TestDir::new("verify-valid");
    let (_session, target) = write_test_archive(&dir);

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(error) => panic!("verification must return a result: {error}"),
    };

    assert!(result.verified, "failure: {:?}", result.failure_code);
    assert_eq!(result.failure_stage, None);
    assert_eq!(result.file_count, 7); // 3 artifacts + 4 submissions
    assert!(
        result
            .files
            .iter()
            .all(|file| file.present && file.digest_ok)
    );
    assert_eq!(result.ballot_package_count, 4);
    assert_eq!(result.accepted_count, 3);
    assert_eq!(result.rejected_count, 1);
    assert!(result.transcript_complete);
    assert!(result.archive_hash_consistent);
    assert_eq!(result.archive_hash_hex, result.recomputed_archive_hash_hex);
    assert!(result.tally.is_some());
}

#[test]
fn changed_ballot_package_is_detected() {
    let dir = TestDir::new("verify-tampered-ballot");
    let (_session, target) = write_test_archive(&dir);
    flip_first_byte(&target.join("submissions/00000000.cbor"));

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
    assert_eq!(
        result.failure_code.as_deref(),
        Some("ARCHIVE_FILE_DIGEST_MISMATCH")
    );
}

#[test]
fn changed_election_manifest_is_detected() {
    let dir = TestDir::new("verify-tampered-manifest");
    let (_session, target) = write_test_archive(&dir);
    flip_first_byte(&target.join("election-manifest.cbor"));

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
}

#[test]
fn changed_registry_is_detected() {
    let dir = TestDir::new("verify-tampered-registry");
    let (_session, target) = write_test_archive(&dir);
    flip_first_byte(&target.join("voter-registry.cbor"));

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
}

#[test]
fn changed_candidate_set_is_detected() {
    let dir = TestDir::new("verify-tampered-candidates");
    let (_session, target) = write_test_archive(&dir);
    flip_first_byte(&target.join("candidate-set.cbor"));

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
}

#[test]
fn changed_catalog_digest_is_detected() {
    let dir = TestDir::new("verify-tampered-catalog");
    let (_session, target) = write_test_archive(&dir);

    // Flip a byte inside a recorded file digest within the archive manifest.
    let manifest_path = target.join("archive-manifest.cbor");
    let bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(_) => panic!("archive manifest must be readable"),
    };
    let mut tampered = bytes.clone();
    let index = tampered.len() / 2;
    tampered[index] ^= 0x01;
    assert!(std::fs::write(&manifest_path, tampered).is_ok());

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    // Either the manifest no longer decodes or a file digest no longer
    // matches; both are catalog-stage integrity failures.
    assert!(matches!(
        result.failure_stage,
        Some("ARCHIVE_MANIFEST") | Some("CATALOG_FILES")
    ));
}

#[test]
fn missing_file_is_detected() {
    let dir = TestDir::new("verify-missing-file");
    let (_session, target) = write_test_archive(&dir);
    assert!(std::fs::remove_file(target.join("submissions/00000002.cbor")).is_ok());

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
    assert_eq!(
        result.failure_code.as_deref(),
        Some("GUI_ARCHIVE_MISSING_FILE")
    );
}

#[test]
fn unexpected_extra_file_is_detected() {
    let dir = TestDir::new("verify-extra-file");
    let (_session, target) = write_test_archive(&dir);
    assert!(std::fs::write(target.join("stray-file.cbor"), b"unexpected").is_ok());

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("CATALOG_FILES"));
    assert_eq!(
        result.failure_code.as_deref(),
        Some("GUI_ARCHIVE_UNEXPECTED_FILE")
    );
}

#[test]
fn replay_reproduces_duplicate_decisions_tally_and_hash() {
    let dir = TestDir::new("verify-reproduction");
    let (session, target) = write_test_archive(&dir);

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(result.verified, "failure: {:?}", result.failure_code);

    // Duplicate/replay decisions reproduce identically.
    assert_eq!(result.accepted_count, session.transcript().accepted_count());
    assert_eq!(result.rejected_count, session.transcript().rejected_count());

    // The tally reproduces identically.
    let session_tally = match session.tally() {
        Ok(tally) => tally,
        Err(_) => panic!("session tally must compute"),
    };
    assert_eq!(result.tally, Some(session_tally));

    // The archive hash reproduces identically.
    let write_result = match write_archive_directory_v1(&session, &dir.join("second")) {
        Ok(result) => result,
        Err(_) => panic!("second write must succeed"),
    };
    assert_eq!(result.archive_hash_hex, Some(write_result.archive_hash_hex));
}

#[test]
fn two_independent_verification_runs_are_identical() {
    let dir = TestDir::new("verify-twice");
    let (_session, target) = write_test_archive(&dir);

    let first = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("first verification must return a result"),
    };
    let second = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("second verification must return a result"),
    };
    assert_eq!(first, second);
    assert!(first.verified);
}

#[test]
fn missing_archive_directory_is_an_io_error() {
    let dir = TestDir::new("verify-missing-dir");
    let error = match verify_archive_directory_v1(&dir.join("absent")) {
        Ok(_) => panic!("missing directory must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "GUI_FILE_NOT_FOUND");
}

#[test]
fn missing_archive_manifest_is_an_integrity_failure() {
    let dir = TestDir::new("verify-missing-manifest");
    let (_session, target) = write_test_archive(&dir);
    assert!(std::fs::remove_file(target.join("archive-manifest.cbor")).is_ok());

    let result = match verify_archive_directory_v1(&target) {
        Ok(result) => result,
        Err(_) => panic!("verification must return a result"),
    };
    assert!(!result.verified);
    assert_eq!(result.failure_stage, Some("ARCHIVE_MANIFEST"));
    assert_eq!(
        result.failure_code.as_deref(),
        Some("GUI_ARCHIVE_MISSING_FILE")
    );
}
