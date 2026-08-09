//! Archive writer tests (required cases 20-26).

#![allow(clippy::expect_used)]

mod common;

use tari_cc_private_ballot_gui_core::archive_writer::{
    submission_archive_path, write_archive_directory_v1, write_archive_directory_v1_with_transport_binding,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, verify_archive_directory_v1, verify_transport_archive_anchor_v1,
};
use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveHashV1, ArchiveManifestV1, TransportArchiveBatchV1,
    TransportArchiveBindingV1, TRANSPORT_ARCHIVE_BINDING_PATH_V1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use common::{
    TestDir, open_session, triptych_package_bytes, write_accepted_anchor_evidence_for,
    write_anchor_evidence,
};

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

fn transport_binding(session: &GuiElectionSessionV1) -> TransportArchiveBindingV1 {
    TransportArchiveBindingV1::new(
        session.artifacts().manifest().election_id().as_bytes().to_vec(),
        session.artifacts().manifest_hash(),
        [7; 32],
        3,
        vec![
            TransportArchiveBatchV1::new(9, [9; 32], 2, false),
            TransportArchiveBatchV1::new(4, [4; 32], 1, true),
        ],
    )
    .expect("fixture transport binding must construct")
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn transport_binding_is_covered_by_the_completed_archive_hash() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-binding");
    let target = dir.join("archive");
    let binding = transport_binding(&session);

    let written = write_archive_directory_v1_with_transport_binding(&session, &target, &binding)
        .expect("bound archive must write");
    assert!(written
        .files
        .iter()
        .any(|file| file.path == TRANSPORT_ARCHIVE_BINDING_PATH_V1));

    let verified = verify_archive_directory_v1(&target).expect("archive must verify");
    assert!(verified.verified, "failure: {:?}", verified.failure_code);
    assert!(verified.transport_binding_present);
    assert!(verified.transport_binding_verified);
    assert_eq!(
        verified.transport_batch_set_commitment_hex,
        Some(lower_hex(&binding.final_batch_set_commitment()))
    );

    let binding_path = target.join(TRANSPORT_ARCHIVE_BINDING_PATH_V1);
    let mut bytes = std::fs::read(&binding_path).expect("binding must be readable");
    bytes[0] ^= 1;
    std::fs::write(binding_path, bytes).expect("binding mutation must write");
    let mutated = verify_archive_directory_v1(&target).expect("integrity result");
    assert!(!mutated.verified);
    assert_eq!(mutated.failure_stage, Some("CATALOG_FILES"));
}

#[test]
fn transport_binding_for_another_election_is_rejected_before_archive_hashing() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-binding-mismatch");
    let binding = TransportArchiveBindingV1::new(
        b"other-election".to_vec(),
        session.artifacts().manifest_hash(),
        [7; 32],
        3,
        vec![TransportArchiveBatchV1::new(1, [1; 32], 1, false)],
    )
    .expect("syntactically valid other-election binding");

    let error = write_archive_directory_v1_with_transport_binding(
        &session,
        &dir.join("archive"),
        &binding,
    )
    .expect_err("mismatched binding must be rejected");
    assert_eq!(error.code(), "GUI_TRANSPORT_ARCHIVE_BINDING_MISMATCH");
}

#[test]
fn unrelated_or_non_success_phase4_evidence_never_marks_transport_anchored() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-rejected");
    let target = dir.join("archive");
    write_archive_directory_v1_with_transport_binding(&session, &target, &transport_binding(&session))
        .expect("bound archive must write");

    // The fixture is a valid existing Phase 4 non-success evidence record for
    // another archive. It must not promote this transport commitment.
    let evidence_path = write_anchor_evidence(dir.path());
    let result = verify_transport_archive_anchor_v1(&target, &evidence_path)
        .expect("verification result");
    assert_eq!(result.state, "INCLUDED");
    assert!(result.transport_binding_verified);
    assert!(!result.anchor_verified);
}

#[test]
fn exact_finalized_accept_evidence_marks_transport_anchored() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-accepted");
    let target = dir.join("archive");
    write_archive_directory_v1_with_transport_binding(&session, &target, &transport_binding(&session))
        .expect("bound archive must write");
    let manifest_bytes = std::fs::read(target.join(ARCHIVE_MANIFEST_CANONICAL_PATH))
        .expect("archive manifest reads");
    let archive_manifest = ArchiveManifestV1::from_canonical_cbor(&manifest_bytes)
        .expect("archive manifest decodes");
    let archive_hash = archive_manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("archive hash derives");
    let evidence = write_accepted_anchor_evidence_for(
        dir.path(),
        session.artifacts().manifest_hash(),
        archive_hash,
    );
    let result = verify_transport_archive_anchor_v1(&target, &evidence)
        .expect("accepted evidence verifies");
    assert_eq!(result.state, "ANCHORED");
    assert!(result.anchor_verified);
}

#[test]
fn finalized_accept_evidence_for_another_archive_never_marks_transport_anchored() {
    let session = session_with_ballots();
    let dir = TestDir::new("archive-transport-anchor-wrong-archive");
    let target = dir.join("archive");
    write_archive_directory_v1_with_transport_binding(&session, &target, &transport_binding(&session))
        .expect("bound archive must write");
    let evidence = write_accepted_anchor_evidence_for(
        dir.path(),
        session.artifacts().manifest_hash(),
        ArchiveHashV1::new([0xA5; 32]),
    );
    let result = verify_transport_archive_anchor_v1(&target, &evidence)
        .expect("mismatched evidence returns safe state");
    assert_eq!(result.state, "INCLUDED");
    assert!(!result.anchor_verified);
}
