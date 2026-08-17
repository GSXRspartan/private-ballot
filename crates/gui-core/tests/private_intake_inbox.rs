//! Durable private-intake inbox → authoritative organizer workspace bridge.
//!
//! These deterministic tests prove the Tor intake hand-off invariants without
//! any network or real Tor: a privately-accepted canonical ballot package written
//! to the app-owned inbox is ingested through the SAME gui-core intake boundary an
//! offline ballot uses, becomes part of the ONE durable organizer workspace, and
//! survives a workspace restart; exact retries never double-count; and a different
//! ballot re-using the same credential nullifier stays rejected.

mod common;

use std::fs;

use tari_cc_private_ballot_gui_core::{
    LoadedElectionWorkspaceV1, append_accepted_ballot_package_to_inbox_v1,
    ballot_package_digest_hex_v1, ensure_election_workspaces_directory_v1,
    ensure_private_intake_inbox_directory_v1, ingest_private_intake_inbox_into_session_v1,
    private_intake_inbox_directory_v1, resume_election_workspace_v1,
    workspace_id_for_session_v1, write_session_workspace_revision_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

#[test]
fn accepted_package_from_inbox_enters_the_session() {
    let dir = TestDir::new("inbox-accept");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);

    let wrote = append_accepted_ballot_package_to_inbox_v1(&inbox, &package)
        .expect("append must succeed");
    assert!(wrote, "a fresh package must be written");

    let mut session = open_session();
    let summary =
        ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("ingest ok");
    assert_eq!(summary.discovered, 1);
    assert_eq!(summary.newly_accepted, 1);
    assert_eq!(summary.duplicates, 0);
    assert_eq!(summary.rejected, 0);
    assert_eq!(session.accepted_count(), 1);
}

#[test]
fn exact_retry_is_content_addressed_and_never_double_counts() {
    let dir = TestDir::new("inbox-retry");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);

    assert!(
        append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("first append"),
        "first append writes a new file"
    );
    // An exact-retry of the same accepted envelope maps to the same file: a
    // durable no-op, never a second file.
    assert!(
        !append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("second append"),
        "an exact duplicate is a durable no-op"
    );
    let digest_hex = ballot_package_digest_hex_v1(&package);
    let files: Vec<_> = fs::read_dir(&inbox)
        .expect("inbox readable")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .ends_with(".package")
        })
        .collect();
    assert_eq!(files.len(), 1, "exactly one content-addressed file exists");
    assert_eq!(
        files[0].file_name().to_string_lossy(),
        format!("{digest_hex}.package")
    );

    let mut session = open_session();
    let first = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("ingest");
    assert_eq!(first.newly_accepted, 1);
    assert_eq!(session.accepted_count(), 1);

    // Ingesting again is idempotent: the same package is now a duplicate
    // nullifier and never re-counted.
    let second = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("re-sync");
    assert_eq!(second.discovered, 1);
    assert_eq!(second.newly_accepted, 0);
    assert_eq!(second.duplicates, 1);
    assert_eq!(session.accepted_count(), 1, "no double count on re-sync");
}

#[test]
fn different_ballot_same_nullifier_is_rejected() {
    let dir = TestDir::new("inbox-nullifier");
    let inbox = dir.join("inbox");
    // Same voter (index 0) → same election nullifier; different selection →
    // different package bytes/digest → two distinct inbox files.
    let ballot_a = triptych_package_bytes(0, &[b"candidate-a"]);
    let ballot_b = triptych_package_bytes(0, &[b"candidate-b"]);
    assert!(append_accepted_ballot_package_to_inbox_v1(&inbox, &ballot_a).expect("append a"));
    assert!(append_accepted_ballot_package_to_inbox_v1(&inbox, &ballot_b).expect("append b"));

    let mut session = open_session();
    let summary = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("ingest");
    assert_eq!(summary.discovered, 2);
    assert_eq!(summary.newly_accepted, 1, "only the first vote counts");
    assert_eq!(summary.duplicates, 1, "the same-nullifier ballot is a duplicate");
    assert_eq!(session.accepted_count(), 1, "double-vote rule is preserved");
}

#[test]
fn accepted_tor_ballot_survives_workspace_restart_and_tally_sees_it() {
    let dir = TestDir::new("inbox-restart");
    let inbox = dir.join("inbox");
    let workspaces_root = dir.join("app-data");
    ensure_election_workspaces_directory_v1(&workspaces_root).expect("workspaces root");

    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    // Ingest into the authoritative session and persist a durable revision,
    // exactly as the Tauri sync command does.
    let mut session = open_session();
    ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("ingest");
    assert_eq!(session.accepted_count(), 1);
    let workspace_id = workspace_id_for_session_v1(&session);
    write_session_workspace_revision_v1(&workspaces_root, &workspace_id, &session)
        .expect("persist revision");

    // Destroy the in-memory session and reconstruct from disk.
    drop(session);
    let loaded =
        resume_election_workspace_v1(&workspaces_root, &workspace_id).expect("resume workspace");
    let mut resumed = match loaded {
        LoadedElectionWorkspaceV1::Session { session, .. } => session,
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected a session workspace"),
    };
    assert_eq!(
        resumed.accepted_count(),
        1,
        "the accepted Tor ballot survives restart"
    );

    // Close and tally on the recovered workspace.
    resumed.close().expect("close");
    let tally = resumed.tally().expect("tally after close");
    assert_eq!(tally.accepted_ballots, 1, "tally sees the durable Tor ballot");
}

#[test]
fn inbox_file_content_must_match_its_digest_name() {
    let dir = TestDir::new("inbox-tamper");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");

    // Corrupt the content while keeping the (now wrong) digest filename.
    let digest_hex = ballot_package_digest_hex_v1(&package);
    let path = inbox.join(format!("{digest_hex}.package"));
    let mut tampered = fs::read(&path).expect("read");
    tampered.push(0xFF);
    fs::write(&path, &tampered).expect("write tampered");

    let mut session = open_session();
    let result = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session);
    assert!(result.is_err(), "a digest/content mismatch must fail closed");
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn stray_non_package_files_are_ignored() {
    let dir = TestDir::new("inbox-stray");
    let inbox = dir.join("inbox");
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    append_accepted_ballot_package_to_inbox_v1(&inbox, &package).expect("append");
    // A leftover temp file and an unrelated file must not fail the pass.
    fs::write(inbox.join("notes.txt"), b"ignore me").expect("stray write");
    fs::write(inbox.join("deadbeef.package.tmp"), b"partial").expect("tmp write");

    let mut session = open_session();
    let summary = ingest_private_intake_inbox_into_session_v1(&inbox, &mut session).expect("ingest");
    assert_eq!(summary.discovered, 1);
    assert_eq!(summary.newly_accepted, 1);
}

#[test]
fn missing_inbox_is_an_empty_sync_not_an_error() {
    let dir = TestDir::new("inbox-missing");
    let mut session = open_session();
    let summary =
        ingest_private_intake_inbox_into_session_v1(&dir.join("does-not-exist"), &mut session)
            .expect("missing inbox yields an empty summary");
    assert_eq!(summary.discovered, 0);
    assert_eq!(summary.newly_accepted, 0);
    assert_eq!(session.accepted_count(), 0);
}

#[test]
fn inbox_directory_is_app_owned_and_election_scoped() {
    let dir = TestDir::new("inbox-scope");
    let app_data_root = dir.path();
    let manifest_hash_hex = open_session().summary().manifest_hash_hex;

    let resolved = private_intake_inbox_directory_v1(app_data_root, &manifest_hash_hex)
        .expect("valid election hash resolves");
    assert!(resolved.starts_with(app_data_root), "inbox lives under app-data");
    assert!(
        resolved
            .to_string_lossy()
            .contains(&format!("election-{manifest_hash_hex}")),
        "inbox directory is election-scoped by manifest hash"
    );

    // A non-hex / arbitrary election identifier is rejected, so no remote or
    // arbitrary value can influence the path.
    assert!(private_intake_inbox_directory_v1(app_data_root, "../escape").is_err());
    assert!(private_intake_inbox_directory_v1(app_data_root, "not-hex").is_err());

    let ensured = ensure_private_intake_inbox_directory_v1(app_data_root, &manifest_hash_hex)
        .expect("ensure creates the election inbox");
    assert!(ensured.is_dir());
}
