//! Durable election workspace tests.

mod common;

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use tari_cc_private_ballot_gui_core::{
    GuiElectionDraftV1, GuiElectionSessionV1, LoadedElectionWorkspaceV1,
    MAX_WORKSPACE_REVISION_BYTES_V1, create_draft_workspace_id_v1, delete_election_workspace_v1,
    ensure_election_workspaces_directory_v1, list_election_workspaces_v1,
    mark_draft_workspace_superseded_v1, resume_election_workspace_v1, workspace_id_for_session_v1,
    write_draft_workspace_revision_v1, write_session_workspace_revision_v1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider, ValidationCode};

use common::{TestDir, artifacts, triptych_package_bytes};

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, msg: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{msg}: {error}"),
    }
}

fn err<T, E>(result: Result<T, E>, msg: &str) -> E {
    match result {
        Ok(_) => panic!("{msg}"),
        Err(error) => error,
    }
}

fn open_session() -> GuiElectionSessionV1 {
    common::open_session()
}

fn revision_files(root: &Path, workspace_id: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = ok(
        fs::read_dir(root.join(workspace_id).join("revisions")),
        "revision read dir",
    )
    .map(|entry| ok(entry, "revision entry").path())
    .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("workspace"))
    .collect();
    paths.sort();
    paths
}

fn commit_files(root: &Path, workspace_id: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = ok(
        fs::read_dir(root.join(workspace_id).join("commits")),
        "commit read dir",
    )
    .map(|entry| ok(entry, "commit entry").path())
    .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("commit"))
    .collect();
    paths.sort();
    paths
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn revision_digest_hex(payload: &[u8]) -> String {
    const DOMAIN: &[u8] = b"tari-cc-private-ballot/durable-election-workspace-revision/v1";
    let mut framed = Vec::with_capacity(DOMAIN.len() + 1 + payload.len());
    framed.extend_from_slice(DOMAIN);
    framed.push(0);
    framed.extend_from_slice(payload);
    let provider = Blake3HashProviderV1;
    lower_hex(&provider.hash(&framed))
}

fn encode_commit_marker(workspace_id: &str, revision: u64, revision_digest_hex: &str) -> Vec<u8> {
    const MAGIC: &[u8] = b"TARI_PRIVATE_BALLOT_DURABLE_ELECTION_WORKSPACE_COMMIT_V1";
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes.extend_from_slice(&(workspace_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(workspace_id.as_bytes());
    bytes.extend_from_slice(&(revision_digest_hex.len() as u32).to_be_bytes());
    bytes.extend_from_slice(revision_digest_hex.as_bytes());
    bytes
}

fn revision_path(root: &Path, workspace_id: &str, revision: u64) -> PathBuf {
    revision_files(root, workspace_id)
        .into_iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("{revision:010}-")))
        })
        .unwrap_or_else(|| panic!("revision {revision} file must exist"))
}

fn commit_path(root: &Path, workspace_id: &str, revision: u64) -> PathBuf {
    commit_files(root, workspace_id)
        .into_iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("{revision:010}-")))
        })
        .unwrap_or_else(|| panic!("revision {revision} commit must exist"))
}

fn corrupt_file(path: &Path) {
    let mut bytes = ok(fs::read(path), "read file to corrupt");
    let last = bytes.len().checked_sub(1).expect("non-empty file");
    bytes[last] ^= 0x01;
    ok(fs::write(path, bytes), "write corrupt file");
}

fn truncate_file(path: &Path) {
    let file = ok(
        File::options().write(true).open(path),
        "open file to truncate",
    );
    ok(file.set_len(8), "truncate file");
}

fn remove_commit_marker(root: &Path, workspace_id: &str, revision: u64) {
    ok(
        fs::remove_file(commit_path(root, workspace_id, revision)),
        "remove commit marker",
    );
}

fn two_revision_workspace(root: &Path) -> (String, GuiElectionSessionV1) {
    let mut session = open_session();
    assert!(
        ok(
            session.intake_ballot_package_bytes(&triptych_package_bytes(0, &[b"candidate-a"])),
            "first intake",
        )
        .accepted
    );
    let workspace_id = workspace_id_for_session_v1(&session);
    assert_eq!(
        ok(
            write_session_workspace_revision_v1(root, &workspace_id, &session),
            "write revision 1",
        ),
        1
    );
    assert!(
        ok(
            session.intake_ballot_package_bytes(&triptych_package_bytes(1, &[b"candidate-b"])),
            "second intake",
        )
        .accepted
    );
    assert_eq!(
        ok(
            write_session_workspace_revision_v1(root, &workspace_id, &session),
            "write revision 2",
        ),
        2
    );
    (workspace_id, session)
}

#[test]
fn workspace_root_is_derived_from_injected_app_data_root() {
    let dir = TestDir::new("workspace-root");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );

    assert_eq!(root, dir.path().join("election-workspaces"));
    assert!(root.is_dir());
}

#[test]
fn delete_removes_only_the_named_workspace_and_leaves_others() {
    let dir = TestDir::new("workspace-delete");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let (workspace_id, _session) = two_revision_workspace(&root);
    // A second, unrelated workspace that must survive the delete.
    let other_id = ok(create_draft_workspace_id_v1(&root), "other id");
    let mut other = GuiElectionDraftV1::new();
    ok(
        other.set_basics(
            "other-election".to_owned(),
            "Other?".to_owned(),
            "other-revision".to_owned(),
        ),
        "other basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &other_id, &other),
        "write other",
    );
    assert!(root.join(&workspace_id).is_dir());
    assert!(root.join(&other_id).is_dir());

    ok(
        delete_election_workspace_v1(&root, &workspace_id),
        "delete target",
    );

    assert!(
        !root.join(&workspace_id).exists(),
        "the named workspace directory is removed",
    );
    assert!(
        root.join(&other_id).is_dir(),
        "an unrelated workspace is untouched",
    );
    let remaining = ok(list_election_workspaces_v1(&root), "list after delete");
    assert!(
        remaining.iter().all(|w| w.workspace_id != workspace_id),
        "the deleted workspace no longer appears in discovery",
    );
}

#[test]
fn delete_is_idempotent_for_a_missing_workspace() {
    let dir = TestDir::new("workspace-delete-missing");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    // A valid-but-absent id deletes to a no-op success (idempotent recovery).
    ok(
        delete_election_workspace_v1(&root, "never-created-workspace-id"),
        "idempotent delete",
    );
}

#[test]
fn delete_refuses_ids_that_could_escape_app_owned_storage() {
    let dir = TestDir::new("workspace-delete-traversal");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    // A sibling directory OUTSIDE the workspaces root that a traversal id would
    // target; it must never be touched.
    let outside = dir.path().join("outside-secret");
    ok(fs::create_dir_all(&outside), "outside dir");
    // Every id containing a path separator, parent ref, drive letter, or colon
    // is rejected by the strict validator BEFORE any filesystem action.
    for bad in [
        "../outside-secret",
        "..\\outside-secret",
        "a/b",
        "a\\b",
        "..",
        ".",
        "C:",
        "with space",
        "",
    ] {
        let error = err(
            delete_election_workspace_v1(&root, bad),
            &format!("id {bad:?} must be rejected"),
        );
        assert_eq!(error.code(), "GUI_WORKSPACE_INVALID_ID", "id {bad:?}");
    }
    assert!(
        outside.is_dir(),
        "a directory outside the workspaces root is never deleted",
    );
}

#[test]
fn draft_revision_is_versioned_and_discoverable_without_internal_path() {
    let dir = TestDir::new("workspace-draft");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let workspace_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "draft-election".to_owned(),
            "Should the draft survive restart?".to_owned(),
            "draft-revision".to_owned(),
        ),
        "draft basics",
    );

    let revision = ok(
        write_draft_workspace_revision_v1(&root, &workspace_id, &draft),
        "write draft",
    );
    assert_eq!(revision, 1);

    let summaries = ok(list_election_workspaces_v1(&root), "list workspaces");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].workspace_id, workspace_id);
    assert_eq!(summaries[0].lifecycle_state, "DRAFT");
    assert_eq!(
        summaries[0].question_preview.as_deref(),
        Some("Should the draft survive restart?")
    );
    let rendered = ok(serde_json::to_string(&summaries[0]), "summary json");
    assert!(!rendered.contains(dir.path().to_string_lossy().as_ref()));
}

#[test]
fn draft_created_then_resumed_preserves_public_organizer_fields() {
    let dir = TestDir::new("workspace-draft-resume");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let workspace_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "draft-election".to_owned(),
            "Should the recovered draft keep public fields?".to_owned(),
            "draft-revision".to_owned(),
        ),
        "draft basics",
    );
    ok(draft.set_rules(1, 2, false), "draft rules");
    ok(
        draft.set_voters(
            common::voters()
                .into_iter()
                .map(|voter| lower_hex(&voter.public_bytes))
                .collect(),
        ),
        "draft voters",
    );
    ok(
        draft.set_options(vec![
            ("candidate-a".to_owned(), "Candidate A".to_owned()),
            ("candidate-b".to_owned(), "Candidate B".to_owned()),
        ]),
        "draft options",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &workspace_id, &draft),
        "write draft",
    );

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume draft",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Draft { workspace, draft } => {
            let preview = draft.preview();
            assert_eq!(workspace.lifecycle_state, "DRAFT");
            assert_eq!(
                preview.proposal_question.as_deref(),
                Some("Should the recovered draft keep public fields?")
            );
            assert_eq!(preview.voter_count, 3);
            assert_eq!(preview.options.len(), 2);
            assert!(preview.complete);
        }
        LoadedElectionWorkspaceV1::Session { .. } => panic!("expected draft workspace"),
    }
}

#[test]
fn lifecycle_resume_preserves_state_and_reconstructs_tally() {
    let dir = TestDir::new("workspace-lifecycle");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&session);

    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write frozen",
    );
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume frozen",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "FROZEN");
            assert_eq!(session.lifecycle_state(), "FROZEN");
            assert_eq!(session.accepted_count(), 0);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }

    ok(session.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write open",
    );
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume open",
    );
    let mut session = match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "OPEN");
            assert_eq!(session.accepted_count(), 0);
            session
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    };

    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"])),
            "first intake",
        )
        .accepted
    );
    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"])),
            "second intake",
        )
        .accepted
    );
    ok(session.close(), "close");
    let expected_tally = ok(session.tally(), "closed tally");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write closed",
    );
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume closed",
    );
    let mut session = match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "CLOSED");
            assert_eq!(workspace.accepted_ballot_count, 2);
            assert_eq!(session.accepted_count(), 2);
            assert_eq!(ok(session.tally(), "resumed tally"), expected_tally);
            session
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    };

    ok(session.mark_verified(), "verify");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write verified",
    );
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume verified",
    );
    let mut session = match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "VERIFIED");
            assert_eq!(session.lifecycle_state(), "VERIFIED");
            session
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    };

    ok(session.finalize(), "finalize");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write finalized",
    );
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume finalized",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "FINALIZED");
            assert!(workspace.finalized);
            assert_eq!(session.lifecycle_state(), "FINALIZED");
            assert_eq!(session.accepted_count(), 2);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn frozen_draft_is_retired_from_resume_discovery_while_session_reaches_finalized() {
    let dir = TestDir::new("workspace-supersede");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );

    // A pre-freeze draft workspace exists on disk.
    let draft_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "supersede-election".to_owned(),
            "Should the frozen draft vanish from resume?".to_owned(),
            "draft-revision".to_owned(),
        ),
        "draft basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &draft_id, &draft),
        "write draft",
    );

    // The draft is frozen into its authoritative session workspace, which is
    // durably committed first (mirroring `freeze_election`).
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let session_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &session_id, &session),
        "write frozen session",
    );

    // Before marking, a crash would leave BOTH resumable (fail-open); nothing
    // is retired until the successor is durably committed AND marked.
    let before = ok(list_election_workspaces_v1(&root), "list before mark");
    assert!(before.iter().any(|w| w.workspace_id == draft_id));
    assert!(before.iter().any(|w| w.workspace_id == session_id));

    // Retire the originating draft, binding it to the authoritative session id.
    ok(
        mark_draft_workspace_superseded_v1(&root, &draft_id, &session_id),
        "supersede draft",
    );

    // The stale draft no longer competes with the authoritative session.
    let after_freeze = ok(list_election_workspaces_v1(&root), "list after mark");
    assert!(
        !after_freeze.iter().any(|w| w.workspace_id == draft_id),
        "a successfully frozen draft must be retired from resume discovery",
    );
    let session_summary = after_freeze
        .iter()
        .find(|w| w.workspace_id == session_id)
        .expect("authoritative session must remain discoverable");
    assert_eq!(session_summary.lifecycle_state, "FROZEN");

    // Advance the authoritative session through the full lifecycle: the draft
    // must stay retired and the session must remain monotonic to FINALIZED.
    ok(session.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &session_id, &session),
        "write open",
    );
    ok(session.close(), "close");
    ok(
        write_session_workspace_revision_v1(&root, &session_id, &session),
        "write closed",
    );
    ok(session.mark_verified(), "verify");
    ok(
        write_session_workspace_revision_v1(&root, &session_id, &session),
        "write verified",
    );
    ok(session.finalize(), "finalize");
    ok(
        write_session_workspace_revision_v1(&root, &session_id, &session),
        "write finalized",
    );

    let finalized = ok(list_election_workspaces_v1(&root), "list finalized");
    assert!(
        !finalized.iter().any(|w| w.workspace_id == draft_id),
        "the retired draft must not reappear beside the finalized election",
    );
    let final_summary = finalized
        .iter()
        .find(|w| w.workspace_id == session_id)
        .expect("finalized session must remain discoverable");
    assert_eq!(final_summary.lifecycle_state, "FINALIZED");
    assert!(final_summary.finalized);

    // Resuming the retired draft directly by id (a caller that still knows the
    // stale id) must be refused, not revive the draft over the finalized
    // election.
    let resume_stale = err(
        resume_election_workspace_v1(&root, &draft_id),
        "superseded draft must not resume by id after finalization",
    );
    assert_eq!(resume_stale.code(), "GUI_WORKSPACE_SUPERSEDED");

    // The authoritative finalized workspace still resumes as terminal FINALIZED.
    match ok(
        resume_election_workspace_v1(&root, &session_id),
        "resume finalized",
    ) {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "FINALIZED");
            assert!(workspace.finalized);
            assert_eq!(session.lifecycle_state(), "FINALIZED");
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

/// Finding 2: a superseded draft must not be resumable by id, even directly.
#[test]
fn superseded_draft_cannot_resume_by_id() {
    let dir = TestDir::new("workspace-supersede-resume");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let draft_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "resume-guard".to_owned(),
            "Can a superseded draft resume by id?".to_owned(),
            "draft-revision".to_owned(),
        ),
        "draft basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &draft_id, &draft),
        "write draft",
    );

    let session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let session_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &session_id, &session),
        "write session",
    );
    ok(
        mark_draft_workspace_superseded_v1(&root, &draft_id, &session_id),
        "supersede draft",
    );

    // Direct resume-by-id of the stale draft is refused with a bounded code.
    let error = err(
        resume_election_workspace_v1(&root, &draft_id),
        "superseded draft must not resume by id",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_SUPERSEDED");

    // The authoritative successor session still resumes.
    match ok(
        resume_election_workspace_v1(&root, &session_id),
        "resume successor session",
    ) {
        LoadedElectionWorkspaceV1::Session { .. } => {}
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

/// Finding 3: a non-draft (Session) workspace that happens to contain a
/// well-formed marker must NOT be hidden by supersession discovery.
#[test]
fn session_workspace_with_marker_is_still_listed_and_resumable() {
    let dir = TestDir::new("workspace-session-marker");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );

    // A committed session that the marker will (spuriously) point at.
    let other_session = ok(GuiElectionSessionV1::new(artifacts()), "other session");
    let other_session_id = workspace_id_for_session_v1(&other_session);
    ok(
        write_session_workspace_revision_v1(&root, &other_session_id, &other_session),
        "write other session",
    );

    // A distinct committed session (different manifest revision -> different
    // workspace id) that carries a stray marker in its directory.
    let marked_session = ok(
        GuiElectionSessionV1::new(common::artifacts_with_revision("stray-marker-rev")),
        "marked session",
    );
    let marked_session_id = workspace_id_for_session_v1(&marked_session);
    ok(
        write_session_workspace_revision_v1(&root, &marked_session_id, &marked_session),
        "write marked session",
    );
    // Place a syntactically valid marker inside the SESSION directory.
    ok(
        mark_draft_workspace_superseded_v1(&root, &marked_session_id, &other_session_id),
        "write stray marker in session",
    );

    // The marker must not hide the Session: it is not a Draft.
    let listed = ok(list_election_workspaces_v1(&root), "list");
    assert!(
        listed.iter().any(|w| w.workspace_id == marked_session_id),
        "a Session workspace must never be hidden by a marker file",
    );

    // And it still resumes as a Session (marker does not block non-drafts).
    match ok(
        resume_election_workspace_v1(&root, &marked_session_id),
        "resume marked session",
    ) {
        LoadedElectionWorkspaceV1::Session { .. } => {}
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

/// Finding 3: a draft whose marker points to another Draft (not a Session) is
/// NOT superseded — it stays discoverable and resumable.
#[test]
fn draft_with_draft_successor_is_not_superseded() {
    let dir = TestDir::new("workspace-draft-successor");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );

    let draft_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "draft-one".to_owned(),
            "Draft one".to_owned(),
            "rev".to_owned(),
        ),
        "draft one basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &draft_id, &draft),
        "write draft one",
    );

    // A second, committed DRAFT workspace used (incorrectly) as the successor.
    let successor_draft_id = ok(create_draft_workspace_id_v1(&root), "successor draft id");
    let mut successor_draft = GuiElectionDraftV1::new();
    ok(
        successor_draft.set_basics(
            "draft-two".to_owned(),
            "Draft two".to_owned(),
            "rev".to_owned(),
        ),
        "draft two basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &successor_draft_id, &successor_draft),
        "write draft two",
    );

    ok(
        mark_draft_workspace_superseded_v1(&root, &draft_id, &successor_draft_id),
        "mark superseded by a draft",
    );

    // A Draft successor does not supersede: the original draft stays listed.
    let listed = ok(list_election_workspaces_v1(&root), "list");
    assert!(
        listed.iter().any(|w| w.workspace_id == draft_id),
        "a draft whose successor is another Draft must remain discoverable",
    );

    // And it still resumes as a Draft.
    match ok(
        resume_election_workspace_v1(&root, &draft_id),
        "resume draft with draft successor",
    ) {
        LoadedElectionWorkspaceV1::Draft { .. } => {}
        LoadedElectionWorkspaceV1::Session { .. } => panic!("expected draft workspace"),
    }
}

/// Finding 2 fail-open: a marker pointing at a never-committed successor must
/// leave the draft resumable by id (not error).
#[test]
fn superseded_marker_with_uncommitted_successor_still_resumes_draft() {
    let dir = TestDir::new("workspace-supersede-resume-failopen");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let draft_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "failopen-resume".to_owned(),
            "Recoverable draft?".to_owned(),
            "rev".to_owned(),
        ),
        "draft basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &draft_id, &draft),
        "write draft",
    );
    let phantom_session_id = format!("election-{}", "0".repeat(64));
    ok(
        mark_draft_workspace_superseded_v1(&root, &draft_id, &phantom_session_id),
        "mark superseded by phantom",
    );

    // Resume-by-id fails open: the draft is still recoverable.
    match ok(
        resume_election_workspace_v1(&root, &draft_id),
        "fail-open resume of draft with uncommitted successor",
    ) {
        LoadedElectionWorkspaceV1::Draft { .. } => {}
        LoadedElectionWorkspaceV1::Session { .. } => panic!("expected draft workspace"),
    }
}

#[test]
fn supersession_marker_fails_open_when_successor_is_not_committed() {
    let dir = TestDir::new("workspace-supersede-failopen");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let draft_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let mut draft = GuiElectionDraftV1::new();
    ok(
        draft.set_basics(
            "failopen-election".to_owned(),
            "Is this draft still recoverable?".to_owned(),
            "draft-revision".to_owned(),
        ),
        "draft basics",
    );
    ok(
        write_draft_workspace_revision_v1(&root, &draft_id, &draft),
        "write draft",
    );

    // Mark the draft as superseded by a session id that was never committed.
    // The real ordering never produces this, but discovery MUST fail open so a
    // corrupt or premature marker never orphans a genuinely recoverable draft.
    let phantom_session_id = format!("election-{}", "0".repeat(64));
    ok(
        mark_draft_workspace_superseded_v1(&root, &draft_id, &phantom_session_id),
        "mark superseded by phantom",
    );

    let listed = ok(list_election_workspaces_v1(&root), "list");
    assert!(
        listed.iter().any(|w| w.workspace_id == draft_id),
        "a draft whose successor is not committed must remain resumable",
    );
}

#[test]
fn malformed_or_oversized_revision_is_rejected_before_resume() {
    let dir = TestDir::new("workspace-malformed");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let workspace_id = ok(create_draft_workspace_id_v1(&root), "draft id");
    let revisions = root.join(&workspace_id).join("revisions");
    let malformed = revisions.join(format!("0000000001-{}{}", "0".repeat(64), ".workspace"));
    ok(fs::write(&malformed, b"not-a-workspace"), "malformed write");

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "malformed only must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");

    ok(fs::remove_file(&malformed), "remove malformed");
    let oversized = revisions.join(format!("0000000001-{}{}", "1".repeat(64), ".workspace"));
    let file = ok(File::create(&oversized), "oversized create");
    ok(
        file.set_len((MAX_WORKSPACE_REVISION_BYTES_V1 as u64) + 1),
        "oversized set_len",
    );
    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "oversized only must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn uncommitted_orphan_revision_without_marker_does_not_advance_state() {
    let dir = TestDir::new("workspace-orphan-no-advance");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write frozen",
    );
    ok(session.open(), "open orphan future");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write open orphan fixture",
    );
    remove_commit_marker(&root, &workspace_id, 2);

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume committed head with orphan future",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.last_revision, 1);
            assert_eq!(workspace.lifecycle_state, "FROZEN");
            assert_eq!(session.lifecycle_state(), "FROZEN");
            assert_eq!(session.accepted_count(), 0);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn incomplete_temp_and_orphan_revision_with_ballot_do_not_destroy_committed_resume() {
    let dir = TestDir::new("workspace-uncommitted-final");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    let result = ok(session.intake_ballot_package_bytes(&first), "first intake");
    assert!(result.accepted);

    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write committed session",
    );
    let revisions = root.join(&workspace_id).join("revisions");
    let mut tmp = ok(
        File::create(revisions.join("0000000002-incomplete.workspace.tmp")),
        "tmp create",
    );
    ok(tmp.write_all(b"partial"), "tmp write");
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume with temp",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.last_revision, 1);
            assert_eq!(workspace.accepted_ballot_count, 1);
            assert_eq!(session.accepted_count(), 1);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }

    let second = triptych_package_bytes(1, &[b"candidate-b"]);
    let result = ok(
        session.intake_ballot_package_bytes(&second),
        "second intake",
    );
    assert!(result.accepted);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write orphan future with ballot",
    );
    remove_commit_marker(&root, &workspace_id, 2);

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume committed head ignoring orphan ballot",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.last_revision, 1);
            assert_eq!(workspace.accepted_ballot_count, 1);
            assert_eq!(session.accepted_count(), 1);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn multiple_uncommitted_future_revisions_do_not_become_authoritative() {
    let dir = TestDir::new("workspace-multiple-orphans");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write frozen",
    );
    ok(session.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write open orphan",
    );
    ok(session.close(), "close");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write closed orphan",
    );
    ok(session.mark_verified(), "verify");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write verified orphan",
    );
    for revision in 2..=4 {
        remove_commit_marker(&root, &workspace_id, revision);
    }

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume committed head with multiple orphans",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.last_revision, 1);
            assert_eq!(workspace.lifecycle_state, "FROZEN");
            assert_eq!(session.lifecycle_state(), "FROZEN");
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn invalid_future_revision_without_marker_is_ignored_as_uncommitted_orphan() {
    let dir = TestDir::new("workspace-invalid-orphan");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    assert!(ok(session.intake_ballot_package_bytes(&first), "first intake").accepted);
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write committed session",
    );
    let revisions = root.join(&workspace_id).join("revisions");
    ok(
        fs::write(
            revisions.join(format!("0000000002-{}{}", "2".repeat(64), ".workspace")),
            b"invalid-newest",
        ),
        "invalid newest",
    );
    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume committed head ignoring invalid orphan",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.last_revision, 1);
            assert_eq!(workspace.accepted_ballot_count, 1);
            assert_eq!(session.accepted_count(), 1);
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn committed_newest_revision_damage_fails_closed_without_rollback() {
    for (case, damage) in [
        ("corrupt", corrupt_file as fn(&Path)),
        ("truncate", truncate_file as fn(&Path)),
    ] {
        let dir = TestDir::new(&format!("workspace-newest-{case}"));
        let root = ok(
            ensure_election_workspaces_directory_v1(dir.path()),
            "workspace root",
        );
        let (workspace_id, _session) = two_revision_workspace(&root);
        let newest = revision_path(&root, &workspace_id, 2);
        damage(&newest);

        let error = err(
            resume_election_workspace_v1(&root, &workspace_id),
            "damaged committed newest revision must fail closed",
        );
        assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
    }
}

#[test]
fn deleted_committed_newest_revision_fails_closed_without_rollback() {
    let dir = TestDir::new("workspace-newest-delete");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let (workspace_id, _session) = two_revision_workspace(&root);
    ok(
        fs::remove_file(revision_path(&root, &workspace_id, 2)),
        "delete newest revision",
    );

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "deleted committed newest revision must fail closed",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn tampered_committed_newest_revision_fails_closed_without_rollback() {
    let dir = TestDir::new("workspace-newest-tamper");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let (workspace_id, _session) = two_revision_workspace(&root);
    let newest = revision_path(&root, &workspace_id, 2);
    let mut bytes = ok(fs::read(&newest), "read newest revision");
    bytes.extend_from_slice(b"tamper");
    ok(fs::write(&newest, bytes), "tamper newest revision");

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "tampered committed newest revision must fail closed",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn corrupt_committed_head_metadata_fails_closed() {
    let dir = TestDir::new("workspace-head-corrupt");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let (workspace_id, _session) = two_revision_workspace(&root);
    let head = commit_path(&root, &workspace_id, 2);
    corrupt_file(&head);

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "corrupt committed head metadata must fail closed",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn revision_predecessor_chain_validates_across_three_commits() {
    let dir = TestDir::new("workspace-history-valid");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write frozen",
    );
    ok(session.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write open",
    );
    ok(session.close(), "close");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write closed",
    );

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume three revision chain",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.last_revision, 3);
            assert_eq!(session.lifecycle_state(), "CLOSED");
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn missing_middle_committed_revision_fails_closed() {
    let dir = TestDir::new("workspace-history-missing-middle");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write frozen",
    );
    ok(session.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write open",
    );
    ok(session.close(), "close");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write closed",
    );
    ok(
        fs::remove_file(revision_path(&root, &workspace_id, 2)),
        "delete middle revision",
    );

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "missing middle revision must fail closed",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn wrong_predecessor_digest_fails_closed_even_when_redigested() {
    let dir = TestDir::new("workspace-history-wrong-predecessor");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write frozen",
    );
    ok(session.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write open",
    );
    ok(session.close(), "close");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write closed",
    );

    let rev2_digest = revision_path(&root, &workspace_id, 2)
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("0000000002-"))
        .and_then(|name| name.strip_suffix(".workspace"))
        .expect("revision 2 digest")
        .to_owned();
    let rev3 = revision_path(&root, &workspace_id, 3);
    let mut payload = ok(fs::read(&rev3), "read revision 3");
    let offset = payload
        .windows(rev2_digest.len())
        .position(|window| window == rev2_digest.as_bytes())
        .expect("revision 3 predecessor digest");
    payload[offset] = if payload[offset] == b'a' { b'b' } else { b'a' };
    let new_digest = revision_digest_hex(&payload);
    let new_rev3 = root
        .join(&workspace_id)
        .join("revisions")
        .join(format!("0000000003-{new_digest}.workspace"));
    ok(fs::write(&new_rev3, payload), "write redigested revision 3");
    ok(fs::remove_file(&rev3), "remove original revision 3");
    let old_commit = commit_path(&root, &workspace_id, 3);
    ok(fs::remove_file(&old_commit), "remove original commit 3");
    ok(
        fs::write(
            root.join(&workspace_id)
                .join("commits")
                .join(format!("0000000003-{new_digest}.commit")),
            encode_commit_marker(&workspace_id, 3, &new_digest),
        ),
        "write redigested commit 3",
    );

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "wrong predecessor digest must fail closed",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn same_generation_divergent_revision_commits_conflict_even_with_future_orphan() {
    let dir = TestDir::new("workspace-same-generation-conflict-a");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let other_dir = TestDir::new("workspace-same-generation-conflict-b");
    let other_root = ok(
        ensure_election_workspaces_directory_v1(other_dir.path()),
        "other workspace root",
    );

    let mut base = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&base);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &base),
        "write base revision",
    );
    ok(
        fs::create_dir_all(other_root.join(&workspace_id).join("revisions")),
        "other revisions",
    );
    ok(
        fs::create_dir_all(other_root.join(&workspace_id).join("commits")),
        "other commits",
    );
    for path in revision_files(&root, &workspace_id) {
        ok(
            fs::copy(
                &path,
                other_root
                    .join(&workspace_id)
                    .join("revisions")
                    .join(path.file_name().unwrap()),
            ),
            "copy base revision",
        );
    }
    for path in commit_files(&root, &workspace_id) {
        ok(
            fs::copy(
                &path,
                other_root
                    .join(&workspace_id)
                    .join("commits")
                    .join(path.file_name().unwrap()),
            ),
            "copy base commit",
        );
    }

    ok(base.open(), "open base");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &base),
        "write revision 2a",
    );
    let mut divergent = ok(
        GuiElectionSessionV1::new(artifacts()),
        "divergent frozen session",
    );
    ok(divergent.open(), "open divergent");
    assert!(
        ok(
            divergent.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"])),
            "divergent intake",
        )
        .accepted
    );
    ok(
        write_session_workspace_revision_v1(&other_root, &workspace_id, &divergent),
        "write revision 2b",
    );
    ok(
        fs::copy(
            revision_path(&other_root, &workspace_id, 2),
            root.join(&workspace_id).join("revisions").join(
                revision_path(&other_root, &workspace_id, 2)
                    .file_name()
                    .unwrap(),
            ),
        ),
        "copy divergent revision",
    );
    ok(
        fs::copy(
            commit_path(&other_root, &workspace_id, 2),
            root.join(&workspace_id).join("commits").join(
                commit_path(&other_root, &workspace_id, 2)
                    .file_name()
                    .unwrap(),
            ),
        ),
        "copy divergent commit",
    );
    ok(
        fs::write(
            root.join(&workspace_id).join("revisions").join(format!(
                "0000000003-{}{}",
                "3".repeat(64),
                ".workspace"
            )),
            b"uncommitted-future",
        ),
        "write uncommitted future orphan",
    );

    let error = err(
        resume_election_workspace_v1(&root, &workspace_id),
        "divergent same-generation commits must conflict",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CONFLICT");
}

#[test]
fn revision_copied_into_different_workspace_id_is_rejected() {
    let dir = TestDir::new("workspace-copy-wrong-id");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let (workspace_id, _session) = two_revision_workspace(&root);
    let copy_id = "election-copy-wrong-id";
    ok(
        fs::create_dir_all(root.join(copy_id).join("revisions")),
        "copy revisions",
    );
    ok(
        fs::create_dir_all(root.join(copy_id).join("commits")),
        "copy commits",
    );
    for path in revision_files(&root, &workspace_id) {
        ok(
            fs::copy(
                &path,
                root.join(copy_id)
                    .join("revisions")
                    .join(path.file_name().unwrap()),
            ),
            "copy revision",
        );
    }
    for path in commit_files(&root, &workspace_id) {
        ok(
            fs::copy(
                &path,
                root.join(copy_id)
                    .join("commits")
                    .join(path.file_name().unwrap()),
            ),
            "copy commit",
        );
    }

    let error = err(
        resume_election_workspace_v1(&root, copy_id),
        "copied revision must not validate under another workspace id",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_CORRUPT");
}

#[test]
fn lifecycle_regressions_and_finalized_appends_are_rejected() {
    let dir = TestDir::new("workspace-lifecycle-regression");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let frozen = ok(GuiElectionSessionV1::new(artifacts()), "frozen session");
    let workspace_id = workspace_id_for_session_v1(&frozen);
    assert_eq!(
        ok(
            write_session_workspace_revision_v1(&root, &workspace_id, &frozen),
            "write frozen",
        ),
        1
    );
    assert_eq!(
        ok(
            write_session_workspace_revision_v1(&root, &workspace_id, &frozen),
            "duplicate frozen idempotent",
        ),
        1
    );
    assert_eq!(revision_files(&root, &workspace_id).len(), 1);
    assert_eq!(commit_files(&root, &workspace_id).len(), 1);

    let mut open = frozen.transactional_clone();
    ok(open.open(), "open");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &open),
        "write open",
    );
    let error = err(
        write_session_workspace_revision_v1(&root, &workspace_id, &frozen),
        "frozen over open must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_RESUME_REQUIRED");

    let mut closed = open.transactional_clone();
    ok(closed.close(), "close");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &closed),
        "write closed",
    );
    let error = err(
        write_session_workspace_revision_v1(&root, &workspace_id, &open),
        "open over closed must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_RESUME_REQUIRED");

    let mut verified = closed.transactional_clone();
    ok(verified.mark_verified(), "verify");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &verified),
        "write verified",
    );
    let error = err(
        write_session_workspace_revision_v1(&root, &workspace_id, &frozen),
        "frozen over verified must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_RESUME_REQUIRED");

    let mut finalized = verified.transactional_clone();
    ok(finalized.finalize(), "finalize");
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &finalized),
        "write finalized",
    );
    for (label, stale) in [
        ("frozen", &frozen),
        ("open", &open),
        ("closed", &closed),
        ("verified", &verified),
    ] {
        let error = err(
            write_session_workspace_revision_v1(&root, &workspace_id, stale),
            &format!("{label} over finalized must fail"),
        );
        assert!(
            matches!(
                error.code(),
                "GUI_WORKSPACE_RESUME_REQUIRED" | "GUI_WORKSPACE_FINALIZED"
            ),
            "unexpected code {}",
            error.code()
        );
    }
}

#[test]
fn finalized_resume_is_terminal_and_rejects_ballot_intake() {
    let dir = TestDir::new("workspace-finalized-terminal");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"])),
            "first intake",
        )
        .accepted
    );
    ok(session.close(), "close");
    ok(session.mark_verified(), "verify");
    ok(session.finalize(), "finalize");
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write finalized",
    );

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume finalized",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session {
            workspace,
            mut session,
        } => {
            assert_eq!(workspace.lifecycle_state, "FINALIZED");
            assert!(workspace.finalized);
            let error = err(
                session.intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"])),
                "finalized intake must fail",
            );
            assert_eq!(error.code(), ValidationCode::ElectionNotOpen.as_str());
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn load_or_freeze_frozen_collision_after_finalized_requires_resume() {
    let dir = TestDir::new("workspace-load-finalized-collision");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut finalized = open_session();
    ok(finalized.close(), "close");
    ok(finalized.mark_verified(), "verify");
    ok(finalized.finalize(), "finalize");
    let workspace_id = workspace_id_for_session_v1(&finalized);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &finalized),
        "write finalized",
    );

    let stale_frozen = ok(GuiElectionSessionV1::new(artifacts()), "stale frozen");
    let error = err(
        write_session_workspace_revision_v1(&root, &workspace_id, &stale_frozen),
        "stale frozen over finalized must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_FINALIZED");

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume after failed stale frozen",
    );
    match loaded {
        LoadedElectionWorkspaceV1::Session { workspace, session } => {
            assert_eq!(workspace.lifecycle_state, "FINALIZED");
            assert_eq!(session.lifecycle_state(), "FINALIZED");
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    }
}

#[test]
fn transactional_clone_preserves_validated_state_without_durable_replay() {
    let mut session = open_session();
    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"])),
            "first intake",
        )
        .accepted
    );
    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(1, &[b"candidate-b"])),
            "second intake",
        )
        .accepted
    );

    let mut cloned = session.transactional_clone();
    assert_eq!(cloned.lifecycle_state(), "OPEN");
    assert_eq!(cloned.accepted_count(), 2);
    assert_eq!(cloned.packages(), session.packages());

    let duplicate = ok(
        cloned.intake_ballot(&triptych_package_bytes(0, &[b"candidate-c"])),
        "duplicate intake",
    );
    assert!(!duplicate.accepted);
    assert_eq!(duplicate.code, "DUPLICATE_BALLOT");
    assert_eq!(cloned.accepted_count(), 2);
    assert!(
        ok(
            cloned.intake_ballot(&triptych_package_bytes(2, &[b"candidate-c"])),
            "third intake",
        )
        .accepted
    );
    assert_eq!(cloned.accepted_count(), 3);
    assert_eq!(session.accepted_count(), 2);
}

#[test]
fn resume_replays_accepted_packages_and_rejects_duplicate_nullifier() {
    let dir = TestDir::new("workspace-duplicate");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    let duplicate = triptych_package_bytes(0, &[b"candidate-b"]);
    assert!(ok(session.intake_ballot(&first), "first intake").accepted);
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write session",
    );

    let loaded = ok(
        resume_election_workspace_v1(&root, &workspace_id),
        "resume session",
    );
    let mut resumed = match loaded {
        LoadedElectionWorkspaceV1::Session { session, workspace } => {
            assert_eq!(workspace.lifecycle_state, "OPEN");
            assert_eq!(workspace.accepted_ballot_count, 1);
            session
        }
        LoadedElectionWorkspaceV1::Draft { .. } => panic!("expected session workspace"),
    };

    let duplicate_result = ok(resumed.intake_ballot(&duplicate), "duplicate intake");
    assert!(!duplicate_result.accepted);
    assert_eq!(duplicate_result.code, "DUPLICATE_BALLOT");
    assert_eq!(resumed.accepted_count(), 1);
}

#[test]
fn workspace_revision_is_versioned_and_has_no_secret_type_markers() {
    let dir = TestDir::new("workspace-privacy-markers");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let mut session = open_session();
    assert!(
        ok(
            session.intake_ballot(&triptych_package_bytes(0, &[b"candidate-a"])),
            "first intake",
        )
        .accepted
    );
    let workspace_id = workspace_id_for_session_v1(&session);
    ok(
        write_session_workspace_revision_v1(&root, &workspace_id, &session),
        "write session",
    );
    let files = revision_files(&root, &workspace_id);
    assert_eq!(files.len(), 1);
    let payload = ok(fs::read(&files[0]), "read revision");

    assert!(payload.starts_with(b"TARI_PRIVATE_BALLOT_DURABLE_ELECTION_WORKSPACE_V1"));
    for forbidden in [
        b"VoterGovernanceCredentialV1".as_slice(),
        b"TariTriptychSecretKeyV1".as_slice(),
        b"credential passphrase".as_slice(),
        b"passphrase".as_slice(),
        b"member_index".as_slice(),
        b"selected_choice".as_slice(),
    ] {
        assert!(
            !payload
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "workspace revision must not contain marker {:?}",
            std::str::from_utf8(forbidden).unwrap_or("<binary>")
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_workspace_root_is_rejected_where_supported() {
    use std::os::unix::fs::symlink;

    let dir = TestDir::new("workspace-symlink");
    let target = dir.join("target");
    ok(fs::create_dir_all(&target), "target");
    let app_data = dir.join("app-data");
    ok(symlink(&target, &app_data), "symlink");
    let error = err(
        ensure_election_workspaces_directory_v1(&app_data),
        "symlink app-data root must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_UNSAFE_PATH");
}

#[cfg(unix)]
#[test]
fn symlink_workspace_entry_is_rejected_where_supported() {
    use std::os::unix::fs::symlink;

    let dir = TestDir::new("workspace-entry-symlink");
    let root = ok(
        ensure_election_workspaces_directory_v1(dir.path()),
        "workspace root",
    );
    let target = dir.join("target-workspace");
    ok(
        fs::create_dir_all(target.join("revisions")),
        "target revisions",
    );
    ok(
        symlink(&target, root.join("draft-symlink")),
        "workspace symlink",
    );

    let error = err(
        resume_election_workspace_v1(&root, "draft-symlink"),
        "symlink workspace entry must fail",
    );
    assert_eq!(error.code(), "GUI_WORKSPACE_UNSAFE_PATH");
}
