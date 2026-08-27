//! Durable local organizer election workspaces.
//!
//! The workspace is local operational recovery state, not a replacement for
//! final archives or Ootle anchor evidence. Each revision stores a narrow,
//! replayable representation: public organizer draft fields, or canonical
//! public election artifacts plus exact canonical ballot-package bytes.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, HashProvider, MAX_CANDIDATE_DISPLAY_NAME_BYTES, MAX_CANDIDATE_ID_BYTES,
    MAX_CANDIDATES, MAX_CANONICAL_OBJECT_BYTES, MAX_GOVERNANCE_KEY_BYTES, MAX_REGISTRY_MEMBERS,
};

use crate::creation::{GuiBallotPresentationType, GuiElectionDraftSnapshotV1, GuiElectionDraftV1};
use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::governance::MAX_GOVERNANCE_DOCUMENT_BYTES;
use crate::hex::to_lower_hex;
use crate::session::{GuiElectionSessionSnapshotV1, GuiElectionSessionV1};
use crate::summary::GuiElectionSummaryV1;

/// Backend-controlled directory name below the Tauri app-data root.
pub const ELECTION_WORKSPACES_DIRECTORY_NAME: &str = "election-workspaces";

/// Maximum size of one canonical ballot package read by the GUI boundary.
pub const MAX_BALLOT_PACKAGE_BYTES_V1: usize = MAX_CANONICAL_OBJECT_BYTES;
/// Maximum stored intake records in one workspace revision.
pub const MAX_WORKSPACE_PACKAGE_COUNT_V1: usize = MAX_REGISTRY_MEMBERS * 2;
/// Maximum completed revision file size accepted before allocation.
pub const MAX_WORKSPACE_REVISION_BYTES_V1: usize = 512 * 1024 * 1024;
/// Maximum workspace directories considered during one bounded discovery pass.
pub const MAX_ELECTION_WORKSPACES_V1: usize = 512;
/// Maximum revision files considered inside one workspace.
pub const MAX_WORKSPACE_REVISIONS_V1: usize = 10_000;

const WORKSPACE_MAGIC_V1: &[u8] = b"TARI_PRIVATE_BALLOT_DURABLE_ELECTION_WORKSPACE_V1";
const REVISION_DIGEST_DOMAIN_V1: &[u8] =
    b"tari-cc-private-ballot/durable-election-workspace-revision/v1";
const COMMIT_MAGIC_V1: &[u8] = b"TARI_PRIVATE_BALLOT_DURABLE_ELECTION_WORKSPACE_COMMIT_V1";
const FORMAT_VERSION_V1: u32 = 1;
const KIND_DRAFT: u8 = 1;
const KIND_SESSION: u8 = 2;
const PREDECESSOR_GENESIS: u8 = 0;
const PREDECESSOR_REVISION: u8 = 1;
const MAX_WORKSPACE_ID_BYTES: usize = 96;
const DIGEST_HEX_BYTES: usize = 64;
const MAX_LIFECYCLE_STATE_BYTES: usize = 16;
const MAX_PRESENTATION_BYTES: usize = 32;
const MAX_OPTION_DISPLAY_BYTES: usize = MAX_CANDIDATE_DISPLAY_NAME_BYTES;
const MAX_STRING_FIELD_BYTES: usize = 1024;
const REVISION_FILE_SUFFIX: &str = ".workspace";
const COMMIT_FILE_SUFFIX: &str = ".commit";
const MAX_WORKSPACE_COMMIT_BYTES_V1: usize = 1024;
const SUPERSEDED_MAGIC_V1: &[u8] = b"TARI_PRIVATE_BALLOT_DURABLE_ELECTION_WORKSPACE_SUPERSEDED_V1";
const SUPERSEDED_FILE_NAME: &str = "superseded";
const SUPERSEDED_TMP_FILE_NAME: &str = "superseded.tmp";
const MAX_SUPERSEDED_MARKER_BYTES_V1: usize = 1024;

/// Sidecar marker naming the durable ORGANIZER-AUTHORITY provenance of a
/// session workspace.
///
/// A durable workspace body holds ONLY public artifacts plus accepted public
/// ballot packages, so workspace content alone can never distinguish a real
/// ballot-office workspace from one synthesized from imported public election
/// artifacts. Authority provenance is therefore recorded EXPLICITLY, at the
/// moment an organizer flow first commits the workspace (freeze), in this
/// app-owned sidecar marker. Resume is fail-closed: a missing, unreadable, or
/// malformed marker means the workspace confers NO organizer authority.
const ORGANIZER_AUTHORITY_MARKER_FILE_NAME: &str = "organizer-authority";
const ORGANIZER_AUTHORITY_TMP_FILE_NAME: &str = "organizer-authority.tmp";
const ORGANIZER_AUTHORITY_MAGIC_V1: &[u8] = b"TARI_PRIVATE_BALLOT_WORKSPACE_ORGANIZER_AUTHORITY_V1";
const MAX_ORGANIZER_AUTHORITY_MARKER_BYTES_V1: usize = 256;

/// Public, organizer-safe discovery summary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionWorkspaceSummaryV1 {
    pub workspace_id: String,
    pub election_manifest_hash_hex: Option<String>,
    pub question_preview: Option<String>,
    pub lifecycle_state: String,
    pub accepted_ballot_count: usize,
    pub last_revision: u64,
    pub updated_at_unix_secs: Option<u64>,
    pub finalized: bool,
    /// True only when this workspace carries a valid durable ORGANIZER-AUTHORITY
    /// provenance marker. Session workspaces without it were created from public
    /// artifacts (or predate role separation) and confer voter-only authority on
    /// resume — fail-closed by design.
    pub organizer_workspace: bool,
}

/// Public response returned after a resume command installs a workspace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiElectionWorkspaceResumeResultV1 {
    pub workspace: GuiElectionWorkspaceSummaryV1,
    pub election: Option<GuiElectionSummaryV1>,
    pub draft: Option<crate::creation::GuiElectionDraftPreviewV1>,
    /// Whether the resumed workspace carries durable ORGANIZER-AUTHORITY
    /// provenance. Drafts are always organizer-created; session workspaces are
    /// organizer-authoritative only with a valid marker (fail-closed).
    pub organizer_workspace: bool,
}

/// Loaded workspace with reconstructed Rust state for the Tauri shell.
pub enum LoadedElectionWorkspaceV1 {
    Draft {
        workspace: GuiElectionWorkspaceSummaryV1,
        draft: GuiElectionDraftV1,
    },
    Session {
        workspace: GuiElectionWorkspaceSummaryV1,
        session: GuiElectionSessionV1,
    },
}

#[derive(Clone, PartialEq, Eq)]
enum DurableElectionWorkspaceBodyV1 {
    Draft(GuiElectionDraftSnapshotV1),
    Session(GuiElectionSessionSnapshotV1),
}

#[derive(Clone, PartialEq, Eq)]
enum RevisionPredecessorV1 {
    Genesis,
    Previous { revision: u64, digest_hex: String },
}

#[derive(Clone)]
struct DurableElectionWorkspaceV1 {
    workspace_id: String,
    revision: u64,
    predecessor: RevisionPredecessorV1,
    updated_at_unix_secs: Option<u64>,
    body: DurableElectionWorkspaceBodyV1,
}

struct ValidRevision {
    revision: u64,
    digest_hex: String,
    payload: Vec<u8>,
}

struct CommittedRevision {
    revision: u64,
    digest_hex: String,
    record: DurableElectionWorkspaceV1,
}

struct DurableWorkspaceCommitV1 {
    workspace_id: String,
    revision: u64,
    revision_digest_hex: String,
}

/// Returns the backend-controlled election-workspaces root for an app-data
/// directory supplied by the shell.
#[must_use]
pub fn election_workspaces_directory_v1(app_data_root: &Path) -> PathBuf {
    app_data_root.join(ELECTION_WORKSPACES_DIRECTORY_NAME)
}

/// Ensures and returns the backend-controlled workspace root under app data.
///
/// # Errors
///
/// Returns a bounded error if the app-data root or workspace root is a
/// symlink/reparse point, not a directory, or cannot be created.
pub fn ensure_election_workspaces_directory_v1(
    app_data_root: &Path,
) -> Result<PathBuf, GuiCoreError> {
    ensure_direct_directory(app_data_root, "app-data")?;
    let root = election_workspaces_directory_v1(app_data_root);
    ensure_direct_directory(&root, "election-workspaces")?;
    Ok(root)
}

/// Creates a backend-generated opaque draft workspace id.
///
/// # Errors
///
/// Returns a bounded I/O error after bounded collision attempts.
pub fn create_draft_workspace_id_v1(workspaces_root: &Path) -> Result<String, GuiCoreError> {
    ensure_direct_directory(workspaces_root, "election-workspaces")?;
    let timestamp = now_nanos()?;
    let pid = u128::from(std::process::id());
    for attempt in 0_u128..1024 {
        let id = format!("draft-{timestamp:032x}{pid:08x}{attempt:04x}");
        validate_workspace_id_v1(&id)?;
        let workspace_dir = workspaces_root.join(&id);
        match fs::create_dir(&workspace_dir) {
            Ok(()) => {
                restrict_directory_permissions(&workspace_dir)?;
                ensure_direct_directory(&workspace_dir.join("revisions"), "election-workspace")?;
                ensure_direct_directory(&workspace_dir.join("commits"), "election-workspace")?;
                return Ok(id);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(GuiCoreError::io_failure("election-workspace")),
        }
    }
    Err(GuiCoreError::new(
        "GUI_WORKSPACE_ID_COLLISION",
        GuiErrorCategory::FileIo,
        Some("election-workspace"),
        "could not allocate a unique election workspace identifier",
    ))
}

/// Returns the manifest-derived workspace id for a session.
#[must_use]
pub fn workspace_id_for_session_v1(session: &GuiElectionSessionV1) -> String {
    format!(
        "election-{}",
        to_lower_hex(session.artifacts().manifest_hash().as_bytes())
    )
}

/// Validates one public workspace id supplied by the frontend.
pub fn validate_workspace_id_v1(workspace_id: &str) -> Result<(), GuiCoreError> {
    if workspace_id.is_empty()
        || workspace_id.len() > MAX_WORKSPACE_ID_BYTES
        || !workspace_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(GuiCoreError::new(
            "GUI_WORKSPACE_INVALID_ID",
            GuiErrorCategory::InvalidInput,
            Some("election-workspace"),
            "workspace id is not a valid backend-issued identifier",
        ));
    }
    Ok(())
}

/// Writes the next crash-resilient revision for a draft.
pub fn write_draft_workspace_revision_v1(
    workspaces_root: &Path,
    workspace_id: &str,
    draft: &GuiElectionDraftV1,
) -> Result<u64, GuiCoreError> {
    let body = DurableElectionWorkspaceBodyV1::Draft(draft.to_durable_snapshot());
    write_workspace_revision(workspaces_root, workspace_id, body)
}

/// Writes the next crash-resilient revision for a session.
pub fn write_session_workspace_revision_v1(
    workspaces_root: &Path,
    workspace_id: &str,
    session: &GuiElectionSessionV1,
) -> Result<u64, GuiCoreError> {
    let body = DurableElectionWorkspaceBodyV1::Session(session.to_durable_snapshot()?);
    write_workspace_revision(workspaces_root, workspace_id, body)
}

/// Lists public, organizer-safe summaries for valid resumable workspaces.
pub fn list_election_workspaces_v1(
    workspaces_root: &Path,
) -> Result<Vec<GuiElectionWorkspaceSummaryV1>, GuiCoreError> {
    ensure_direct_directory(workspaces_root, "election-workspaces")?;

    let mut summaries = Vec::new();
    let mut inspected = 0_usize;
    for entry in fs::read_dir(workspaces_root)
        .map_err(|_| GuiCoreError::io_failure("election-workspaces"))?
    {
        let entry = entry.map_err(|_| GuiCoreError::io_failure("election-workspaces"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| GuiCoreError::io_failure("election-workspaces"))?;
        if !metadata.is_dir() {
            continue;
        }
        if metadata_is_reparse_point(&metadata) {
            return Err(unsafe_workspace_path());
        }
        inspected = inspected.checked_add(1).ok_or_else(too_many_workspaces)?;
        if inspected > MAX_ELECTION_WORKSPACES_V1 {
            return Err(too_many_workspaces());
        }

        let Some(workspace_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if validate_workspace_id_v1(&workspace_id).is_err() {
            continue;
        }
        match load_newest_workspace(workspaces_root, &workspace_id) {
            // A draft that was frozen into an authoritative session workspace is
            // retired from resume discovery once that successor session is
            // durably committed. The supersession decision is made on the
            // loaded record (see `draft_superseding_session_v1`): only a real
            // Draft, with a valid marker pointing to a committed *Session*, is
            // hidden. Fail-open otherwise, so a crash between freeze and marking
            // (or a stray marker on a non-draft) never orphans a workspace.
            Ok(Some(record)) => {
                if draft_superseding_session_v1(workspaces_root, &record).is_none() {
                    summaries.push(summarize_workspace(workspaces_root, &record)?);
                }
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }

    summaries.sort_by(|a, b| {
        b.updated_at_unix_secs
            .cmp(&a.updated_at_unix_secs)
            .then_with(|| b.last_revision.cmp(&a.last_revision))
            .then_with(|| a.workspace_id.cmp(&b.workspace_id))
    });
    Ok(summaries)
}

/// Loads, validates, and reconstructs one workspace by public id.
pub fn resume_election_workspace_v1(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<LoadedElectionWorkspaceV1, GuiCoreError> {
    let record = load_newest_workspace(workspaces_root, workspace_id)?.ok_or_else(|| {
        GuiCoreError::new(
            "GUI_WORKSPACE_NOT_FOUND",
            GuiErrorCategory::FileIo,
            Some("election-workspace"),
            "no valid election workspace revision was found",
        )
    })?;
    // Resume-by-id must honor the same supersession rule as discovery: a stale
    // draft that was already frozen into a committed session must never be
    // revived as an active mutable draft, even when the caller already knows
    // its workspace id. Fail-open cases (malformed marker, missing/uncommitted
    // successor, non-session successor, self-reference) fall through and the
    // draft resumes normally.
    if draft_superseding_session_v1(workspaces_root, &record).is_some() {
        return Err(GuiCoreError::new(
            "GUI_WORKSPACE_SUPERSEDED",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("election-workspace"),
            "this draft was superseded by a frozen election workspace; resume the successor election instead",
        ));
    }
    let workspace = summarize_workspace(workspaces_root, &record)?;
    match record.body {
        DurableElectionWorkspaceBodyV1::Draft(snapshot) => {
            let draft = GuiElectionDraftV1::from_durable_snapshot(snapshot)?;
            Ok(LoadedElectionWorkspaceV1::Draft { workspace, draft })
        }
        DurableElectionWorkspaceBodyV1::Session(snapshot) => {
            let session = GuiElectionSessionV1::from_durable_snapshot(snapshot)?;
            Ok(LoadedElectionWorkspaceV1::Session { workspace, session })
        }
    }
}

/// Deletes one local election workspace directory by backend-issued id.
///
/// Safety: the id is validated by [`validate_workspace_id_v1`] (ASCII
/// alphanumeric, `-`, `_` only, bounded length), so `workspaces_root.join(id)`
/// is always a DIRECT child of the app-owned workspaces root — it can never
/// contain `.`, `..`, `/`, `\`, a drive letter, or a colon, and therefore can
/// never traverse outside app-owned storage. The target is additionally
/// required to be a real directory that is NOT a symlink / Windows reparse
/// point, so a redirected entry can never redirect the recursive removal
/// outside the workspaces root. Only the durable workspace under the app-data
/// root is removed; exported canonical election files and finalized archives
/// stored elsewhere are never touched. A missing workspace is treated as
/// already-deleted (idempotent success).
pub fn delete_election_workspace_v1(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<(), GuiCoreError> {
    validate_workspace_id_v1(workspace_id)?;
    let dir = workspaces_root.join(workspace_id);
    let metadata = match fs::symlink_metadata(&dir) {
        Ok(metadata) => metadata,
        // Already gone → idempotent success (nothing left to delete).
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(workspace_delete_error()),
    };
    if metadata.file_type().is_symlink()
        || is_workspace_reparse_point_v1(&metadata)
        || !metadata.is_dir()
    {
        return Err(GuiCoreError::new(
            "GUI_WORKSPACE_DELETE_REFUSED",
            GuiErrorCategory::InvalidInput,
            Some("election-workspace"),
            "refusing to delete a workspace entry that is not an app-owned directory",
        ));
    }
    fs::remove_dir_all(&dir).map_err(|_| workspace_delete_error())
}

fn workspace_delete_error() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_DELETE_FAILED",
        GuiErrorCategory::FileIo,
        Some("election-workspace"),
        "the local election workspace could not be deleted",
    )
}

#[cfg(windows)]
fn is_workspace_reparse_point_v1(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT (0x400): junctions and mount points that
    // could otherwise redirect a recursive delete outside app-owned storage.
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
fn is_workspace_reparse_point_v1(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Reads one ballot package with a pre-allocation size bound.
pub fn read_ballot_package_file_bounded_v1(path: &Path) -> Result<Vec<u8>, GuiCoreError> {
    read_bounded_file(path, MAX_BALLOT_PACKAGE_BYTES_V1, "ballot-package")
}

/// Durably records that a draft workspace has been superseded by the frozen
/// session workspace it produced.
///
/// The marker binds the draft to the authoritative session workspace id
/// (`election-<manifest-hash>`). Discovery then retires the draft from the
/// resumable list once that successor is durably committed, so a successfully
/// frozen election never appears twice on Home.
///
/// # Crash safety
///
/// This MUST be called only *after* the superseding session workspace revision
/// is durably committed. A crash between the freeze commit and this marker
/// leaves the draft resumable (fail-open), never orphaned. The marker itself is
/// written atomically (temp file, then rename) so a partial write is never
/// observed as a valid marker.
///
/// # Errors
///
/// Returns a bounded error if either id is not a valid backend-issued
/// identifier, the draft workspace path is unsafe, or the marker cannot be
/// written.
pub fn mark_draft_workspace_superseded_v1(
    workspaces_root: &Path,
    draft_workspace_id: &str,
    superseded_by_workspace_id: &str,
) -> Result<(), GuiCoreError> {
    validate_workspace_id_v1(draft_workspace_id)?;
    validate_workspace_id_v1(superseded_by_workspace_id)?;
    let workspace_dir = workspaces_root.join(draft_workspace_id);
    match fs::symlink_metadata(&workspace_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(GuiCoreError::new(
                "GUI_WORKSPACE_NOT_FOUND",
                GuiErrorCategory::FileIo,
                Some("election-workspace"),
                "no draft election workspace exists to supersede",
            ));
        }
        Err(_) => return Err(GuiCoreError::io_failure("election-workspace")),
    }

    let marker_path = workspace_dir.join(SUPERSEDED_FILE_NAME);
    // Idempotent: re-marking with the same successor (e.g. a re-freeze) is a
    // no-op rather than an error.
    if read_supersession_marker(&marker_path).as_deref() == Some(superseded_by_workspace_id) {
        return Ok(());
    }

    let payload = encode_supersession_marker(superseded_by_workspace_id)?;
    let tmp_path = workspace_dir.join(SUPERSEDED_TMP_FILE_NAME);
    let _ = fs::remove_file(&tmp_path);
    write_create_new_sync(&tmp_path, &payload, "election-workspace")?;
    if fs::rename(&tmp_path, &marker_path).is_err() {
        let _ = fs::remove_file(&tmp_path);
        return Err(GuiCoreError::io_failure("election-workspace"));
    }
    sync_directory_best_effort(&workspace_dir);
    Ok(())
}

/// Reads and validates the supersession marker for one workspace directory,
/// returning the recorded successor session workspace id. Fail-open: any
/// missing, unreadable, or malformed marker yields `None` so a draft is only
/// hidden when a positively valid marker exists.
fn read_supersession_marker_for(workspaces_root: &Path, workspace_id: &str) -> Option<String> {
    let marker_path = workspaces_root
        .join(workspace_id)
        .join(SUPERSEDED_FILE_NAME);
    read_supersession_marker(&marker_path)
}

fn read_supersession_marker(marker_path: &Path) -> Option<String> {
    let bytes = read_bounded_file(
        marker_path,
        MAX_SUPERSEDED_MARKER_BYTES_V1,
        "election-workspace",
    )
    .ok()?;
    let mut reader = BinaryReader::new(&bytes);
    reader.expect_bytes(SUPERSEDED_MAGIC_V1).ok()?;
    if reader.u32().ok()? != FORMAT_VERSION_V1 {
        return None;
    }
    let successor_id = reader.string(MAX_WORKSPACE_ID_BYTES).ok()?;
    validate_workspace_id_v1(&successor_id).ok()?;
    Some(successor_id)
}

fn encode_supersession_marker(superseded_by_workspace_id: &str) -> Result<Vec<u8>, GuiCoreError> {
    let mut writer = BinaryWriter::new();
    writer.bytes(SUPERSEDED_MAGIC_V1);
    writer.u32(FORMAT_VERSION_V1);
    writer.string(superseded_by_workspace_id, MAX_WORKSPACE_ID_BYTES)?;
    Ok(writer.into_bytes())
}

// -------------------------------------------------------------------------
// Durable organizer-authority provenance
// -------------------------------------------------------------------------

/// Durably records that `workspace_id` is an ORGANIZER-AUTHORITATIVE workspace.
///
/// This MUST be called only by organizer flows that themselves establish
/// authority over the election (today: freezing a newly created election), and
/// strictly AFTER the workspace revision it vouches for is durably committed.
/// The marker is idempotent: marking an already-marked workspace succeeds
/// without rewriting anything.
///
/// # Crash safety
///
/// A crash before the marker write leaves the workspace resumable WITHOUT
/// organizer authority (the fail-closed direction): the operator re-runs the
/// organizer flow rather than silently gaining authority from public data. The
/// marker itself is written atomically (temp file, then rename) so a partial
/// write is never observed as a valid marker.
///
/// # Errors
///
/// Returns a bounded error if the id is not a valid backend-issued identifier,
/// the workspace path is unsafe, or the marker cannot be written.
pub fn mark_workspace_organizer_authority_v1(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<(), GuiCoreError> {
    validate_workspace_id_v1(workspace_id)?;
    let workspace_dir = workspaces_root.join(workspace_id);
    match fs::symlink_metadata(&workspace_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(GuiCoreError::new(
                "GUI_WORKSPACE_NOT_FOUND",
                GuiErrorCategory::FileIo,
                Some("election-workspace"),
                "no election workspace exists to mark as organizer-authoritative",
            ));
        }
        Err(_) => return Err(GuiCoreError::io_failure("election-workspace")),
    }

    let marker_path = workspace_dir.join(ORGANIZER_AUTHORITY_MARKER_FILE_NAME);
    // Idempotent: an existing valid marker means nothing changes.
    if decode_organizer_authority_marker(
        &read_bounded_file(
            &marker_path,
            MAX_ORGANIZER_AUTHORITY_MARKER_BYTES_V1,
            "election-workspace",
        )
        .unwrap_or_default(),
    ) {
        return Ok(());
    }

    let payload = encode_organizer_authority_marker();
    let tmp_path = workspace_dir.join(ORGANIZER_AUTHORITY_TMP_FILE_NAME);
    let _ = fs::remove_file(&tmp_path);
    write_create_new_sync(&tmp_path, &payload, "election-workspace")?;
    if fs::rename(&tmp_path, &marker_path).is_err() {
        let _ = fs::remove_file(&tmp_path);
        return Err(GuiCoreError::io_failure("election-workspace"));
    }
    sync_directory_best_effort(&workspace_dir);
    Ok(())
}

/// Fail-closed provenance probe: true ONLY when `workspace_id` carries a valid
/// durable organizer-authority marker. Any missing, unreadable, malformed,
/// wrong-version, or unsafe marker yields `false`, so public artifacts alone —
/// or any legacy workspace written before role separation — can never confer
/// organizer authority on resume.
#[must_use]
pub fn workspace_has_organizer_authority_v1(workspaces_root: &Path, workspace_id: &str) -> bool {
    validate_workspace_id_v1(workspace_id).is_ok()
        && decode_organizer_authority_marker(
            &read_bounded_file(
                &workspaces_root
                    .join(workspace_id)
                    .join(ORGANIZER_AUTHORITY_MARKER_FILE_NAME),
                MAX_ORGANIZER_AUTHORITY_MARKER_BYTES_V1,
                "election-workspace",
            )
            .unwrap_or_default(),
        )
}

fn encode_organizer_authority_marker() -> Vec<u8> {
    let mut writer = BinaryWriter::new();
    writer.bytes(ORGANIZER_AUTHORITY_MAGIC_V1);
    writer.u32(FORMAT_VERSION_V1);
    writer.into_bytes()
}

/// Strict marker validation: exact magic + current format version + exact
/// length (nothing may trail).
fn decode_organizer_authority_marker(bytes: &[u8]) -> bool {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_bytes(ORGANIZER_AUTHORITY_MAGIC_V1).is_ok()
        && reader.u32().ok() == Some(FORMAT_VERSION_V1)
        && reader.finish().is_ok()
}

/// Decides whether `record` is a Draft that has been genuinely superseded by a
/// committed successor Session, returning that successor's workspace id.
///
/// This is the single authoritative supersession gate shared by discovery and
/// resume-by-id. It returns `Some(successor_id)` **only** when every condition
/// holds; otherwise it fails open (`None`) so a workspace is never wrongly
/// hidden or blocked:
///
/// 1. `record` itself loads/validates as a Draft (a Session is never hidden,
///    even if a marker file is present in its directory).
/// 2. The draft's supersession marker is well-formed and valid.
/// 3. The successor id is not the draft itself (a self-reference is invalid).
/// 4. The successor exists and has a valid committed head.
/// 5. The successor loads/validates as a Session (a Draft successor does not
///    supersede).
///
/// Identity binding is authoritative: the marker is the freeze-written binding
/// from this specific draft to this specific committed session, and the
/// successor type is confirmed by loading it — no election-question text is
/// used.
fn draft_superseding_session_v1(
    workspaces_root: &Path,
    record: &DurableElectionWorkspaceV1,
) -> Option<String> {
    // Only a real Draft can be superseded.
    if !matches!(record.body, DurableElectionWorkspaceBodyV1::Draft(_)) {
        return None;
    }
    let successor_id = read_supersession_marker_for(workspaces_root, &record.workspace_id)?;
    // A marker pointing at the draft's own id is invalid.
    if successor_id == record.workspace_id {
        return None;
    }
    // The successor must exist, have a committed head, and be a Session.
    match load_newest_workspace(workspaces_root, &successor_id) {
        Ok(Some(successor))
            if matches!(successor.body, DurableElectionWorkspaceBodyV1::Session(_)) =>
        {
            Some(successor_id)
        }
        _ => None,
    }
}

fn write_workspace_revision(
    workspaces_root: &Path,
    workspace_id: &str,
    body: DurableElectionWorkspaceBodyV1,
) -> Result<u64, GuiCoreError> {
    ensure_workspace_dirs(workspaces_root, workspace_id)?;
    let committed = load_committed_history(workspaces_root, workspace_id)?;
    let (current_revision, predecessor) = match committed.last() {
        Some(head) => {
            if head.record.body == body {
                return Ok(head.revision);
            }
            enforce_workspace_append_allowed(&head.record.body, &body)?;
            (
                head.revision,
                RevisionPredecessorV1::Previous {
                    revision: head.revision,
                    digest_hex: head.digest_hex.clone(),
                },
            )
        }
        None => (0, RevisionPredecessorV1::Genesis),
    };
    let revision = current_revision.checked_add(1).ok_or_else(|| {
        GuiCoreError::new(
            "GUI_WORKSPACE_REVISION_OVERFLOW",
            GuiErrorCategory::ArchiveIntegrity,
            Some("election-workspace"),
            "workspace revision number overflowed",
        )
    })?;
    let record = DurableElectionWorkspaceV1 {
        workspace_id: workspace_id.to_owned(),
        revision,
        predecessor,
        updated_at_unix_secs: Some(now_unix_secs()?),
        body,
    };
    let payload = encode_workspace(&record)?;
    let digest_hex = revision_digest_hex(&payload);
    let revisions_dir = workspace_revisions_dir(workspaces_root, workspace_id)?;
    let commits_dir = workspace_commits_dir(workspaces_root, workspace_id)?;
    let final_path =
        revisions_dir.join(format!("{revision:010}-{digest_hex}{REVISION_FILE_SUFFIX}"));
    let commit_path = commits_dir.join(format!("{revision:010}-{digest_hex}{COMMIT_FILE_SUFFIX}"));
    let tmp_path = temp_revision_path(&revisions_dir, revision)?;

    write_create_new_sync(&tmp_path, &payload, "election-workspace")?;
    let decoded = decode_workspace(&payload)?;
    if decoded.revision != revision || decoded.workspace_id != workspace_id {
        let _ = fs::remove_file(&tmp_path);
        return Err(corrupt_workspace());
    }
    write_create_new_sync(&final_path, &payload, "election-workspace")?;
    let _ = fs::remove_file(&tmp_path);
    sync_directory_best_effort(&revisions_dir);
    let commit = DurableWorkspaceCommitV1 {
        workspace_id: workspace_id.to_owned(),
        revision,
        revision_digest_hex: digest_hex,
    };
    let commit_payload = encode_commit_marker(&commit)?;
    write_create_new_sync(&commit_path, &commit_payload, "election-workspace")?;
    sync_directory_best_effort(&commits_dir);
    Ok(revision)
}

fn load_newest_workspace(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<Option<DurableElectionWorkspaceV1>, GuiCoreError> {
    Ok(load_committed_history(workspaces_root, workspace_id)?
        .pop()
        .map(|committed| committed.record))
}

fn load_committed_history(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<Vec<CommittedRevision>, GuiCoreError> {
    validate_workspace_id_v1(workspace_id)?;
    let workspace_dir = workspaces_root.join(workspace_id);
    match fs::symlink_metadata(&workspace_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(GuiCoreError::io_failure("election-workspace")),
    }

    let revisions_dir = workspace_revisions_dir(workspaces_root, workspace_id)?;
    match fs::symlink_metadata(&revisions_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if has_revision_files(&revisions_dir)? {
                Err(corrupt_workspace())
            } else {
                Ok(Vec::new())
            };
        }
        Err(_) => return Err(GuiCoreError::io_failure("election-workspace")),
    }

    let commits_dir = workspace_commits_dir(workspaces_root, workspace_id)?;
    match fs::symlink_metadata(&commits_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return if has_revision_files(&revisions_dir)? {
                Err(corrupt_workspace())
            } else {
                Ok(Vec::new())
            };
        }
        Err(_) => return Err(GuiCoreError::io_failure("election-workspace")),
    }

    let committed_digests = load_commit_markers(&commits_dir, workspace_id)?;
    if committed_digests.is_empty() {
        return if has_revision_files(&revisions_dir)? {
            Err(corrupt_workspace())
        } else {
            Ok(Vec::new())
        };
    }

    let head_revision = *committed_digests
        .keys()
        .next_back()
        .ok_or_else(corrupt_workspace)?;
    let observed_revisions =
        load_committed_revision_files(&revisions_dir, workspace_id, head_revision)?;

    let mut committed_history = Vec::with_capacity(committed_digests.len());
    let mut previous_digest_hex: Option<String> = None;
    for expected_revision in 1..=head_revision {
        let expected_digest_hex = committed_digests
            .get(&expected_revision)
            .ok_or_else(corrupt_workspace)?;
        let valid = observed_revisions
            .get(&expected_revision)
            .ok_or_else(corrupt_workspace)?;
        if valid.digest_hex != *expected_digest_hex {
            return Err(corrupt_workspace());
        }
        let record = decode_workspace(&valid.payload)?;
        validate_predecessor(&record, expected_revision, previous_digest_hex.as_deref())?;
        previous_digest_hex = Some(valid.digest_hex.clone());
        committed_history.push(CommittedRevision {
            revision: expected_revision,
            digest_hex: valid.digest_hex.clone(),
            record,
        });
    }

    Ok(committed_history)
}

fn load_commit_markers(
    commits_dir: &Path,
    workspace_id: &str,
) -> Result<BTreeMap<u64, String>, GuiCoreError> {
    let mut committed_digests: BTreeMap<u64, String> = BTreeMap::new();
    let mut inspected = 0_usize;

    for entry in
        fs::read_dir(commits_dir).map_err(|_| GuiCoreError::io_failure("election-workspace"))?
    {
        let entry = entry.map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.ends_with(COMMIT_FILE_SUFFIX) {
            continue;
        }
        inspected = inspected.checked_add(1).ok_or_else(too_many_revisions)?;
        if inspected > MAX_WORKSPACE_REVISIONS_V1 {
            return Err(too_many_revisions());
        }

        let Some((revision, expected_digest)) = parse_commit_filename(&name) else {
            return Err(corrupt_workspace());
        };
        let commit = read_commit_marker(&entry.path(), revision, expected_digest, workspace_id)?;
        if let Some(existing_digest) =
            committed_digests.insert(revision, commit.revision_digest_hex.clone())
            && existing_digest != commit.revision_digest_hex
        {
            return Err(conflicting_workspace());
        }
    }

    let mut expected_revision = 1_u64;
    for revision in committed_digests.keys() {
        if *revision != expected_revision {
            return Err(corrupt_workspace());
        }
        expected_revision = expected_revision
            .checked_add(1)
            .ok_or_else(corrupt_workspace)?;
    }

    Ok(committed_digests)
}

fn load_committed_revision_files(
    revisions_dir: &Path,
    workspace_id: &str,
    committed_head_revision: u64,
) -> Result<BTreeMap<u64, ValidRevision>, GuiCoreError> {
    let mut valid_by_revision: BTreeMap<u64, ValidRevision> = BTreeMap::new();
    let mut inspected = 0_usize;

    for entry in
        fs::read_dir(revisions_dir).map_err(|_| GuiCoreError::io_failure("election-workspace"))?
    {
        let entry = entry.map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.ends_with(REVISION_FILE_SUFFIX) {
            continue;
        }
        inspected = inspected.checked_add(1).ok_or_else(too_many_revisions)?;
        if inspected > MAX_WORKSPACE_REVISIONS_V1 {
            return Err(too_many_revisions());
        }

        let Some((revision, expected_digest)) = parse_revision_filename(&name) else {
            return Err(corrupt_workspace());
        };
        if revision > committed_head_revision {
            continue;
        }
        let valid =
            read_valid_revision_file(&entry.path(), revision, expected_digest, workspace_id)?;
        if let Some(existing) = valid_by_revision.get(&valid.revision)
            && existing.digest_hex != valid.digest_hex
        {
            return Err(conflicting_workspace());
        }
        valid_by_revision.insert(valid.revision, valid);
    }

    Ok(valid_by_revision)
}

fn read_valid_revision_file(
    path: &Path,
    revision: u64,
    expected_digest_hex: &str,
    workspace_id: &str,
) -> Result<ValidRevision, GuiCoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(unsafe_workspace_path());
    }
    if metadata.len() > MAX_WORKSPACE_REVISION_BYTES_V1 as u64 {
        return Err(corrupt_workspace());
    }
    let payload = fs::read(path).map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
    let digest_hex = revision_digest_hex(&payload);
    if digest_hex != expected_digest_hex {
        return Err(corrupt_workspace());
    }
    let record = decode_workspace(&payload)?;
    if record.revision != revision || record.workspace_id != workspace_id {
        return Err(corrupt_workspace());
    }
    Ok(ValidRevision {
        revision,
        digest_hex,
        payload,
    })
}

fn read_commit_marker(
    path: &Path,
    revision: u64,
    expected_digest_hex: &str,
    workspace_id: &str,
) -> Result<DurableWorkspaceCommitV1, GuiCoreError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(unsafe_workspace_path());
    }
    if metadata.len() > MAX_WORKSPACE_COMMIT_BYTES_V1 as u64 {
        return Err(corrupt_workspace());
    }
    let payload = fs::read(path).map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
    let commit = decode_commit_marker(&payload)?;
    if commit.revision != revision
        || commit.workspace_id != workspace_id
        || commit.revision_digest_hex != expected_digest_hex
    {
        return Err(corrupt_workspace());
    }
    Ok(commit)
}

fn validate_predecessor(
    record: &DurableElectionWorkspaceV1,
    expected_revision: u64,
    previous_digest_hex: Option<&str>,
) -> Result<(), GuiCoreError> {
    if record.revision != expected_revision {
        return Err(corrupt_workspace());
    }
    match (&record.predecessor, expected_revision, previous_digest_hex) {
        (RevisionPredecessorV1::Genesis, 1, None) => Ok(()),
        (
            RevisionPredecessorV1::Previous {
                revision,
                digest_hex,
            },
            current_revision,
            Some(previous_digest_hex),
        ) if revision.checked_add(1) == Some(current_revision)
            && digest_hex == previous_digest_hex =>
        {
            Ok(())
        }
        _ => Err(corrupt_workspace()),
    }
}

fn enforce_workspace_append_allowed(
    current: &DurableElectionWorkspaceBodyV1,
    next: &DurableElectionWorkspaceBodyV1,
) -> Result<(), GuiCoreError> {
    match (current, next) {
        (
            DurableElectionWorkspaceBodyV1::Session(current),
            DurableElectionWorkspaceBodyV1::Session(next),
        ) => enforce_session_lifecycle_append(current.lifecycle_state, next.lifecycle_state),
        (DurableElectionWorkspaceBodyV1::Draft(_), DurableElectionWorkspaceBodyV1::Draft(_)) => {
            Ok(())
        }
        _ => Err(conflicting_workspace()),
    }
}

fn enforce_session_lifecycle_append(
    current: ElectionLifecycleStateV1,
    next: ElectionLifecycleStateV1,
) -> Result<(), GuiCoreError> {
    if matches!(current, ElectionLifecycleStateV1::Finalized) {
        return Err(finalized_workspace_terminal());
    }
    if lifecycle_rank(next)? < lifecycle_rank(current)? {
        return Err(existing_workspace_must_be_resumed());
    }
    Ok(())
}

fn lifecycle_rank(state: ElectionLifecycleStateV1) -> Result<u8, GuiCoreError> {
    match state {
        ElectionLifecycleStateV1::Draft => Err(corrupt_workspace()),
        ElectionLifecycleStateV1::Frozen => Ok(0),
        ElectionLifecycleStateV1::Open => Ok(1),
        ElectionLifecycleStateV1::Closed => Ok(2),
        ElectionLifecycleStateV1::Verified => Ok(3),
        ElectionLifecycleStateV1::Finalized => Ok(4),
    }
}

fn summarize_workspace(
    workspaces_root: &Path,
    record: &DurableElectionWorkspaceV1,
) -> Result<GuiElectionWorkspaceSummaryV1, GuiCoreError> {
    // Provenance is a durable property of the WORKSPACE DIRECTORY: drafts are
    // organizer-created objects by construction, while session workspaces are
    // organizer-authoritative only with a valid marker (fail-closed otherwise).
    let organizer_workspace = match &record.body {
        DurableElectionWorkspaceBodyV1::Draft(_) => true,
        DurableElectionWorkspaceBodyV1::Session(_) => {
            workspace_has_organizer_authority_v1(workspaces_root, &record.workspace_id)
        }
    };
    match &record.body {
        DurableElectionWorkspaceBodyV1::Draft(snapshot) => {
            let draft = GuiElectionDraftV1::from_durable_snapshot(snapshot.clone())?;
            let preview = draft.preview();
            Ok(GuiElectionWorkspaceSummaryV1 {
                workspace_id: record.workspace_id.clone(),
                election_manifest_hash_hex: preview.manifest_hash_hex,
                question_preview: preview.proposal_question.as_deref().map(question_preview),
                lifecycle_state: "DRAFT".to_owned(),
                accepted_ballot_count: 0,
                last_revision: record.revision,
                updated_at_unix_secs: record.updated_at_unix_secs,
                finalized: false,
                organizer_workspace,
            })
        }
        DurableElectionWorkspaceBodyV1::Session(snapshot) => {
            let session = GuiElectionSessionV1::from_durable_snapshot(snapshot.clone())?;
            let election = session.summary();
            let lifecycle_state = session.lifecycle_state().to_owned();
            Ok(GuiElectionWorkspaceSummaryV1 {
                workspace_id: record.workspace_id.clone(),
                election_manifest_hash_hex: Some(election.manifest_hash_hex),
                question_preview: election.proposal_question.as_deref().map(question_preview),
                lifecycle_state,
                accepted_ballot_count: session.accepted_count(),
                last_revision: record.revision,
                updated_at_unix_secs: record.updated_at_unix_secs,
                finalized: session.lifecycle_state_v1() == ElectionLifecycleStateV1::Finalized,
                organizer_workspace,
            })
        }
    }
}

fn encode_workspace(record: &DurableElectionWorkspaceV1) -> Result<Vec<u8>, GuiCoreError> {
    let mut writer = BinaryWriter::new();
    writer.bytes(WORKSPACE_MAGIC_V1);
    writer.u32(FORMAT_VERSION_V1);
    writer.u64(record.revision);
    encode_predecessor(&mut writer, &record.predecessor)?;
    writer.u64(record.updated_at_unix_secs.unwrap_or(0));
    writer.string(&record.workspace_id, MAX_WORKSPACE_ID_BYTES)?;
    match &record.body {
        DurableElectionWorkspaceBodyV1::Draft(snapshot) => {
            writer.u8(KIND_DRAFT);
            encode_draft(&mut writer, snapshot)?;
        }
        DurableElectionWorkspaceBodyV1::Session(snapshot) => {
            writer.u8(KIND_SESSION);
            encode_session(&mut writer, snapshot)?;
        }
    }
    Ok(writer.into_bytes())
}

fn encode_predecessor(
    writer: &mut BinaryWriter,
    predecessor: &RevisionPredecessorV1,
) -> Result<(), GuiCoreError> {
    match predecessor {
        RevisionPredecessorV1::Genesis => writer.u8(PREDECESSOR_GENESIS),
        RevisionPredecessorV1::Previous {
            revision,
            digest_hex,
        } => {
            writer.u8(PREDECESSOR_REVISION);
            writer.u64(*revision);
            writer.digest_hex(digest_hex)?;
        }
    }
    Ok(())
}

fn decode_predecessor(
    reader: &mut BinaryReader<'_>,
) -> Result<RevisionPredecessorV1, GuiCoreError> {
    match reader.u8()? {
        PREDECESSOR_GENESIS => Ok(RevisionPredecessorV1::Genesis),
        PREDECESSOR_REVISION => Ok(RevisionPredecessorV1::Previous {
            revision: reader.u64()?,
            digest_hex: reader.digest_hex()?,
        }),
        _ => Err(corrupt_workspace()),
    }
}

fn decode_workspace(bytes: &[u8]) -> Result<DurableElectionWorkspaceV1, GuiCoreError> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_bytes(WORKSPACE_MAGIC_V1)?;
    let version = reader.u32()?;
    if version != FORMAT_VERSION_V1 {
        return Err(GuiCoreError::new(
            "GUI_WORKSPACE_UNSUPPORTED_VERSION",
            GuiErrorCategory::UnsupportedFormat,
            Some("election-workspace"),
            "durable election workspace version is not supported",
        ));
    }
    let revision = reader.u64()?;
    let predecessor = decode_predecessor(&mut reader)?;
    let updated_at = match reader.u64()? {
        0 => None,
        value => Some(value),
    };
    let workspace_id = reader.string(MAX_WORKSPACE_ID_BYTES)?;
    validate_workspace_id_v1(&workspace_id)?;
    let body = match reader.u8()? {
        KIND_DRAFT => DurableElectionWorkspaceBodyV1::Draft(decode_draft(&mut reader)?),
        KIND_SESSION => DurableElectionWorkspaceBodyV1::Session(decode_session(&mut reader)?),
        _ => return Err(corrupt_workspace()),
    };
    reader.finish()?;
    Ok(DurableElectionWorkspaceV1 {
        workspace_id,
        revision,
        predecessor,
        updated_at_unix_secs: updated_at,
        body,
    })
}

fn encode_commit_marker(commit: &DurableWorkspaceCommitV1) -> Result<Vec<u8>, GuiCoreError> {
    let mut writer = BinaryWriter::new();
    writer.bytes(COMMIT_MAGIC_V1);
    writer.u32(FORMAT_VERSION_V1);
    writer.u64(commit.revision);
    writer.string(&commit.workspace_id, MAX_WORKSPACE_ID_BYTES)?;
    writer.digest_hex(&commit.revision_digest_hex)?;
    Ok(writer.into_bytes())
}

fn decode_commit_marker(bytes: &[u8]) -> Result<DurableWorkspaceCommitV1, GuiCoreError> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_bytes(COMMIT_MAGIC_V1)?;
    let version = reader.u32()?;
    if version != FORMAT_VERSION_V1 {
        return Err(GuiCoreError::new(
            "GUI_WORKSPACE_UNSUPPORTED_VERSION",
            GuiErrorCategory::UnsupportedFormat,
            Some("election-workspace"),
            "durable election workspace version is not supported",
        ));
    }
    let revision = reader.u64()?;
    let workspace_id = reader.string(MAX_WORKSPACE_ID_BYTES)?;
    validate_workspace_id_v1(&workspace_id)?;
    let revision_digest_hex = reader.digest_hex()?;
    reader.finish()?;
    Ok(DurableWorkspaceCommitV1 {
        workspace_id,
        revision,
        revision_digest_hex,
    })
}

fn encode_draft(
    writer: &mut BinaryWriter,
    snapshot: &GuiElectionDraftSnapshotV1,
) -> Result<(), GuiCoreError> {
    writer.optional_bytes(snapshot.election_id.as_deref(), MAX_STRING_FIELD_BYTES)?;
    writer.optional_string(
        snapshot.proposal_question.as_deref(),
        MAX_STRING_FIELD_BYTES,
    )?;
    writer.optional_string(
        snapshot.governance_source_revision.as_deref(),
        MAX_STRING_FIELD_BYTES,
    )?;
    writer.optional_usize(snapshot.approval_min)?;
    writer.optional_usize(snapshot.approval_max)?;
    writer.bool(snapshot.allow_abstention);
    writer.string(snapshot.presentation.as_str(), MAX_PRESENTATION_BYTES)?;
    writer.vec_of_bytes(
        &snapshot.voters,
        MAX_REGISTRY_MEMBERS,
        MAX_GOVERNANCE_KEY_BYTES,
    )?;
    writer.u32(usize_to_u32(snapshot.options.len())?);
    for (id, display) in &snapshot.options {
        writer.len_bytes(id, MAX_CANDIDATE_ID_BYTES)?;
        writer.string(display, MAX_OPTION_DISPLAY_BYTES)?;
    }
    writer.optional_bytes(
        snapshot.governance_document_bytes.as_deref(),
        MAX_GOVERNANCE_DOCUMENT_BYTES,
    )?;
    Ok(())
}

fn decode_draft(reader: &mut BinaryReader<'_>) -> Result<GuiElectionDraftSnapshotV1, GuiCoreError> {
    let election_id = reader.optional_bytes(MAX_STRING_FIELD_BYTES)?;
    let proposal_question = reader.optional_string(MAX_STRING_FIELD_BYTES)?;
    let governance_source_revision = reader.optional_string(MAX_STRING_FIELD_BYTES)?;
    let approval_min = reader.optional_usize()?;
    let approval_max = reader.optional_usize()?;
    let allow_abstention = reader.bool()?;
    let presentation =
        GuiBallotPresentationType::from_identifier(&reader.string(MAX_PRESENTATION_BYTES)?)?;
    let voters = reader.vec_of_bytes(MAX_REGISTRY_MEMBERS, MAX_GOVERNANCE_KEY_BYTES)?;
    let option_count = reader.count(MAX_CANDIDATES)?;
    let mut options = Vec::with_capacity(option_count);
    for _ in 0..option_count {
        let id = reader.len_bytes(MAX_CANDIDATE_ID_BYTES)?;
        let display = reader.string(MAX_OPTION_DISPLAY_BYTES)?;
        options.push((id, display));
    }
    let governance_document_bytes = reader.optional_bytes(MAX_GOVERNANCE_DOCUMENT_BYTES)?;
    Ok(GuiElectionDraftSnapshotV1 {
        election_id,
        proposal_question,
        governance_source_revision,
        approval_min,
        approval_max,
        allow_abstention,
        voters,
        options,
        presentation,
        governance_document_bytes,
    })
}

fn encode_session(
    writer: &mut BinaryWriter,
    snapshot: &GuiElectionSessionSnapshotV1,
) -> Result<(), GuiCoreError> {
    writer.string(snapshot.lifecycle_state.as_str(), MAX_LIFECYCLE_STATE_BYTES)?;
    writer.len_bytes(&snapshot.manifest_bytes, MAX_CANONICAL_OBJECT_BYTES)?;
    writer.len_bytes(&snapshot.registry_bytes, MAX_CANONICAL_OBJECT_BYTES)?;
    writer.len_bytes(&snapshot.candidate_bytes, MAX_CANONICAL_OBJECT_BYTES)?;
    writer.vec_of_bytes(
        &snapshot.packages,
        MAX_WORKSPACE_PACKAGE_COUNT_V1,
        MAX_BALLOT_PACKAGE_BYTES_V1,
    )?;
    Ok(())
}

fn decode_session(
    reader: &mut BinaryReader<'_>,
) -> Result<GuiElectionSessionSnapshotV1, GuiCoreError> {
    let lifecycle_state = parse_lifecycle_state(&reader.string(MAX_LIFECYCLE_STATE_BYTES)?)?;
    let manifest_bytes = reader.len_bytes(MAX_CANONICAL_OBJECT_BYTES)?;
    let registry_bytes = reader.len_bytes(MAX_CANONICAL_OBJECT_BYTES)?;
    let candidate_bytes = reader.len_bytes(MAX_CANONICAL_OBJECT_BYTES)?;
    let packages =
        reader.vec_of_bytes(MAX_WORKSPACE_PACKAGE_COUNT_V1, MAX_BALLOT_PACKAGE_BYTES_V1)?;
    Ok(GuiElectionSessionSnapshotV1 {
        lifecycle_state,
        manifest_bytes,
        registry_bytes,
        candidate_bytes,
        packages,
    })
}

fn parse_lifecycle_state(value: &str) -> Result<ElectionLifecycleStateV1, GuiCoreError> {
    match value {
        "DRAFT" => Ok(ElectionLifecycleStateV1::Draft),
        "FROZEN" => Ok(ElectionLifecycleStateV1::Frozen),
        "OPEN" => Ok(ElectionLifecycleStateV1::Open),
        "CLOSED" => Ok(ElectionLifecycleStateV1::Closed),
        "VERIFIED" => Ok(ElectionLifecycleStateV1::Verified),
        "FINALIZED" => Ok(ElectionLifecycleStateV1::Finalized),
        _ => Err(corrupt_workspace()),
    }
}

fn workspace_revisions_dir(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<PathBuf, GuiCoreError> {
    validate_workspace_id_v1(workspace_id)?;
    Ok(workspaces_root.join(workspace_id).join("revisions"))
}

fn workspace_commits_dir(
    workspaces_root: &Path,
    workspace_id: &str,
) -> Result<PathBuf, GuiCoreError> {
    validate_workspace_id_v1(workspace_id)?;
    Ok(workspaces_root.join(workspace_id).join("commits"))
}

fn ensure_workspace_dirs(workspaces_root: &Path, workspace_id: &str) -> Result<(), GuiCoreError> {
    ensure_direct_directory(workspaces_root, "election-workspaces")?;
    validate_workspace_id_v1(workspace_id)?;
    let workspace_dir = workspaces_root.join(workspace_id);
    ensure_direct_directory(&workspace_dir, "election-workspace")?;
    ensure_direct_directory(&workspace_dir.join("revisions"), "election-workspace")?;
    ensure_direct_directory(&workspace_dir.join("commits"), "election-workspace")?;
    Ok(())
}

fn ensure_direct_directory(path: &Path, context: &'static str) -> Result<(), GuiCoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
            restrict_directory_permissions(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| GuiCoreError::io_failure(context))?;
            let metadata =
                fs::symlink_metadata(path).map_err(|_| GuiCoreError::io_failure(context))?;
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_workspace_path());
            }
            restrict_directory_permissions(path)
        }
        Err(_) => Err(GuiCoreError::io_failure(context)),
    }
}

fn read_bounded_file(
    path: &Path,
    max_bytes: usize,
    context: &'static str,
) -> Result<Vec<u8>, GuiCoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found(context)
        } else {
            GuiCoreError::io_failure(context)
        }
    })?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(unsafe_workspace_path());
    }
    if metadata.len() > max_bytes as u64 {
        return Err(GuiCoreError::new(
            "GUI_WORKSPACE_SIZE_LIMIT_EXCEEDED",
            GuiErrorCategory::InvalidInput,
            Some(context),
            "file exceeds the durable election workspace size limit",
        ));
    }
    fs::read(path).map_err(|_| GuiCoreError::io_failure(context))
}

fn write_create_new_sync(
    path: &Path,
    bytes: &[u8],
    context: &'static str,
) -> Result<(), GuiCoreError> {
    let mut created = false;
    let result = (|| -> Result<(), GuiCoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| GuiCoreError::io_failure(context))?;
        created = true;
        file.write_all(bytes)
            .map_err(|_| GuiCoreError::io_failure(context))?;
        file.flush()
            .map_err(|_| GuiCoreError::io_failure(context))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure(context))?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(path);
    }
    result
}

fn has_revision_files(revisions_dir: &Path) -> Result<bool, GuiCoreError> {
    match fs::read_dir(revisions_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|_| GuiCoreError::io_failure("election-workspace"))?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.ends_with(REVISION_FILE_SUFFIX) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(GuiCoreError::io_failure("election-workspace")),
    }
}

fn sync_directory_best_effort(path: &Path) {
    if let Ok(file) = File::open(path) {
        let _ = file.sync_all();
    }
}

fn temp_revision_path(revisions_dir: &Path, revision: u64) -> Result<PathBuf, GuiCoreError> {
    let stamp = now_nanos()?;
    let pid = std::process::id();
    Ok(revisions_dir.join(format!(
        "{revision:010}-{stamp:032x}-{pid:08x}.workspace.tmp"
    )))
}

fn parse_revision_filename(name: &str) -> Option<(u64, &str)> {
    parse_number_digest_filename(name, REVISION_FILE_SUFFIX)
}

fn parse_commit_filename(name: &str) -> Option<(u64, &str)> {
    parse_number_digest_filename(name, COMMIT_FILE_SUFFIX)
}

fn parse_number_digest_filename<'a>(name: &'a str, suffix: &str) -> Option<(u64, &'a str)> {
    let stem = name.strip_suffix(suffix)?;
    let (revision_text, digest_hex) = stem.split_once('-')?;
    if revision_text.len() != 10
        || !revision_text.bytes().all(|byte| byte.is_ascii_digit())
        || !digest_hex_is_canonical(digest_hex)
    {
        return None;
    }
    let revision = revision_text.parse::<u64>().ok()?;
    Some((revision, digest_hex))
}

fn digest_hex_is_canonical(value: &str) -> bool {
    value.len() == DIGEST_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest_hex(value: &str) -> Result<(), GuiCoreError> {
    if digest_hex_is_canonical(value) {
        Ok(())
    } else {
        Err(corrupt_workspace())
    }
}

fn revision_digest_hex(payload: &[u8]) -> String {
    let mut framed = Vec::with_capacity(REVISION_DIGEST_DOMAIN_V1.len() + 1 + payload.len());
    framed.extend_from_slice(REVISION_DIGEST_DOMAIN_V1);
    framed.push(0);
    framed.extend_from_slice(payload);
    let provider = Blake3HashProviderV1;
    to_lower_hex(&provider.hash(&framed))
}

fn question_preview(question: &str) -> String {
    const MAX_CHARS: usize = 120;
    let mut preview = String::new();
    for (index, ch) in question.chars().enumerate() {
        if index >= MAX_CHARS {
            preview.push_str("...");
            return preview;
        }
        preview.push(ch);
    }
    preview
}

fn now_unix_secs() -> Result<u64, GuiCoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| GuiCoreError::io_failure("election-workspace"))
}

fn now_nanos() -> Result<u128, GuiCoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|_| GuiCoreError::io_failure("election-workspace"))
}

fn usize_to_u32(value: usize) -> Result<u32, GuiCoreError> {
    u32::try_from(value).map_err(|_| {
        GuiCoreError::new(
            "GUI_WORKSPACE_SIZE_LIMIT_EXCEEDED",
            GuiErrorCategory::InvalidInput,
            Some("election-workspace"),
            "workspace field exceeds the durable election workspace size limit",
        )
    })
}

fn u64_to_usize(value: u64) -> Result<usize, GuiCoreError> {
    usize::try_from(value).map_err(|_| corrupt_workspace())
}

fn too_many_workspaces() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_DISCOVERY_LIMIT_EXCEEDED",
        GuiErrorCategory::InvalidInput,
        Some("election-workspace"),
        "too many election workspaces were present for one bounded discovery pass",
    )
}

fn too_many_revisions() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_REVISION_LIMIT_EXCEEDED",
        GuiErrorCategory::InvalidInput,
        Some("election-workspace"),
        "too many workspace revisions were present for one bounded discovery pass",
    )
}

fn corrupt_workspace() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_CORRUPT",
        GuiErrorCategory::ArchiveIntegrity,
        Some("election-workspace"),
        "durable election workspace failed validation",
    )
}

fn conflicting_workspace() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_CONFLICT",
        GuiErrorCategory::ArchiveIntegrity,
        Some("election-workspace"),
        "durable election workspace has conflicting revision history",
    )
}

fn existing_workspace_must_be_resumed() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_RESUME_REQUIRED",
        GuiErrorCategory::InvalidLifecycleTransition,
        Some("election-workspace"),
        "an existing durable election workspace is later in its lifecycle and must be resumed",
    )
}

fn finalized_workspace_terminal() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_FINALIZED",
        GuiErrorCategory::InvalidLifecycleTransition,
        Some("election-workspace"),
        "a finalized durable election workspace is terminal and cannot be appended",
    )
}

fn unsafe_workspace_path() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_WORKSPACE_UNSAFE_PATH",
        GuiErrorCategory::FileIo,
        Some("election-workspace"),
        "workspace path is a symlink, reparse point, or unsafe non-direct path",
    )
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), GuiCoreError> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|_| GuiCoreError::io_failure("election-workspace"))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), GuiCoreError> {
    Ok(())
}

struct BinaryWriter {
    bytes: Vec<u8>,
}

impl BinaryWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn optional_usize(&mut self, value: Option<usize>) -> Result<(), GuiCoreError> {
        match value {
            Some(value) => {
                self.bool(true);
                self.u64(u64::try_from(value).map_err(|_| corrupt_workspace())?);
            }
            None => self.bool(false),
        }
        Ok(())
    }

    fn string(&mut self, value: &str, max_bytes: usize) -> Result<(), GuiCoreError> {
        self.len_bytes(value.as_bytes(), max_bytes)
    }

    fn digest_hex(&mut self, value: &str) -> Result<(), GuiCoreError> {
        validate_digest_hex(value)?;
        self.string(value, DIGEST_HEX_BYTES)
    }

    fn optional_string(
        &mut self,
        value: Option<&str>,
        max_bytes: usize,
    ) -> Result<(), GuiCoreError> {
        match value {
            Some(value) => {
                self.bool(true);
                self.string(value, max_bytes)?;
            }
            None => self.bool(false),
        }
        Ok(())
    }

    fn optional_bytes(
        &mut self,
        value: Option<&[u8]>,
        max_bytes: usize,
    ) -> Result<(), GuiCoreError> {
        match value {
            Some(value) => {
                self.bool(true);
                self.len_bytes(value, max_bytes)?;
            }
            None => self.bool(false),
        }
        Ok(())
    }

    fn len_bytes(&mut self, value: &[u8], max_bytes: usize) -> Result<(), GuiCoreError> {
        if value.len() > max_bytes {
            return Err(GuiCoreError::new(
                "GUI_WORKSPACE_SIZE_LIMIT_EXCEEDED",
                GuiErrorCategory::InvalidInput,
                Some("election-workspace"),
                "workspace field exceeds the durable election workspace size limit",
            ));
        }
        self.u32(usize_to_u32(value.len())?);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn vec_of_bytes(
        &mut self,
        values: &[Vec<u8>],
        max_count: usize,
        max_bytes: usize,
    ) -> Result<(), GuiCoreError> {
        if values.len() > max_count {
            return Err(GuiCoreError::new(
                "GUI_WORKSPACE_SIZE_LIMIT_EXCEEDED",
                GuiErrorCategory::InvalidInput,
                Some("election-workspace"),
                "workspace vector exceeds the durable election workspace count limit",
            ));
        }
        self.u32(usize_to_u32(values.len())?);
        for value in values {
            self.len_bytes(value, max_bytes)?;
        }
        Ok(())
    }
}

struct BinaryReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), GuiCoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(corrupt_workspace())
        }
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), GuiCoreError> {
        let actual = self.take(expected.len())?;
        if actual == expected {
            Ok(())
        } else {
            Err(corrupt_workspace())
        }
    }

    fn u8(&mut self) -> Result<u8, GuiCoreError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn bool(&mut self) -> Result<bool, GuiCoreError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(corrupt_workspace()),
        }
    }

    fn u32(&mut self) -> Result<u32, GuiCoreError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, GuiCoreError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn optional_usize(&mut self) -> Result<Option<usize>, GuiCoreError> {
        if self.bool()? {
            Ok(Some(u64_to_usize(self.u64()?)?))
        } else {
            Ok(None)
        }
    }

    fn string(&mut self, max_bytes: usize) -> Result<String, GuiCoreError> {
        let bytes = self.len_bytes(max_bytes)?;
        String::from_utf8(bytes).map_err(|_| corrupt_workspace())
    }

    fn digest_hex(&mut self) -> Result<String, GuiCoreError> {
        let value = self.string(DIGEST_HEX_BYTES)?;
        validate_digest_hex(&value)?;
        Ok(value)
    }

    fn optional_string(&mut self, max_bytes: usize) -> Result<Option<String>, GuiCoreError> {
        if self.bool()? {
            Ok(Some(self.string(max_bytes)?))
        } else {
            Ok(None)
        }
    }

    fn optional_bytes(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, GuiCoreError> {
        if self.bool()? {
            Ok(Some(self.len_bytes(max_bytes)?))
        } else {
            Ok(None)
        }
    }

    fn len_bytes(&mut self, max_bytes: usize) -> Result<Vec<u8>, GuiCoreError> {
        let len = self.count(max_bytes)?;
        Ok(self.take(len)?.to_vec())
    }

    fn vec_of_bytes(
        &mut self,
        max_count: usize,
        max_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, GuiCoreError> {
        let count = self.count(max_count)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.len_bytes(max_bytes)?);
        }
        Ok(values)
    }

    fn count(&mut self, max_count: usize) -> Result<usize, GuiCoreError> {
        let count = self.u32()? as usize;
        if count > max_count {
            return Err(corrupt_workspace());
        }
        Ok(count)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], GuiCoreError> {
        let end = self.offset.checked_add(len).ok_or_else(corrupt_workspace)?;
        if end > self.bytes.len() {
            return Err(corrupt_workspace());
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
}
