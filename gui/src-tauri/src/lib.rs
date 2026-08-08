//! Tauri 2 desktop shell for Tari Private Ballot (Phase 5, Slice 5A3).
//!
//! This crate is a thin typed-command boundary over
//! `tari-cc-private-ballot-gui-core`, exactly as staged by ADR-0007: the GUI
//! calls the backend in process, through gui-core only. There is no local
//! HTTP server, no CLI stdout parsing, and no shelling out to project
//! binaries. No protocol, cryptographic, archive, tally, verification,
//! walletd, or lifecycle logic lives here: every command delegates verbatim
//! to a gui-core facade entry point and returns its bounded view models.
//!
//! The shell holds no secrets. No command accepts or returns a voter secret
//! scalar, walletd bearer token, wallet seed, mnemonic, or signing material.

use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;
use tari_cc_private_ballot_gui_core::{
    GuiAnchorConfigInspectionV1, GuiAnchorEvidenceInspectionV1, GuiAnchorSnapshotInspectionV1,
    GuiArchiveVerificationV1, GuiArchiveWriteResultV1, GuiBallotIntakeResultV1, GuiCoreError,
    GuiElectionArtifactsV1, GuiElectionSessionV1, GuiElectionSummaryV1, GuiParticipationSummaryV1,
    GuiTallySummaryV1, inspect_anchor_config_v1, inspect_anchor_evidence_v1,
    inspect_anchor_snapshot_v1, verify_archive_directory_v1, write_archive_directory_v1,
};

/// Serializable command error: a bounded copy of the gui-core error model.
///
/// Carries the same stable machine code, coarse category, optional static
/// context label, and bounded static message. No path, secret, or raw
/// third-party text crosses the boundary (inherited from gui-core).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CommandError {
    code: String,
    category: String,
    context: Option<String>,
    message: String,
}

impl CommandError {
    fn new(code: &'static str, category: &'static str, message: &'static str) -> Self {
        Self {
            code: code.to_owned(),
            category: category.to_owned(),
            context: None,
            message: message.to_owned(),
        }
    }

    fn no_session() -> Self {
        Self::new(
            "GUI_NO_ACTIVE_ELECTION",
            "INVALID_LIFECYCLE_TRANSITION",
            "no election session is active in this shell",
        )
    }

    fn state_poisoned() -> Self {
        Self::new(
            "GUI_STATE_UNAVAILABLE",
            "FILE_IO",
            "the shell session state is unavailable",
        )
    }

    fn package_read_failed() -> Self {
        Self::new(
            "GUI_IO_ERROR",
            "FILE_IO",
            "the ballot package file could not be read",
        )
    }
}

impl From<GuiCoreError> for CommandError {
    fn from(error: GuiCoreError) -> Self {
        Self {
            code: error.code().to_owned(),
            category: error.category().as_str().to_owned(),
            context: error.context().map(str::to_owned),
            message: error.message().to_owned(),
        }
    }
}

/// Shell-owned application state: at most one organizer election session.
///
/// The session itself is owned by gui-core and is never persisted by the
/// shell (ADR-0007: no new canonical format, no credential persistence).
#[derive(Default)]
struct AppState {
    session: Mutex<Option<GuiElectionSessionV1>>,
}

impl AppState {
    fn with_session<T>(
        &self,
        f: impl FnOnce(&GuiElectionSessionV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let guard = self.session.lock().map_err(|_| CommandError::state_poisoned())?;
        match guard.as_ref() {
            Some(session) => f(session),
            None => Err(CommandError::no_session()),
        }
    }

    fn with_session_mut<T>(
        &self,
        f: impl FnOnce(&mut GuiElectionSessionV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let mut guard = self.session.lock().map_err(|_| CommandError::state_poisoned())?;
        match guard.as_mut() {
            Some(session) => f(session),
            None => Err(CommandError::no_session()),
        }
    }
}

/// Static shell identity for the About screen. Contains no state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ShellInfoV1 {
    application: &'static str,
    shell_version: &'static str,
    gui_core_boundary: &'static str,
    binding_notice: &'static str,
}

/// Returns static shell identity information.
#[tauri::command]
fn shell_info() -> ShellInfoV1 {
    ShellInfoV1 {
        application: "Tari Private Ballot",
        shell_version: env!("CARGO_PKG_VERSION"),
        gui_core_boundary: "gui-core typed commands (in process, no server)",
        binding_notice: "This release is intended for governance pilots. Binding governance use requires the applicable review and authorization process.",
    }
}

/// Loads the three canonical election artifacts (manifest, registry, option
/// set) from exact paths, validates every cross-binding through gui-core, and
/// opens a fresh organizer session in the frozen lifecycle state.
#[tauri::command]
fn load_election(
    manifest_path: String,
    registry_path: String,
    option_set_path: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    let artifacts = GuiElectionArtifactsV1::from_paths(
        Path::new(&manifest_path),
        Path::new(&registry_path),
        Path::new(&option_set_path),
    )?;
    let session = GuiElectionSessionV1::new(artifacts)?;
    let summary = session.summary();
    let mut guard = state.session.lock().map_err(|_| CommandError::state_poisoned())?;
    *guard = Some(session);
    Ok(summary)
}

/// Drops the active election session, if any. The session holds no secret
/// material; dropping it forgets the in-memory workspace only.
#[tauri::command]
fn unload_election(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut guard = state.session.lock().map_err(|_| CommandError::state_poisoned())?;
    *guard = None;
    Ok(())
}

/// Returns the summary of the active election, or `None` when no session is
/// active.
#[tauri::command]
fn election_summary(
    state: tauri::State<'_, AppState>,
) -> Result<Option<GuiElectionSummaryV1>, CommandError> {
    let guard = state.session.lock().map_err(|_| CommandError::state_poisoned())?;
    Ok(guard.as_ref().map(GuiElectionSessionV1::summary))
}

/// Opens the frozen election for ballot intake (lifecycle delegation).
#[tauri::command]
fn open_voting(state: tauri::State<'_, AppState>) -> Result<GuiElectionSummaryV1, CommandError> {
    state.with_session_mut(|session| {
        session.open()?;
        Ok(session.summary())
    })
}

/// Closes ballot acceptance permanently (lifecycle delegation).
#[tauri::command]
fn close_voting(state: tauri::State<'_, AppState>) -> Result<GuiElectionSummaryV1, CommandError> {
    state.with_session_mut(|session| {
        session.close()?;
        Ok(session.summary())
    })
}

/// Records completion of public verification (lifecycle delegation).
#[tauri::command]
fn mark_verified(state: tauri::State<'_, AppState>) -> Result<GuiElectionSummaryV1, CommandError> {
    state.with_session_mut(|session| {
        session.mark_verified()?;
        Ok(session.summary())
    })
}

/// Finalizes the verified result and archive commitments (lifecycle
/// delegation).
#[tauri::command]
fn finalize_election(
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    state.with_session_mut(|session| {
        session.finalize()?;
        Ok(session.summary())
    })
}

/// Ingests one canonical ballot package file through the gui-core intake
/// pipeline (decode, binding, suite policy, proof verification, first-valid
/// nullifier acceptance). The shell only reads the file bytes; every
/// validation step is gui-core's.
#[tauri::command]
fn intake_ballot_package(
    package_path: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiBallotIntakeResultV1, CommandError> {
    let package_bytes =
        std::fs::read(Path::new(&package_path)).map_err(|_| CommandError::package_read_failed())?;
    state.with_session_mut(|session| Ok(session.intake_ballot(&package_bytes)?))
}

/// Computes the deterministic tally over the currently accepted ballots.
#[tauri::command]
fn current_tally(state: tauri::State<'_, AppState>) -> Result<GuiTallySummaryV1, CommandError> {
    state.with_session(|session| Ok(session.tally()?))
}

/// Returns the privacy-aware participation summary for the active session.
///
/// Numeric participation fields are `None` while the application-local
/// visibility policy seals them, so a modified frontend cannot retrieve
/// sealed counts. The Rust session gate remains authoritative.
#[tauri::command]
fn participation_summary(
    state: tauri::State<'_, AppState>,
) -> Result<GuiParticipationSummaryV1, CommandError> {
    state.with_session(|session| Ok(session.participation_summary()))
}

/// Writes the complete offline archive directory for the active session.
#[tauri::command]
fn write_archive(
    target_dir: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiArchiveWriteResultV1, CommandError> {
    state.with_session(|session| {
        Ok(write_archive_directory_v1(session, Path::new(&target_dir))?)
    })
}

/// Runs the full offline archive replay verifier over one archive directory.
/// The archive is authoritative; no organizer state is consulted.
#[tauri::command]
fn verify_archive(directory: String) -> Result<GuiArchiveVerificationV1, CommandError> {
    Ok(verify_archive_directory_v1(Path::new(&directory))?)
}

/// Inspects one canonical anchor application config (read-only, no network).
#[tauri::command]
fn inspect_anchor_config(path: String) -> Result<GuiAnchorConfigInspectionV1, CommandError> {
    Ok(inspect_anchor_config_v1(Path::new(&path))?)
}

/// Inspects one durable anchor lifecycle snapshot (read-only, no network).
#[tauri::command]
fn inspect_anchor_snapshot(path: String) -> Result<GuiAnchorSnapshotInspectionV1, CommandError> {
    Ok(inspect_anchor_snapshot_v1(Path::new(&path))?)
}

/// Inspects one canonical anchor evidence record (read-only, no network).
#[tauri::command]
fn inspect_anchor_evidence(path: String) -> Result<GuiAnchorEvidenceInspectionV1, CommandError> {
    Ok(inspect_anchor_evidence_v1(Path::new(&path))?)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            shell_info,
            load_election,
            unload_election,
            election_summary,
            open_voting,
            close_voting,
            mark_verified,
            finalize_election,
            intake_ballot_package,
            current_tally,
            participation_summary,
            write_archive,
            verify_archive,
            inspect_anchor_config,
            inspect_anchor_snapshot,
            inspect_anchor_evidence,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Tari Private Ballot shell");
}
