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
//! The shell holds one optional voter governance credential in Rust managed
//! state for Slice 5A9. No command accepts or returns a voter secret scalar,
//! credential bytes, walletd bearer token, wallet seed, mnemonic, or wallet
//! signing material.

use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_gui_core::{
    ElectionLifecycleStateV1, GuiAnchorConfigInspectionV1, GuiAnchorEvidenceInspectionV1,
    GuiAnchorSnapshotInspectionV1, GuiArchiveVerificationV1, GuiArchiveWriteResultV1,
    GuiBallotIntakeResultV1, GuiBallotPresentationType, GuiCoreError, GuiElectionArtifactsV1,
    GuiElectionCreationResultV1, GuiElectionDraftPreviewV1, GuiElectionDraftV1,
    GuiElectionExportResultV1, GuiElectionSessionV1, GuiElectionSummaryV1,
    GuiGovernanceDocumentDigestV1, GuiGovernanceDocumentStatusV1, GuiLiveAnchorConfigRequestV1,
    GuiLiveAnchorConfigResultV1, GuiParticipationSummaryV1, GuiPreparedBallotExportV1,
    GuiPreparedBallotStatusV1, GuiTallySummaryV1, GuiTransportAnchorVerificationV1,
    GuiVoterCredentialStatusV1, GuiVoterElectionConfirmationV1, GuiVoterSelectionStatusV1,
    GuiVoterSessionV1, GuiVoterWorkflowStatusV1, VoterGovernanceCredentialV1,
    inspect_anchor_config_v1, inspect_anchor_evidence_v1, inspect_anchor_snapshot_v1,
    verify_archive_directory_v1, verify_transport_archive_anchor_v1, write_archive_directory_v1,
    write_election_artifacts_v1, write_live_anchor_config_from_verified_archive_v1,
};
use tari_cc_private_ballot_transport_gateway::{
    PrivateSubmissionCarrierV1, PrivateSubmissionCoordinatorV1,
};
use tari_cc_private_ballot_transport_network::VoterPrivateRouteV1;

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

    fn no_draft() -> Self {
        Self::new(
            "GUI_NO_ACTIVE_DRAFT",
            "INVALID_INPUT",
            "no election draft is active; start one first",
        )
    }

    fn no_voter_session() -> Self {
        Self::new(
            "GUI_NO_VOTER_SESSION",
            "INVALID_LIFECYCLE_TRANSITION",
            "no voter workflow session is active in this shell",
        )
    }

    fn pending_credential_exists() -> Self {
        Self::new(
            "GUI_PENDING_CREDENTIAL_EXISTS",
            "INVALID_LIFECYCLE_TRANSITION",
            "a local pilot credential already exists; clear it before generating a new one",
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

    fn private_transport_unavailable() -> Self {
        Self::new(
            "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
            "UNAVAILABLE",
            "private transport unavailable; select offline export or explicitly choose another available route",
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

/// Shell-owned application state: at most one organizer election session and
/// at most one Rust-side voter workflow session. A pending credential is
/// Rust-owned separately so a voter may create it before the registry freezes.
///
/// The election session and voter workflow session are owned by gui-core and
/// are never persisted by the shell (ADR-0007: no new canonical format, no
/// credential persistence). Election replacement clears workflow state, while
/// the Rust-only pending credential survives for same-process membership checks.
struct AppState {
    session: Mutex<Option<GuiElectionSessionV1>>,
    draft: Mutex<Option<GuiElectionDraftV1>>,
    voter: Mutex<Option<GuiVoterSessionV1>>,
    pending_voter_credential: Mutex<Option<VoterGovernanceCredentialV1>>,
    transport: Mutex<PrivateSubmissionCoordinatorV1>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            draft: Mutex::new(None),
            voter: Mutex::new(None),
            pending_voter_credential: Mutex::new(None),
            transport: Mutex::new(PrivateSubmissionCoordinatorV1::production_unprovisioned()),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
enum GuiPrivateRouteV1 {
    ManagedTor,
    SplitTrustRelay,
    OfflineExport,
}

impl From<GuiPrivateRouteV1> for VoterPrivateRouteV1 {
    fn from(route: GuiPrivateRouteV1) -> Self {
        match route {
            GuiPrivateRouteV1::ManagedTor => Self::ManagedTor,
            GuiPrivateRouteV1::SplitTrustRelay => Self::SplitTrustRelay,
            GuiPrivateRouteV1::OfflineExport => Self::OfflineExport,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GuiPrivateTransportAvailabilityV1 {
    managed_tor_available: bool,
    split_trust_relay_available: bool,
    offline_export_available: bool,
    development_transport: bool,
    message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GuiPrivateSubmissionResultV1 {
    route: &'static str,
    receipt_state: &'static str,
    retry_status: &'static str,
    reduced_anonymity: bool,
}

struct ProductionUnavailableCarrier;

impl PrivateSubmissionCarrierV1 for ProductionUnavailableCarrier {
    fn send_managed_tor(
        &mut self,
        _: &tari_cc_private_ballot_gui_core::TransportDescriptorV1,
        _: &[u8],
    ) -> Result<(), tari_cc_private_ballot_gui_core::TransportError> {
        Err(tari_cc_private_ballot_gui_core::TransportError::Unavailable)
    }

    fn send_split_trust_relay(
        &mut self,
        _: &tari_cc_private_ballot_gui_core::TransportDescriptorV1,
        _: &[u8],
    ) -> Result<(), tari_cc_private_ballot_gui_core::TransportError> {
        Err(tari_cc_private_ballot_gui_core::TransportError::Unavailable)
    }
}

impl AppState {
    fn with_session<T>(
        &self,
        f: impl FnOnce(&GuiElectionSessionV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        match guard.as_ref() {
            Some(session) => f(session),
            None => Err(CommandError::no_session()),
        }
    }

    fn with_session_mut<T>(
        &self,
        f: impl FnOnce(&mut GuiElectionSessionV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        match guard.as_mut() {
            Some(session) => f(session),
            None => Err(CommandError::no_session()),
        }
    }

    fn with_draft_mut<T>(
        &self,
        f: impl FnOnce(&mut GuiElectionDraftV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let mut guard = self
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        match guard.as_mut() {
            Some(draft) => f(draft),
            None => Err(CommandError::no_draft()),
        }
    }

    fn get_or_create_draft_preview(&self) -> Result<GuiElectionDraftPreviewV1, CommandError> {
        let mut guard = self
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let draft = guard.get_or_insert_with(GuiElectionDraftV1::new);
        Ok(draft.preview())
    }

    fn start_new_draft(&self) -> Result<(), CommandError> {
        let mut guard = self
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = Some(GuiElectionDraftV1::new());
        Ok(())
    }

    fn voter_credential_status(&self) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(voter) = guard.as_ref() {
            return Ok(voter.credential_status());
        }
        drop(guard);
        let pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        pending
            .as_ref()
            .map(VoterGovernanceCredentialV1::pending_status)
            .transpose()?
            .map_or_else(|| Ok(GuiVoterCredentialStatusV1::unloaded()), Ok)
    }

    fn generate_pending_credential(&self) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let mut pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if pending.is_some() {
            return Err(CommandError::pending_credential_exists());
        }
        let credential = VoterGovernanceCredentialV1::generate()?;
        let status = credential.pending_status()?;
        *pending = Some(credential);
        Ok(status)
    }

    fn reset_pending_credential(&self) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let mut pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *pending = None;
        Ok(GuiVoterCredentialStatusV1::unloaded())
    }

    /// Moves a Rust-owned pre-freeze credential, if present, into a voter
    /// session bound to this exact frozen election. gui-core recomputes
    /// eligibility from the canonical registry during installation.
    fn install_frozen_session(&self, session: GuiElectionSessionV1) -> Result<(), CommandError> {
        let mut voter = GuiVoterSessionV1::new(session.artifacts());
        let pending_credential = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?
            .take();
        if let Some(credential) = pending_credential {
            voter.install_credential(credential, session.artifacts())?;
        }
        let mut session_guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *session_guard = Some(session);
        let mut voter_guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *voter_guard = Some(voter);
        Ok(())
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
    // Preserve a same-process credential across an explicit reload. Its
    // eligibility is recomputed only after the new canonical registry loads.
    let carried_credential = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .as_mut()
        .and_then(GuiVoterSessionV1::take_credential);
    let pending_credential = state
        .pending_voter_credential
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .take()
        .or(carried_credential);
    let mut voter = GuiVoterSessionV1::new(session.artifacts());
    if let Some(credential) = pending_credential {
        voter.install_credential(credential, session.artifacts())?;
    }
    let summary = session.summary();
    let mut guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *guard = Some(session);
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *voter_guard = Some(voter);
    Ok(summary)
}

/// Drops the active election session and workflow state. A deliberately
/// generated credential returns to the Rust-only pending slot so navigation
/// and reloads do not destroy it during this application session.
#[tauri::command]
fn unload_election(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *guard = None;
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let credential = voter_guard
        .as_mut()
        .and_then(GuiVoterSessionV1::take_credential);
    *voter_guard = None;
    if let Some(credential) = credential {
        let mut pending_guard = state
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *pending_guard = Some(credential);
    }
    Ok(())
}

/// Returns the summary of the active election, or `None` when no session is
/// active.
#[tauri::command]
fn election_summary(
    state: tauri::State<'_, AppState>,
) -> Result<Option<GuiElectionSummaryV1>, CommandError> {
    let guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
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
    let (summary, lifecycle_state) = state.with_session_mut(|session| {
        session.close()?;
        Ok((session.summary(), session.lifecycle_state_v1()))
    })?;
    invalidate_voter_for_lifecycle(&state, lifecycle_state)?;
    Ok(summary)
}

/// Records completion of public verification (lifecycle delegation).
#[tauri::command]
fn mark_verified(state: tauri::State<'_, AppState>) -> Result<GuiElectionSummaryV1, CommandError> {
    let (summary, lifecycle_state) = state.with_session_mut(|session| {
        session.mark_verified()?;
        Ok((session.summary(), session.lifecycle_state_v1()))
    })?;
    invalidate_voter_for_lifecycle(&state, lifecycle_state)?;
    Ok(summary)
}

/// Finalizes the verified result and archive commitments (lifecycle
/// delegation).
#[tauri::command]
fn finalize_election(
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    let (summary, lifecycle_state) = state.with_session_mut(|session| {
        session.finalize()?;
        Ok((session.summary(), session.lifecycle_state_v1()))
    })?;
    invalidate_voter_for_lifecycle(&state, lifecycle_state)?;
    Ok(summary)
}

fn invalidate_voter_for_lifecycle(
    state: &tauri::State<'_, AppState>,
    lifecycle_state: ElectionLifecycleStateV1,
) -> Result<(), CommandError> {
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    if let Some(voter) = voter_guard.as_mut() {
        voter.invalidate_for_lifecycle_change(lifecycle_state);
    }
    Ok(())
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
    state.with_session_mut(|session| Ok(session.intake_ballot_package_bytes(&package_bytes)?))
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
    state.with_session(|session| Ok(write_archive_directory_v1(session, Path::new(&target_dir))?))
}

/// Runs the full offline archive replay verifier over one archive directory.
/// The archive is authoritative; no organizer state is consulted.
#[tauri::command]
fn verify_archive(directory: String) -> Result<GuiArchiveVerificationV1, CommandError> {
    Ok(verify_archive_directory_v1(Path::new(&directory))?)
}

/// Verifies the public transport-binding → completed archive → existing Phase
/// 4 evidence chain. This is inspection only: no walletd/indexer access,
/// signing, fee payment, ballot package, or transport secret crosses Tauri.
#[tauri::command]
fn verify_transport_archive_anchor(
    archive_directory: String,
    anchor_evidence_path: String,
) -> Result<GuiTransportAnchorVerificationV1, CommandError> {
    Ok(verify_transport_archive_anchor_v1(
        Path::new(&archive_directory),
        Path::new(&anchor_evidence_path),
    )?)
}

/// Generates a standalone anchor-app config from a verified finalized archive.
///
/// The frontend supplies only public operator locators, paths, and policy
/// acknowledgement fields. Rust derives manifest hash, archive hash,
/// finalized status, and accepted count from the archive verifier.
#[tauri::command]
fn write_live_anchor_config_from_verified_archive(
    request: GuiLiveAnchorConfigRequestV1,
) -> Result<GuiLiveAnchorConfigResultV1, CommandError> {
    Ok(write_live_anchor_config_from_verified_archive_v1(&request)?)
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

// ---------------------------------------------------------------------------
// Organizer election creation (Slice 5A6).
//
// The shell owns one mutable draft and one loaded session. The frontend
// collects ordinary strings and public keys; every validation lives in
// gui-core. After freeze, the draft becomes immutable and a frozen session is
// loaded. Exporting writes the three canonical artifacts; opening voting is a
// separate deliberate action.
// ---------------------------------------------------------------------------

/// Returns the existing organizer draft preview, creating an empty draft only
/// when none exists. This is the non-destructive Create Election entry point.
#[tauri::command]
fn get_or_create_election_draft(
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionDraftPreviewV1, CommandError> {
    state.get_or_create_draft_preview()
}

/// Starts a fresh organizer election draft, clearing any existing draft. A
/// previously loaded frozen session is left intact so the organizer can review
/// it; calling this discards only the in-progress draft.
#[tauri::command]
fn start_election_draft(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    state.start_new_draft()
}

/// Discards the in-progress draft. Does not unload a frozen session.
#[tauri::command]
fn discard_election_draft(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut guard = state
        .draft
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *guard = None;
    Ok(())
}

/// Sets the election basics (identifier text + governance source revision).
#[tauri::command]
fn set_draft_basics(
    election_id_text: String,
    governance_source_revision: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        draft.set_basics(election_id_text, governance_source_revision)?;
        Ok(())
    })
}

/// Sets the voting rules (minimum/maximum approvals, abstention policy).
#[tauri::command]
fn set_draft_rules(
    approval_min: usize,
    approval_max: usize,
    allow_abstention: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        draft.set_rules(approval_min, approval_max, allow_abstention)?;
        Ok(())
    })
}

/// Replaces the eligible-voter list from hex governance public keys.
#[tauri::command]
fn set_draft_voters(
    public_key_hexs: Vec<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        draft.set_voters(public_key_hexs)?;
        Ok(())
    })
}

/// Replaces the ballot option list from `(machine_id_text, display_name)` pairs.
#[tauri::command]
fn set_draft_options(
    options: Vec<DraftOptionInput>,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        let parsed: Vec<(String, String)> = options
            .into_iter()
            .map(|o| (o.machine_id_text, o.display_name))
            .collect();
        draft.set_options(parsed)?;
        Ok(())
    })
}

/// Sets the application-local ballot presentation type (non-canonical).
#[tauri::command]
fn set_draft_presentation(
    presentation: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        let parsed = GuiBallotPresentationType::from_identifier(&presentation)?;
        draft.set_presentation(parsed)?;
        Ok(())
    })
}

/// Imports an existing canonical registry CBOR file into the draft, replacing
/// the current voter list with its public keys.
#[tauri::command]
fn import_registry_to_draft(
    registry_path: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    let bytes = std::fs::read(Path::new(&registry_path))
        .map_err(|_| CommandError::package_read_failed())?;
    state.with_draft_mut(|draft| {
        draft.import_registry_bytes(&bytes)?;
        Ok(())
    })
}

/// Returns a pre-freeze review of the current draft.
#[tauri::command]
fn preview_draft(
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionDraftPreviewV1, CommandError> {
    state.with_draft_mut(|draft| Ok(draft.preview()))
}

/// Freezes the draft and loads the frozen election session. Returns the
/// creation result. After this, the draft is immutable and the session is
/// active in the `FROZEN` lifecycle state.
#[tauri::command]
fn freeze_election(
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionCreationResultV1, CommandError> {
    let (result, session) = state.with_draft_mut(|draft| Ok(draft.freeze()?))?;
    state.install_frozen_session(session)?;
    Ok(result)
}

/// Exports the three canonical election artifacts from the loaded frozen
/// session into `target_dir`, never overwriting existing files.
#[tauri::command]
fn export_election_artifacts(
    target_dir: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionExportResultV1, CommandError> {
    state.with_session(|session| {
        Ok(write_election_artifacts_v1(
            session.artifacts(),
            Path::new(&target_dir),
        )?)
    })
}

// ---------------------------------------------------------------------------
// Slice 5A8: governance source pinning, document archival, voter confirmation.
//
// All governance-source work is local. No network, walletd, indexer, or
// signing is performed. The shell owns the optional governance document bytes
// selected by the organizer so the archive writer can include the exact bytes
// the organizer pinned. The shell holds no voter secrets.
// ---------------------------------------------------------------------------

/// Sets only the governance source revision, leaving the election identifier
/// intact. Used after a governance document digest is computed.
#[tauri::command]
fn set_draft_governance_source_revision(
    governance_source_revision: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        draft.set_governance_source_revision(governance_source_revision)?;
        Ok(())
    })
}

/// Selects a governance document from a local path, reading, size-checking,
/// and digesting the exact raw bytes in Rust. Symlinks, directories, and
/// oversized files are rejected.
#[tauri::command]
fn set_draft_governance_document(
    path: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiGovernanceDocumentDigestV1, CommandError> {
    state.with_draft_mut(|draft| Ok(draft.set_governance_document(Path::new(&path))?))
}

/// Clears any selected governance document.
#[tauri::command]
fn clear_draft_governance_document(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        draft.clear_governance_document()?;
        Ok(())
    })
}

/// Pins the currently selected governance document by content digest, setting
/// `governance_source_revision` to `blake3:<digest>`. Requires that a document
/// has been selected.
#[tauri::command]
fn use_governance_document_digest_as_revision(
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    state.with_draft_mut(|draft| {
        draft.use_governance_document_digest_as_revision()?;
        Ok(())
    })
}

/// Computes the governance document digest from a local path (read-only; no
/// draft mutation). Used by the voter to inspect a locally selected governance
/// document without affecting an organizer draft.
#[tauri::command]
fn compute_governance_document_digest(
    path: String,
) -> Result<GuiGovernanceDocumentDigestV1, CommandError> {
    Ok(tari_cc_private_ballot_gui_core::compute_governance_document_digest(Path::new(&path))?)
}

/// Matches a governance document digest against a bound
/// `governance_source_revision` pin. When `governance_document_path` is set,
/// the digest is computed in Rust from the local file; otherwise the bound
/// revision is validated against no document. Pure besides the optional read:
/// no network.
#[tauri::command]
fn match_governance_document(
    governance_source_revision: String,
    governance_document_path: Option<String>,
) -> Result<GuiGovernanceDocumentStatusV1, CommandError> {
    let digest = governance_document_path
        .map(|path| {
            tari_cc_private_ballot_gui_core::compute_governance_document_digest(Path::new(&path))
        })
        .transpose()?;
    Ok(tari_cc_private_ballot_gui_core::match_governance_document(
        &governance_source_revision,
        digest.as_ref(),
    ))
}

/// Builds the voter confirmation view model from the active session and an
/// optional governance document digest (computed from a locally selected
/// document). Read-only: no credential handling, no proof generation.
#[tauri::command]
fn voter_confirmation(
    governance_document_path: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterElectionConfirmationV1, CommandError> {
    state.with_session(|session| {
        let digest = governance_document_path
            .map(|path| {
                tari_cc_private_ballot_gui_core::compute_governance_document_digest(Path::new(
                    &path,
                ))
            })
            .transpose()?;
        Ok(
            tari_cc_private_ballot_gui_core::build_voter_election_confirmation(
                session.artifacts(),
                digest.as_ref(),
            ),
        )
    })
}

/// Returns only safe public metadata about the active Rust-side voter
/// credential session. No secret bytes, scalar, seed, mnemonic, proof,
/// nullifier, ballot package, or registry index is returned.
#[tauri::command]
fn voter_governance_credential_status(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    state.voter_credential_status()
}

/// Generates one session-only voter governance credential in Rust, derives
/// its public governance key, and checks that key against the current frozen
/// registry. The private credential remains in Rust managed state only.
#[tauri::command]
fn generate_voter_governance_credential(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    if let Some(session) = session_guard.as_ref() {
        let mut voter_guard = state
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(voter) = voter_guard.as_mut() else {
            return Err(CommandError::no_voter_session());
        };
        return Ok(voter.generate_credential(session.artifacts())?);
    }
    drop(session_guard);
    state.generate_pending_credential()
}

/// Generates a Rust-owned local credential before an election is frozen. This
/// deliberately does not depend on a loaded election or issue credentials on
/// behalf of an organizer; the caller receives only the public enrollment key.
#[tauri::command]
fn generate_pending_voter_governance_credential(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    state.generate_pending_credential()
}

/// Explicitly clears the Rust-side voter governance credential.
#[tauri::command]
fn reset_voter_governance_credential(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    let mut guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    if let Some(voter) = guard.as_mut() {
        return Ok(voter.reset_credential());
    }
    drop(guard);
    let mut pending = state
        .pending_voter_credential
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *pending = None;
    Ok(GuiVoterCredentialStatusV1::unloaded())
}

/// Explicitly clears only the Rust-owned pre-freeze pending credential.
#[tauri::command]
fn reset_pending_voter_governance_credential(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    state.reset_pending_credential()
}

/// Returns the complete safe voter workflow status. The frontend supplies
/// whether the voter has checked the local review box; Rust supplies every
/// protocol/state gate.
#[tauri::command]
fn voter_workflow_status(
    review_confirmed: bool,
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterWorkflowStatusV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_ref() else {
        return Err(CommandError::no_voter_session());
    };
    Ok(voter.workflow_status(
        session.artifacts(),
        session.lifecycle_state_v1(),
        review_confirmed,
    ))
}

/// Returns the public Rust-authoritative ballot selection status.
#[tauri::command]
fn voter_ballot_selection_status(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterSelectionStatusV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_ref() else {
        return Err(CommandError::no_voter_session());
    };
    Ok(voter.selection_status(session.artifacts(), session.lifecycle_state_v1()))
}

/// Sets one Rust-authoritative ballot selection from public option machine
/// IDs. This validates through the existing canonical ballot payload rules.
#[tauri::command]
fn set_voter_ballot_selection(
    selected_option_ids_hex: Vec<String>,
    abstain: bool,
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterSelectionStatusV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    Ok(voter.set_selection(
        session.artifacts(),
        session.lifecycle_state_v1(),
        selected_option_ids_hex,
        abstain,
    )?)
}

/// Clears the Rust-authoritative ballot selection and invalidates future
/// prepared-ballot state.
#[tauri::command]
fn clear_voter_ballot_selection(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterSelectionStatusV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    Ok(voter.clear_selection(session.artifacts(), session.lifecycle_state_v1())?)
}

/// Generates a real local Triptych proof and canonical ballot package while
/// holding the Rust voter-session mutex. The result contains safe metadata
/// only; neither proof bytes nor credential material cross to TypeScript.
#[tauri::command]
fn prepare_voter_ballot(
    state: tauri::State<'_, AppState>,
) -> Result<GuiPreparedBallotStatusV1, CommandError> {
    let (artifacts, lifecycle_state) = {
        let session_guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = session_guard.as_ref() else {
            return Err(CommandError::no_session());
        };
        (session.artifacts().clone(), session.lifecycle_state_v1())
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    Ok(voter.prepare_ballot(&artifacts, lifecycle_state)?)
}

/// Writes a prepared canonical ballot package to the user-selected new path.
/// Rust performs the no-overwrite write and full read-back verification.
#[tauri::command]
fn export_prepared_voter_ballot(
    package_path: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiPreparedBallotExportV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_ref() else {
        return Err(CommandError::no_voter_session());
    };
    Ok(voter.export_prepared_ballot(
        session.artifacts(),
        session.lifecycle_state_v1(),
        Path::new(&package_path),
    )?)
}

/// Returns the safe route availability projection. Production deliberately
/// fails closed until a release provisions a pinned root and authenticated
/// descriptor; offline export is independent of transport configuration.
#[tauri::command]
fn private_transport_availability(
    state: tauri::State<'_, AppState>,
) -> Result<GuiPrivateTransportAvailabilityV1, CommandError> {
    let transport = state
        .transport
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let online = transport.online_configured();
    Ok(GuiPrivateTransportAvailabilityV1 {
        managed_tor_available: online,
        split_trust_relay_available: online,
        offline_export_available: true,
        development_transport: online,
        message: if online {
            "TEST / DEVELOPMENT TRANSPORT is configured."
        } else {
            "Production private transport is unavailable until a transport authority root is provisioned. Offline export remains available."
        },
    })
}

/// Submits the existing Rust-owned Ready ballot through one explicit route.
/// JavaScript supplies no ballot bytes and receives no secret or organizer
/// intake fields. Offline export stays the separate canonical file command.
#[tauri::command]
fn submit_prepared_voter_ballot_privately(
    route: GuiPrivateRouteV1,
    state: tauri::State<'_, AppState>,
) -> Result<GuiPrivateSubmissionResultV1, CommandError> {
    let selected: VoterPrivateRouteV1 = route.into();
    if selected == VoterPrivateRouteV1::OfflineExport {
        return Ok(GuiPrivateSubmissionResultV1 {
            route: "OfflineExport",
            receipt_state: "OFFLINE_EXPORT",
            retry_status: "NOT_APPLICABLE",
            reduced_anonymity: false,
        });
    }
    let mut session = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let session = session.as_mut().ok_or_else(CommandError::no_session)?;
    let voter = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let voter = voter.as_ref().ok_or_else(CommandError::no_voter_session)?;
    let ballot_bytes =
        voter.prepared_canonical_ballot_bytes(session.artifacts(), session.lifecycle_state_v1())?;
    let mut transport = state
        .transport
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let mut carrier = ProductionUnavailableCarrier;
    let result = transport
        .submit(selected, ballot_bytes, session, &mut carrier)
        .map_err(|_| CommandError::private_transport_unavailable())?;
    Ok(GuiPrivateSubmissionResultV1 {
        route: match result.route {
            VoterPrivateRouteV1::ManagedTor => "ManagedTor",
            VoterPrivateRouteV1::SplitTrustRelay => "SplitTrustRelay",
            VoterPrivateRouteV1::OfflineExport => "OfflineExport",
        },
        receipt_state: match result.receipt.state {
            tari_cc_private_ballot_gui_core::VoterReceiptStateV1::Received => "RECEIVED",
            tari_cc_private_ballot_gui_core::VoterReceiptStateV1::Accepted => "ACCEPTED",
            tari_cc_private_ballot_gui_core::VoterReceiptStateV1::Rejected => "REJECTED",
        },
        retry_status: match result.receipt.retry_status {
            tari_cc_private_ballot_gui_core::RetryStatusV1::NewDelivery => "NEW_DELIVERY",
            tari_cc_private_ballot_gui_core::RetryStatusV1::PreviousDeliveryAccepted => {
                "PREVIOUS_ACCEPTED"
            }
            tari_cc_private_ballot_gui_core::RetryStatusV1::PreviousDeliveryRejected => {
                "PREVIOUS_REJECTED"
            }
            tari_cc_private_ballot_gui_core::RetryStatusV1::GenericDuplicate => "GENERIC_DUPLICATE",
        },
        reduced_anonymity: result.reduced_anonymity,
    })
}

/// Resets the whole voter workflow for the current election.
#[tauri::command]
fn reset_voter_workflow(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterWorkflowStatusV1, CommandError> {
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    voter.reset_workflow();
    Ok(voter.workflow_status(session.artifacts(), session.lifecycle_state_v1(), false))
}

/// Writes the complete offline archive directory, optionally including a
/// governance supporting document. When `governance_document_path` is set, the
/// exact bytes are read in Rust and archived at the project-controlled
/// `governance/source.bin` path.
#[tauri::command]
fn write_archive_with_governance_document(
    target_dir: String,
    governance_document_path: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<GuiArchiveWriteResultV1, CommandError> {
    state.with_session(|session| {
        let doc_bytes = governance_document_path
            .map(|path| {
                let bytes = std::fs::read(Path::new(&path))
                    .map_err(|_| CommandError::package_read_failed())?;
                Ok::<Vec<u8>, CommandError>(bytes)
            })
            .transpose()?;
        Ok(tari_cc_private_ballot_gui_core::archive_writer::write_archive_directory_v1_with_governance_document(
            session,
            Path::new(&target_dir),
            doc_bytes.as_deref(),
        )?)
    })
}

/// One ballot option input from the frontend.
#[derive(Debug, Clone, serde::Deserialize)]
struct DraftOptionInput {
    machine_id_text: String,
    display_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit_draft(state: &AppState, public_key_hex: String) {
        let mut guard = state.draft.lock().expect("draft lock");
        let draft = guard.as_mut().expect("draft exists");
        draft
            .set_basics(
                "preserved-election".to_owned(),
                "preserved-revision".to_owned(),
            )
            .expect("valid basics");
        draft
            .set_voters(vec![public_key_hex])
            .expect("valid generated governance key");
        draft
            .set_options(vec![("yes".to_owned(), "Yes".to_owned())])
            .expect("valid option");
        draft.set_rules(1, 1, false).expect("valid rules");
        draft
            .set_presentation(GuiBallotPresentationType::GovernanceProposal)
            .expect("valid presentation");
    }

    #[test]
    fn get_or_create_draft_creates_empty_draft_without_credential_data() {
        let state = AppState::default();
        let preview = state.get_or_create_draft_preview().expect("draft preview");
        assert_eq!(preview.election_id_text, None);
        assert!(state.draft.lock().expect("draft lock").is_some());
        let serialized = serde_json::to_string(&preview).expect("safe preview JSON");
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("nullifier"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn get_or_create_draft_preserves_committed_fields_and_start_new_replaces_them() {
        let state = AppState::default();
        let credential = state.generate_pending_credential().expect("credential");
        let public_key = credential.public_governance_key_hex.expect("public key");
        state.get_or_create_draft_preview().expect("initial draft");
        commit_draft(&state, public_key);

        let preserved = state
            .get_or_create_draft_preview()
            .expect("preserved preview");
        assert_eq!(
            preserved.election_id_text.as_deref(),
            Some("preserved-election")
        );
        assert_eq!(
            preserved.governance_source_revision.as_deref(),
            Some("preserved-revision")
        );
        assert_eq!(preserved.voter_count, 1);
        assert_eq!(preserved.options.len(), 1);
        assert_eq!(preserved.approval_min, Some(1));
        assert_eq!(preserved.approval_max, Some(1));
        assert_eq!(
            preserved.presentation,
            GuiBallotPresentationType::GovernanceProposal
        );

        state.start_new_draft().expect("replace draft");
        let replacement = state
            .get_or_create_draft_preview()
            .expect("replacement preview");
        assert_eq!(replacement.election_id_text, None);
        assert_eq!(replacement.voter_count, 0);
        assert!(replacement.options.is_empty());
        assert_eq!(replacement.approval_min, None);
    }

    #[test]
    fn pending_credential_generation_fails_closed_until_explicit_reset() {
        let state = AppState::default();
        let first = state
            .generate_pending_credential()
            .expect("first credential");
        let first_key = first.public_governance_key_hex.expect("first public key");

        let duplicate = state
            .generate_pending_credential()
            .expect_err("duplicate rejected");
        assert_eq!(duplicate.code, "GUI_PENDING_CREDENTIAL_EXISTS");
        let retained = state.voter_credential_status().expect("retained status");
        assert_eq!(
            retained.public_governance_key_hex.as_deref(),
            Some(first_key.as_str())
        );

        let unloaded = state.reset_pending_credential().expect("reset credential");
        assert!(!unloaded.credential_loaded);
        let second = state
            .generate_pending_credential()
            .expect("second credential");
        assert!(second.credential_loaded);
        assert_ne!(
            second.public_governance_key_hex.as_deref(),
            Some(first_key.as_str())
        );
    }

    fn freeze_draft_into_active_session(state: &AppState) {
        let (_, session) = state
            .with_draft_mut(|draft| Ok(draft.freeze()?))
            .expect("freeze draft");
        state
            .install_frozen_session(session)
            .expect("install frozen voter session");
    }

    #[test]
    fn carried_credential_remains_eligible_after_freeze_and_open_and_prepares_a_ballot() {
        let state = AppState::default();
        let pending = state
            .generate_pending_credential()
            .expect("generate credential");
        let public_key = pending.public_governance_key_hex.expect("public key");
        state.get_or_create_draft_preview().expect("create draft");
        commit_draft(&state, public_key.clone());

        freeze_draft_into_active_session(&state);
        let frozen_status = state
            .voter_credential_status()
            .expect("frozen credential status");
        assert_eq!(
            frozen_status.public_governance_key_hex.as_deref(),
            Some(public_key.as_str())
        );
        assert_eq!(
            frozen_status.eligibility,
            tari_cc_private_ballot_gui_core::GuiVoterEligibilityV1::Eligible
        );

        state
            .with_session_mut(|session| {
                session.open()?;
                Ok(())
            })
            .expect("open election");
        let open_status = state
            .voter_credential_status()
            .expect("open credential status");
        assert_eq!(
            open_status.public_governance_key_hex.as_deref(),
            Some(public_key.as_str())
        );
        assert_eq!(
            open_status.eligibility,
            tari_cc_private_ballot_gui_core::GuiVoterEligibilityV1::Eligible
        );

        let serialized = serde_json::to_value(&open_status).expect("safe credential status JSON");
        let fields = serialized
            .as_object()
            .expect("credential status should be an object");
        for marker in [
            "secret",
            "scalar",
            "seed",
            "mnemonic",
            "private",
            "credential_bytes",
            "nullifier",
            "proof",
        ] {
            assert!(
                fields
                    .keys()
                    .all(|field| !field.to_lowercase().contains(marker))
            );
        }

        let session_guard = state.session.lock().expect("session lock");
        let session = session_guard.as_ref().expect("active session");
        let mut voter_guard = state.voter.lock().expect("voter lock");
        let voter = voter_guard.as_mut().expect("active voter session");
        let selection = voter
            .set_selection(
                session.artifacts(),
                session.lifecycle_state_v1(),
                vec!["796573".to_owned()],
                false,
            )
            .expect("select the enrolled election option");
        assert!(selection.can_prepare_ballot);
        let prepared = voter
            .prepare_ballot(session.artifacts(), session.lifecycle_state_v1())
            .expect("real Triptych preparation with carried credential");
        assert!(prepared.ready_to_export);
    }

    #[test]
    fn carried_credential_is_not_eligible_when_the_frozen_registry_excludes_it() {
        let state = AppState::default();
        let pending = state
            .generate_pending_credential()
            .expect("generate credential");
        let pending_key = pending
            .public_governance_key_hex
            .expect("pending public key");
        let other_state = AppState::default();
        let enrolled_key = other_state
            .generate_pending_credential()
            .expect("generate different credential")
            .public_governance_key_hex
            .expect("different public key");
        assert_ne!(pending_key, enrolled_key);
        state.get_or_create_draft_preview().expect("create draft");
        commit_draft(&state, enrolled_key);

        freeze_draft_into_active_session(&state);
        state
            .with_session_mut(|session| {
                session.open()?;
                Ok(())
            })
            .expect("open election");
        let status = state.voter_credential_status().expect("credential status");
        assert_eq!(
            status.public_governance_key_hex.as_deref(),
            Some(pending_key.as_str())
        );
        assert_eq!(
            status.eligibility,
            tari_cc_private_ballot_gui_core::GuiVoterEligibilityV1::NotEligible
        );
        assert!(!status.can_continue);
    }
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
            verify_transport_archive_anchor,
            write_live_anchor_config_from_verified_archive,
            inspect_anchor_config,
            inspect_anchor_snapshot,
            inspect_anchor_evidence,
            get_or_create_election_draft,
            start_election_draft,
            discard_election_draft,
            set_draft_basics,
            set_draft_rules,
            set_draft_voters,
            set_draft_options,
            set_draft_presentation,
            import_registry_to_draft,
            preview_draft,
            freeze_election,
            export_election_artifacts,
            set_draft_governance_source_revision,
            set_draft_governance_document,
            clear_draft_governance_document,
            use_governance_document_digest_as_revision,
            compute_governance_document_digest,
            match_governance_document,
            voter_confirmation,
            voter_governance_credential_status,
            generate_voter_governance_credential,
            generate_pending_voter_governance_credential,
            reset_voter_governance_credential,
            reset_pending_voter_governance_credential,
            voter_workflow_status,
            voter_ballot_selection_status,
            set_voter_ballot_selection,
            clear_voter_ballot_selection,
            prepare_voter_ballot,
            export_prepared_voter_ballot,
            private_transport_availability,
            submit_prepared_voter_ballot_privately,
            reset_voter_workflow,
            write_archive_with_governance_document,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Tari Private Ballot shell");
}
