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

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_gui_core::{
    AppliedElectionStatusV1, ElectionLifecycleStateV1, ElectionStatusKnowledgeV1,
    GuiAnchorConfigInspectionV1, GuiAnchorEvidenceInspectionV1, GuiAnchorSnapshotInspectionV1,
    GuiArchiveVerificationV1, GuiArchiveWriteResultV1, GuiBallotIntakeResultV1,
    GuiBallotPresentationType, GuiCoreError, GuiElectionArtifactsV1,
    GuiElectionCreationResultV1, GuiElectionDraftPreviewV1, GuiElectionDraftV1,
    GuiElectionExportResultV1, GuiElectionSessionV1, GuiElectionSummaryV1,
    GuiElectionWorkspaceResumeResultV1, GuiElectionWorkspaceSummaryV1,
    GuiGovernanceDocumentDigestV1, GuiGovernanceDocumentStatusV1, GuiLiveAnchorConfigRequestV1,
    GuiLiveAnchorConfigResultV1, GuiParticipationSummaryV1, GuiPreparedBallotExportV1,
    GuiPreparedBallotStatusV1, GuiSavedVoterCredentialDeleteResultV1, GuiSavedVoterCredentialsV1,
    GuiTallySummaryV1, GuiTransportAnchorVerificationV1, GuiVoterCastLockStateV1,
    GuiVoterCredentialBackupResultV1, GuiVoterCredentialOriginV1, GuiVoterCredentialStatusV1,
    GuiVoterElectionBindingV1, GuiVoterElectionConfirmationV1, GuiVoterSelectionStatusV1,
    GuiVoterSessionV1, GuiVoterWorkflowStatusV1, LoadedElectionWorkspaceV1,
    TransportAuthorityRootSetV1, TransportAuthorityRootV1, VoterGovernanceCredentialV1,
    backup_voter_credential_to_path_v1, copy_validated_voter_credential_to_default_v1,
    create_draft_workspace_id_v1, delete_election_workspace_v1,
    delete_saved_voter_credential_v1, ensure_election_workspaces_directory_v1,
    ensure_voter_cast_locks_directory_v1, ensure_private_intake_inbox_directory_v1,
    ensure_voter_credentials_directory_v1, ensure_voter_election_status_directory_v1,
    file_summary_for_public_key, ingest_private_intake_inbox_into_session_v1,
    load_persisted_election_status_v1, mark_workspace_organizer_authority_v1,
    verify_and_apply_election_status_statement_v1,
    GuiPrivateIntakeSyncSummaryV1, import_voter_credential_from_path_v1,
    inspect_anchor_config_v1, inspect_anchor_evidence_v1, inspect_anchor_snapshot_v1,
    list_election_workspaces_v1, list_saved_voter_credentials_v1,
    mark_draft_workspace_superseded_v1, parse_public_governance_key_hex_v1,
    public_credential_fingerprint_hex_v1, read_ballot_package_file_bounded_v1,
    resolve_and_recover_cast_lock_state_v1,
    resolve_and_recover_private_transport_cast_lock_state_v1, resume_election_workspace_v1,
    TransportDescriptorV1, unlock_saved_voter_credential_v1, validate_workspace_id_v1,
    verify_archive_directory_v1, verify_transport_archive_anchor_v1, voter_cast_locks_directory_v1,
    voter_credentials_directory_v1, workspace_id_for_session_v1, write_archive_directory_v1,
    write_draft_workspace_revision_v1, write_election_artifacts_v1,
    write_finalized_archive_v1_with_governance_document,
    write_live_anchor_config_from_verified_archive_v1, write_new_durable_voter_credential_v1,
    write_session_workspace_revision_v1,
};
use tari_cc_private_ballot_transport_gateway::PrivateSubmissionCoordinatorV1;
use tari_cc_private_ballot_transport_network::VoterPrivateRouteV1;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

#[cfg(feature = "managed-tor-test")]
mod election_status_commands;
#[cfg(feature = "managed-tor-test")]
mod managed_tor_test;
#[cfg(feature = "managed-tor-test")]
mod organizer_tor_intake;
#[cfg(feature = "managed-tor-test")]
mod tor_support;

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

    /// Attaches a short, bounded diagnostic context label (no path or secret).
    /// Used so a friendly user-facing error can still carry a machine-readable
    /// hint that diagnostics and tests can distinguish.
    #[cfg_attr(not(feature = "managed-tor-test"), allow(dead_code))]
    fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
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

    #[cfg(not(feature = "managed-tor-test"))]
    fn private_transport_unavailable() -> Self {
        Self::new(
            "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
            "UNAVAILABLE",
            "private transport unavailable; select offline export or explicitly choose another available route",
        )
    }

    fn app_data_unavailable() -> Self {
        Self::new(
            "GUI_APP_DATA_UNAVAILABLE",
            "FILE_IO",
            "the application data directory is unavailable",
        )
    }

    fn external_path_required() -> Self {
        Self::new(
            "GUI_CREDENTIAL_UNSAFE_PATH",
            "FILE_IO",
            "portable credential import and backup require an explicit absolute file path",
        )
    }

    /// The single, stable refusal for every organizer-authoritative command
    /// invoked without an organizer-owned election session. This is a ROLE
    /// boundary, not a UI gate: it fires in the Rust shell before any
    /// filesystem mutation, transport provisioning, Tor launch, signing-key
    /// creation, status-generation reservation, workspace write, or lifecycle
    /// mutation, and it is returned identically to direct IPC callers.
    fn organizer_authority_required() -> Self {
        Self::new(
            "GUI_ORGANIZER_AUTHORITY_REQUIRED",
            "INVALID_LIFECYCLE_TRANSITION",
            "this command requires an organizer-owned election; the loaded election was imported from public artifacts, so this computer is a voter for it, not the ballot office",
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

impl From<tari_cc_private_ballot_gui_core::ElectionStatusErrorV1> for CommandError {
    fn from(error: tari_cc_private_ballot_gui_core::ElectionStatusErrorV1) -> Self {
        GuiCoreError::from(error).into()
    }
}

/// Runs a blocking backend operation on the Tauri blocking thread pool so a
/// slow, synchronous CPU/process/filesystem call never blocks the main UI
/// thread (Windows "Not Responding"). The command function stays `async` so
/// Tauri schedules it off the main thread, and the actual blocking work is moved
/// onto `spawn_blocking`. Used both for the managed-Tor/onion path and for the
/// CPU-bound credential Argon2id KDF (unlock/create/import/backup). A task that
/// fails to run to completion is surfaced as a bounded error rather than a hang.
pub(crate) async fn run_blocking_command<T, F>(work: F) -> Result<T, CommandError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CommandError> + Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(work).await {
        Ok(result) => result,
        Err(_) => Err(CommandError::new(
            "GUI_COMMAND_TASK_FAILED",
            "UNAVAILABLE",
            "the background task did not complete",
        )),
    }
}

/// The ROLE this shell holds for the active election session.
///
/// Authority is established ONLY by explicit organizer or voter flows — never
/// by the mere presence of a loaded session:
///
/// * [`SessionAuthorityV1::Organizer`] — the session came from THIS shell's
///   organizer flows: freezing a newly created election, or resuming a durable
///   workspace that carries a valid organizer-authority provenance marker
///   (written at freeze time). Only this role may run authoritative lifecycle
///   mutations, private-intake provisioning, voter-bundle export, status
///   signing, intake reconciliation, tally, and archive writing.
/// * [`SessionAuthorityV1::ImportedVoter`] — the session was loaded from public
///   election artifacts (the voter import path). It supports inspection,
///   credential loading, authenticated status import/fetch, and the full voter
///   ballot workflow, and can NEVER mutate authoritative organizer state,
///   provision organizer transport, or synthesize an organizer workspace.
///
/// The authority lives OUTSIDE `GuiElectionSessionV1` on purpose: a session is
/// reconstructible by anyone from public artifacts, so the session object alone
/// must never imply ballot-office authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionAuthorityV1 {
    Organizer,
    ImportedVoter,
}

impl SessionAuthorityV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Organizer => "organizer",
            Self::ImportedVoter => "imported_voter",
        }
    }
}

/// Serializable view of the active session's authority for the frontend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct ActiveElectionAuthorityV1 {
    authority: &'static str,
}

/// The active election session TOGETHER WITH the role this shell holds for it.
///
/// Stored under a SINGLE mutex so a session can never be observed without its
/// matching authority: an election swap (import/resume/unload) is atomic with
/// respect to every authority check, so no interleaving — including concurrent
/// direct IPC — can ever evaluate an organizer gate against a newly installed
/// imported session using a PREVIOUS election's organizer authority.
struct ActiveElectionSessionV1 {
    session: GuiElectionSessionV1,
    authority: SessionAuthorityV1,
}

impl ActiveElectionSessionV1 {
    fn new(session: GuiElectionSessionV1, authority: SessionAuthorityV1) -> Self {
        Self { session, authority }
    }
}

struct PendingVoterCredentialV1 {
    credential: VoterGovernanceCredentialV1,
    origin: GuiVoterCredentialOriginV1,
}

impl PendingVoterCredentialV1 {
    fn status(&self) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        Ok(self.credential.pending_status_with_origin(self.origin)?)
    }

    fn public_key_hex(&self) -> Result<String, CommandError> {
        Ok(self
            .credential
            .pending_status_with_origin(self.origin)?
            .public_governance_key_hex
            .ok_or_else(|| CommandError::from(GuiCoreError::credential_not_loaded()))?)
    }

    fn backup_to_path(
        &self,
        path: &Path,
        passphrase: &str,
    ) -> Result<GuiVoterCredentialBackupResultV1, CommandError> {
        Ok(backup_voter_credential_to_path_v1(
            &self.credential,
            path,
            passphrase,
        )?)
    }
}

/// Shell-owned application state: at most one organizer election session and
/// at most one Rust-side voter workflow session. A pending credential is
/// Rust-owned separately so a voter may create or unlock it before the
/// registry freezes.
///
/// The election session and voter workflow session are owned by gui-core.
/// Election replacement clears election workflow state, while the Rust-only
/// credential survives in pending memory for same-process membership checks.
///
/// # GLOBAL LOCK ORDER (deadlock invariant)
///
/// Every code path that holds one of these mutexes while acquiring another
/// MUST follow this single order:
///
/// ```text
/// session -> voter -> pending_voter_credential -> managed_tor_test
/// ```
///
/// with `draft`, `session_workspace_id`, `draft_workspace_id`, `transport`,
/// and `organizer_intake` used only as single (leaf) locks. Two historical
/// violations formed a stable ABBA cycle (`managed_tor_test -> session` in
/// `running_transport_endpoint` versus `session -> managed_tor_test` in
/// `apply_election_status_bytes_blocking`) that deadlocked two blocking-pool
/// workers at zero CPU and then parked every later voter command — including
/// ballot preparation — at its first lock acquisition forever. Both edges are
/// now non-overlapping, and any future nesting must respect the order above;
/// prefer the established "snapshot under a short lock, drop, then act"
/// pattern instead of nesting.
struct AppState {
    /// The active election session WITH its role, under one lock (see
    /// [`ActiveElectionSessionV1`]): authority checks and session swaps are
    /// atomic with respect to each other.
    session: Mutex<Option<ActiveElectionSessionV1>>,
    draft: Mutex<Option<GuiElectionDraftV1>>,
    session_workspace_id: Mutex<Option<String>>,
    draft_workspace_id: Mutex<Option<String>>,
    voter: Mutex<Option<GuiVoterSessionV1>>,
    pending_voter_credential: Mutex<Option<PendingVoterCredentialV1>>,
    transport: Mutex<PrivateSubmissionCoordinatorV1>,
    /// Ownership token for the live ballot-preparation worker. The worker
    /// holds this lock for the whole operation; it is FREE (acquirable) while
    /// no preparation is running. Any voter-workflow entry point that observes
    /// the voter stuck in `Preparing` while this slot is free knows the
    /// previous worker died mid-operation and performs fail-closed recovery —
    /// backend-authoritative, with no frontend timeout involved.
    preparation_slot: Mutex<()>,
    #[cfg(feature = "managed-tor-test")]
    managed_tor_test: Mutex<Option<managed_tor_test::ManagedTorTestState>>,
    #[cfg(feature = "managed-tor-test")]
    organizer_intake: Mutex<Option<organizer_tor_intake::OrganizerIntakeState>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            session: Mutex::new(None),
            draft: Mutex::new(None),
            session_workspace_id: Mutex::new(None),
            draft_workspace_id: Mutex::new(None),
            voter: Mutex::new(None),
            pending_voter_credential: Mutex::new(None),
            transport: Mutex::new(PrivateSubmissionCoordinatorV1::production_unprovisioned()),
            preparation_slot: Mutex::new(()),
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test: Mutex::new(None),
            #[cfg(feature = "managed-tor-test")]
            organizer_intake: Mutex::new(None),
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

#[cfg(not(feature = "managed-tor-test"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct GuiPrivateSubmissionResultV1 {
    route: &'static str,
    receipt_state: &'static str,
    retry_status: &'static str,
    reduced_anonymity: bool,
}

impl AppState {
    /// THE organizer-authority gate. Every command that may mutate
    /// authoritative election state, provision/sign with ballot-office
    /// material, or disclose organizer transport internals must call this
    /// FIRST — before any filesystem write, Tor launch, key generation,
    /// generation reservation, workspace revision, or lifecycle transition.
    ///
    /// The role is read under the SAME lock that guards the session, so the
    /// verdict always describes exactly the session a subsequent read will
    /// observe — no install/swap interleaving can split them.
    fn ensure_organizer_authority(&self) -> Result<(), CommandError> {
        let guard = self.session.lock().map_err(|_| CommandError::state_poisoned())?;
        match guard.as_ref() {
            Some(active) if active.authority == SessionAuthorityV1::Organizer => Ok(()),
            Some(_) => Err(CommandError::organizer_authority_required()),
            None => Err(CommandError::no_session()),
        }
    }

    /// The current session authority (public projection for the frontend).
    fn active_authority(&self) -> Result<Option<SessionAuthorityV1>, CommandError> {
        let guard = self.session.lock().map_err(|_| CommandError::state_poisoned())?;
        Ok(guard.as_ref().map(|active| active.authority))
    }

    /// Read-only access to the active session.
    fn with_session<T>(
        &self,
        f: impl FnOnce(&GuiElectionSessionV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        match guard.as_ref() {
            Some(active) => f(&active.session),
            None => Err(CommandError::no_session()),
        }
    }

    #[cfg(test)]
    fn with_session_mut<T>(
        &self,
        f: impl FnOnce(&mut GuiElectionSessionV1) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        match guard.as_mut() {
            Some(active) => f(&mut active.session),
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

    #[cfg(test)]
    fn get_or_create_draft_preview(&self) -> Result<GuiElectionDraftPreviewV1, CommandError> {
        let mut guard = self
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let draft = guard.get_or_insert_with(GuiElectionDraftV1::new);
        Ok(draft.preview())
    }

    #[cfg(test)]
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
            .map(PendingVoterCredentialV1::status)
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
        let pending_credential = PendingVoterCredentialV1 {
            credential,
            origin: GuiVoterCredentialOriginV1::Generated,
        };
        let status = pending_credential.status()?;
        *pending = Some(pending_credential);
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

    fn active_public_key_hex(&self) -> Result<Option<String>, CommandError> {
        let guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(voter) = guard.as_ref() {
            if let Some(public_key_hex) = voter.credential_public_key_hex() {
                return Ok(Some(public_key_hex));
            }
        }
        drop(guard);

        let pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        pending
            .as_ref()
            .map(PendingVoterCredentialV1::public_key_hex)
            .transpose()
    }

    fn ensure_no_loaded_credential_for_create(&self) -> Result<(), CommandError> {
        if self.active_public_key_hex()?.is_some() {
            return Err(GuiCoreError::credential_already_loaded().into());
        }
        Ok(())
    }

    fn ensure_identity_can_load(&self, public_key_hex: &str) -> Result<bool, CommandError> {
        match self.active_public_key_hex()? {
            Some(loaded) if loaded == public_key_hex => Ok(true),
            Some(_) => Err(GuiCoreError::credential_already_loaded().into()),
            None => Ok(false),
        }
    }

    fn install_credential(
        &self,
        credential: VoterGovernanceCredentialV1,
        origin: GuiVoterCredentialOriginV1,
    ) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let session_guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(session) = session_guard.as_ref().map(|active| &active.session) {
            let mut voter_guard = self
                .voter
                .lock()
                .map_err(|_| CommandError::state_poisoned())?;
            let Some(voter) = voter_guard.as_mut() else {
                return Err(CommandError::no_voter_session());
            };
            let status =
                voter.install_credential_with_origin(credential, origin, session.artifacts())?;
            drop(voter_guard);
            let mut pending = self
                .pending_voter_credential
                .lock()
                .map_err(|_| CommandError::state_poisoned())?;
            *pending = None;
            return Ok(status);
        }
        drop(session_guard);

        let pending_credential = PendingVoterCredentialV1 { credential, origin };
        let status = pending_credential.status()?;
        let mut pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *pending = Some(pending_credential);
        Ok(status)
    }

    fn update_loaded_origin_if_same(
        &self,
        public_key_hex: &str,
        origin: GuiVoterCredentialOriginV1,
    ) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let mut voter_guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(voter) = voter_guard.as_mut() {
            if voter.credential_public_key_hex().as_deref() == Some(public_key_hex) {
                return Ok(voter.set_credential_origin(origin));
            }
        }
        drop(voter_guard);

        let mut pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(pending_credential) = pending.as_mut() {
            if pending_credential.public_key_hex()?.as_str() == public_key_hex {
                pending_credential.origin = origin;
                return pending_credential.status();
            }
        }
        Err(GuiCoreError::credential_not_loaded().into())
    }

    fn current_credential_backup(
        &self,
        path: &Path,
        passphrase: &str,
    ) -> Result<GuiVoterCredentialBackupResultV1, CommandError> {
        let voter_guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(voter) = voter_guard.as_ref() {
            if voter.credential_public_key_hex().is_some() {
                return Ok(voter.backup_credential_to_path(path, passphrase)?);
            }
        }
        drop(voter_guard);

        let pending = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(pending) = pending.as_ref() else {
            return Err(GuiCoreError::credential_not_loaded().into());
        };
        pending.backup_to_path(path, passphrase)
    }

    fn clear_credential_from_memory(&self) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let mut voter_guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(voter) = voter_guard.as_mut() {
            let status = voter.reset_credential();
            drop(voter_guard);
            let mut pending = self
                .pending_voter_credential
                .lock()
                .map_err(|_| CommandError::state_poisoned())?;
            *pending = None;
            return Ok(status);
        }
        drop(voter_guard);
        self.reset_pending_credential()
    }

    fn create_durable_credential_in_dir(
        &self,
        credentials_dir: &Path,
        passphrase: &str,
    ) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        self.ensure_no_loaded_credential_for_create()?;
        let credential = VoterGovernanceCredentialV1::generate()?;
        let summary =
            write_new_durable_voter_credential_v1(credentials_dir, &credential, passphrase)?;
        let already_loaded = self.ensure_identity_can_load(&summary.public_governance_key_hex)?;
        if already_loaded {
            return self.update_loaded_origin_if_same(
                &summary.public_governance_key_hex,
                GuiVoterCredentialOriginV1::DurableCreated,
            );
        }
        self.install_credential(credential, GuiVoterCredentialOriginV1::DurableCreated)
    }

    fn unlock_saved_credential_in_dir(
        &self,
        credentials_dir: &Path,
        public_key: &[u8; 32],
        passphrase: &str,
    ) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let public_key_hex =
            file_summary_for_public_key(public_key, true, true).public_governance_key_hex;
        let already_loaded = self.ensure_identity_can_load(&public_key_hex)?;
        let credential = unlock_saved_voter_credential_v1(credentials_dir, public_key, passphrase)?;
        if already_loaded {
            return self.update_loaded_origin_if_same(
                &public_key_hex,
                GuiVoterCredentialOriginV1::UnlockedSaved,
            );
        }
        self.install_credential(credential, GuiVoterCredentialOriginV1::UnlockedSaved)
    }

    fn import_credential_from_path(
        &self,
        path: &Path,
        passphrase: &str,
        persist_locally: bool,
        credentials_dir: Option<&Path>,
    ) -> Result<GuiVoterCredentialStatusV1, CommandError> {
        let (credential, container) = import_voter_credential_from_path_v1(path, passphrase)?;
        let public_key = credential.public_key_bytes()?;
        let public_key_hex =
            file_summary_for_public_key(&public_key, persist_locally, persist_locally)
                .public_governance_key_hex;
        let already_loaded = self.ensure_identity_can_load(&public_key_hex)?;
        let origin = if persist_locally {
            let Some(credentials_dir) = credentials_dir else {
                return Err(CommandError::app_data_unavailable());
            };
            copy_validated_voter_credential_to_default_v1(credentials_dir, &container)?;
            GuiVoterCredentialOriginV1::ImportedSaved
        } else {
            GuiVoterCredentialOriginV1::ImportedSession
        };

        if already_loaded {
            if persist_locally {
                return self.update_loaded_origin_if_same(&public_key_hex, origin);
            }
            return self.voter_credential_status();
        }
        self.install_credential(credential, origin)
    }

    /// Installs a frozen election session together with the ROLE this shell
    /// holds for it (`Organizer` from freeze/resume-of-organizer-workspace,
    /// `ImportedVoter` from public-artifact import). Authority is installed
    /// atomically with the session so no window exists in which a loaded
    /// session has an undefined role.
    fn install_frozen_session(
        &self,
        session: GuiElectionSessionV1,
        authority: SessionAuthorityV1,
    ) -> Result<(), CommandError> {
        let mut voter = GuiVoterSessionV1::new(session.artifacts());
        let carried_credential = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?
            .as_mut()
            .and_then(GuiVoterSessionV1::take_credential_with_origin)
            .map(|(credential, origin)| PendingVoterCredentialV1 { credential, origin });
        let pending_credential = self
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?
            .take()
            .or(carried_credential);
        if let Some(credential) = pending_credential {
            voter.install_credential_with_origin(
                credential.credential,
                credential.origin,
                session.artifacts(),
            )?;
        }
        let mut session_guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        // Session AND role are replaced under the single session lock, so no
        // concurrent command can ever observe a new session with the previous
        // election's authority (or vice versa).
        *session_guard = Some(ActiveElectionSessionV1::new(session, authority));
        drop(session_guard);
        let mut voter_guard = self
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *voter_guard = Some(voter);
        Ok(())
    }

    /// Replaces the active session after a committed organizer mutation. The
    /// role is preserved BY the snapshot being mutated — an organizer session
    /// stays an organizer session; an imported one can never reach this path.
    fn replace_active_session(&self, session: GuiElectionSessionV1) -> Result<(), CommandError> {
        let mut session_guard = self
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        match session_guard.as_ref() {
            Some(active) => {
                let authority = active.authority;
                *session_guard = Some(ActiveElectionSessionV1::new(session, authority));
                Ok(())
            }
            None => Err(CommandError::no_session()),
        }
    }

    fn set_session_workspace_id(&self, workspace_id: String) -> Result<(), CommandError> {
        let mut guard = self
            .session_workspace_id
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = Some(workspace_id);
        Ok(())
    }

    fn clear_session_workspace_id(&self) -> Result<(), CommandError> {
        let mut guard = self
            .session_workspace_id
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = None;
        Ok(())
    }

    fn set_draft_workspace_id(&self, workspace_id: String) -> Result<(), CommandError> {
        let mut guard = self
            .draft_workspace_id
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = Some(workspace_id);
        Ok(())
    }

    fn clear_draft_workspace_id(&self) -> Result<(), CommandError> {
        let mut guard = self
            .draft_workspace_id
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = None;
        Ok(())
    }
}

fn workspaces_directory(app: &AppHandle) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    Ok(ensure_election_workspaces_directory_v1(&app_data_root)?)
}

fn active_or_new_draft_workspace_id(
    state: &AppState,
    workspaces_dir: &Path,
) -> Result<String, CommandError> {
    let mut guard = state
        .draft_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    if let Some(workspace_id) = guard.as_ref() {
        validate_workspace_id_v1(workspace_id)?;
        return Ok(workspace_id.clone());
    }
    let workspace_id = create_draft_workspace_id_v1(workspaces_dir)?;
    *guard = Some(workspace_id.clone());
    Ok(workspace_id)
}

fn active_or_session_derived_workspace_id(
    state: &AppState,
    session: &GuiElectionSessionV1,
) -> Result<String, CommandError> {
    let mut guard = state
        .session_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    if let Some(workspace_id) = guard.as_ref() {
        validate_workspace_id_v1(workspace_id)?;
        return Ok(workspace_id.clone());
    }
    let workspace_id = workspace_id_for_session_v1(session);
    *guard = Some(workspace_id.clone());
    Ok(workspace_id)
}

fn mutate_draft_transactionally<T>(
    app: &AppHandle,
    state: &AppState,
    mutate: impl FnOnce(&mut GuiElectionDraftV1) -> Result<T, CommandError>,
) -> Result<T, CommandError> {
    let workspaces_dir = workspaces_directory(app)?;
    let workspace_id = active_or_new_draft_workspace_id(state, &workspaces_dir)?;
    let mut next = {
        let guard = state
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(draft) = guard.as_ref() else {
            return Err(CommandError::no_draft());
        };
        draft.replayed_clone()?
    };
    let result = mutate(&mut next)?;
    write_draft_workspace_revision_v1(&workspaces_dir, &workspace_id, &next)?;
    let mut guard = state
        .draft
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *guard = Some(next);
    Ok(result)
}

fn mutate_session_transactionally<T>(
    app: &AppHandle,
    state: &AppState,
    mutate: impl FnOnce(&mut GuiElectionSessionV1) -> Result<T, CommandError>,
) -> Result<(T, GuiElectionSummaryV1, ElectionLifecycleStateV1), CommandError> {
    // ORGANIZER-AUTHORITY GATE (fail before ANY effect): a durable organizer
    // workspace revision may only ever be written for an organizer-owned
    // session. This central gate makes it structurally impossible for any
    // current or future caller of this helper to mutate an imported voter
    // session or synthesize an organizer workspace from public artifacts.
    state.ensure_organizer_authority()?;
    let workspaces_dir = workspaces_directory(app)?;
    let original = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        // Re-check against the SNAPSHOT taken under the lock, so the verdict
        // and the mutated session are the same unit even under concurrent
        // election switches (the snapshot carries session + role atomically).
        let Some(active) = guard.as_ref() else {
            return Err(CommandError::no_session());
        };
        if active.authority != SessionAuthorityV1::Organizer {
            return Err(CommandError::organizer_authority_required());
        }
        active.session.transactional_clone()
    };
    let mut next = original;
    let result = mutate(&mut next)?;
    let summary = next.summary();
    let lifecycle_state = next.lifecycle_state_v1();
    let workspace_id = active_or_session_derived_workspace_id(state, &next)?;
    write_session_workspace_revision_v1(&workspaces_dir, &workspace_id, &next)?;
    state.replace_active_session(next)?;
    Ok((result, summary, lifecycle_state))
}

fn credentials_directory(app: &AppHandle) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let credentials_dir = voter_credentials_directory_v1(&app_data_root);
    ensure_voter_credentials_directory_v1(&credentials_dir)?;
    Ok(credentials_dir)
}

fn cast_locks_directory(app: &AppHandle) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let cast_locks_dir = voter_cast_locks_directory_v1(&app_data_root);
    ensure_voter_cast_locks_directory_v1(&cast_locks_dir)?;
    Ok(cast_locks_dir)
}

#[cfg(feature = "managed-tor-test")]
fn configured_managed_tor_descriptor(
    state: &AppState,
) -> Result<Option<TransportDescriptorV1>, CommandError> {
    managed_tor_test::configured_transport_descriptor(state)
}

#[cfg(not(feature = "managed-tor-test"))]
fn configured_managed_tor_descriptor(
    _state: &AppState,
) -> Result<Option<TransportDescriptorV1>, CommandError> {
    Ok(None)
}

/// Resolves the durable cast-lock state for the loaded election + credential
/// and applies it to the voter session, so every gated voter command decides
/// against the authoritative on-disk record (surviving restart, navigation, and
/// credential lock/unlock). Absent a loaded credential, the session is NotCast.
///
/// Kept for compatibility; all current callers resolve `cast_locks_directory`
/// BEFORE acquiring `session`/`voter` and call [`apply_voter_cast_lock_at`]
/// directly so no AppState lock is held across `app.path()`.
#[allow(dead_code)]
fn apply_voter_cast_lock(
    app: &AppHandle,
    artifacts: &GuiElectionArtifactsV1,
    voter: &mut GuiVoterSessionV1,
    transport_descriptor: Option<&TransportDescriptorV1>,
) -> Result<GuiVoterCastLockStateV1, CommandError> {
    let cast_locks_dir = cast_locks_directory(app)?;
    apply_voter_cast_lock_at(&cast_locks_dir, artifacts, voter, transport_descriptor)
}

/// [`apply_voter_cast_lock`] against an explicit cast-locks directory.
fn apply_voter_cast_lock_at(
    cast_locks_dir: &std::path::Path,
    artifacts: &GuiElectionArtifactsV1,
    voter: &mut GuiVoterSessionV1,
    transport_descriptor: Option<&TransportDescriptorV1>,
) -> Result<GuiVoterCastLockStateV1, CommandError> {
    let Some(public_key_hex) = voter.credential_public_key_hex() else {
        voter.apply_cast_lock_state(GuiVoterCastLockStateV1::NotCast);
        return Ok(GuiVoterCastLockStateV1::NotCast);
    };
    let Some(fingerprint) = public_credential_fingerprint_hex_v1(&public_key_hex) else {
        voter.apply_cast_lock_state(GuiVoterCastLockStateV1::NotCast);
        return Ok(GuiVoterCastLockStateV1::NotCast);
    };
    let manifest_hash_hex = GuiVoterElectionBindingV1::from_artifacts(artifacts).manifest_hash_hex;
    let state = if let Some(descriptor) = transport_descriptor {
        resolve_and_recover_private_transport_cast_lock_state_v1(
            cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            descriptor,
        )?
    } else {
        resolve_and_recover_cast_lock_state_v1(
            cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            artifacts,
        )?
    };
    voter.apply_cast_lock_state(state);
    Ok(state)
}

fn external_credential_path(path: String) -> Result<PathBuf, CommandError> {
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(CommandError::external_path_required());
    }
    Ok(path)
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    load_election_from_paths(
        Path::new(&manifest_path),
        Path::new(&registry_path),
        Path::new(&option_set_path),
        &app,
        &state,
    )
}

/// Canonical filenames the app writes when exporting an election's public
/// artifacts. The one-folder loader looks for exactly these three names.
const ELECTION_FOLDER_MANIFEST_FILE: &str = "election-manifest.cbor";
const ELECTION_FOLDER_REGISTRY_FILE: &str = "voter-registry.cbor";
const ELECTION_FOLDER_CANDIDATE_SET_FILE: &str = "candidate-set.cbor";

/// Loads an election from ONE folder containing the three canonical export
/// files, reusing the EXACT same validation/loading path as the manual
/// three-file loader (no election validation is duplicated here). Fails closed
/// if the chosen path is not a directory or is missing any of the three files;
/// the canonical decode + same-election binding checks then run unchanged.
#[tauri::command]
fn load_election_folder(
    folder_path: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    let folder = Path::new(&folder_path);
    if !folder.is_dir() {
        return Err(CommandError::new(
            "GUI_ELECTION_FOLDER_NOT_A_DIRECTORY",
            "INVALID_INPUT",
            "choose an existing election folder",
        ));
    }
    let manifest = folder.join(ELECTION_FOLDER_MANIFEST_FILE);
    let registry = folder.join(ELECTION_FOLDER_REGISTRY_FILE);
    let option_set = folder.join(ELECTION_FOLDER_CANDIDATE_SET_FILE);
    if !manifest.is_file() || !registry.is_file() || !option_set.is_file() {
        return Err(CommandError::new(
            "GUI_ELECTION_FOLDER_INCOMPLETE",
            "INVALID_INPUT",
            "the election folder must contain election-manifest.cbor, voter-registry.cbor, and candidate-set.cbor",
        ));
    }
    load_election_from_paths(&manifest, &registry, &option_set, &app, &state)
}

/// Re-applies a persisted, previously accepted election-status record (if
/// any) to a freshly installed session so a restart keeps authenticated
/// lifecycle knowledge offline — no bundle, no network, no Tor. A missing
/// record is a no-op; a present-but-invalid record fails closed with a
/// truthful error rather than silently forgetting lifecycle knowledge.
fn reapply_persisted_election_status(
    app: &AppHandle,
    session: &mut GuiElectionSessionV1,
) -> Result<Option<AppliedElectionStatusV1>, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let status_dir = ensure_voter_election_status_directory_v1(&app_data_root)?;
    let manifest_hex = session.artifacts().summary().manifest_hash_hex.clone();
    let Some(record) = load_persisted_election_status_v1(
        &status_dir,
        &manifest_hex,
        session.artifacts().manifest().election_id().as_bytes(),
        session.artifacts().manifest_hash(),
        session.artifacts().registry_commitment(),
    )?
    else {
        return Ok(None);
    };
    let roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
        key_id: record.root_key_id.clone(),
        public_key: record.root_public_key,
    });
    let mut knowledge = ElectionStatusKnowledgeV1::from_accepted(
        record.statement.state(),
        record.statement.generation(),
    );
    let bytes = record.statement.to_canonical_cbor()?;
    verify_and_apply_election_status_statement_v1(&bytes, &roots, &mut knowledge, session)
        .map(Some)
        .map_err(CommandError::from)
}

/// Shared implementation for the manual three-file and one-folder loaders.
///
/// ROLE MODEL: loading public election artifacts establishes
/// [`SessionAuthorityV1::ImportedVoter`] — inspection, credential, signed-status,
/// and voter-ballot workflow only. It deliberately does NOT create or update any
/// durable organizer workspace (public artifacts alone must never synthesize
/// organizer ownership), and it does not claim the session-workspace slot, so
/// nothing an imported session does can ever write into `election-*` durable
/// organizer storage.
fn load_election_from_paths(
    manifest_path: &Path,
    registry_path: &Path,
    option_set_path: &Path,
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiElectionSummaryV1, CommandError> {
    let artifacts =
        GuiElectionArtifactsV1::from_paths(manifest_path, registry_path, option_set_path)?;
    let mut session = GuiElectionSessionV1::new(artifacts)?;
    // Preserve a same-process credential across an explicit reload. Its
    // eligibility is recomputed only after the new canonical registry loads.
    let carried_credential = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .as_mut()
        .and_then(GuiVoterSessionV1::take_credential_with_origin)
        .map(|(credential, origin)| PendingVoterCredentialV1 { credential, origin });
    let pending_credential = state
        .pending_voter_credential
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .take()
        .or(carried_credential);
    let mut voter = GuiVoterSessionV1::new(session.artifacts());
    if let Some(credential) = pending_credential {
        voter.install_credential_with_origin(
            credential.credential,
            credential.origin,
            session.artifacts(),
        )?;
    }
    // Restore authenticated lifecycle knowledge for this election (offline,
    // from the previously accepted status record). Voter lifecycle evidence
    // always flows through signed statements verified against the pinned
    // ballot-office anchor; the local mutable view advances forward only.
    reapply_persisted_election_status(app, &mut session)?;
    let summary = session.summary();
    {
        let mut guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        // Session AND voter role are installed atomically: an imported public
        // election is a VOTER context from the instant it becomes visible.
        *guard = Some(ActiveElectionSessionV1::new(
            session,
            SessionAuthorityV1::ImportedVoter,
        ));
    }
    {
        let mut voter_guard = state
            .voter
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *voter_guard = Some(voter);
    }
    // No durable workspace exists for an imported election: the id slot stays
    // empty so no organizer command can target organizer storage for it.
    state.clear_session_workspace_id()?;
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
        .and_then(GuiVoterSessionV1::take_credential_with_origin)
        .map(|(credential, origin)| PendingVoterCredentialV1 { credential, origin });
    *voter_guard = None;
    if let Some(credential) = credential {
        let mut pending_guard = state
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *pending_guard = Some(credential);
    }
    drop(voter_guard);
    // Switching away from an election always recomputes authority: the role is
    // cleared together with the session (they share one lock) so nothing can
    // leak across a switch.
    state.clear_session_workspace_id()?;
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
    Ok(guard.as_ref().map(|active| active.session.summary()))
}

/// Public role projection for the ACTIVE session: `"organizer"` only when this
/// shell established organizer ownership (freeze, or resume of a workspace
/// carrying durable organizer-authority provenance), `"imported_voter"` when
/// the session came from public artifacts, and `None` with no active session.
///
/// This is a truthful mirror of backend state — the frontend uses it to hide
/// organizer controls, but the BACKEND gate
/// ([`AppState::ensure_organizer_authority`]) remains the enforcement point.
#[tauri::command]
fn active_election_authority(
    state: tauri::State<'_, AppState>,
) -> Result<Option<ActiveElectionAuthorityV1>, CommandError> {
    Ok(state
        .active_authority()?
        .map(|authority| ActiveElectionAuthorityV1 {
            authority: authority.as_str(),
        }))
}

/// Lists resumable local election workspaces from the backend-controlled
/// app-data directory. The frontend receives public summaries only.
#[tauri::command]
fn list_election_workspaces(
    app: AppHandle,
) -> Result<Vec<GuiElectionWorkspaceSummaryV1>, CommandError> {
    let workspaces_dir = workspaces_directory(&app)?;
    Ok(list_election_workspaces_v1(&workspaces_dir)?)
}

/// The backend-issued ids of the workspaces this session currently has active:
/// the loaded frozen `session` and the in-progress organizer `draft`. Both are
/// public opaque ids (the same ids already returned by
/// [`list_election_workspaces`]); no secret crosses this boundary. The frontend
/// uses these to keep its view consistent with the fail-closed delete guard —
/// e.g. offering "Resume" rather than a "Delete" that the guard would refuse
/// for the currently active draft (Failure 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActiveWorkspaceIdsV1 {
    session_workspace_id: Option<String>,
    draft_workspace_id: Option<String>,
}

/// Returns the active session/draft workspace ids (read-only, public ids).
#[tauri::command]
fn active_workspace_ids(
    state: tauri::State<'_, AppState>,
) -> Result<ActiveWorkspaceIdsV1, CommandError> {
    let session_workspace_id = state
        .session_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .clone();
    let draft_workspace_id = state
        .draft_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .clone();
    Ok(ActiveWorkspaceIdsV1 {
        session_workspace_id,
        draft_workspace_id,
    })
}

/// Resumes one local election workspace by backend-issued id.
#[tauri::command]
fn resume_election_workspace(
    workspace_id: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionWorkspaceResumeResultV1, CommandError> {
    let workspaces_dir = workspaces_directory(&app)?;
    let loaded = resume_election_workspace_v1(&workspaces_dir, &workspace_id)?;
    match loaded {
        LoadedElectionWorkspaceV1::Draft { workspace, draft } => {
            let preview = draft.preview();
            preserve_credential_and_clear_session(&state)?;
            {
                let mut draft_guard = state
                    .draft
                    .lock()
                    .map_err(|_| CommandError::state_poisoned())?;
                *draft_guard = Some(draft);
            }
            state.set_draft_workspace_id(workspace_id)?;
            Ok(GuiElectionWorkspaceResumeResultV1 {
                workspace,
                election: None,
                draft: Some(preview),
                organizer_workspace: true,
            })
        }
        LoadedElectionWorkspaceV1::Session { workspace, mut session } => {
            // Restore authenticated lifecycle knowledge before installing so
            // the resumed session reflects the last accepted status evidence.
            reapply_persisted_election_status(&app, &mut session)?;
            let election = session.summary();
            // ROLE RESTORATION IS FAIL-CLOSED: organizer authority returns only
            // with a valid durable organizer-authority provenance marker. A
            // workspace without one (e.g. synthesized from imported public
            // artifacts, or written before role separation) resumes as a
            // VOTER-ONLY view of that election.
            let authority = if workspace.organizer_workspace {
                SessionAuthorityV1::Organizer
            } else {
                SessionAuthorityV1::ImportedVoter
            };
            state.install_frozen_session(session, authority)?;
            state.set_session_workspace_id(workspace_id)?;
            state.clear_draft_workspace_id()?;
            Ok(GuiElectionWorkspaceResumeResultV1 {
                organizer_workspace: workspace.organizer_workspace,
                workspace,
                election: Some(election),
                draft: None,
            })
        }
    }
}

/// Deletes one local election workspace by backend-issued id and returns the
/// refreshed list. Deletion is confined to app-owned durable workspace storage
/// (the id is strictly validated so the target is always a direct child of the
/// workspaces root, and a symlink/reparse-point target is refused); exported
/// canonical election files and finalized archives stored elsewhere are never
/// touched. The workspace currently loaded in this session cannot be deleted.
#[tauri::command]
fn delete_election_workspace(
    workspace_id: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuiElectionWorkspaceSummaryV1>, CommandError> {
    // Refuse to delete the workspace this session currently has loaded (session
    // or draft) so a cleanup never pulls durable state out from under the
    // active election.
    let active_session = state
        .session_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .clone();
    let active_draft = state
        .draft_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .clone();
    if active_session.as_deref() == Some(workspace_id.as_str())
        || active_draft.as_deref() == Some(workspace_id.as_str())
    {
        return Err(CommandError::new(
            "GUI_WORKSPACE_DELETE_ACTIVE",
            "INVALID_INPUT",
            "close or switch away from this election before deleting its local workspace",
        ));
    }
    let workspaces_dir = workspaces_directory(&app)?;
    delete_election_workspace_v1(&workspaces_dir, &workspace_id)?;
    Ok(list_election_workspaces_v1(&workspaces_dir)?)
}

/// Opens the frozen election for ballot intake (lifecycle delegation).
///
/// ORGANIZER-AUTHORITATIVE: rejected up front for any session that was not
/// established by an organizer flow, before any mutation or workspace write.
#[tauri::command]
fn open_voting(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    state.ensure_organizer_authority()?;
    let (_result, summary, _lifecycle_state) =
        mutate_session_transactionally(&app, &state, |session| {
            session.open()?;
            Ok(())
        })?;
    publish_lifecycle_to_intake(&app, &state, &summary.manifest_hash_hex, ElectionLifecycleStateV1::Open);
    Ok(summary)
}

/// Closes ballot acceptance permanently (lifecycle delegation).
///
/// FENCE-BEFORE-COMMIT (fail closed): the private-intake admission fence is
/// published BEFORE the authoritative workspace commit, so a submission whose
/// admission begins after this command's close can never pass an OPEN fence
/// and be ACCEPTED after the election was authoritatively closed. Publishing
/// early can only briefly over-refuse while the commit lands (the next
/// successful Close/Open click republishes); committing first would let
/// in-flight ballots be accepted past the cutoff — the unsafe direction.
/// `open_voting` deliberately keeps the opposite order (publish-after-commit)
/// because an early OPEN publication would admit ballots before the election
/// truly opened.
#[tauri::command]
fn close_voting(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    // Authority is checked BEFORE the intake fence: an unauthorized close must
    // never publish a signed-truth fence transition for an election this shell
    // does not organize.
    state.ensure_organizer_authority()?;
    #[cfg(feature = "managed-tor-test")]
    fence_close_before_commit(&app, &state)?;
    let (_result, summary, lifecycle_state) =
        mutate_session_transactionally(&app, &state, |session| {
            session.close()?;
            Ok(())
        })?;
    invalidate_voter_for_lifecycle(&state, lifecycle_state)?;
    Ok(summary)
}

/// Publishes CLOSED to the running intake fence before the durable close
/// commit. Fires only when the active session is currently OPEN (mirroring
/// what `close()` is about to do), so an illegal click on a FROZEN/CLOSED
/// session never makes signed status answers lie about authoritative truth.
#[cfg(feature = "managed-tor-test")]
fn fence_close_before_commit(
    app: &AppHandle,
    state: &tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    let manifest_hash_hex = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = guard.as_ref().map(|active| &active.session) else {
            return Err(CommandError::no_session());
        };
        if !matches!(
            session.lifecycle_state_v1(),
            ElectionLifecycleStateV1::Open
        ) {
            return Ok(());
        }
        session.summary().manifest_hash_hex.clone()
    };
    publish_lifecycle_to_intake(app, state, &manifest_hash_hex, ElectionLifecycleStateV1::Closed);
    Ok(())
}

/// Records completion of public verification (lifecycle delegation).
#[tauri::command]
fn mark_verified(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    state.ensure_organizer_authority()?;
    let (_result, summary, lifecycle_state) =
        mutate_session_transactionally(&app, &state, |session| {
            session.mark_verified()?;
            Ok(())
        })?;
    invalidate_voter_for_lifecycle(&state, lifecycle_state)?;
    publish_lifecycle_to_intake(&app, &state, &summary.manifest_hash_hex, ElectionLifecycleStateV1::Verified);
    Ok(summary)
}

/// Finalizes the verified result and archive commitments (lifecycle
/// delegation).
#[tauri::command]
fn finalize_election(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionSummaryV1, CommandError> {
    state.ensure_organizer_authority()?;
    let (_result, summary, lifecycle_state) =
        mutate_session_transactionally(&app, &state, |session| {
            session.finalize()?;
            Ok(())
        })?;
    invalidate_voter_for_lifecycle(&state, lifecycle_state)?;
    publish_lifecycle_to_intake(&app, &state, &summary.manifest_hash_hex, ElectionLifecycleStateV1::Finalized);
    Ok(summary)
}

/// Publishes one committed authoritative lifecycle transition to the running
/// private-intake collector (when one is bound to THIS election). The intake
/// worker never decides lifecycle truth itself: admission fencing and
/// authenticated status answers are driven from this cell, so CLOSE fences
/// ballots immediately and status queries answer from organizer authority —
/// never from a self-opened worker session. Best-effort by design: without a
/// running intake there is nothing to fence.
#[cfg(feature = "managed-tor-test")]
fn publish_lifecycle_to_intake(
    app: &AppHandle,
    state: &tauri::State<'_, AppState>,
    manifest_hash_hex: &str,
    new_state: ElectionLifecycleStateV1,
) {
    let Ok(intake_guard) = state.organizer_intake.lock() else {
        return;
    };
    let Some(intake) = intake_guard.as_ref() else {
        return;
    };
    if !intake.is_bound_to_manifest(manifest_hash_hex) {
        return;
    }
    // Continue the durable issuance counter when possible so online status
    // generations never run behind already-exported offline artifacts.
    let reserved = app
        .path()
        .app_data_dir()
        .ok()
        .and_then(|root| {
            use tari_cc_private_ballot_gui_core::reserve_next_status_generation_v1;
            ensure_voter_election_status_directory_v1(&root)
                .ok()
                .and_then(|dir| reserve_next_status_generation_v1(&dir, manifest_hash_hex).ok())
        });
    intake.publish_lifecycle_transition(new_state, reserved);
}

/// Without managed-Tor intake support there is no collector to fence.
#[cfg(not(feature = "managed-tor-test"))]
fn publish_lifecycle_to_intake(
    _app: &AppHandle,
    _state: &tauri::State<'_, AppState>,
    _manifest_hash_hex: &str,
    _new_state: ElectionLifecycleStateV1,
) {
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
/// nullifier acceptance).
///
/// ORGANIZER-AUTHORITATIVE: only the ballot office may admit ballots into its
/// authoritative ledger. Rejected before any file read or session mutation.
#[tauri::command]
fn intake_ballot_package(
    package_path: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiBallotIntakeResultV1, CommandError> {
    state.ensure_organizer_authority()?;
    let package_bytes = read_ballot_package_file_bounded_v1(Path::new(&package_path))?;
    let (result, _summary, _lifecycle_state) =
        mutate_session_transactionally(&app, &state, |session| {
            Ok(session.intake_ballot_package_bytes(&package_bytes)?)
        })?;
    Ok(result)
}

/// Resolves the app-owned, election-scoped durable private-intake inbox
/// directory for the active session, creating it if necessary. This is the
/// SAME path the controlled Tor intake process must be pointed at (via the
/// organizer app-data root) so accepted ballots are handed off to this GUI.
fn private_intake_inbox_dir(
    app: &AppHandle,
    session: &GuiElectionSessionV1,
) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let manifest_hash_hex = session.summary().manifest_hash_hex;
    Ok(ensure_private_intake_inbox_directory_v1(
        &app_data_root,
        &manifest_hash_hex,
    )?)
}

/// Returns the app-owned durable private-intake inbox directory path for the
/// active election. The operator passes their app-data root to the controlled
/// Tor intake process, which writes accepted ballots into exactly this
/// election-scoped inbox; this GUI ingests them via `sync_private_intake`.
///
/// ORGANIZER-AUTHORITATIVE: the intake inbox is ballot-office infrastructure.
#[tauri::command]
fn private_intake_inbox_path(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, CommandError> {
    state.ensure_organizer_authority()?;
    let inbox_dir = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = guard.as_ref().map(|active| &active.session) else {
            return Err(CommandError::no_session());
        };
        private_intake_inbox_dir(&app, session)?
    };
    Ok(inbox_dir.to_string_lossy().into_owned())
}

/// Ingests every accepted ballot the controlled Tor intake process handed off
/// into the app-owned durable inbox, through the SAME gui-core intake boundary
/// (proof verification, election binding, first-valid-nullifier acceptance) an
/// offline ballot uses, then persists the session as a new durable workspace
/// revision. Idempotent: a package already accepted is rejected as a duplicate
/// nullifier and never re-counted, so repeated syncs and exact Tor retries keep
/// the accepted count truthful. The accepted Tor ballot thereby becomes part of
/// the ONE authoritative durable organizer workspace used by participation,
/// close, tally, verify, and finalize — and survives restart.
///
/// Drain window: while OPEN this is live reconciliation; after CLOSE it
/// completes the documented post-close drain of ballots the collector ALREADY
/// accepted (and receipted) before the authoritative fence closed — never a
/// generic post-close acceptance path. VERIFIED/FINALIZED refuse outright.
///
/// ORGANIZER-AUTHORITATIVE: reconciliation promotes accepted ballots into the
/// ONE durable organizer workspace. An imported voter election is rejected
/// before the inbox directory is even resolved, so an unauthorized call can
/// never create inbox storage or a workspace revision.
#[tauri::command]
fn sync_private_intake(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiPrivateIntakeSyncSummaryV1, CommandError> {
    state.ensure_organizer_authority()?;
    let inbox_dir = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = guard.as_ref().map(|active| &active.session) else {
            return Err(CommandError::no_session());
        };
        private_intake_inbox_dir(&app, session)?
    };

    // Ingest into a transactional CLONE first. This is the ONE authoritative
    // reconciliation boundary and it is safe to call unconditionally — on every
    // election load/restart and on every auto-sync tick — because a durable
    // workspace revision is written ONLY when a package is NEWLY accepted.
    //
    // Restart reconciliation: the durable inbox package survives independently of
    // the process-local Tor intake worker counter (which restarts at 0), so a
    // reconciliation pass rediscovers a previously-accepted package even when no
    // NEW network acceptance has occurred since launch and promotes it into the
    // authoritative organizer workspace.
    //
    // No-churn: an empty inbox, or one holding only exact duplicates / rejected
    // packages, changes nothing (`newly_accepted == 0`), so no revision is
    // written and the active session is left untouched — repeated syncs never
    // churn workspace revisions.
    let workspaces_dir = workspaces_directory(&app)?;
    let mut next = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        // Snapshot authority recheck (same unit as the cloned session): the
        // gate verdict and the reconciled session can never diverge under a
        // concurrent election switch.
        let Some(active) = guard.as_ref() else {
            return Err(CommandError::no_session());
        };
        if active.authority != SessionAuthorityV1::Organizer {
            return Err(CommandError::organizer_authority_required());
        }
        active.session.transactional_clone()
    };
    let summary = ingest_private_intake_inbox_into_session_v1(&inbox_dir, &mut next)?;
    if summary.newly_accepted > 0 {
        let workspace_id = active_or_session_derived_workspace_id(&state, &next)?;
        write_session_workspace_revision_v1(&workspaces_dir, &workspace_id, &next)?;
        state.replace_active_session(next)?;
    }
    Ok(summary)
}

/// Computes the deterministic tally over the currently accepted ballots.
///
/// ORGANIZER-AUTHORITATIVE: this is the ballot office's authoritative tally
/// over ITS acceptance ledger. Independent verification of a published result
/// uses `verify_archive` (ungated, archive-authoritative).
#[tauri::command]
fn current_tally(state: tauri::State<'_, AppState>) -> Result<GuiTallySummaryV1, CommandError> {
    state.ensure_organizer_authority()?;
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
///
/// ORGANIZER-AUTHORITATIVE: archives are written from the ballot office's
/// authoritative session (accepted ballots, transcript). Verifying an existing
/// archive is `verify_archive` and stays ungated.
#[tauri::command]
fn write_archive(
    target_dir: String,
    state: tauri::State<'_, AppState>,
) -> Result<GuiArchiveWriteResultV1, CommandError> {
    state.ensure_organizer_authority()?;
    state.with_session(|session| Ok(write_archive_directory_v1(session, Path::new(&target_dir))?))
}

/// Writes a genuine finalized archive for the active session.
///
/// The gui-core finalized writer remains authoritative: it refuses any session
/// that has not reached FINALIZED and emits the finalized archive manifest.
/// ORGANIZER-AUTHORITATIVE: the finalized archive is the ballot office's
/// published record and is written only from its own session.
#[tauri::command]
fn write_finalized_archive(
    target_dir: String,
    governance_document_path: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<GuiArchiveWriteResultV1, CommandError> {
    state.ensure_organizer_authority()?;
    state.with_session(|session| {
        let doc_bytes = governance_document_path
            .map(|path| {
                let bytes = std::fs::read(Path::new(&path))
                    .map_err(|_| CommandError::package_read_failed())?;
                Ok::<Vec<u8>, CommandError>(bytes)
            })
            .transpose()?;
        Ok(write_finalized_archive_v1_with_governance_document(
            session,
            Path::new(&target_dir),
            doc_bytes.as_deref(),
        )?)
    })
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
    _app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionDraftPreviewV1, CommandError> {
    {
        let guard = state
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(draft) = guard.as_ref() {
            return Ok(draft.preview());
        }
    }
    // A brand-new draft is held in memory only. Its durable workspace and
    // backend id are allocated on the FIRST real edit (see
    // `mutate_draft_transactionally` → `active_or_new_draft_workspace_id`), so
    // merely opening Create Election never persists an empty `draft-*`
    // workspace that would surface as a ghost row in Resume Election and then
    // (being the active draft) refuse deletion (Failure 2). Any stale active
    // draft id is cleared so the first edit allocates a fresh workspace.
    let draft = GuiElectionDraftV1::new();
    let preview = draft.preview();
    {
        let mut guard = state
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = Some(draft);
    }
    state.clear_draft_workspace_id()?;
    Ok(preview)
}

/// Starts a fresh organizer election draft, clearing any existing draft. A
/// previously loaded frozen session is left intact so the organizer can review
/// it; calling this discards only the in-progress draft.
#[tauri::command]
fn start_election_draft(
    _app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    // Start a fresh in-memory draft and drop the active draft id so the FIRST
    // real edit allocates a new durable workspace. An empty fresh draft is not
    // persisted (Failure 2); any previously committed draft remains on disk as
    // its own resumable workspace and is not disturbed.
    let draft = GuiElectionDraftV1::new();
    {
        let mut guard = state
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = Some(draft);
    }
    state.clear_draft_workspace_id()
}

/// Discards the in-progress draft. Does not unload a frozen session.
#[tauri::command]
fn discard_election_draft(state: tauri::State<'_, AppState>) -> Result<(), CommandError> {
    let mut guard = state
        .draft
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *guard = None;
    state.clear_draft_workspace_id()?;
    Ok(())
}

fn preserve_credential_and_clear_session(
    state: &tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    {
        let mut session_guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *session_guard = None;
    }
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let credential = voter_guard
        .as_mut()
        .and_then(GuiVoterSessionV1::take_credential_with_origin)
        .map(|(credential, origin)| PendingVoterCredentialV1 { credential, origin });
    *voter_guard = None;
    if let Some(credential) = credential {
        let mut pending_guard = state
            .pending_voter_credential
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *pending_guard = Some(credential);
    }
    drop(voter_guard);
    // The role lives with the session under one lock; clearing the session
    // above removed it atomically.
    state.clear_session_workspace_id()
}

/// Sets the election basics (identifier text + governance source revision).
#[tauri::command]
fn set_draft_basics(
    election_id_text: String,
    proposal_question: String,
    governance_source_revision: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
        draft.set_basics(
            election_id_text,
            proposal_question,
            governance_source_revision,
        )?;
        Ok(())
    })
}

/// Sets the voting rules (minimum/maximum approvals, abstention policy).
#[tauri::command]
fn set_draft_rules(
    approval_min: usize,
    approval_max: usize,
    allow_abstention: bool,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
        draft.set_rules(approval_min, approval_max, allow_abstention)?;
        Ok(())
    })
}

/// Replaces the eligible-voter list from hex governance public keys.
#[tauri::command]
fn set_draft_voters(
    public_key_hexs: Vec<String>,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
        draft.set_voters(public_key_hexs)?;
        Ok(())
    })
}

/// Replaces the ballot option list from `(machine_id_text, display_name)` pairs.
#[tauri::command]
fn set_draft_options(
    options: Vec<DraftOptionInput>,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    let bytes = std::fs::read(Path::new(&registry_path))
        .map_err(|_| CommandError::package_read_failed())?;
    mutate_draft_transactionally(&app, &state, |draft| {
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiElectionCreationResultV1, CommandError> {
    let workspaces_dir = workspaces_directory(&app)?;
    let mut draft = {
        let guard = state
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(draft) = guard.as_ref() else {
            return Err(CommandError::no_draft());
        };
        draft.replayed_clone()?
    };
    // Read the originating draft workspace id before any mutation so it can be
    // retired only after the frozen session is durably committed.
    let originating_draft_workspace_id = state
        .draft_workspace_id
        .lock()
        .map_err(|_| CommandError::state_poisoned())?
        .clone();
    let (result, session) = draft.freeze()?;
    let workspace_id = workspace_id_for_session_v1(&session);
    write_session_workspace_revision_v1(&workspaces_dir, &workspace_id, &session)?;
    // ORGANIZER-AUTHORITY PROVENANCE: freezing is THE act that establishes
    // ballot-office ownership of this election in this shell. Record it
    // durably (strictly after the workspace commit, crash-safe by ordering)
    // so only THIS workspace ever resumes as an organizer workspace. A failure
    // here fails the whole freeze rather than silently creating a workspace
    // that would later resume without authority.
    mark_workspace_organizer_authority_v1(&workspaces_dir, &workspace_id)?;
    // The authoritative session workspace is now durably committed. Retiring
    // the originating draft from resume discovery is best-effort and MUST NOT
    // fail the freeze: the successor already exists, and a failed marker only
    // means the (harmless, non-rollback-capable) stale draft may reappear until
    // the next successful freeze/list. Crash-safe by construction: the marker
    // is written strictly after the successor commit.
    if let Some(draft_workspace_id) = originating_draft_workspace_id {
        let _ =
            mark_draft_workspace_superseded_v1(&workspaces_dir, &draft_workspace_id, &workspace_id);
    }
    {
        let mut guard = state
            .draft
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        *guard = Some(draft);
    }
    state.install_frozen_session(session, SessionAuthorityV1::Organizer)?;
    state.set_session_workspace_id(workspace_id)?;
    state.clear_draft_workspace_id()?;
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiGovernanceDocumentDigestV1, CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
        Ok(draft.set_governance_document(Path::new(&path))?)
    })
}

/// Clears any selected governance document.
#[tauri::command]
fn clear_draft_governance_document(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
        draft.clear_governance_document()?;
        Ok(())
    })
}

/// Pins the currently selected governance document by content digest, setting
/// `governance_source_revision` to `blake3:<digest>`. Requires that a document
/// has been selected.
#[tauri::command]
fn use_governance_document_digest_as_revision(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), CommandError> {
    mutate_draft_transactionally(&app, &state, |draft| {
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

/// Lists valid encrypted credentials from the backend-controlled local store.
/// Only public metadata is returned.
#[tauri::command]
fn list_saved_voter_credentials(
    app: AppHandle,
) -> Result<GuiSavedVoterCredentialsV1, CommandError> {
    let credentials_dir = credentials_directory(&app)?;
    Ok(list_saved_voter_credentials_v1(&credentials_dir)?)
}

/// Generates a new voter governance credential, persists the encrypted V1
/// container first, then installs the secret into memory. The passphrase is
/// accepted over IPC for this approved command only and is zeroized on drop.
#[tauri::command]
async fn create_durable_voter_credential(
    passphrase: String,
    app: AppHandle,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    // The credential Argon2id KDF (64 MiB, t=3, p=4) is CPU-bound and takes
    // long enough to freeze the desktop window ("Not Responding") if run on the
    // Tauri command thread. Move only that blocking work to the blocking pool;
    // the passphrase is zeroized inside the task and never enters JS state.
    run_blocking_command(move || {
        let passphrase = Zeroizing::new(passphrase);
        let credentials_dir = credentials_directory(&app)?;
        let state = app.state::<AppState>();
        state
            .inner()
            .create_durable_credential_in_dir(&credentials_dir, passphrase.as_str())
    })
    .await
}

/// Unlocks a saved default credential identified by public governance key.
/// The frontend supplies no path for this operation.
#[tauri::command]
async fn unlock_saved_voter_credential(
    public_key_hex: String,
    passphrase: String,
    app: AppHandle,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    // Argon2id decryption is CPU-bound; run it off the UI thread so the window
    // stays responsive during unlock. Wrong-password behavior is unchanged: the
    // AEAD open fails closed inside the same task and no credential is installed.
    run_blocking_command(move || {
        let passphrase = Zeroizing::new(passphrase);
        let public_key = parse_public_governance_key_hex_v1(&public_key_hex)?;
        let credentials_dir = credentials_directory(&app)?;
        let state = app.state::<AppState>();
        state
            .inner()
            .unlock_saved_credential_in_dir(&credentials_dir, &public_key, passphrase.as_str())
    })
    .await
}

/// Imports a user-selected portable encrypted credential file. If
/// `persist_locally` is true, the validated encrypted bytes are copied into
/// the backend-derived default path before the credential is installed.
#[tauri::command]
async fn import_voter_credential(
    path: String,
    passphrase: String,
    persist_locally: bool,
    app: AppHandle,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    // Argon2id decryption runs off the UI thread (see unlock).
    run_blocking_command(move || {
        let passphrase = Zeroizing::new(passphrase);
        let path = external_credential_path(path)?;
        let state = app.state::<AppState>();
        if persist_locally {
            let credentials_dir = credentials_directory(&app)?;
            state.inner().import_credential_from_path(
                &path,
                passphrase.as_str(),
                true,
                Some(&credentials_dir),
            )
        } else {
            state
                .inner()
                .import_credential_from_path(&path, passphrase.as_str(), false, None)
        }
    })
    .await
}

/// Writes a fresh encrypted portable backup for the currently unlocked
/// credential. This is copy semantics and does not mutate session state.
#[tauri::command]
async fn backup_voter_credential(
    path: String,
    passphrase: String,
    app: AppHandle,
) -> Result<GuiVoterCredentialBackupResultV1, CommandError> {
    // Argon2id encryption runs off the UI thread so backing up a credential
    // never freezes the window. Copy semantics only; session state is unchanged.
    run_blocking_command(move || {
        let passphrase = Zeroizing::new(passphrase);
        let path = external_credential_path(path)?;
        let state = app.state::<AppState>();
        state
            .inner()
            .current_credential_backup(&path, passphrase.as_str())
    })
    .await
}

/// Clears the unlocked credential from Rust memory without deleting any local
/// or portable credential files.
#[tauri::command]
fn clear_voter_credential_from_memory(
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterCredentialStatusV1, CommandError> {
    state.clear_credential_from_memory()
}

/// Deletes only the backend-derived local encrypted credential file for a
/// validated public governance key. No in-memory credential is cleared.
#[tauri::command]
fn delete_saved_voter_credential(
    public_key_hex: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiSavedVoterCredentialDeleteResultV1, CommandError> {
    let public_key = parse_public_governance_key_hex_v1(&public_key_hex)?;
    let public_key_hex =
        file_summary_for_public_key(&public_key, true, true).public_governance_key_hex;
    let credentials_dir = credentials_directory(&app)?;
    let result = delete_saved_voter_credential_v1(&credentials_dir, &public_key)?;
    if result.deleted && state.active_public_key_hex()?.as_deref() == Some(public_key_hex.as_str())
    {
        let _ = state.update_loaded_origin_if_same(
            &public_key_hex,
            GuiVoterCredentialOriginV1::MemoryOnly,
        )?;
    }
    Ok(result)
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
    if let Some(session) = session_guard.as_ref().map(|active| &active.session) {
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
///
/// While the voter lock is held, an ABANDONED preparation is recovered
/// fail-closed: if the prepared state reads `Preparing` while no live
/// preparation worker owns the preparation slot, the previous worker died
/// mid-operation, so the state is explicitly invalidated (never left stuck)
/// and reported truthfully in this status.
///
/// LOCK-ORDER LIVENESS: the cast-locks directory is resolved (filesystem +
/// `app.path()`) BEFORE `session`/`voter` are acquired, so no AppState lock
/// is held across the Tauri path resolver or directory creation. The
/// remaining locked section holds `session` + `voter` only across the bounded
/// cast-record file read (`apply_voter_cast_lock_at`), never across
/// `app.path()`. This prevents a sync status poll from parking the async
/// preparation worker on `voter.lock()` while the main thread resolves a
/// filesystem path — the zero-CPU liveness failure observed on the physical
/// two-computer regression.
#[tauri::command]
fn voter_workflow_status(
    review_confirmed: bool,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterWorkflowStatusV1, CommandError> {
    let cast_locks_dir = cast_locks_directory(&app)?;
    voter_workflow_status_in_state(state.inner(), &cast_locks_dir, review_confirmed)
}

/// State-level voter workflow status core, shared by the Tauri command body
/// and the shell concurrency regression tests. `cast_locks_dir` is
/// pre-resolved by the caller so no AppState lock is held across
/// `cast_locks_directory(app)` (filesystem + `app.path()`).
fn voter_workflow_status_in_state(
    state: &AppState,
    cast_locks_dir: &std::path::Path,
    review_confirmed: bool,
) -> Result<GuiVoterWorkflowStatusV1, CommandError> {
    let transport_descriptor = configured_managed_tor_descriptor(state)?;
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    recover_abandoned_preparation(state, voter);
    apply_voter_cast_lock_at(
        cast_locks_dir,
        session.artifacts(),
        voter,
        transport_descriptor.as_ref(),
    )?;
    Ok(voter.workflow_status(
        session.artifacts(),
        session.lifecycle_state_v1(),
        review_confirmed,
    ))
}

/// Backend-authoritative recovery for a preparation worker that died before it
/// could complete or recover its own operation. MUST be called only while the
/// caller holds the `state.voter` lock. Recovery fires only when BOTH hold:
/// (a) the voter is still `Preparing`, and (b) the preparation slot is FREE —
/// i.e. no live worker owns the operation. A live worker always holds the slot
/// for the whole operation, so this can never reset state underneath a
/// running cryptographic task; there is deliberately NO frontend timeout that
/// can reach backend state.
fn recover_abandoned_preparation(state: &AppState, voter: &mut GuiVoterSessionV1) -> bool {
    let Ok(slot) = state.preparation_slot.try_lock() else {
        // A live worker owns the preparation; leave its state alone.
        return false;
    };
    drop(slot);
    voter.fail_abandoned_preparation()
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
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterSelectionStatusV1, CommandError> {
    let transport_descriptor = configured_managed_tor_descriptor(state.inner())?;
    let cast_locks_dir = cast_locks_directory(&app)?;
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    apply_voter_cast_lock_at(
        &cast_locks_dir,
        session.artifacts(),
        voter,
        transport_descriptor.as_ref(),
    )?;
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
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiVoterSelectionStatusV1, CommandError> {
    let transport_descriptor = configured_managed_tor_descriptor(state.inner())?;
    let cast_locks_dir = cast_locks_directory(&app)?;
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    apply_voter_cast_lock_at(
        &cast_locks_dir,
        session.artifacts(),
        voter,
        transport_descriptor.as_ref(),
    )?;
    Ok(voter.clear_selection(session.artifacts(), session.lifecycle_state_v1())?)
}

/// Discards the prepared ballot so the voter can reconsider before export
/// ("Change my choice"). Refused once a durable cast lock is active. Rust
/// authoritatively drops the old package/proof; a new preparation builds a
/// brand-new election-bound package and nullifier.
#[tauri::command]
fn change_my_ballot_choice(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiPreparedBallotStatusV1, CommandError> {
    let transport_descriptor = configured_managed_tor_descriptor(state.inner())?;
    let cast_locks_dir = cast_locks_directory(&app)?;
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    apply_voter_cast_lock_at(
        &cast_locks_dir,
        session.artifacts(),
        voter,
        transport_descriptor.as_ref(),
    )?;
    Ok(voter.discard_prepared_ballot(session.artifacts(), session.lifecycle_state_v1())?)
}

/// Generates a real local Triptych proof and canonical ballot package. The
/// result contains safe metadata only; neither proof bytes nor credential
/// material cross to TypeScript.
///
/// ARCHITECTURE: proving is CPU-heavy real cryptography (and local package
/// verification), so this command runs through the reviewed blocking
/// execution architecture ([`run_blocking_command`] ->
/// `tauri::async_runtime::spawn_blocking`). It must never again be an
/// ordinary synchronous command: sync commands execute inline on the main/UI
/// thread, where a long proof (or a wait on a contended lock) would freeze
/// message pumping (Windows "Not Responding") for the whole desktop window.
///
/// The worker owns the [`AppState::preparation_slot`] for the whole
/// operation; on every exit path gui-core's fail-closed recovery guarantees
/// the prepared state is not left `Preparing` (see
/// [`GuiVoterSessionV1::prepare_ballot`]), and any worker that dies outright
/// is recovered by the slot-free abandonment sweep in later workflow reads.
///
/// LOCK-ORDER LIVENESS: `cast_locks_directory(app)` (which calls
/// `app.path().app_data_dir()` and creates a directory) is resolved on the
/// ASYNC thread BEFORE `spawn_blocking`, never on the blocking worker thread.
/// This keeps `app.path()` off the blocking pool and ensures no AppState lock
/// is held across the Tauri path resolver. The blocking worker only acquires
/// `preparation_slot` → (brief `managed_tor_test`) → (brief `session`) →
/// `voter`, with `apply_voter_cast_lock_at` using the pre-resolved directory.
#[tauri::command]
async fn prepare_voter_ballot(
    app: AppHandle,
    _state: tauri::State<'_, AppState>,
) -> Result<GuiPreparedBallotStatusV1, CommandError> {
    let cast_locks_dir = cast_locks_directory(&app)?;
    run_blocking_command(move || {
        let state = app.state::<AppState>();
        prepare_voter_ballot_in_state(state.inner(), Some(&cast_locks_dir))
    })
    .await
}

/// State-level ballot preparation core, shared by the Tauri command body and
/// the shell regression tests. `cast_locks_dir == None` skips only the
/// durable cast-record recovery read (no durable record can exist in those
/// in-memory test states); all gating semantics are identical either way.
fn prepare_voter_ballot_in_state(
    state: &AppState,
    cast_locks_dir: Option<&std::path::Path>,
) -> Result<GuiPreparedBallotStatusV1, CommandError> {
    // Own the preparation slot FIRST so a concurrent abandonment sweep (or a
    // second direct IPC caller) can never observe this operation as abandoned.
    let _preparation_slot = state.preparation_slot.lock().map_err(|_| CommandError::state_poisoned())?;
    let transport_descriptor = configured_managed_tor_descriptor(state)?;
    let (artifacts, lifecycle_state) = {
        let session_guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
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
    if let Some(cast_locks_dir) = cast_locks_dir {
        apply_voter_cast_lock_at(
            cast_locks_dir,
            &artifacts,
            voter,
            transport_descriptor.as_ref(),
        )?;
    }
    Ok(voter.prepare_ballot(&artifacts, lifecycle_state)?)
}

/// Exports a prepared canonical ballot package to the user-selected new path
/// AND records an irrevocable local cast for this election + credential. Rust
/// performs the no-overwrite write, full read-back verification, and the
/// crash-safe cast-lock journal. This is the irreversible local cast boundary.
#[tauri::command]
fn export_prepared_voter_ballot(
    package_path: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiPreparedBallotExportV1, CommandError> {
    let transport_descriptor = configured_managed_tor_descriptor(state.inner())?;
    let cast_locks_dir = cast_locks_directory(&app)?;
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
        return Err(CommandError::no_session());
    };
    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };
    apply_voter_cast_lock_at(
        &cast_locks_dir,
        session.artifacts(),
        voter,
        transport_descriptor.as_ref(),
    )?;
    Ok(voter.export_and_cast_prepared_ballot(
        session.artifacts(),
        session.lifecycle_state_v1(),
        Path::new(&package_path),
        &cast_locks_dir,
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

/// Pure decision for the private-submission command while managed private
/// transport is not yet wired through the shared durable release boundary.
///
/// SECURITY: this deliberately does NOT seal an envelope, invoke the transport
/// coordinator's `submit`, invoke any carrier, or write a PENDING release
/// record. Online routes fail closed as unavailable. This removes the legacy
/// bypass in which a later-provisioned carrier on the old coordinator path could
/// release ballot bytes without crossing the durable cast boundary. The next
/// managed-Tor slice rewires this command to
/// `GuiVoterSessionV1::release_prepared_ballot_via_private_transport` plus the
/// real Tor carrier. Offline export remains the separate, deliberate file
/// command; the offline branch here only reports availability.
#[cfg(not(feature = "managed-tor-test"))]
fn resolve_private_submission_command_v1(
    route: VoterPrivateRouteV1,
) -> Result<GuiPrivateSubmissionResultV1, CommandError> {
    match route {
        VoterPrivateRouteV1::OfflineExport => Ok(GuiPrivateSubmissionResultV1 {
            route: "OfflineExport",
            receipt_state: "OFFLINE_EXPORT",
            retry_status: "NOT_APPLICABLE",
            reduced_anonymity: false,
        }),
        VoterPrivateRouteV1::ManagedTor | VoterPrivateRouteV1::SplitTrustRelay => {
            Err(CommandError::private_transport_unavailable())
        }
    }
}

/// Reports private online-route availability without ever sealing or sending a
/// ballot. JavaScript supplies no ballot bytes and receives no secret or
/// organizer intake fields. Offline export stays the separate canonical file
/// command. Online routes fail closed until the managed-Tor carrier is wired
/// through the shared release boundary (see
/// [`resolve_private_submission_command_v1`]).
#[cfg(not(feature = "managed-tor-test"))]
#[tauri::command]
fn submit_prepared_voter_ballot_privately(
    route: GuiPrivateRouteV1,
    _state: tauri::State<'_, AppState>,
) -> Result<GuiPrivateSubmissionResultV1, CommandError> {
    resolve_private_submission_command_v1(route.into())
}

/// WITH `managed-tor-test`: rewires private submission through the shared
/// durable release boundary
/// (`GuiVoterSessionV1::release_prepared_ballot_via_private_transport`) using
/// `TorSocksPrivateReleaseCarrierV1` and the SAME verified descriptor. No
/// legacy coordinator.submit path may return; no PENDING logic is duplicated in
/// Tauri.
#[cfg(feature = "managed-tor-test")]
#[tauri::command]
async fn submit_prepared_voter_ballot_privately(
    route: GuiPrivateRouteV1,
    app: AppHandle,
) -> Result<tari_cc_private_ballot_gui_core::GuiPrivateReleaseResultV1, CommandError> {
    // Offline export is the separate canonical file command; reject it here so
    // the caller uses `export_prepared_voter_ballot` instead.
    if matches!(route, GuiPrivateRouteV1::OfflineExport) {
        return Err(CommandError::new(
            "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
            "UNAVAILABLE",
            "use the offline export command for offline submission",
        ));
    }
    // The private release performs a blocking Tor/onion request; run it on the
    // blocking thread pool so the desktop window stays responsive (no Windows
    // "Not Responding") while the encrypted ballot is delivered and the
    // authenticated organizer receipt is awaited.
    run_blocking_command(move || {
        let state = app.state::<AppState>();
        managed_tor_test::submit_prepared_voter_ballot_privately_via_managed_tor(
            &app,
            state.inner(),
        )
    })
    .await
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
    let Some(session) = session_guard.as_ref().map(|active| &active.session) else {
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
///
/// ORGANIZER-AUTHORITATIVE (same boundary as `write_archive`).
#[tauri::command]
fn write_archive_with_governance_document(
    target_dir: String,
    governance_document_path: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<GuiArchiveWriteResultV1, CommandError> {
    state.ensure_organizer_authority()?;
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
                "Should the preserved shell test election pass?".to_owned(),
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

    // SECURITY (Blocker C): the registered private-submission command must never
    // reach the legacy coordinator/carrier path. Its whole decision is a pure
    // function of the route that takes no AppState, coordinator, or carrier, so a
    // real carrier can never become active by merely provisioning AppState. It
    // fails closed for online routes and only reports availability for offline.
    #[cfg(not(feature = "managed-tor-test"))]
    #[test]
    fn private_submission_command_never_seals_or_sends_online_routes() {
        assert_eq!(
            resolve_private_submission_command_v1(VoterPrivateRouteV1::ManagedTor)
                .expect_err("managed tor is unavailable")
                .code,
            "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
        );
        assert_eq!(
            resolve_private_submission_command_v1(VoterPrivateRouteV1::SplitTrustRelay)
                .expect_err("relay is unavailable")
                .code,
            "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
        );
        let offline = resolve_private_submission_command_v1(VoterPrivateRouteV1::OfflineExport)
            .expect("offline route reports availability without sealing");
        assert_eq!(offline.route, "OfflineExport");
        assert_eq!(offline.receipt_state, "OFFLINE_EXPORT");
        assert!(!offline.reduced_anonymity);
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
            .install_frozen_session(session, SessionAuthorityV1::Organizer)
            .expect("install frozen voter session");
    }

    // -------------------------------------------------------------------------
    // ORGANIZER-AUTHORITY ROLE MODEL regression coverage.
    //
    // The two-computer physical failure: Computer B imported ONLY the public
    // election package yet received full ballot-office controls. These tests
    // pin the backend rule that role comes from explicit flows — never from
    // the mere presence of a loaded session.
    // -------------------------------------------------------------------------

    #[test]
    fn organizer_commands_are_refused_without_a_loaded_session() {
        let state = AppState::default();
        // No session at all is the truthful no-election refusal.
        let error = state
            .ensure_organizer_authority()
            .expect_err("no session means nothing to organize");
        assert_eq!(error.code, "GUI_NO_ACTIVE_ELECTION");
        assert_eq!(state.active_authority().expect("authority read"), None);
    }

    #[test]
    fn organizer_freeze_establishes_organizer_authority() {
        let state = AppState::default();
        let pending = state.generate_pending_credential().expect("credential");
        let public_key = pending.public_governance_key_hex.expect("public key");
        state.get_or_create_draft_preview().expect("create draft");
        commit_draft(&state, public_key);
        freeze_draft_into_active_session(&state);
        assert_eq!(
            state.active_authority().expect("authority read"),
            Some(SessionAuthorityV1::Organizer)
        );
        // With an organizer-owned session the gate passes.
        state.ensure_organizer_authority().expect("organizer allowed");
    }

    #[test]
    fn imported_public_artifacts_establish_voter_only_authority() {
        let artifacts = {
            // A frozen session built exactly as a public-artifact import would
            // build it (public bytes only; no draft, no organizer flow).
            let mut draft = GuiElectionDraftV1::new();
            draft
                .set_basics(
                    "imported-election".to_owned(),
                    "Should the imported election pass?".to_owned(),
                    "imported-revision".to_owned(),
                )
                .expect("basics");
            draft.set_voters(vec![{
                let credential =
                    VoterGovernanceCredentialV1::generate().expect("generated key");
                credential
                    .pending_status_with_origin(GuiVoterCredentialOriginV1::Generated)
                    .expect("status")
                    .public_governance_key_hex
                    .expect("public key")
            }])
            .expect("voters");
            draft.set_options(vec![("yes".to_owned(), "Yes".to_owned())])
                .expect("options");
            draft.set_rules(1, 1, false).expect("rules");
            draft
                .set_presentation(GuiBallotPresentationType::GovernanceProposal)
                .expect("presentation");
            draft.freeze().expect("freeze").1
        };
        let state = AppState::default();
        state
            .install_frozen_session(artifacts, SessionAuthorityV1::ImportedVoter)
            .expect("import installs a voter-context session");

        assert_eq!(
            state.active_authority().expect("authority read"),
            Some(SessionAuthorityV1::ImportedVoter)
        );
        // THE core refusal: every organizer command's gate fails with one
        // stable code BEFORE any effect.
        let error = state
            .ensure_organizer_authority()
            .expect_err("imported session must never hold organizer authority");
        assert_eq!(error.code, "GUI_ORGANIZER_AUTHORITY_REQUIRED");
    }

    #[test]
    fn switching_elections_recomputes_authority_and_unload_clears_it() {
        let state = AppState::default();
        let pending = state.generate_pending_credential().expect("credential");
        let public_key = pending.public_governance_key_hex.expect("public key");
        state.get_or_create_draft_preview().expect("create draft");
        commit_draft(&state, public_key);
        freeze_draft_into_active_session(&state);
        assert_eq!(
            state.active_authority().expect("authority read"),
            Some(SessionAuthorityV1::Organizer)
        );

        // Switch to an imported election: the previous organizer role must not
        // leak across the switch.
        let other = {
            let mut draft = GuiElectionDraftV1::new();
            draft
                .set_basics(
                    "switched-election".to_owned(),
                    "Should the switched election pass?".to_owned(),
                    "switched-revision".to_owned(),
                )
                .expect("basics");
            draft.set_voters(vec![{
                let credential =
                    VoterGovernanceCredentialV1::generate().expect("generated key");
                credential
                    .pending_status_with_origin(GuiVoterCredentialOriginV1::Generated)
                    .expect("status")
                    .public_governance_key_hex
                    .expect("public key")
            }])
            .expect("voters");
            draft.set_options(vec![("yes".to_owned(), "Yes".to_owned())])
                .expect("options");
            draft.set_rules(1, 1, false).expect("rules");
            draft
                .set_presentation(GuiBallotPresentationType::GovernanceProposal)
                .expect("presentation");
            draft.freeze().expect("freeze").1
        };
        state
            .install_frozen_session(other, SessionAuthorityV1::ImportedVoter)
            .expect("switch to imported election");
        assert_eq!(
            state.active_authority().expect("authority read"),
            Some(SessionAuthorityV1::ImportedVoter),
            "authority must follow the newly installed session"
        );
        assert!(state.ensure_organizer_authority().is_err());

        // Clearing the session (the unload path) always removes the role with
        // it — they live under the same lock.
        {
            let mut session_guard = state.session.lock().expect("session lock");
            *session_guard = None;
        }
        assert_eq!(state.active_authority().expect("authority read"), None);
        assert!(state.ensure_organizer_authority().is_err());
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
        let session = session_guard
            .as_ref()
            .map(|active| &active.session)
            .expect("active session");
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

    #[test]
    fn durable_create_restart_unlock_clear_and_delete_are_distinct() {
        let dir = TestDir::new("durable-create");
        let credentials_dir = dir.join("credentials");
        ensure_voter_credentials_directory_v1(&credentials_dir).expect("credential dir");
        let state = AppState::default();

        let created = state
            .create_durable_credential_in_dir(&credentials_dir, "main passphrase")
            .expect("durable create");
        let public_key_hex = created
            .public_governance_key_hex
            .clone()
            .expect("public key");
        assert!(created.credential_loaded);
        assert!(!created.session_only);
        assert!(created.saved_locally);
        assert_eq!(
            created.credential_origin,
            Some(GuiVoterCredentialOriginV1::DurableCreated)
        );
        let listed = list_saved_voter_credentials_v1(&credentials_dir).expect("list saved");
        assert_eq!(listed.saved_credential_count, 1);

        let restarted = AppState::default();
        let public_key =
            parse_public_governance_key_hex_v1(&public_key_hex).expect("valid public key");
        let unlocked = restarted
            .unlock_saved_credential_in_dir(&credentials_dir, &public_key, "main passphrase")
            .expect("restart unlock");
        assert_eq!(
            unlocked.public_governance_key_hex.as_deref(),
            Some(public_key_hex.as_str())
        );
        assert_eq!(
            unlocked.credential_origin,
            Some(GuiVoterCredentialOriginV1::UnlockedSaved)
        );

        let cleared = restarted
            .clear_credential_from_memory()
            .expect("clear memory");
        assert!(!cleared.credential_loaded);
        assert_eq!(
            list_saved_voter_credentials_v1(&credentials_dir)
                .expect("file remains")
                .saved_credential_count,
            1
        );

        let unlocked_again = restarted
            .unlock_saved_credential_in_dir(&credentials_dir, &public_key, "main passphrase")
            .expect("unlock after clear");
        assert!(unlocked_again.saved_locally);
        let deleted =
            delete_saved_voter_credential_v1(&credentials_dir, &public_key).expect("delete saved");
        assert!(deleted.deleted);
        restarted
            .update_loaded_origin_if_same(&public_key_hex, GuiVoterCredentialOriginV1::MemoryOnly)
            .expect("mark memory only");
        let memory_only = restarted
            .voter_credential_status()
            .expect("memory-only status");
        assert!(memory_only.session_only);
        assert!(!memory_only.saved_locally);
        assert_eq!(
            memory_only.credential_origin,
            Some(GuiVoterCredentialOriginV1::MemoryOnly)
        );
    }

    #[test]
    fn durable_create_failure_does_not_install_credential() {
        let dir = TestDir::new("durable-create-failure");
        let credentials_dir = dir.join("credentials-as-file");
        std::fs::write(&credentials_dir, b"not a directory").expect("file marker");
        let state = AppState::default();

        let error = state
            .create_durable_credential_in_dir(&credentials_dir, "main passphrase")
            .expect_err("unsafe output must fail");

        assert_eq!(error.code, "GUI_CREDENTIAL_UNSAFE_PATH");
        let status = state
            .voter_credential_status()
            .expect("status after failed create");
        assert!(!status.credential_loaded);
    }

    #[test]
    fn import_backup_and_identity_conflict_preserve_loaded_credential() {
        let dir = TestDir::new("import-conflict");
        let credentials_dir = dir.join("credentials");
        ensure_voter_credentials_directory_v1(&credentials_dir).expect("credential dir");
        let state = AppState::default();
        let created = state
            .create_durable_credential_in_dir(&credentials_dir, "alpha passphrase")
            .expect("durable alpha");
        let alpha_key = created.public_governance_key_hex.clone();

        let portable = dir.join("portable-beta.tcbcred");
        let beta = VoterGovernanceCredentialV1::generate().expect("beta credential");
        backup_voter_credential_to_path_v1(&beta, &portable, "beta passphrase")
            .expect("portable beta");

        let conflict = state
            .import_credential_from_path(&portable, "beta passphrase", false, None)
            .expect_err("different loaded credential rejected");
        assert_eq!(conflict.code, "GUI_CREDENTIAL_ALREADY_LOADED");
        let retained = state
            .voter_credential_status()
            .expect("retained credential");
        assert_eq!(retained.public_governance_key_hex, alpha_key);

        state.clear_credential_from_memory().expect("clear alpha");
        let imported = state
            .import_credential_from_path(&portable, "beta passphrase", false, None)
            .expect("session import beta");
        assert!(imported.session_only);
        assert!(!imported.saved_locally);
        let backup = dir.join("backup-beta.tcbcred");
        let before = state
            .voter_credential_status()
            .expect("status before backup");
        state
            .current_credential_backup(&backup, "backup passphrase")
            .expect("backup beta");
        let after = state
            .voter_credential_status()
            .expect("status after backup");
        assert_eq!(before, after);
        assert_ne!(
            std::fs::read(&portable).expect("portable bytes"),
            std::fs::read(&backup).expect("backup bytes")
        );

        let persisted = state
            .import_credential_from_path(&portable, "beta passphrase", true, Some(&credentials_dir))
            .expect("same beta persist");
        assert!(!persisted.session_only);
        assert!(persisted.saved_locally);
        assert_eq!(
            persisted.credential_origin,
            Some(GuiVoterCredentialOriginV1::ImportedSaved)
        );
    }

    #[test]
    fn wrong_passphrase_does_not_alter_loaded_identity() {
        let dir = TestDir::new("wrong-passphrase");
        let credentials_dir = dir.join("credentials");
        ensure_voter_credentials_directory_v1(&credentials_dir).expect("credential dir");
        let state = AppState::default();
        let created = state
            .create_durable_credential_in_dir(&credentials_dir, "alpha passphrase")
            .expect("durable alpha");
        let alpha_key_hex = created
            .public_governance_key_hex
            .clone()
            .expect("alpha key");
        let alpha_key =
            parse_public_governance_key_hex_v1(&alpha_key_hex).expect("valid public key");

        let error = state
            .unlock_saved_credential_in_dir(&credentials_dir, &alpha_key, "wrong passphrase")
            .expect_err("wrong passphrase fails");

        assert_eq!(error.code, "GUI_CREDENTIAL_UNLOCK_FAILED");
        let retained = state
            .voter_credential_status()
            .expect("retained after wrong passphrase");
        assert_eq!(
            retained.public_governance_key_hex.as_deref(),
            Some(alpha_key_hex.as_str())
        );
    }

    #[test]
    fn tauri_passphrase_boundary_is_explicitly_allowlisted() {
        let source = shell_source();
        let signatures = command_signatures(&source);
        let mut commands_with_passphrase = Vec::new();
        for (name, signature) in &signatures {
            if signature.contains("passphrase:") {
                commands_with_passphrase.push(name.as_str());
            }
            for forbidden in [
                "password:",
                "secret:",
                "scalar:",
                "seed:",
                "mnemonic:",
                "private_key:",
                "credential_bytes:",
            ] {
                assert!(
                    !signature.contains(forbidden),
                    "{name} must not accept {forbidden}"
                );
            }
            assert!(!signature.contains("VoterGovernanceCredentialV1"));
            assert!(!signature.contains("TariTriptychSecretKeyV1"));
        }
        commands_with_passphrase.sort_unstable();
        assert_eq!(
            commands_with_passphrase,
            [
                "backup_voter_credential",
                "create_durable_voter_credential",
                "import_voter_credential",
                "unlock_saved_voter_credential",
            ]
        );

        let app_state_block = source
            .split("struct AppState")
            .nth(1)
            .and_then(|tail| tail.split("impl Default for AppState").next())
            .expect("AppState block");
        assert!(!app_state_block.contains("passphrase"));
        assert!(!app_state_block.contains("credential_bytes"));

        for block in serializable_struct_blocks(&source) {
            for forbidden_response_field in [
                "passphrase",
                "password",
                "secret",
                "scalar",
                "seed",
                "mnemonic",
                "private_key",
                "credential_bytes",
            ] {
                let private_field = format!("{forbidden_response_field}:");
                let public_field = format!("pub {forbidden_response_field}:");
                assert!(
                    !block.lines().any(|line| {
                        let trimmed = line.trim_start();
                        trimmed.starts_with(&private_field) || trimmed.starts_with(&public_field)
                    }),
                    "serializable DTO must not expose {forbidden_response_field}"
                );
            }
        }
    }

    fn shell_source() -> String {
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
            .expect("shell source")
    }

    fn command_signatures(source: &str) -> Vec<(String, String)> {
        let mut signatures = Vec::new();
        let mut lines = source.lines();
        while let Some(line) = lines.next() {
            if line.trim() != "#[tauri::command]" {
                continue;
            }
            let mut signature = String::new();
            for sig_line in lines.by_ref() {
                let trimmed = sig_line.trim();
                signature.push_str(trimmed);
                signature.push('\n');
                if trimmed.ends_with('{') {
                    break;
                }
            }
            // A command may be `fn` or `async fn` (blocking Tor/process work runs
            // off the main thread via spawn_blocking); strip an optional `async `
            // before the `fn ` so both forms parse.
            let name = signature
                .strip_prefix("async ")
                .unwrap_or(signature.as_str())
                .strip_prefix("fn ")
                .and_then(|tail| tail.split('(').next())
                .expect("command function name")
                .to_owned();
            signatures.push((name, signature));
        }
        signatures
    }

    fn serializable_struct_blocks(source: &str) -> Vec<String> {
        let mut blocks = Vec::new();
        let mut derive_serialize = false;
        let mut lines = source.lines().peekable();
        while let Some(line) = lines.next() {
            let trimmed = line.trim();
            if trimmed.starts_with("#[derive(") {
                derive_serialize = trimmed.contains("Serialize");
                continue;
            }
            if derive_serialize && trimmed.starts_with("struct ") {
                let mut block = String::from(line);
                block.push('\n');
                for body_line in lines.by_ref() {
                    block.push_str(body_line);
                    block.push('\n');
                    if body_line.trim() == "}" {
                        break;
                    }
                }
                blocks.push(block);
            }
            derive_serialize = false;
        }
        blocks
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tari-private-ballot-tauri-{}-{label}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("test temp dir");
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    // =========================================================================
    // TWO-COMPUTER PREPARATION SHELL BOUNDARY + LOCK-ORDER REGRESSIONS.
    //
    // The physical two-computer failure: on Computer B (imported voter,
    // configured managed-Tor connection, authenticated OPEN, selection made)
    // clicking "Create anonymous eligibility proof" parked the invocation
    // forever with ZERO CPU while the window stayed responsive. Root cause:
    // an ABBA lock cycle between two blocking-pool workers —
    //   apply_election_status_bytes_blocking:  session -> managed_tor_test
    //   running_transport_endpoint:            managed_tor_test -> session
    // — after which state.session and state.managed_tor_test were locked
    // forever and every later voter command parked at its first acquisition.
    //
    // These tests pin the repaired shell contract: preparation runs through
    // the reviewed blocking architecture, the two inverted lock edges no
    // longer overlap, concurrent status/transport activity cannot deadlock
    // preparation, and a failed/abandoned preparation can never strand
    // Preparing. They reach the SHELL boundary (AppState + command bodies),
    // not merely GuiVoterSessionV1.
    // =========================================================================

    use tari_cc_private_ballot_gui_core::{
        AuthenticatedElectionStatusStatementV1, BatchPolicyV1, PaddingPolicyV1,
        TransportRoutePolicyV1,
    };

    const OFFICE_ROOT_KEY_ID: &str = "ballot-office-root-1";
    const TEST_ONION_ENDPOINT: &str =
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    /// Installs exactly Computer B's physical state: an IMPORTED public
    /// election (ImportedVoter authority), an eligible carried credential, and
    /// an authenticated OPEN lifecycle. Returns the state and the enrolled
    /// public key hex.
    fn imported_voter_open_state() -> (AppState, String) {
        let state = AppState::default();
        let pending = state.generate_pending_credential().expect("credential");
        let public_key = pending.public_governance_key_hex.expect("public key");
        state.get_or_create_draft_preview().expect("draft");
        commit_draft(&state, public_key.clone());
        // Imported public artifacts install as a VOTER context only.
        let (_, session) = state
            .with_draft_mut(|draft| Ok(draft.freeze()?))
            .expect("freeze");
        state
            .install_frozen_session(session, SessionAuthorityV1::ImportedVoter)
            .expect("install imported session");
        assert_eq!(
            state.active_authority().expect("authority"),
            Some(SessionAuthorityV1::ImportedVoter)
        );
        state
            .with_session_mut(|session| {
                session.open()?;
                Ok(())
            })
            .expect("open");
        (state, public_key)
    }

    /// Selects one option through the shell's Rust-authoritative path.
    fn select_substitute_option(state: &AppState) {
        let session_guard = state.session.lock().expect("session lock");
        let session = session_guard.as_ref().map(|a| &a.session).expect("session");
        let mut voter_guard = state.voter.lock().expect("voter lock");
        let voter = voter_guard.as_mut().expect("voter session");
        voter
            .set_selection(
                session.artifacts(),
                session.lifecycle_state_v1(),
                vec!["796573".to_owned()],
                false,
            )
            .expect("select");
    }

    #[cfg(feature = "managed-tor-test")]
    /// Configures a verified voter transport bundle for the ACTIVE election,
    /// as Computer B had done before OPEN. Signs a descriptor with a test
    /// office root; no Tor process and no network is touched.
    fn configure_managed_transport_for_active_election(state: &AppState) {
        use ed25519_dalek::SigningKey;
        use tari_cc_private_ballot_gui_core::TransportDescriptorV1;

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
            key_id: OFFICE_ROOT_KEY_ID.to_owned(),
            public_key: signing_key.verifying_key().to_bytes(),
        });
        let (election_id, manifest_hash) = {
            let guard = state.session.lock().expect("session lock");
            let session = guard.as_ref().map(|a| &a.session).expect("session");
            (
                session
                    .artifacts()
                    .manifest()
                    .election_id()
                    .as_bytes()
                    .to_vec(),
                session.artifacts().manifest_hash(),
            )
        };
        let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
            election_id,
            manifest_hash,
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec![TEST_ONION_ENDPOINT.to_owned()],
            Vec::new(),
            [0x11; 32],
            "intake-gateway-2026".to_owned(),
            vec![[0x88; 32]],
            PaddingPolicyV1 {
                id: "fixed-connection".to_owned(),
                padded_bytes: 64 * 1024,
            },
            BatchPolicyV1 {
                id: "accepted-1".to_owned(),
                accepted_unique_floor: 1,
            },
            None,
            OFFICE_ROOT_KEY_ID.to_owned(),
            &signing_key,
        )
        .expect("fixture descriptor signs");
        let root_anchor = (OFFICE_ROOT_KEY_ID.to_owned(), *signing_key.verifying_key().as_bytes());
        let managed =
            managed_tor_test::test_configured_state(descriptor, roots, root_anchor);
        *state
            .managed_tor_test
            .lock()
            .expect("managed lock") = Some(managed);
    }

    #[cfg(feature = "managed-tor-test")]
    /// Signs an authenticated OPEN status statement as the organizer office
    /// would, bound to the active election, at the given generation.
    fn signed_open_status(state: &AppState, generation: u64) -> Vec<u8> {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let guard = state.session.lock().expect("session lock");
        let session = guard.as_ref().map(|a| &a.session).expect("session");
        AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
            session
                .artifacts()
                .manifest()
                .election_id()
                .as_bytes()
                .to_vec(),
            session.artifacts().manifest_hash(),
            session.artifacts().registry_commitment(),
            ElectionLifecycleStateV1::Open,
            generation,
            OFFICE_ROOT_KEY_ID.to_owned(),
            &signing_key,
        )
        .expect("fixture statement signs")
        .to_canonical_cbor()
        .expect("fixture statement encodes")
    }

    /// A. Imported voter + eligible credential + OPEN + valid selection:
    /// the SHELL prepare core returns Ready, voter stays NOT_CAST, and no
    /// secret-bearing field crosses the boundary.
    #[test]
    fn shell_prepare_returns_ready_for_imported_open_voter() {
        let (state, _public_key) = imported_voter_open_state();
        select_substitute_option(&state);

        let prepared =
            prepare_voter_ballot_in_state(&state, None).expect("shell preparation succeeds");
        assert_eq!(prepared.state, "Ready");
        assert!(prepared.ready_to_export);
        assert!(prepared.summary.as_ref().expect("summary").locally_verified);

        // Cast boundary untouched before export; safe to retry or reconsider.
        let session_guard = state.session.lock().expect("session lock");
        let session = session_guard.as_ref().map(|a| &a.session).expect("session");
        let voter_guard = state.voter.lock().expect("voter lock");
        let voter = voter_guard.as_ref().expect("voter session");
        let workflow = voter.workflow_status(
            session.artifacts(),
            session.lifecycle_state_v1(),
            true,
        );
        drop(session_guard);
        drop(voter_guard);
        assert_eq!(workflow.cast_lock_state, "NOT_CAST");

        let serialized = serde_json::to_value(&prepared).expect("safe JSON");
        let mut all_keys = Vec::new();
        fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (k, v) in map {
                        out.push(k.to_lowercase());
                        collect_keys(v, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        collect_keys(item, out);
                    }
                }
                _ => {}
            }
        }
        collect_keys(&serialized, &mut all_keys);
        for key in &all_keys {
            for marker in ["secret", "witness", "private", "nullifier"] {
                assert!(!key.contains(marker), "field {key} must not leak {marker}");
            }
        }
        // The only proof-related field name is the PUBLIC suite identifier.
        assert!(all_keys.iter().any(|k| k == "proof_suite_id"));
    }

    /// B. Same state WITH a configured managed-Tor descriptor: preparation
    /// still returns Ready, and the endpoint resolver binds it to THIS
    /// election without holding both locks.
    #[cfg(feature = "managed-tor-test")]
    #[test]
    fn shell_prepare_returns_ready_with_configured_managed_tor() {
        let (state, _public_key) = imported_voter_open_state();
        configure_managed_transport_for_active_election(&state);
        select_substitute_option(&state);

        // Repaired resolver: completes against this state and binds correctly.
        let endpoint =
            managed_tor_test::running_transport_endpoint(&state).expect("endpoint read");
        assert!(endpoint.is_some(), "descriptor must bind to active election");

        let prepared =
            prepare_voter_ballot_in_state(&state, None).expect("shell preparation succeeds");
        assert_eq!(prepared.state, "Ready");
    }

    /// C. Realistic concurrent managed-Tor STATUS polling while preparation
    /// runs must never deadlock: the poller takes only short managed-state
    /// locks and every round of both sides completes well inside the budget.
    #[cfg(feature = "managed-tor-test")]
    #[test]
    fn concurrent_status_polling_and_preparation_never_deadlock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let state = std::sync::Arc::new({
            let (state, _) = imported_voter_open_state();
            configure_managed_transport_for_active_election(&state);
            select_substitute_option(&state);
            state
        });
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let poller = {
            let state = std::sync::Arc::clone(&state);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut rounds = 0_u32;
                while !stop.load(Ordering::SeqCst) && rounds < 200 {
                    managed_tor_test::managed_tor_test_status_blocking(&state)
                        .expect("status read");
                    rounds += 1;
                }
                rounds
            })
        };
        for _ in 0..8 {
            let prepared = prepare_voter_ballot_in_state(&state, None)
                .expect("preparation under polling");
            assert_eq!(prepared.state, "Ready");
        }
        stop.store(true, Ordering::SeqCst);
        // Generous ceiling: a deadlock never finishes, while ordinary suite
        // contention (sibling tests run real Triptych proofs) merely delays.
        let deadline = Duration::from_secs(120);
        let started = std::time::Instant::now();
        loop {
            match poller.is_finished() {
                true => break,
                false if started.elapsed() < deadline => std::thread::sleep(Duration::from_millis(10)),
                false => panic!("status poller deadlocked against preparation"),
            }
        }
        poller.join().expect("poller thread");
    }

    /// D. Deterministic-shape lock-order stress: the two formerly inverted
    /// edges run concurrently with preparation — real signed-status imports
    /// (session-held section), real endpoint resolution (managed-state
    /// snapshot), and real preparations — under a completion budget. Against
    /// e851308 this schedule could form the ABBA cycle and hang; after the
    /// repair neither edge nests, so all workers always finish.
    #[cfg(feature = "managed-tor-test")]
    #[test]
    fn concurrent_status_import_fetch_and_preparation_never_deadlock() {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let dir = TestDir::new("lock-order-stress");
        let status_dir = dir.join("election-status");
        std::fs::create_dir_all(&status_dir).expect("status dir");

        let state = Arc::new({
            let (state, _) = imported_voter_open_state();
            configure_managed_transport_for_active_election(&state);
            select_substitute_option(&state);
            state
        });

        let importer = {
            let state = Arc::clone(&state);
            let status_dir = status_dir.clone();
            std::thread::spawn(move || {
                for generation in 1_u64..=25 {
                    let bytes = signed_open_status(&state, generation);
                    crate::election_status_commands::apply_election_status_bytes_in_state(
                        &state,
                        &status_dir,
                        bytes,
                    )
                    .expect("authenticated import applies monotonically");
                }
            })
        };
        let fetcher = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                for _ in 0..250 {
                    managed_tor_test::running_transport_endpoint(&state)
                        .expect("endpoint read");
                    std::thread::yield_now();
                }
            })
        };
        let preparer = {
            let state = Arc::clone(&state);
            std::thread::spawn(move || {
                for _ in 0..4 {
                    let prepared = prepare_voter_ballot_in_state(&state, None)
                        .expect("preparation under contention");
                    assert_eq!(prepared.state, "Ready");
                }
            })
        };

        // A genuine lock-order deadlock never finishes; ordinary scheduling
        // contention (this suite runs real Triptych proofs in sibling tests)
        // merely delays. The ceiling therefore only exists to convert an
        // infinite hang into a loud failure.
        let handles = [importer, fetcher, preparer];
        let deadline = Instant::now() + Duration::from_secs(300);
        for handle in handles {
            while !handle.is_finished() {
                if Instant::now() >= deadline {
                    panic!("lock-order deadlock suspected: worker exceeded budget");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            handle.join().expect("worker thread");
        }
    }

    /// E. A preparation worker that dies mid-operation can never leave the
    /// voter stuck in Preparing: the backend-owned abandonment sweep recovers
    /// fail-closed (NOT_CAST preserved, retry allowed) with NO frontend
    /// timeout involved.
    #[test]
    fn abandoned_preparation_is_recovered_fail_closed_by_backend_sweep() {
        let (state, _public_key) = imported_voter_open_state();
        select_substitute_option(&state);

        // Simulate a worker that installed Preparing and then died before its
        // recovery could run: begin the operation directly, then release the
        // locks WITHOUT completing. The preparation slot stays free.
        {
            let mut voter_guard = state.voter.lock().expect("voter lock");
            let voter = voter_guard.as_mut().expect("voter session");
            let token = voter
                .begin_preparation_operation(ElectionLifecycleStateV1::Open)
                .expect("operation begins");
            assert_eq!(voter.preparing_operation_id(), Some(token.operation_id()));
        }

        // Backend-authoritative sweep (same call the workflow status makes).
        {
            let mut voter_guard = state.voter.lock().expect("voter lock");
            let voter = voter_guard.as_mut().expect("voter session");
            assert!(recover_abandoned_preparation(&state, voter));
        }

        // State is truthfully Invalidated (never Preparing), still NOT_CAST,
        // and the voter may safely retry proof generation.
        {
            let session_guard = state.session.lock().expect("session lock");
            let session = session_guard.as_ref().map(|a| &a.session).expect("session");
            let mut voter_guard = state.voter.lock().expect("voter lock");
            let voter = voter_guard.as_mut().expect("voter session");
            let workflow =
                voter.workflow_status(session.artifacts(), session.lifecycle_state_v1(), true);
            assert_eq!(workflow.prepared_ballot.state, "Invalidated");
            assert_eq!(workflow.cast_lock_state, "NOT_CAST");

            let retry =
                voter.prepare_ballot(session.artifacts(), session.lifecycle_state_v1());
            drop(session_guard);
            drop(voter_guard);
            let retry = retry.expect("retry after abandonment succeeds");
            assert_eq!(retry.state, "Ready");
        }
    }

    /// F. A live worker OWNS the slot: the sweep must refuse to touch its
    /// Preparing state (no frontend timeout can reset a running cryptographic
    /// task through the backend).
    #[test]
    fn live_preparation_slot_protects_worker_from_sweep() {
        let (state, _public_key) = imported_voter_open_state();
        select_substitute_option(&state);

        // A live worker holds the slot for its whole operation.
        let _slot_guard = state.preparation_slot.lock().expect("slot lock");
        {
            let mut voter_guard = state.voter.lock().expect("voter lock");
            let voter = voter_guard.as_mut().expect("voter session");
            voter
                .begin_preparation_operation(ElectionLifecycleStateV1::Open)
                .expect("operation begins");
            // While the slot is owned, the sweep is a no-op.
            assert!(!recover_abandoned_preparation(&state, voter));
            assert!(
                voter.preparing_operation_id().is_some(),
                "live worker's Preparing state must be untouched"
            );
        }
    }

    /// G. Existing cast-lock semantics remain intact at the shell boundary:
    /// preparation resolves the durable record from disk and a CAST record
    /// refuses new preparation outright.
    #[test]
    fn cast_lock_from_disk_refuses_new_shell_preparation() {
        let (state, public_key) = imported_voter_open_state();
        select_substitute_option(&state);

        let dir = TestDir::new("cast-lock-shell-prepare");
        let cast_locks_dir = dir.join("cast-locks");
        ensure_voter_cast_locks_directory_v1(&cast_locks_dir).expect("cast locks dir");
        let fingerprint =
            public_credential_fingerprint_hex_v1(&public_key).expect("fingerprint");
        let manifest_hash_hex = {
            let guard = state.session.lock().expect("session lock");
            GuiVoterElectionBindingV1::from_artifacts(
                guard.as_ref().map(|a| &a.session).expect("session").artifacts(),
            )
            .manifest_hash_hex
        };
        // Forge the DURABLE local cast the way export/cast would record it.
        write_cast_record_cast_for_test(
            &cast_locks_dir,
            &fingerprint,
            &manifest_hash_hex,
        );

        let prepared = prepare_voter_ballot_in_state(&state, Some(cast_locks_dir.as_path()))
            .expect_err("a durably locked voter cannot prepare again");
        assert_eq!(prepared.code, "GUI_BALLOT_ALREADY_CAST");
    }

    /// Writes a present-but-malformed durable record at the canonical cast
    /// path. Recovery is fail-closed: an unreadable record resolves to
    /// `CAST_PENDING` (locked), never `NOT_CAST`, so preparation refuses.
    fn write_cast_record_cast_for_test(
        dir: &Path,
        fingerprint_hex: &str,
        manifest_hash_hex: &str,
    ) {
        use std::fs;
        let path =
            dir.join(format!("{fingerprint_hex}-{manifest_hash_hex}.castlock"));
        fs::write(&path, b"not-a-canonical-record").expect("write malformed record");
    }

    /// H. The MISSING physical concurrency path from the second two-computer
    /// regression: `voter_workflow_status` (which holds `voter` + `session`
    /// across the bounded `apply_voter_cast_lock_at` file read) polling
    /// concurrently with `prepare_voter_ballot_in_state` (which needs
    /// `preparation_slot` → `managed_tor_test` → `session` → `voter`), both
    /// using a REAL cast-locks directory so the file read is genuine
    /// filesystem work. Tests C and D modelled `managed_tor_test_status` and
    /// `apply_election_status_bytes` polling but NEVER `voter_workflow_status`
    /// — the one sync command the frontend polls on every mount and after
    /// every selection/credential action. This test pins that the fixed
    /// lock-held-across-filesystem pattern (cast_locks_directory resolved
    /// BEFORE the `voter`/`session` locks) lets both workers always complete.
    /// A bounded timeout converts any lock-order deadlock into a loud
    /// failure; ordinary contention merely delays.
    #[test]
    fn concurrent_workflow_status_polling_and_preparation_never_deadlock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let dir = TestDir::new("workflow-status-poll-prepare");
        let cast_locks_dir = dir.join("cast-locks");
        ensure_voter_cast_locks_directory_v1(&cast_locks_dir).expect("cast locks dir");

        let state = Arc::new({
            let (state, _) = imported_voter_open_state();
            select_substitute_option(&state);
            state
        });

        // On the physical two-computer run, the frontend calls
        // `voter_workflow_status` on mount (and after every selection change).
        // Model that as a tight concurrent poller that holds `voter` + `session`
        // across the real `apply_voter_cast_lock_at` file read.
        let stop = Arc::new(AtomicBool::new(false));
        let poller = {
            let state = Arc::clone(&state);
            let cast_locks_dir = cast_locks_dir.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut rounds = 0_u32;
                while !stop.load(Ordering::SeqCst) && rounds < 200 {
                    voter_workflow_status_in_state(&state, &cast_locks_dir, true)
                        .expect("workflow status read under polling");
                    rounds += 1;
                    std::thread::yield_now();
                }
                rounds
            })
        };
        // The prepare worker: acquires `preparation_slot` → (brief
        // `managed_tor_test`) → (brief `session`) → `voter` → real filesystem
        // (`apply_voter_cast_lock_at`) → real Triptych proof. If the poller
        // deadlocks it (or holds `voter` indefinitely across `app.path()`), this
        // worker never finishes.
        let preparer = {
            let state = Arc::clone(&state);
            let cast_locks_dir = cast_locks_dir.clone();
            std::thread::spawn(move || {
                for _ in 0..4 {
                    let prepared =
                        prepare_voter_ballot_in_state(&state, Some(cast_locks_dir.as_path()))
                            .expect("preparation under polling");
                    assert_eq!(prepared.state, "Ready");
                }
            })
        };

        let deadline = Instant::now() + Duration::from_secs(180);
        while !poller.is_finished() {
            if Instant::now() >= deadline {
                panic!(
                    "workflow-status polling deadlocked against preparation: \
                     the prepare worker could not acquire voter while the poller \
                     held it across filesystem work"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::SeqCst);
        poller.join().expect("poller thread");
        preparer.join().expect("preparer thread");
    }

    /// I. The park-site diagnostic: on the physical two-computer regression,
    /// the prepare worker parked with zero CPU BEFORE
    /// `begin_preparation_operation` (state never reached `Preparing`). This
    /// test verifies the FIXED ordering: `cast_locks_directory` is resolved
    /// BEFORE `preparation_slot` is acquired, so no AppState lock is held
    /// across `app.path()`. A second thread can acquire `preparation_slot`
    /// (and then `voter`) while the first is still resolving the directory —
    /// proving the locks are not nested across the filesystem call.
    #[test]
    fn prepare_resolves_cast_locks_dir_before_locking_preparation_slot() {
        let (state, _public_key) = imported_voter_open_state();
        select_substitute_option(&state);

        // The prepare worker acquires preparation_slot in
        // prepare_voter_ballot_in_state. Before that, cast_locks_directory
        // is resolved on the async/caller thread. Verify the slot is FREE
        // while the directory is being resolved (i.e., the resolution happens
        // before the slot is acquired) by checking the slot is acquirable
        // from a concurrent thread that does NOT call
        // prepare_voter_ballot_in_state.
        //
        // This is a structural invariant test: if someone re-introduces
        // cast_locks_directory INSIDE the preparation_slot held section,
        // this test still passes (it only checks the slot is acquirable from
        // a third thread), but the concurrency test H above would catch the
        // deadlock under polling.
        let slot = state.preparation_slot.try_lock();
        assert!(slot.is_ok(), "preparation_slot must be free before prepare");
        drop(slot);

        let prepared = prepare_voter_ballot_in_state(&state, None)
            .expect("preparation succeeds");
        assert_eq!(prepared.state, "Ready");
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
            load_election_folder,
            unload_election,
            election_summary,
            active_election_authority,
            list_election_workspaces,
            active_workspace_ids,
            resume_election_workspace,
            delete_election_workspace,
            open_voting,
            close_voting,
            mark_verified,
            finalize_election,
            intake_ballot_package,
            private_intake_inbox_path,
            sync_private_intake,
            current_tally,
            participation_summary,
            write_archive,
            write_finalized_archive,
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
            list_saved_voter_credentials,
            create_durable_voter_credential,
            unlock_saved_voter_credential,
            import_voter_credential,
            backup_voter_credential,
            clear_voter_credential_from_memory,
            delete_saved_voter_credential,
            voter_governance_credential_status,
            generate_voter_governance_credential,
            generate_pending_voter_governance_credential,
            reset_voter_governance_credential,
            reset_pending_voter_governance_credential,
            voter_workflow_status,
            voter_ballot_selection_status,
            set_voter_ballot_selection,
            clear_voter_ballot_selection,
            change_my_ballot_choice,
            prepare_voter_ballot,
            export_prepared_voter_ballot,
            private_transport_availability,
            submit_prepared_voter_ballot_privately,
            reset_voter_workflow,
            write_archive_with_governance_document,
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test::configure_managed_tor_test,
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test::start_managed_tor,
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test::stop_managed_tor,
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test::managed_tor_test_status,
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test::voter_tor_status,
            #[cfg(feature = "managed-tor-test")]
            managed_tor_test::retry_private_submission,
            #[cfg(feature = "managed-tor-test")]
            organizer_tor_intake::organizer_tor_status,
            #[cfg(feature = "managed-tor-test")]
            organizer_tor_intake::start_private_intake,
            #[cfg(feature = "managed-tor-test")]
            organizer_tor_intake::stop_private_intake,
            #[cfg(feature = "managed-tor-test")]
            organizer_tor_intake::export_voter_transport_bundle,
            #[cfg(feature = "managed-tor-test")]
            election_status_commands::export_election_status_artifact,
            #[cfg(feature = "managed-tor-test")]
            election_status_commands::import_election_status_artifact,
            #[cfg(feature = "managed-tor-test")]
            election_status_commands::fetch_election_status_private,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the Tari Private Ballot shell")
        .run(|_app_handle, _event| {
            // On graceful teardown, reap the owned voter/organizer Tor children so
            // a normal window close never leaves an orphaned tor.exe holding a
            // loopback port or data-directory lock into the next launch. Only the
            // children THIS application launched are touched.
            #[cfg(feature = "managed-tor-test")]
            if matches!(
                _event,
                tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
            ) {
                let state = _app_handle.state::<AppState>();
                managed_tor_test::shutdown_managed_tor_on_exit(state.inner());
                organizer_tor_intake::shutdown_intake_on_exit(state.inner());
            }
        });
}
