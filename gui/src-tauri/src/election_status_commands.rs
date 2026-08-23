//! Authenticated election-status artifact export/import (feature-gated).
//!
//! Compiled only under the `managed-tor-test` feature because the ONLY
//! provisioned ballot-office signing material in this pilot is the controlled-
//! test organizer bundle (ADR-0010 keeps the production root offline until a
//! release ceremony pins it). The underlying gui-core machinery
//! (`election_status` module) is NOT feature-gated and remains the single
//! authoritative verify/apply path.
//!
//! Organizer (Computer A): export a signed statement of the CURRENT
//! authoritative lifecycle, bound to the exact frozen election identity,
//! signed by the SAME root key that signs descriptors and receipts. Every
//! export reserves the next durable generation BEFORE signing (write-ahead),
//! so generations never repeat across restarts.
//!
//! Voter (Computer B): import such an artifact, verify it against the pinned
//! transport authority anchor from the configured voter bundle (or against the
//! previously persisted anchor after a restart), apply it monotonically to the
//! loaded election's mutable lifecycle view, and persist the accepted record
//! so restarts keep the knowledge offline.
//!
//! No voter credential, selection, proof, nullifier, or ballot package is
//! sent, stored, or required by any of these commands.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tauri::{AppHandle, Manager};

use tari_cc_private_ballot_gui_core::{
    AppliedElectionStatusV1, AuthenticatedElectionStatusStatementV1,
    ElectionStatusKnowledgeV1, PersistedElectionStatusRecordV1,
    TransportAuthorityRootSetV1, TransportAuthorityRootV1,
    ensure_voter_election_status_directory_v1, load_persisted_election_status_v1,
    persist_election_status_record_v1, reserve_next_status_generation_v1,
    verify_and_apply_election_status_statement_v1, MAX_ELECTION_STATUS_STATEMENT_BYTES,
};

use crate::managed_tor_test::configured_transport_root_anchor;
use crate::organizer_tor_intake::{bound_election, organizer_private_bundle_dir};
use crate::{AppState, CommandError};

/// Result of exporting one authenticated election-status artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiElectionStatusExportResultV1 {
    pub written_path: String,
    /// Lifecycle state that was signed (stable machine code).
    pub lifecycle_state: &'static str,
    /// Monotonic generation reserved for this statement.
    pub generation: u64,
}

/// Result of importing one authenticated election-status artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiElectionStatusImportResultV1 {
    pub applied: AppliedElectionStatusResultV1,
    /// Refreshed public summary of the active election after application.
    pub election_summary: tari_cc_private_ballot_gui_core::GuiElectionSummaryV1,
}

/// Voter-safe projection of [`AppliedElectionStatusV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AppliedElectionStatusResultV1 {
    /// Effective lifecycle state after application (stable machine code).
    pub effective_state: &'static str,
    /// Whether the local lifecycle moved forward with this import.
    pub advanced: bool,
    /// The accepted statement's generation.
    pub generation: u64,
}

impl AppliedElectionStatusResultV1 {
    fn from_applied(applied: &AppliedElectionStatusV1) -> Self {
        Self {
            effective_state: applied.effective_state.as_str(),
            advanced: applied.advanced,
            generation: applied.generation,
        }
    }
}

// -------------------------------------------------------------------------
// Organizer export
// -------------------------------------------------------------------------

/// Exports one authenticated election-status statement for the active
/// election to `destination_path` (no-overwrite). Signed with the SAME
/// release-pinned root key as the transport descriptor.
///
/// ORGANIZER-AUTHORITATIVE — the gate fires FIRST: an imported voter election
/// must never reserve a status generation, load ballot-office signing
/// material, or produce a signed lifecycle statement. Only the organizer flows
/// (freeze / organizer-workspace resume) establish that authority.
#[tauri::command]
pub async fn export_election_status_artifact(
    destination_path: String,
    app: AppHandle,
) -> Result<GuiElectionStatusExportResultV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        export_election_status_blocking(destination_path, &app, state.inner())
    })
    .await
}

fn export_election_status_blocking(
    destination_path: String,
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiElectionStatusExportResultV1, CommandError> {
    // ORGANIZER-AUTHORITY GATE — before binding resolution, before any durable
    // generation reservation, before any signing material is touched.
    state.ensure_organizer_authority()?;
    let bound = bound_election(state)?;

    let destination = PathBuf::from(&destination_path);
    if !destination.is_absolute() {
        return Err(CommandError::new(
            "GUI_ELECTION_STATUS_EXPORT_NOT_ABSOLUTE",
            "INVALID_INPUT",
            "the status artifact destination must be an absolute path",
        ));
    }
    // No-overwrite: refuse to silently replace an existing artifact.
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(CommandError::new(
            "GUI_ELECTION_STATUS_EXPORT_TARGET_EXISTS",
            "INVALID_INPUT",
            "an election status file already exists at that path; choose another name",
        ));
    }

    // Signing identity: the SAME root key that signs descriptors/receipts.
    let private_dir = organizer_private_bundle_dir(app, &bound.manifest_hash_hex)?;
    let bundle = load_bundle_or_error(&private_dir)?;
    let root_key_id = bundle.material.root.key_id().to_owned();

    // Durable write-ahead generation reservation (never reused, restart-safe).
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let status_dir = ensure_voter_election_status_directory_v1(&app_data_root)?;
    let generation =
        reserve_next_status_generation_v1(&status_dir, &bound.manifest_hash_hex)?;

    // Read the AUTHORITATIVE lifecycle at signing time (short lock).
    let lifecycle_state = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = guard.as_ref().map(|active| &active.session) else {
            return Err(CommandError::no_session());
        };
        session.lifecycle_state_v1()
    };

    let statement = AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
        bound.election_id.clone(),
        bound.artifacts.manifest_hash(),
        bound.artifacts.registry_commitment(),
        lifecycle_state,
        generation,
        root_key_id,
        &bundle.material.root_signing_key,
    )
    .map_err(CommandError::from)?;

    let bytes = statement.to_canonical_cbor().map_err(CommandError::from)?;
    write_create_new_sync(&destination, &bytes)?;
    Ok(GuiElectionStatusExportResultV1 {
        written_path: destination.to_string_lossy().into_owned(),
        lifecycle_state: lifecycle_state.as_str(),
        generation,
    })
}

fn load_bundle_or_error(
    private_dir: &Path,
) -> Result<tari_cc_private_ballot_transport_gateway::LoadedOrganizerPrivateBundleV1, CommandError>
{
    use tari_cc_private_ballot_transport_gateway::load_organizer_private_bundle_v1;
    load_organizer_private_bundle_v1(private_dir).map_err(|_| {
        CommandError::new(
            "GUI_ELECTION_STATUS_NO_SIGNING_IDENTITY",
            "UNAVAILABLE",
            "no provisioned ballot-office signing bundle exists for this election; start private intake once to provision it",
        )
    })
}

fn write_create_new_sync(path: &Path, bytes: &[u8]) -> Result<(), CommandError> {
    let Some(parent) = path.parent() else {
        return Err(CommandError::new(
            "GUI_ELECTION_STATUS_IO",
            "FILE_IO",
            "the status artifact path has no parent directory",
        ));
    };
    fs::create_dir_all(parent).map_err(|_| status_io_error())?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            CommandError::new(
                "GUI_ELECTION_STATUS_EXPORT_WRITE_FAILED",
                "FILE_IO",
                "the election status file could not be created",
            )
        })?;
    file.write_all(bytes).map_err(|_| status_io_error())?;
    file.flush().map_err(|_| status_io_error())?;
    file.sync_all().map_err(|_| status_io_error())?;
    Ok(())
}

fn status_io_error() -> CommandError {
    CommandError::new(
        "GUI_ELECTION_STATUS_IO",
        "FILE_IO",
        "an election status storage operation failed",
    )
}

// -------------------------------------------------------------------------
// Voter import
// -------------------------------------------------------------------------

/// Imports one authenticated election-status artifact for the active election.
///
/// Verification uses, in order:
/// 1. the configured voter transport bundle's pinned authority anchor;
/// 2. the previously persisted acceptance anchor for this election (offline
///    restart path).
/// With neither, the command fails closed with a truthful error.
#[tauri::command]
pub async fn import_election_status_artifact(
    status_path: String,
    app: AppHandle,
) -> Result<GuiElectionStatusImportResultV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        import_election_status_blocking(status_path, &app, state.inner())
    })
    .await
}

fn import_election_status_blocking(
    status_path: String,
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiElectionStatusImportResultV1, CommandError> {
    let statement_bytes = read_bounded_status_file(Path::new(&status_path))?;
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let status_dir = ensure_voter_election_status_directory_v1(&app_data_root)?;
    apply_election_status_bytes_in_state(state, &status_dir, statement_bytes)
}

/// State-level voter-side application core, shared by the Tauri command body
/// and the shell concurrency regression tests (which supply their own bounded
/// status directory instead of an AppHandle).
///
/// THE single voter-side application path for authenticated status bytes,
/// shared by the offline file import and the online private-transport fetch.
///
/// LOCK-ORDERING INVARIANT (see [`crate::AppState`]): the trust-anchor lookup
/// (a brief managed-Tor state lock) is resolved BEFORE the session lock is
/// taken, so this function never holds `session` while acquiring
/// `managed_tor_test`. Holding both here formed the `session ->
/// managed_tor_test` half of an ABBA cycle against
/// `running_transport_endpoint` (`managed_tor_test -> session`) — a stable,
/// zero-CPU deadlock between two blocking-pool workers that permanently parked
/// every later voter command (including ballot preparation).
fn apply_election_status_bytes_blocking(
    statement_bytes: Vec<u8>,
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiElectionStatusImportResultV1, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let status_dir = ensure_voter_election_status_directory_v1(&app_data_root)?;
    apply_election_status_bytes_in_state(state, &status_dir, statement_bytes)
}

pub(crate) fn apply_election_status_bytes_in_state(
    state: &AppState,
    status_dir: &Path,
    statement_bytes: Vec<u8>,
) -> Result<GuiElectionStatusImportResultV1, CommandError> {
    // Trust-root resolution step 1: the configured voter transport bundle's
    // pinned anchor, read under a BRIEF managed-Tor lock while NO other lock
    // is held.
    let configured_anchor: Option<AnchorMaterial> =
        configured_transport_root_anchor(state)?.map(AnchorMaterial::from);

    // Single locked section: resolve bindings, verify, apply, persist.
    let mut session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_mut().map(|active| &mut active.session) else {
        return Err(CommandError::no_session());
    };

    let manifest_hex = session.artifacts().summary().manifest_hash_hex.clone();

    // Previously accepted record for THIS election (offline restart path and
    // monotonic knowledge source).
    let persisted = load_persisted_election_status_v1(
        status_dir,
        &manifest_hex,
        session.artifacts().manifest().election_id().as_bytes(),
        session.artifacts().manifest_hash(),
        session.artifacts().registry_commitment(),
    )?;

    // Trust-root resolution step 2 (precedence unchanged): the configured
    // anchor first; otherwise the previously persisted acceptance anchor. With
    // neither, fail closed with the same bounded error as before.
    let (anchor, roots) = match configured_anchor {
        Some(material) => {
            let roots = single_root_set(&material);
            (material, roots)
        }
        None => {
            let Some(record) = persisted.as_ref() else {
                return Err(CommandError::new(
                    "GUI_ELECTION_STATUS_NO_TRUSTED_AUTHORITY",
                    "UNAVAILABLE",
                    "configure the ballot-office transport bundle first; election status must be authenticated by its pinned authority",
                ));
            };
            let material = AnchorMaterial {
                root_key_id: record.root_key_id.clone(),
                root_public_key: record.root_public_key,
            };
            let roots = single_root_set(&material);
            (material, roots)
        }
    };

    // Reconstruct monotonic knowledge from the previously accepted record.
    let mut knowledge = persisted
        .as_ref()
        .map(|record| {
            ElectionStatusKnowledgeV1::from_accepted(
                record.statement.state(),
                record.statement.generation(),
            )
        })
        .unwrap_or_default();

    let applied = verify_and_apply_election_status_statement_v1(
        &statement_bytes,
        &roots,
        &mut knowledge,
        session,
    )
    .map_err(CommandError::from)?;

    // Persist the newly accepted statement (with the anchor that verified it)
    // so restarts keep the knowledge without any network or bundle.
    let accepted = AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&statement_bytes)
        .map_err(CommandError::from)?;
    persist_election_status_record_v1(
        status_dir,
        &manifest_hex,
        &PersistedElectionStatusRecordV1 {
            root_key_id: anchor.root_key_id,
            root_public_key: anchor.root_public_key,
            statement: accepted,
        },
    )?;

    let summary = session.summary();
    Ok(GuiElectionStatusImportResultV1 {
        applied: AppliedElectionStatusResultV1::from_applied(&applied),
        election_summary: summary,
    })
}

/// The trust anchor material used to authenticate one status statement.
struct AnchorMaterial {
    root_key_id: String,
    root_public_key: [u8; 32],
}

impl From<(String, [u8; 32])> for AnchorMaterial {
    fn from(value: (String, [u8; 32])) -> Self {
        Self {
            root_key_id: value.0,
            root_public_key: value.1,
        }
    }
}

fn single_root_set(anchor: &AnchorMaterial) -> TransportAuthorityRootSetV1 {
    TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
        key_id: anchor.root_key_id.clone(),
        public_key: anchor.root_public_key,
    })
}

fn read_bounded_status_file(path: &Path) -> Result<Vec<u8>, CommandError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        CommandError::new(
            "GUI_ELECTION_STATUS_FILE_NOT_FOUND",
            "FILE_IO",
            "the election status file was not found",
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_ELECTION_STATUS_STATEMENT_BYTES as u64 {
        return Err(status_unsafe_file());
    }
    fs::read(path).map_err(|_| status_io_error())
}

fn status_unsafe_file() -> CommandError {
    CommandError::new(
        "GUI_ELECTION_STATUS_UNSAFE_FILE",
        "INVALID_INPUT",
        "the election status file is not a bounded regular file",
    )
}

// -------------------------------------------------------------------------
// Online retrieval (managed Tor)
// -------------------------------------------------------------------------

/// Fetches the ballot office's authenticated election-status statement through
/// the RUNNING managed Tor connection and applies it with the exact same
/// verify/monotonic/persist path as the offline import.
///
/// The request carries only public data — no credential, selection, proof,
/// nullifier, or package bytes — so discovering lifecycle state never links a
/// voter to a ballot. The route derives from the verified descriptor's onion
/// endpoints; there is no clearnet fallback.
#[tauri::command]
pub async fn fetch_election_status_private(
    app: AppHandle,
) -> Result<GuiElectionStatusImportResultV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        fetch_election_status_blocking(&app, state.inner())
    })
    .await
}

fn fetch_election_status_blocking(
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiElectionStatusImportResultV1, CommandError> {
    use tari_cc_private_ballot_transport_network::{
        TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1, fetch_election_status_over_tor,
    };

    // Requires a CONFIGURED connection for this election. A running Tor child
    // is not required up-front: the carrier fails bounded-and-truthfully when
    // the route is unreachable, which the UI surfaces as "cannot reach".
    let configured = crate::managed_tor_test::running_transport_endpoint(state)?;
    let Some((socks_addr, descriptor)) = configured else {
        return Err(CommandError::new(
            "GUI_ELECTION_STATUS_NO_PRIVATE_CONNECTION",
            "UNAVAILABLE",
            "configure the ballot-office private connection first, then check the signed election status",
        ));
    };
    let carrier = TorSocksPrivateReleaseCarrierV1::new(socks_addr, TorCarrierTimeoutsV1::default())
        .map_err(|_| status_unavailable())?;
    let statement_bytes =
        fetch_election_status_over_tor(carrier.socks_addr(), &descriptor, &TorCarrierTimeoutsV1::default())
            .map_err(|_| status_unavailable())?;
    if statement_bytes.len() > MAX_ELECTION_STATUS_STATEMENT_BYTES {
        return Err(status_unsafe_file());
    }
    apply_election_status_bytes_blocking(statement_bytes, app, state)
}

fn status_unavailable() -> CommandError {
    CommandError::new(
        "GUI_ELECTION_STATUS_UNREACHABLE",
        "UNAVAILABLE",
        "the signed election status could not be retrieved over the private connection; import the file offline instead or retry later",
    )
}
