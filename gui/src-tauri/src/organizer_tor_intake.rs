//! Organizer near-one-click private ballot intake (feature-gated).
//!
//! Compiled only under the `managed-tor-test` feature. This is the in-process
//! GUI equivalent of the controlled-test `private-ballot-tor-test-provision`
//! and `private-ballot-tor-test-intake` binaries: it runs the SAME reviewed
//! library orchestration on a Tauri-managed background worker so a ballot-office
//! operator never needs PowerShell, cargo, a torrc, a SOCKS/collector port, a
//! hidden-service key directory, a descriptor fingerprint, an onion hostname, or
//! an app-data-root lookup.
//!
//! It duplicates NO Tor descriptor construction, cryptographic validation,
//! ballot validation, receipt logic, or nullifier enforcement: every one of
//! those is a call into the already-reviewed transport-gateway / transport-
//! network / gui-core functions. It never spawns PowerShell, never invokes
//! cargo, and never constructs a shell command string (Tor is launched by the
//! reviewed `SystemManagedTorSpawnerV1`, an argument-vector spawn).
//!
//! Authoritative-writer boundary (unchanged): the in-process intake worker keeps
//! its OWN `GuiElectionSessionV1` (exactly like the binary) and hands accepted
//! canonical ballot-package bytes to the app-owned, election-scoped durable
//! inbox. The organizer GUI session remains the ONLY authoritative election
//! writer; it ingests the inbox through `sync_private_intake`.
//!
//! Fail-closed startup ordering (identical to the vetted binary): the collector
//! listener is bound but NOT serviced until the runtime onion hostname equals
//! the signed descriptor onion; the service loop worker is only started after
//! that equality; READY is reported only after the worker is confirmed alive.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tari_cc_private_ballot_gui_core::{
    AuthoritativeLifecycleFenceV1, ElectionLifecycleStateV1, GuiElectionArtifactsV1,
    GuiElectionSessionV1, TransportDescriptorV1, ensure_private_intake_inbox_directory_v1,
    ensure_voter_election_status_directory_v1, read_issued_status_generation_v1,
};
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, LoadedOrganizerPrivateBundleV1, OpaqueEnvelopeCollectorV1,
    OrganizerCollectorServiceLoopV1, TestElectionBindingV1, ThreadSafeCollectorHandlerV1,
    TransportGatewaySimulatorV1, generate_test_authority_material_v1,
    load_organizer_private_bundle_v1, provision_organizer_test_bundles_v1,
    validate_intake_startup_v1,
};
use tari_cc_private_ballot_transport_network::{
    DiscoveryTimeoutV1, ManagedTorSpawnerV1, OrganizerHiddenServiceTorConfigV1,
    discover_organizer_onion_hostname_v1,
};
use tauri::{AppHandle, Manager};

use crate::managed_tor_test::{
    DiagnosticTorSpawnerV1, classify_start_failure_from_log, fresh_run_directory,
    remove_stale_run_directories,
};
use crate::tor_support::{is_windows_reparse_point, resolve_tor_executable, validate_tor_exe};
use crate::{AppState, CommandError};

/// Backend-controlled directory name for app-owned organizer transport state.
const ORGANIZER_TOR_ROOT_DIRECTORY_NAME: &str = "private-tor";
/// Length in characters of a canonical lowercase Blake3 manifest-hash hex.
const MANIFEST_HASH_HEX_LEN: usize = 64;
/// Fixed loopback collector port used only while discovering the persistent
/// hidden-service hostname during first-time provisioning. No live collector is
/// serviced during that phase; the real intake collector uses an ephemeral port.
const PROVISION_COLLECTOR_PORT: u16 = 18080;
/// Bounded Tor startup / hostname-discovery timeout.
const TOR_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
/// Collector worker accept poll interval (bounds shutdown latency).
const COLLECTOR_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Bounded collector shutdown join budget.
const COLLECTOR_STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// The running organizer intake runtime state. Present only while intake is
/// active; dropped/cleared on stop. The worker's session is intentionally NOT
/// the authoritative GUI session.
pub(crate) struct OrganizerIntakeState {
    tor_child: Child,
    service_loop: OrganizerCollectorServiceLoopV1,
    descriptor: TransportDescriptorV1,
    /// The election (manifest hash) this running intake is bound to.
    manifest_hash_hex: String,
    collector_addr: SocketAddr,
    onion_hostname: String,
    /// The FRESH per-run Tor DataDirectory this start allocated (never the
    /// persistent hidden-service directory). Diagnostics only.
    tor_data_dir: PathBuf,
    /// The per-run captured Tor stderr log, used to classify a later early exit
    /// into a bounded, path-free failure reason.
    stderr_log: PathBuf,
    voter_bundle_path: PathBuf,
    durable_inbox_dir: PathBuf,
    /// AUTHORITATIVE lifecycle fence: the GUI publishes every committed
    /// transition here so admission and status answers reflect organizer truth,
    /// never the worker session's own substrate state.
    lifecycle_fence: AuthoritativeLifecycleFenceV1,
}

impl OrganizerIntakeState {
    /// True when this running intake belongs to the supplied election.
    #[must_use]
    pub(crate) fn is_bound_to_manifest(&self, manifest_hash_hex: &str) -> bool {
        self.manifest_hash_hex == manifest_hash_hex
    }

    /// Publishes one committed authoritative lifecycle transition into the
    /// collector's admission/status path.
    pub(crate) fn publish_lifecycle_transition(
        &self,
        state: ElectionLifecycleStateV1,
        reserved_generation: Option<u64>,
    ) {
        self.lifecycle_fence.observe(state, reserved_generation);
    }
}

/// Serializable organizer intake status (organizer-safe aggregates only). No
/// private key material is ever included; onion/fingerprint/ports/paths are
/// diagnostics the frontend surfaces only under an Advanced disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OrganizerIntakeStatusV1 {
    /// A Tor executable can be resolved (allowlist or the supplied path).
    pub tor_found: bool,
    /// The current election already has an app-owned transport (descriptor +
    /// organizer-private bundle) provisioned.
    pub transport_provisioned: bool,
    /// An intake worker is currently running (for any election).
    pub intake_running: bool,
    /// The running intake worker is bound to the CURRENTLY loaded election.
    pub election_bound: bool,
    /// The running intake is fully ready (runtime onion verified, worker alive).
    pub ready: bool,
    /// A start attempt is recorded but a REQUIRED owned component (the Tor child
    /// or the collector worker) has since died. This is a terminal, recoverable
    /// failure — never an indefinite "starting" limbo. Restart clears it.
    pub failed: bool,
    /// Bounded, path-free, secret-free reason for [`Self::failed`] (e.g.
    /// `organizer-tor-datadir-lock`, `organizer-tor-exited-early`,
    /// `organizer-worker-exited`). `None` unless `failed` is true.
    pub failure_reason: Option<String>,
    /// Ballots this intake run has uniquely accepted (worker-side aggregate).
    pub accepted_ballots: u64,
    // ---- Advanced / diagnostics (never secret) ----
    pub onion_hostname: Option<String>,
    pub descriptor_fingerprint: Option<String>,
    pub collector_addr: Option<String>,
    pub tor_data_dir: Option<String>,
    pub voter_bundle_path: Option<String>,
    pub durable_inbox_dir: Option<String>,
    pub message: &'static str,
}

/// Result of exporting the voter-safe transport bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VoterBundleExportResultV1 {
    pub written_path: String,
}

// -------------------------------------------------------------------------
// App-owned, election-scoped storage (derived from the manifest hash only).
// -------------------------------------------------------------------------

/// Pure derivation of the app-owned election transport root under a given
/// app-data root: `<app-data>/private-tor/election-<manifest-hash>`. The hash is
/// the ONLY path input and is validated to be a canonical 64-char lowercase hex
/// digest, so no remote/arbitrary value can influence the path (defense in depth
/// even though the hash originates from the loaded manifest, never the network).
fn election_transport_subpath(
    app_data_root: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    if manifest_hash_hex.len() != MANIFEST_HASH_HEX_LEN
        || !manifest_hash_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommandError::new(
            "GUI_ORGANIZER_TOR_INVALID_ELECTION",
            "INVALID_INPUT",
            "the election manifest hash is not a canonical lowercase hex digest",
        ));
    }
    Ok(app_data_root
        .join(ORGANIZER_TOR_ROOT_DIRECTORY_NAME)
        .join(format!("election-{manifest_hash_hex}")))
}

/// Validates a manifest-hash hex and returns the app-owned election transport
/// root. Resolves the app-data root from the Tauri handle (app-owned, never a
/// remote value).
pub(crate) fn election_transport_root(
    app: &AppHandle,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    election_transport_subpath(&app_data_root, manifest_hash_hex)
}

/// The app-owned organizer-private bundle directory for one election (holds
/// the root signing secret used to sign descriptors, receipts, and
/// election-status statements).
pub(crate) fn organizer_private_bundle_dir(
    app: &AppHandle,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    Ok(election_transport_root(app, manifest_hash_hex)?.join("organizer-private"))
}

/// Ensures `dir` is an app-owned real directory (no symlink/reparse redirect).
fn ensure_app_owned_directory(dir: &Path) -> Result<(), CommandError> {
    std::fs::create_dir_all(dir).map_err(|_| CommandError::app_data_unavailable())?;
    let metadata =
        std::fs::symlink_metadata(dir).map_err(|_| CommandError::app_data_unavailable())?;
    if !metadata.is_dir() || is_windows_reparse_point(&metadata) {
        return Err(CommandError::new(
            "GUI_ORGANIZER_TOR_UNSAFE_PATH",
            "INVALID_INPUT",
            "refusing to use an organizer transport directory that is not an app-owned directory",
        ));
    }
    Ok(())
}

/// The fixed sub-paths inside one election transport root.
///
/// Two of these are PERSISTENT and election-scoped — they carry the onion
/// identity and the organizer-private material and MUST survive every restart so
/// already-distributed voter bundles stay valid: `hidden_service_dir` and
/// `organizer_private_dir`. The Tor runtime DataDirectory is deliberately NOT a
/// fixed persistent path: every start allocates a FRESH run directory under
/// `tor_runs_base` (see [`start_intake_worker`]). This mirrors the voter-side
/// hard-kill defence — an orphaned `tor.exe` that survives a Task-Manager kill of
/// the app keeps the lock of the run directory it was using, so a brand-new run
/// directory is immune to that stale lock while the SAME `hidden_service_dir`
/// keeps the onion address and descriptor fingerprint stable across restarts.
struct TransportPaths {
    organizer_private_dir: PathBuf,
    hidden_service_dir: PathBuf,
    /// Parent directory that holds the per-start `run-*` Tor DataDirectories.
    tor_runs_base: PathBuf,
    voter_bundle_path: PathBuf,
}

impl TransportPaths {
    fn under(root: &Path) -> Self {
        Self {
            organizer_private_dir: root.join("organizer-private"),
            hidden_service_dir: root.join("organizer-hidden-service"),
            tor_runs_base: root.join("organizer-tor-runs"),
            voter_bundle_path: root.join("voter-public-bundle.cbor"),
        }
    }

    /// True when an organizer-private bundle has already been provisioned.
    fn is_provisioned(&self) -> bool {
        load_organizer_private_bundle_v1(&self.organizer_private_dir).is_ok()
    }
}

// -------------------------------------------------------------------------
// Session snapshot (never held across the long Tor bootstrap).
// -------------------------------------------------------------------------

pub(crate) struct BoundElection {
    pub(crate) artifacts: GuiElectionArtifactsV1,
    pub(crate) manifest_hash_hex: String,
    pub(crate) election_id: Vec<u8>,
    pub(crate) manifest_hash: [u8; 32],
}

pub(crate) fn bound_election(state: &AppState) -> Result<BoundElection, CommandError> {
    let guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let artifacts = session.artifacts().clone();
    let manifest_hash_hex = artifacts.summary().manifest_hash_hex.clone();
    let election_id = artifacts.manifest().election_id().as_bytes().to_vec();
    let manifest_hash = *artifacts.manifest_hash().as_bytes();
    Ok(BoundElection {
        artifacts,
        manifest_hash_hex,
        election_id,
        manifest_hash,
    })
}

// -------------------------------------------------------------------------
// Tauri commands
// -------------------------------------------------------------------------

/// Read-only organizer intake status for the currently loaded election. Never
/// starts Tor, provisions, or mutates any election/transport state.
#[tauri::command]
pub async fn organizer_tor_status(
    tor_exe_path: Option<String>,
    app: AppHandle,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        organizer_tor_status_blocking(tor_exe_path, &app, state.inner())
    })
    .await
}

/// Blocking body of [`organizer_tor_status`], run on the blocking thread pool.
fn organizer_tor_status_blocking(
    tor_exe_path: Option<String>,
    app: &AppHandle,
    state: &AppState,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    let tor_found = resolve_tor_executable(tor_exe_path.as_deref()).is_ok();

    // Current election (if any) drives provisioned/bound reporting.
    let bound = bound_election(state).ok();
    let transport_provisioned = match &bound {
        Some(b) => match election_transport_root(app, &b.manifest_hash_hex) {
            Ok(root) => TransportPaths::under(&root).is_provisioned(),
            Err(_) => false,
        },
        None => false,
    };

    let mut managed = state
        .organizer_intake
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let running = managed.as_mut();
    let (intake_running, election_bound, ready, failed, failure_reason, accepted, diag) =
        match running {
            Some(m) => {
                let same_election = bound
                    .as_ref()
                    .is_some_and(|b| b.manifest_hash_hex == m.manifest_hash_hex);
                let child_alive = m
                    .tor_child
                    .try_wait()
                    .map(|status| status.is_none())
                    .unwrap_or(false);
                let worker_alive = m.service_loop.worker_is_alive();
                let ready = same_election && child_alive && worker_alive;
                // A recorded intake whose owned Tor child or collector worker has
                // died is a bounded FAILED state — never an indefinite "starting".
                let failure_reason = intake_failure_reason(m, child_alive, worker_alive);
                let failed = failure_reason.is_some();
                let accepted = m.service_loop.accepted_unique_count();
                let diag = Some((
                    m.onion_hostname.clone(),
                    descriptor_fingerprint_hex(&m.descriptor),
                    m.collector_addr.to_string(),
                    m.tor_data_dir.to_string_lossy().into_owned(),
                    m.voter_bundle_path.to_string_lossy().into_owned(),
                    m.durable_inbox_dir.to_string_lossy().into_owned(),
                ));
                (true, same_election, ready, failed, failure_reason, accepted, diag)
            }
            None => (false, false, false, false, None, 0, None),
        };

    let message = status_message(
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        failed,
    );
    Ok(build_status(
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted,
        diag,
        message,
    ))
}

/// Classifies why a recorded intake is unhealthy, or `None` when both the owned
/// Tor child and the collector worker are alive. A dead Tor child is classified
/// from its captured per-run stderr log (bounded, path-free); a dead worker with
/// a live child is reported as `organizer-worker-exited`.
fn intake_failure_reason(
    m: &OrganizerIntakeState,
    child_alive: bool,
    worker_alive: bool,
) -> Option<String> {
    if child_alive && worker_alive {
        return None;
    }
    if !child_alive {
        let kind = classify_start_failure_from_log(&m.stderr_log);
        return Some(kind.as_organizer_context_label().to_owned());
    }
    // Child alive but the collector worker thread has exited.
    Some("organizer-worker-exited".to_owned())
}

/// Starts (or reuses) private ballot intake for the currently loaded election.
///
/// Provisions app-owned transport on first use, then runs the exact vetted
/// intake orchestration in-process. Fail-closed at every step. Does NOT open
/// voting or mutate the election lifecycle.
#[tauri::command]
pub async fn start_private_intake(
    tor_exe_path: Option<String>,
    app: AppHandle,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        start_private_intake_blocking(tor_exe_path, &app, state.inner())
    })
    .await
}

/// Blocking body of [`start_private_intake`]: the multi-second Tor hidden-service
/// bootstrap and hostname discovery run on the blocking thread pool so the main
/// UI thread keeps pumping while intake comes up.
fn start_private_intake_blocking(
    tor_exe_path: Option<String>,
    app: &AppHandle,
    state: &AppState,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    let tor_executable = resolve_tor_executable(tor_exe_path.as_deref())?;
    validate_tor_exe(&tor_executable)?;

    let bound = bound_election(state)?;

    // If an intake is already recorded, resolve it into exactly one of:
    //   * healthy + THIS election      → return its status (idempotent);
    //   * healthy + a DIFFERENT election → require an explicit stop;
    //   * unhealthy (owned Tor child or worker died, e.g. after a hard-kill
    //     restart) → REAP it and fall through to a single fresh start, so one
    //     Start click recovers a failed intake without ever stacking a second
    //     controller/child for the same app+election.
    let dead_intake = {
        let mut managed = state
            .organizer_intake
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(m) = managed.as_mut() {
            let child_alive = m
                .tor_child
                .try_wait()
                .map(|status| status.is_none())
                .unwrap_or(false);
            let healthy = child_alive && m.service_loop.worker_is_alive();
            if healthy {
                if m.manifest_hash_hex == bound.manifest_hash_hex {
                    return Ok(running_status(m, true, child_alive));
                }
                return Err(CommandError::new(
                    "GUI_ORGANIZER_INTAKE_OTHER_ELECTION",
                    "INVALID_LIFECYCLE_TRANSITION",
                    "stop the running private intake before starting it for a different election",
                ));
            }
            // Unhealthy: take ownership out of the slot so the fresh start below
            // installs the ONLY current controller. Reap outside the lock.
            managed.take()
        } else {
            None
        }
    };
    if let Some(mut dead) = dead_intake {
        let _ = dead.service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        let _ = dead.tor_child.kill();
        let _ = dead.tor_child.wait();
    }

    // Build app-owned, election-scoped storage.
    let root = election_transport_root(app, &bound.manifest_hash_hex)?;
    ensure_app_owned_directory(&root)?;
    let paths = TransportPaths::under(&root);
    ensure_app_owned_directory(&paths.organizer_private_dir)?;

    // Provision transport on first use (writes descriptor + bundles; persistent
    // hidden-service identity is created once and reused on later starts).
    if !paths.is_provisioned() {
        provision_transport(&tor_executable, &paths, &bound)?;
    }

    // Run the vetted intake orchestration; on success this returns the running
    // state to store. The AUTHORITATIVE lifecycle at start seeds the admission
    // fence so a FROZEN election never accepts ballots even if intake starts
    // before voting opens.
    let authoritative_lifecycle = {
        let guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        guard
            .as_ref()
            .map(GuiElectionSessionV1::lifecycle_state_v1)
            .unwrap_or(ElectionLifecycleStateV1::Frozen)
    };
    let running = start_intake_worker(app, &tor_executable, &paths, &bound, authoritative_lifecycle)?;
    // The worker was just confirmed alive (child liveness re-checked after
    // discovery, worker liveness checked in step 9), so report it as running.
    let status = running_status(&running, true, true);
    let mut managed = state
        .organizer_intake
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *managed = Some(running);
    Ok(status)
}

/// Stops private ballot intake cleanly: bounded service-loop shutdown, reap the
/// owned Tor child, release the loopback collector. Preserves the hidden-service
/// identity and every accepted package; never mutates the election lifecycle.
#[tauri::command]
pub async fn stop_private_intake(
    app: AppHandle,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        stop_private_intake_blocking(&app, state.inner())
    })
    .await
}

/// Blocking body of [`stop_private_intake`], run on the blocking thread pool
/// (the bounded worker join + child reap can take up to a few seconds).
fn stop_private_intake_blocking(
    app: &AppHandle,
    state: &AppState,
) -> Result<OrganizerIntakeStatusV1, CommandError> {
    let taken = {
        let mut managed = state
            .organizer_intake
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        managed.take()
    };
    if let Some(mut m) = taken {
        // Stop the collector worker first (no new requests serviced), then reap
        // the owned Tor child. The hidden-service key material in
        // hidden_service_dir is preserved for a later restart.
        let _ = m.service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        let _ = m.tor_child.kill();
        let _ = m.tor_child.wait();
    }
    // Recompute a fresh read-only status (no running worker now).
    organizer_tor_status_blocking(None, app, state)
}

/// Reaps a running organizer intake worker (collector service loop + owned Tor
/// child) on application teardown, preserving the persistent hidden-service
/// identity and every accepted package. Idempotent and best-effort.
pub(crate) fn shutdown_intake_on_exit(state: &AppState) {
    let taken = {
        match state.organizer_intake.lock() {
            Ok(mut managed) => managed.take(),
            Err(_) => None,
        }
    };
    if let Some(mut m) = taken {
        let _ = m.service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        let _ = m.tor_child.kill();
        let _ = m.tor_child.wait();
    }
}

/// Exports ONLY the voter-safe public transport bundle for the loaded election
/// to a chosen directory (no-overwrite). Never exports organizer-private key
/// material.
#[tauri::command]
pub fn export_voter_transport_bundle(
    destination_dir: String,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VoterBundleExportResultV1, CommandError> {
    let destination = PathBuf::from(&destination_dir);
    if !destination.is_absolute() {
        return Err(CommandError::new(
            "GUI_EXPORT_DIR_NOT_ABSOLUTE",
            "INVALID_INPUT",
            "the export destination directory must be absolute",
        ));
    }
    let dest_meta = std::fs::symlink_metadata(&destination).map_err(|_| {
        CommandError::new(
            "GUI_EXPORT_DIR_NOT_FOUND",
            "FILE_IO",
            "the export destination directory was not found",
        )
    })?;
    if !dest_meta.is_dir() || is_windows_reparse_point(&dest_meta) {
        return Err(CommandError::new(
            "GUI_EXPORT_DIR_UNSAFE",
            "INVALID_INPUT",
            "the export destination must be a real directory (no symlinks/reparse points)",
        ));
    }

    let bound = bound_election(&state)?;
    let root = election_transport_root(&app, &bound.manifest_hash_hex)?;
    let paths = TransportPaths::under(&root);
    // The source is the voter PUBLIC bundle only; organizer-private material is
    // never read here.
    let source = &paths.voter_bundle_path;
    let source_meta = std::fs::symlink_metadata(source).map_err(|_| {
        CommandError::new(
            "GUI_VOTER_BUNDLE_MISSING",
            "FILE_IO",
            "no voter transport bundle exists yet; start private intake first to provision it",
        )
    })?;
    if !source_meta.is_file() || is_windows_reparse_point(&source_meta) {
        return Err(CommandError::new(
            "GUI_VOTER_BUNDLE_UNSAFE",
            "INVALID_INPUT",
            "the voter transport bundle is not an app-owned regular file",
        ));
    }

    let target = destination.join("voter-public-bundle.cbor");
    // No-overwrite: refuse if a file already exists at the target.
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(CommandError::new(
            "GUI_EXPORT_TARGET_EXISTS",
            "INVALID_INPUT",
            "a voter-public-bundle.cbor already exists in that folder; choose another folder",
        ));
    }
    let bytes = std::fs::read(source).map_err(|_| CommandError::package_read_failed())?;
    std::fs::write(&target, &bytes).map_err(|_| {
        CommandError::new(
            "GUI_EXPORT_WRITE_FAILED",
            "FILE_IO",
            "the voter transport bundle could not be written to that folder",
        )
    })?;
    Ok(VoterBundleExportResultV1 {
        written_path: target.to_string_lossy().into_owned(),
    })
}

// -------------------------------------------------------------------------
// Orchestration (reuses the vetted library functions; no protocol logic here).
// -------------------------------------------------------------------------

/// First-time transport provisioning: start Tor to discover the persistent
/// hidden-service hostname, stop Tor, then sign the descriptor and write both
/// bundles. Mirrors `private-ballot-tor-test-provision` step-for-step, calling
/// only reviewed library functions.
fn provision_transport(
    tor_executable: &Path,
    paths: &TransportPaths,
    bound: &BoundElection,
) -> Result<(), CommandError> {
    let binding = TestElectionBindingV1 {
        election_id: bound.election_id.clone(),
        manifest_hash: bound.manifest_hash,
    };
    // A FRESH throwaway DataDirectory for the one-shot hostname-discovery run, so
    // even first-time provisioning can never collide with an orphaned tor.exe
    // that still holds a prior run directory's lock. The onion identity is
    // written to the PERSISTENT hidden-service directory, not this run directory.
    ensure_app_owned_directory(&paths.tor_runs_base)?;
    let run_dir = fresh_run_directory(&paths.tor_runs_base)?;
    remove_stale_run_directories(&paths.tor_runs_base, &run_dir);
    let provision_torrc = run_dir.join("organizer-provision-torrc");
    let stderr_log = run_dir.join("tor-stderr.log");
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: run_dir.clone(),
        config_file: provision_torrc.clone(),
        hidden_service_dir: paths.hidden_service_dir.clone(),
        collector_port: PROVISION_COLLECTOR_PORT,
        startup_timeout: TOR_STARTUP_TIMEOUT,
    };
    tor_config.write_config().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_TORRC_FAILED",
            "FILE_IO",
            "the organizer Tor configuration could not be written",
        )
    })?;

    let spawner = DiagnosticTorSpawnerV1 {
        stderr_log: stderr_log.clone(),
    };
    let mut child = spawner
        .spawn(tor_executable, &provision_torrc)
        .map_err(|_| tor_start_failed())?;
    let timeout = DiscoveryTimeoutV1::new(TOR_STARTUP_TIMEOUT);
    let hostname = {
        let child_alive = || {
            child
                .try_wait()
                .map(|status| status.is_none())
                .unwrap_or(false)
        };
        match discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive) {
            Ok(host) => host,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let kind = classify_start_failure_from_log(&stderr_log);
                return Err(hostname_discovery_failed()
                    .with_context(kind.as_organizer_context_label().to_owned()));
            }
        }
    };
    // Stop Tor: the hostname/identity persists in the hidden-service directory.
    let _ = child.kill();
    let _ = child.wait();

    let material = generate_test_authority_material_v1("test-root".to_owned()).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_MATERIAL_FAILED",
            "INVALID_INPUT",
            "the organizer transport authority material could not be generated",
        )
    })?;
    provision_organizer_test_bundles_v1(
        &paths.organizer_private_dir,
        &paths.voter_bundle_path,
        &material,
        &binding,
        hostname,
        // Recorded as inert bundle metadata only (never validated or reused at
        // runtime); the real DataDirectory is a fresh per-start run directory.
        &paths.tor_runs_base,
        &paths.hidden_service_dir,
    )
    .map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_PROVISION_FAILED",
            "INVALID_INPUT",
            "the organizer transport bundles could not be provisioned",
        )
    })?;
    Ok(())
}

/// Starts the intake worker for an already-provisioned election. Mirrors
/// `private-ballot-tor-test-intake` step-for-step with the SAME fail-closed
/// ordering, calling only reviewed library functions.
fn start_intake_worker(
    app: &AppHandle,
    tor_executable: &Path,
    paths: &TransportPaths,
    bound: &BoundElection,
    authoritative_lifecycle: ElectionLifecycleStateV1,
) -> Result<OrganizerIntakeState, CommandError> {
    // 1. Load organizer private bundle and validate ALL bindings before Tor.
    let bundle = load_organizer_private_bundle_v1(&paths.organizer_private_dir).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_BUNDLE_MALFORMED",
            "INVALID_INPUT",
            "the organizer transport bundle could not be loaded",
        )
    })?;
    let persisted_hostname = read_persisted_hostname(&paths.hidden_service_dir);
    validate_intake_startup_v1(&bundle, &bound.artifacts, persisted_hostname.as_deref()).map_err(
        |_| {
            CommandError::new(
                "GUI_ORGANIZER_STARTUP_UNTRUSTED",
                "BINDING_MISMATCH",
                "the organizer transport bundle failed startup validation for this election",
            )
        },
    )?;

    // 2. App-owned, election-scoped durable hand-off inbox (manifest-hash path).
    let durable_inbox_dir =
        ensure_private_intake_inbox_directory_v1(&app_data_root(app)?, &bound.manifest_hash_hex)
            .map_err(CommandError::from)?;

    // 3. Fresh intake worker session (NOT the authoritative GUI session).
    let mut session = GuiElectionSessionV1::new(bound.artifacts.clone())
        .map_err(CommandError::from)?;
    session.open().map_err(CommandError::from)?;

    // 4. Bind the loopback collector (bound but not yet serviced).
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_COLLECTOR_BIND_FAILED",
            "UNAVAILABLE",
            "the loopback collector could not be bound",
        )
    })?;
    let collector_addr = collector.local_addr().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_COLLECTOR_ADDR_FAILED",
            "UNAVAILABLE",
            "the loopback collector address could not be read",
        )
    })?;

    // 5. Allocate a FRESH per-start Tor DataDirectory (never the persistent
    // hidden-service directory), so an orphaned tor.exe surviving a Task-Manager
    // hard-kill of a prior app instance — which still holds the lock of the run
    // directory it was using — can never block this start. The SAME persistent
    // `hidden_service_dir` keeps the onion address/fingerprint stable across
    // restarts. Then write the intake torrc (inside the run directory) with the
    // ACTUAL collector port and launch Tor with a per-run captured stderr log.
    ensure_app_owned_directory(&paths.tor_runs_base)?;
    let run_dir = fresh_run_directory(&paths.tor_runs_base)?;
    remove_stale_run_directories(&paths.tor_runs_base, &run_dir);
    let intake_torrc = run_dir.join("organizer-intake-torrc");
    let stderr_log = run_dir.join("tor-stderr.log");
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: run_dir.clone(),
        config_file: intake_torrc.clone(),
        hidden_service_dir: paths.hidden_service_dir.clone(),
        collector_port: collector_addr.port(),
        startup_timeout: TOR_STARTUP_TIMEOUT,
    };
    tor_config.write_config().map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_TORRC_FAILED",
            "FILE_IO",
            "the organizer intake Tor configuration could not be written",
        )
    })?;
    let spawner = DiagnosticTorSpawnerV1 {
        stderr_log: stderr_log.clone(),
    };
    let mut child = spawner
        .spawn(tor_executable, &intake_torrc)
        .map_err(|_| tor_start_failed())?;

    // 6. Discover the runtime hostname (bounded), watching child liveness. The
    // liveness closure mutably borrows `child`; it is moved into the discovery
    // call, releasing the borrow before any later `child.kill()`/`wait()`. The
    // early-return branch must not touch `child` while the closure holds it.
    //
    // NOTE: the hidden-service `hostname` file is PERSISTENT — on a restart it is
    // already present from the prior run, so discovery can return immediately
    // while the freshly-spawned child is still bootstrapping. That is only safe
    // because the child now runs in its OWN fresh DataDirectory and therefore
    // stays alive; the post-discovery liveness recheck below plus the status
    // command's continuous child-liveness check catch any early exit and surface
    // a bounded FAILED state instead of an indefinite "starting".
    let timeout = DiscoveryTimeoutV1::new(TOR_STARTUP_TIMEOUT);
    let mut child_alive = || {
        child
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    };
    if !child_alive() {
        let kind = classify_start_failure_from_log(&stderr_log);
        return Err(tor_start_failed().with_context(kind.as_organizer_context_label().to_owned()));
    }
    let runtime_hostname =
        match discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive) {
            Ok(host) => host,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let kind = classify_start_failure_from_log(&stderr_log);
                return Err(hostname_discovery_failed()
                    .with_context(kind.as_organizer_context_label().to_owned()));
            }
        };

    // 6b. Post-discovery liveness recheck: discovery can succeed off the
    // PERSISTENT hostname file before the fresh child has fully settled, so
    // confirm the owned child did not exit immediately (e.g. a residual lock or
    // config fault). A dead child here is a bounded, classified start failure —
    // never a false "running".
    if child
        .try_wait()
        .map(|status| status.is_some())
        .unwrap_or(true)
    {
        let _ = child.wait();
        let kind = classify_start_failure_from_log(&stderr_log);
        return Err(tor_start_failed().with_context(kind.as_organizer_context_label().to_owned()));
    }

    // 7. Fail-closed: runtime onion MUST equal the signed descriptor onion
    // BEFORE any request can be serviced.
    let descriptor_onion = bundle
        .descriptor
        .onion_endpoints()
        .first()
        .cloned()
        .ok_or_else(|| {
            CommandError::new(
                "GUI_ORGANIZER_NO_ONION",
                "BINDING_MISMATCH",
                "the transport descriptor has no onion endpoint",
            )
        })?;
    if descriptor_onion != runtime_hostname {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CommandError::new(
            "GUI_ORGANIZER_ONION_MISMATCH",
            "BINDING_MISMATCH",
            "the runtime onion hostname does not match the signed descriptor",
        ));
    }

    // 8. Only now start the collector service loop (first point a ballot could
    // be accepted). Accepted canonical packages flow to the durable inbox.
    // The AUTHORITATIVE lifecycle fence is initialized from the organizer
    // GUI's current state and continues the durable issuance generation, so a
    // FROZEN election fences ballots immediately and status answers carry
    // signed truth (never the worker session's own substrate state).
    let gateway = Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    let session_arc = Arc::new(Mutex::new(session));
    let descriptor_arc = Arc::new(bundle.descriptor.clone());
    let receiver_key_arc = reconstruct_receiver_key(&bundle)?;
    let receipt_key_arc = Arc::new(bundle.material.receipt_signing_key.clone());
    let root_signing_key_arc = Arc::new(bundle.material.root_signing_key.clone());
    let lifecycle_fence = AuthoritativeLifecycleFenceV1::new(
        authoritative_lifecycle,
        read_issued_status_generation_v1(
            &ensure_voter_election_status_directory_v1(&app_data_root(app)?)?,
            &bound.manifest_hash_hex,
        )
        .unwrap_or(0),
    );
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway,
        descriptor_arc,
        receiver_key_arc,
        session_arc,
        receipt_key_arc,
        "organizer-receipt-key".to_owned(),
    )
    .with_accepted_package_inbox(durable_inbox_dir.clone())
    .with_lifecycle_fence(lifecycle_fence.clone())
    .with_election_status_signer(root_signing_key_arc, bundle.material.root.key_id().to_owned());
    let service_loop =
        OrganizerCollectorServiceLoopV1::start(collector, handler, COLLECTOR_POLL_INTERVAL)
            .map_err(|_| {
                CommandError::new(
                    "GUI_ORGANIZER_SERVICE_START_FAILED",
                    "UNAVAILABLE",
                    "the collector service loop could not be started",
                )
            })?;

    // 9. READY only after the worker is confirmed alive.
    if !service_loop.worker_is_alive() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = service_loop.stop(COLLECTOR_STOP_TIMEOUT);
        return Err(CommandError::new(
            "GUI_ORGANIZER_WORKER_DEAD",
            "UNAVAILABLE",
            "the collector service worker exited immediately on start",
        ));
    }

    Ok(OrganizerIntakeState {
        tor_child: child,
        service_loop,
        descriptor: bundle.descriptor.clone(),
        manifest_hash_hex: bound.manifest_hash_hex.clone(),
        collector_addr,
        onion_hostname: runtime_hostname,
        tor_data_dir: run_dir,
        stderr_log,
        voter_bundle_path: paths.voter_bundle_path.clone(),
        durable_inbox_dir,
        lifecycle_fence,
    })
}

fn reconstruct_receiver_key(
    bundle: &LoadedOrganizerPrivateBundleV1,
) -> Result<Arc<GatewayReceiverKeyV1>, CommandError> {
    let secret = bundle.material.gateway_receiver_key.secret_bytes();
    let key = GatewayReceiverKeyV1::from_secret_bytes(secret).map_err(|_| {
        CommandError::new(
            "GUI_ORGANIZER_RECEIVER_KEY_FAILED",
            "INVALID_INPUT",
            "the gateway receiver key could not be reconstructed",
        )
    })?;
    Ok(Arc::new(key))
}

fn read_persisted_hostname(hidden_service_dir: &Path) -> Option<String> {
    let hostname_file = hidden_service_dir.join("hostname");
    match std::fs::read_to_string(&hostname_file) {
        Ok(content) => {
            let trimmed = content.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        Err(_) => None,
    }
}

fn app_data_root(app: &AppHandle) -> Result<PathBuf, CommandError> {
    app.path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())
}

// -------------------------------------------------------------------------
// Status helpers
// -------------------------------------------------------------------------

/// Builds a status for a recorded running intake. `child_alive` MUST be the
/// caller's fresh `try_wait` observation of the owned Tor child, so a dead child
/// is reported as a bounded FAILED state and never a false "running".
fn running_status(
    m: &OrganizerIntakeState,
    election_bound: bool,
    child_alive: bool,
) -> OrganizerIntakeStatusV1 {
    let accepted = m.service_loop.accepted_unique_count();
    let worker_alive = m.service_loop.worker_is_alive();
    let ready = election_bound && child_alive && worker_alive;
    let failure_reason = intake_failure_reason(m, child_alive, worker_alive);
    let failed = failure_reason.is_some();
    OrganizerIntakeStatusV1 {
        tor_found: true,
        transport_provisioned: true,
        intake_running: true,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted_ballots: accepted,
        onion_hostname: Some(m.onion_hostname.clone()),
        descriptor_fingerprint: descriptor_fingerprint_hex(&m.descriptor),
        collector_addr: Some(m.collector_addr.to_string()),
        tor_data_dir: Some(m.tor_data_dir.to_string_lossy().into_owned()),
        voter_bundle_path: Some(m.voter_bundle_path.to_string_lossy().into_owned()),
        durable_inbox_dir: Some(m.durable_inbox_dir.to_string_lossy().into_owned()),
        message: if failed {
            "Private intake could not start."
        } else if ready {
            "Private intake ready."
        } else {
            "Private intake is starting."
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn build_status(
    tor_found: bool,
    transport_provisioned: bool,
    intake_running: bool,
    election_bound: bool,
    ready: bool,
    failed: bool,
    failure_reason: Option<String>,
    accepted: u64,
    diag: Option<(String, Option<String>, String, String, String, String)>,
    message: &'static str,
) -> OrganizerIntakeStatusV1 {
    let (onion, fingerprint, collector, data_dir, bundle, inbox) = match diag {
        Some((o, f, c, d, b, i)) => (Some(o), f, Some(c), Some(d), Some(b), Some(i)),
        None => (None, None, None, None, None, None),
    };
    OrganizerIntakeStatusV1 {
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        ready,
        failed,
        failure_reason,
        accepted_ballots: accepted,
        onion_hostname: onion,
        descriptor_fingerprint: fingerprint,
        collector_addr: collector,
        tor_data_dir: data_dir,
        voter_bundle_path: bundle,
        durable_inbox_dir: inbox,
        message,
    }
}

fn status_message(
    tor_found: bool,
    transport_provisioned: bool,
    intake_running: bool,
    election_bound: bool,
    failed: bool,
) -> &'static str {
    if failed {
        "Private intake could not start. Restart it to try again."
    } else if intake_running && !election_bound {
        "Private intake is running for a different election. Stop it to switch."
    } else if intake_running {
        "Private intake is running."
    } else if !tor_found {
        "Tor was not found. Select a Tor executable to enable private intake."
    } else if transport_provisioned {
        "Ready to start private intake."
    } else {
        "Ready to provision and start private intake."
    }
}

fn descriptor_fingerprint_hex(descriptor: &TransportDescriptorV1) -> Option<String> {
    descriptor.fingerprint().ok().map(|fp| {
        use std::fmt::Write;
        let mut out = String::with_capacity(fp.len() * 2);
        for byte in fp {
            let _ = write!(out, "{byte:02x}");
        }
        out
    })
}

fn tor_start_failed() -> CommandError {
    CommandError::new(
        "GUI_ORGANIZER_TOR_START_FAILED",
        "UNAVAILABLE",
        "tor.exe failed to start for the organizer hidden service",
    )
}

fn hostname_discovery_failed() -> CommandError {
    CommandError::new(
        "GUI_ORGANIZER_HOSTNAME_FAILED",
        "UNAVAILABLE",
        "the organizer hidden-service hostname could not be discovered",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_tor_test::ManagedTorStartFailureKind;

    const VALID_HASH: &str =
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    fn app_root() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            r"C:\app-data-root"
        } else {
            "/app-data-root"
        })
    }

    #[test]
    fn transport_root_is_app_owned_and_election_scoped() {
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("valid hash");
        assert!(root.starts_with(app_root()));
        assert!(
            root.ends_with(format!("election-{VALID_HASH}")),
            "root must be scoped to the election manifest hash: {}",
            root.display()
        );
        assert!(
            root.to_string_lossy().contains(ORGANIZER_TOR_ROOT_DIRECTORY_NAME),
            "root must live under the app-owned private-tor directory"
        );
    }

    #[test]
    fn different_elections_get_different_roots() {
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        let a = election_transport_subpath(&app_root(), VALID_HASH).expect("a");
        let b = election_transport_subpath(&app_root(), other).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn non_hex_manifest_hash_cannot_control_storage() {
        // Uppercase, wrong length, path traversal, and separators all rejected —
        // no remote/arbitrary value can steer the storage path.
        for bad in [
            "..",
            "../../etc",
            "election-1/../../secret",
            "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
            "short",
            "zz112233445566778899001122334455667788990011223344556677889900",
            "aabb/ccdd",
        ] {
            let error = election_transport_subpath(&app_root(), bad)
                .expect_err("non-canonical hash must reject");
            assert_eq!(error.code, "GUI_ORGANIZER_TOR_INVALID_ELECTION");
        }
    }

    #[test]
    fn transport_paths_never_place_private_material_in_the_voter_bundle() {
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("root");
        let paths = TransportPaths::under(&root);
        // The exported artifact is exactly the voter PUBLIC bundle; the private
        // material lives in a separate organizer-private directory.
        assert!(paths.voter_bundle_path.ends_with("voter-public-bundle.cbor"));
        assert!(paths.organizer_private_dir.ends_with("organizer-private"));
        assert_ne!(paths.voter_bundle_path, paths.organizer_private_dir);
        assert!(!paths.voter_bundle_path.starts_with(&paths.organizer_private_dir));
    }

    #[test]
    fn tor_runtime_datadirectory_is_split_from_the_persistent_identity() {
        // The onion identity (hidden-service directory) MUST be a fixed,
        // election-scoped, persistent path so the onion address/fingerprint are
        // stable across restarts. The Tor runtime DataDirectory MUST NOT be that
        // same fixed path: it lives under a distinct per-start run base so an
        // orphaned tor.exe holding a prior run's lock cannot block the next start
        // (mirrors the voter-side hard-kill defence).
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("root");
        let paths = TransportPaths::under(&root);
        assert!(paths.hidden_service_dir.ends_with("organizer-hidden-service"));
        assert!(paths.tor_runs_base.ends_with("organizer-tor-runs"));
        assert_ne!(paths.hidden_service_dir, paths.tor_runs_base);
        assert!(!paths.tor_runs_base.starts_with(&paths.hidden_service_dir));
        assert!(!paths.hidden_service_dir.starts_with(&paths.tor_runs_base));
    }

    #[test]
    fn organizer_failure_labels_are_bounded_prefixed_and_path_free() {
        use ManagedTorStartFailureKind::*;
        for kind in [
            DataDirectoryLock,
            PortBindFailure,
            ConfigError,
            ExitedEarly,
            ReadinessTimeout,
        ] {
            let label = kind.as_organizer_context_label();
            assert!(label.starts_with("organizer-"), "organizer-prefixed: {label}");
            assert!(!label.contains('/') && !label.contains('\\'), "path-free: {label}");
        }
        // A datadir-lock is the exact orphan-after-hard-kill signature.
        assert_eq!(
            DataDirectoryLock.as_organizer_context_label(),
            "organizer-tor-datadir-lock"
        );
    }

    #[test]
    fn status_message_guides_the_operator_through_each_state() {
        assert!(status_message(false, false, false, false, false).contains("Tor was not found"));
        assert_eq!(
            status_message(true, false, false, false, false),
            "Ready to provision and start private intake."
        );
        assert_eq!(
            status_message(true, true, false, false, false),
            "Ready to start private intake."
        );
        assert_eq!(
            status_message(true, true, true, true, false),
            "Private intake is running."
        );
        assert!(
            status_message(true, true, true, false, false).contains("different election"),
            "a running intake bound to another election must be called out"
        );
        // A failed intake must never read as "running" or "starting"; it is an
        // explicit, recoverable state — even when intake_running is still set.
        let failed = status_message(true, true, true, true, true);
        assert!(failed.contains("could not start"), "failed state is explicit: {failed}");
        assert!(!failed.contains("running"));
    }

    #[test]
    fn descriptor_root_directory_name_is_backend_controlled() {
        // The only dynamic path component is the validated hash; the parent
        // directory name is a fixed backend constant.
        assert_eq!(ORGANIZER_TOR_ROOT_DIRECTORY_NAME, "private-tor");
    }

    #[test]
    fn orphan_datadir_lock_signature_maps_to_a_bounded_organizer_reason() {
        // The exact orphan-after-hard-kill diagnostic path: a fresh child whose
        // DataDirectory lock is still held by a surviving orphan writes a
        // "could not lock ... another Tor" stderr; classification must yield the
        // bounded, path-free organizer datadir-lock reason surfaced as the
        // FAILED status reason (never an indefinite "starting").
        let base = std::env::temp_dir().join(format!(
            "tari-organizer-intake-failreason-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("temp base");
        let log = base.join("tor-stderr.log");
        std::fs::write(
            &log,
            b"[warn] Could not lock data directory. Is another Tor process running?\n",
        )
        .expect("write stderr log");
        let reason = classify_start_failure_from_log(&log).as_organizer_context_label();
        assert_eq!(reason, "organizer-tor-datadir-lock");

        // A missing/empty stderr log is a bounded readiness-timeout reason, never
        // a panic and never an unbounded string.
        let missing = base.join("no-such-run").join("tor-stderr.log");
        assert_eq!(
            classify_start_failure_from_log(&missing).as_organizer_context_label(),
            "organizer-readiness-timeout"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn organizer_cleanup_is_ownership_scoped_never_a_global_tor_kill() {
        // Ownership-scope guarantee (defence against a regression that would kill
        // an unrelated Tor Browser / user Tor / another election): this module
        // must NEVER terminate Tor by process NAME or via a shell. Cleanup is
        // limited to the app-owned run directories and the app's OWN Child
        // handles (kill()/wait()), which target only processes this app spawned.
        // Scan ONLY the implementation (everything before the test module) so
        // this test's own list of forbidden literals below cannot match itself.
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        for forbidden in [
            "taskkill",
            "Stop-Process",
            "Get-Process",
            "/IM ",
            "/im ",
            "pkill",
            "killall",
        ] {
            assert!(
                !code.contains(forbidden),
                "organizer Tor lifecycle must never use `{forbidden}` (global/name-based kill)"
            );
        }
        // The only process termination is on an owned std::process::Child handle.
        assert!(code.contains("tor_child.kill()"));
    }

    #[test]
    fn restart_never_rotates_the_onion_identity() {
        // No-onion-rotation invariant: provisioning (which generates the onion
        // identity) is gated behind `!is_provisioned()`, so a restart of an
        // already-provisioned election reuses the persistent hidden-service
        // directory and NEVER creates a new identity. The hidden-service
        // directory is also a deterministic function of the election root, so two
        // "starts" resolve the SAME identity path.
        let source = include_str!("organizer_tor_intake.rs");
        let code = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation precedes the test module");
        assert!(
            code.contains("if !paths.is_provisioned()"),
            "the onion identity must be provisioned once, never regenerated on restart"
        );
        let root = election_transport_subpath(&app_root(), VALID_HASH).expect("root");
        let a = TransportPaths::under(&root).hidden_service_dir;
        let b = TransportPaths::under(&root).hidden_service_dir;
        assert_eq!(a, b, "the hidden-service identity path is stable across starts");
    }
}
