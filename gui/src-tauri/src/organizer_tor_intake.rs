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
    GuiElectionArtifactsV1, GuiElectionSessionV1, TransportDescriptorV1,
    ensure_private_intake_inbox_directory_v1,
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
    SystemManagedTorSpawnerV1, discover_organizer_onion_hostname_v1,
};
use tauri::{AppHandle, Manager};

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
    tor_data_dir: PathBuf,
    voter_bundle_path: PathBuf,
    durable_inbox_dir: PathBuf,
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
fn election_transport_root(
    app: &AppHandle,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    election_transport_subpath(&app_data_root, manifest_hash_hex)
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
struct TransportPaths {
    organizer_private_dir: PathBuf,
    tor_data_dir: PathBuf,
    hidden_service_dir: PathBuf,
    provision_torrc: PathBuf,
    intake_torrc: PathBuf,
    voter_bundle_path: PathBuf,
}

impl TransportPaths {
    fn under(root: &Path) -> Self {
        Self {
            organizer_private_dir: root.join("organizer-private"),
            tor_data_dir: root.join("organizer-tor-data"),
            hidden_service_dir: root.join("organizer-hidden-service"),
            provision_torrc: root.join("organizer-provision-torrc"),
            intake_torrc: root.join("organizer-intake-torrc"),
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

struct BoundElection {
    artifacts: GuiElectionArtifactsV1,
    manifest_hash_hex: String,
    election_id: Vec<u8>,
    manifest_hash: [u8; 32],
}

fn bound_election(state: &AppState) -> Result<BoundElection, CommandError> {
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
    let (intake_running, election_bound, ready, accepted, diag) = match running {
        Some(m) => {
            let same_election = bound
                .as_ref()
                .is_some_and(|b| b.manifest_hash_hex == m.manifest_hash_hex);
            let child_alive = m
                .tor_child
                .try_wait()
                .map(|status| status.is_none())
                .unwrap_or(false);
            let ready = same_election && child_alive && m.service_loop.worker_is_alive();
            let accepted = m.service_loop.accepted_unique_count();
            let diag = Some((
                m.onion_hostname.clone(),
                descriptor_fingerprint_hex(&m.descriptor),
                m.collector_addr.to_string(),
                m.tor_data_dir.to_string_lossy().into_owned(),
                m.voter_bundle_path.to_string_lossy().into_owned(),
                m.durable_inbox_dir.to_string_lossy().into_owned(),
            ));
            (true, same_election, ready, accepted, diag)
        }
        None => (false, false, false, 0, None),
    };

    let message = status_message(tor_found, transport_provisioned, intake_running, election_bound);
    Ok(build_status(
        tor_found,
        transport_provisioned,
        intake_running,
        election_bound,
        ready,
        accepted,
        diag,
        message,
    ))
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

    // If an intake is already running, either it is for THIS election (return
    // its status, idempotent) or for a different one (require an explicit stop).
    {
        let mut managed = state
            .organizer_intake
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        if let Some(m) = managed.as_mut() {
            if m.manifest_hash_hex == bound.manifest_hash_hex {
                return Ok(running_status(m, true));
            }
            return Err(CommandError::new(
                "GUI_ORGANIZER_INTAKE_OTHER_ELECTION",
                "INVALID_LIFECYCLE_TRANSITION",
                "stop the running private intake before starting it for a different election",
            ));
        }
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
    // state to store.
    let running = start_intake_worker(app, &tor_executable, &paths, &bound)?;
    let status = running_status(&running, true);
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
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: paths.tor_data_dir.clone(),
        config_file: paths.provision_torrc.clone(),
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

    let mut child = SystemManagedTorSpawnerV1
        .spawn(tor_executable, &paths.provision_torrc)
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
                return Err(hostname_discovery_failed());
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
        &paths.tor_data_dir,
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

    // 5. Write the intake torrc with the ACTUAL collector port; launch Tor.
    let tor_config = OrganizerHiddenServiceTorConfigV1 {
        executable: tor_executable.to_path_buf(),
        data_directory: paths.tor_data_dir.clone(),
        config_file: paths.intake_torrc.clone(),
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
    let mut child = SystemManagedTorSpawnerV1
        .spawn(tor_executable, &paths.intake_torrc)
        .map_err(|_| tor_start_failed())?;

    // 6. Discover the runtime hostname (bounded), watching child liveness. The
    // liveness closure mutably borrows `child`; it is moved into the discovery
    // call, releasing the borrow before any later `child.kill()`/`wait()`. The
    // early-return branch must not touch `child` while the closure holds it.
    let timeout = DiscoveryTimeoutV1::new(TOR_STARTUP_TIMEOUT);
    let mut child_alive = || {
        child
            .try_wait()
            .map(|status| status.is_none())
            .unwrap_or(false)
    };
    if !child_alive() {
        return Err(tor_start_failed());
    }
    let runtime_hostname =
        match discover_organizer_onion_hostname_v1(&tor_config, &timeout, child_alive) {
            Ok(host) => host,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(hostname_discovery_failed());
            }
        };

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
    let gateway = Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    let session_arc = Arc::new(Mutex::new(session));
    let descriptor_arc = Arc::new(bundle.descriptor.clone());
    let receiver_key_arc = reconstruct_receiver_key(&bundle)?;
    let receipt_key_arc = Arc::new(bundle.material.receipt_signing_key.clone());
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway,
        descriptor_arc,
        receiver_key_arc,
        session_arc,
        receipt_key_arc,
        "organizer-receipt-key".to_owned(),
    )
    .with_accepted_package_inbox(durable_inbox_dir.clone());
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
        tor_data_dir: paths.tor_data_dir.clone(),
        voter_bundle_path: paths.voter_bundle_path.clone(),
        durable_inbox_dir,
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

fn running_status(m: &OrganizerIntakeState, election_bound: bool) -> OrganizerIntakeStatusV1 {
    let accepted = m.service_loop.accepted_unique_count();
    let ready = election_bound && m.service_loop.worker_is_alive();
    OrganizerIntakeStatusV1 {
        tor_found: true,
        transport_provisioned: true,
        intake_running: true,
        election_bound,
        ready,
        accepted_ballots: accepted,
        onion_hostname: Some(m.onion_hostname.clone()),
        descriptor_fingerprint: descriptor_fingerprint_hex(&m.descriptor),
        collector_addr: Some(m.collector_addr.to_string()),
        tor_data_dir: Some(m.tor_data_dir.to_string_lossy().into_owned()),
        voter_bundle_path: Some(m.voter_bundle_path.to_string_lossy().into_owned()),
        durable_inbox_dir: Some(m.durable_inbox_dir.to_string_lossy().into_owned()),
        message: if ready {
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
) -> &'static str {
    if intake_running && !election_bound {
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
    fn status_message_guides_the_operator_through_each_state() {
        assert!(status_message(false, false, false, false).contains("Tor was not found"));
        assert_eq!(
            status_message(true, false, false, false),
            "Ready to provision and start private intake."
        );
        assert_eq!(
            status_message(true, true, false, false),
            "Ready to start private intake."
        );
        assert_eq!(status_message(true, true, true, true), "Private intake is running.");
        assert!(
            status_message(true, true, true, false).contains("different election"),
            "a running intake bound to another election must be called out"
        );
    }

    #[test]
    fn descriptor_root_directory_name_is_backend_controlled() {
        // The only dynamic path component is the validated hash; the parent
        // directory name is a fixed backend constant.
        assert_eq!(ORGANIZER_TOR_ROOT_DIRECTORY_NAME, "private-tor");
    }
}
