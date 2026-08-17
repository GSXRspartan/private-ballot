//! Controlled-test managed-Tor wiring for the voter side (feature-gated).
//!
//! Compiled only under the `managed-tor-test` feature. It adds the minimum
//! backend state needed to:
//!
//!   * configure the voter test transport (absolute tor.exe path, voter Tor
//!     data directory, voter-public transport bundle);
//!   * start/stop a managed `tor.exe` directly (no shell) with a loopback
//!     SOCKS5 listener;
//!   * poll the REAL reviewed SOCKS readiness probe before transitioning to
//!     Ready;
//!   * rewire `submit_prepared_voter_ballot_privately` through the shared
//!     durable release boundary (`GuiVoterSessionV1::release_prepared_ballot_via_private_transport`)
//!     using `TorSocksPrivateReleaseCarrierV1` and the SAME verified
//!     descriptor;
//!   * retry a pending private-transport release with the EXACT staged
//!     envelope.
//!
//! Compile-time feature alone never starts networking. The user must explicitly
//! call `configure_managed_tor_test` with a valid runtime configuration, then
//! `start_managed_tor`, before any carrier can be built.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_gui_core::{
    DescriptorConsistencyStoreV1, GuiPrivateReleaseResultV1, TransportAuthorityRootSetV1,
    TransportDescriptorV1, ensure_voter_cast_locks_directory_v1,
    resolve_and_recover_private_transport_cast_lock_state_v1, voter_cast_locks_directory_v1,
};
use tari_cc_private_ballot_transport_gateway::load_voter_public_bundle_v1;
use tari_cc_private_ballot_transport_network::{
    ManagedTorConfigV1, ManagedTorControllerV1, ManagedTorReadinessProbeV1,
    SystemManagedTorReadinessProbeV1, SystemManagedTorSpawnerV1, TorCarrierTimeoutsV1,
    TorSocksPrivateReleaseCarrierV1, evaluate_managed_tor_readiness_v1,
};
use tauri::{AppHandle, Manager};

use crate::{AppState, CommandError};

/// Default loopback SOCKS port for the voter managed Tor process. A fixed port
/// is acceptable for controlled one-computer testing; a collision is surfaced
/// as a bounded error rather than silently retrying.
const DEFAULT_VOTER_SOCKS_PORT: u16 = 19050;

/// Bounded timeouts for the FRESH SOCKS readiness preflight on the submit/retry
/// path (user-initiated; bounded but not a polling loop).
const PREFLIGHT_SOCKS_CONNECT: Duration = Duration::from_secs(5);
const PREFLIGHT_SOCKS_HANDSHAKE: Duration = Duration::from_secs(5);
/// Shorter bounded timeouts for status polling so a dead Tor does not wedge the
/// status command for the full preflight budget.
const STATUS_SOCKS_CONNECT: Duration = Duration::from_secs(3);
const STATUS_SOCKS_HANDSHAKE: Duration = Duration::from_secs(3);

/// The voter-side managed-Tor test runtime state.
pub(crate) struct ManagedTorTestState {
    controller: Option<ManagedTorControllerV1<Child>>,
    descriptor: TransportDescriptorV1,
    roots: TransportAuthorityRootSetV1,
    consistency: DescriptorConsistencyStoreV1,
    socks_addr: SocketAddr,
    tor_exe_path: PathBuf,
    tor_data_dir: PathBuf,
    socks_port: u16,
}

/// Serializable runtime configuration supplied by the user.
#[derive(Debug, Clone, Deserialize)]
pub struct ManagedTorTestConfigInputV1 {
    /// Absolute path to an already-installed tor.exe.
    pub tor_exe_path: String,
    /// Absolute path to the voter Tor data/config directory (outside the repo).
    pub voter_tor_data_dir: String,
    /// Absolute path to the voter-public transport bundle file.
    pub voter_public_bundle_path: String,
}

/// Serializable status of the managed-Tor test transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedTorTestStatusV1 {
    pub configured: bool,
    pub tor_running: bool,
    pub socks_ready: bool,
    pub socks_addr: Option<String>,
    pub onion_hostname: Option<String>,
    pub descriptor_fingerprint: Option<String>,
    pub message: &'static str,
}

impl Default for ManagedTorTestStatusV1 {
    fn default() -> Self {
        Self {
            configured: false,
            tor_running: false,
            socks_ready: false,
            socks_addr: None,
            onion_hostname: None,
            descriptor_fingerprint: None,
            message: "Managed Tor test transport is not configured.",
        }
    }
}

/// Validates the user-supplied tor.exe path: absolute, exists, regular file,
/// no control characters.
fn validate_tor_exe(path: &Path) -> Result<(), CommandError> {
    if !path.is_absolute() {
        return Err(CommandError::new(
            "GUI_TOR_EXE_PATH_NOT_ABSOLUTE",
            "INVALID_INPUT",
            "the tor.exe path must be absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        CommandError::new("GUI_TOR_EXE_NOT_FOUND", "FILE_IO", "tor.exe was not found")
    })?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(CommandError::new(
            "GUI_TOR_EXE_NOT_REGULAR",
            "FILE_IO",
            "tor.exe must be a regular file (no symlinks/reparse points)",
        ));
    }
    if path
        .as_os_str()
        .to_string_lossy()
        .chars()
        .any(char::is_control)
    {
        return Err(CommandError::new(
            "GUI_TOR_EXE_PATH_CONTROL_CHAR",
            "INVALID_INPUT",
            "the tor.exe path must not contain control characters",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Configures the voter test transport: validates the tor.exe path, loads and
/// verifies the voter-public transport bundle, and confirms the descriptor
/// matches the currently loaded election. No Tor process is started here.
#[tauri::command]
pub fn configure_managed_tor_test(
    input: ManagedTorTestConfigInputV1,
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    let tor_exe = PathBuf::from(&input.tor_exe_path);
    let tor_data_dir = PathBuf::from(&input.voter_tor_data_dir);
    let bundle_path = PathBuf::from(&input.voter_public_bundle_path);
    validate_tor_exe(&tor_exe)?;
    if !tor_data_dir.is_absolute() {
        return Err(CommandError::new(
            "GUI_TOR_DATA_DIR_NOT_ABSOLUTE",
            "INVALID_INPUT",
            "the voter Tor data directory must be an absolute path",
        ));
    }
    if !bundle_path.is_absolute() {
        return Err(CommandError::new(
            "GUI_BUNDLE_PATH_NOT_ABSOLUTE",
            "INVALID_INPUT",
            "the voter-public bundle path must be absolute",
        ));
    }

    // Load and verify the voter public bundle (root + descriptor).
    let bundle = load_voter_public_bundle_v1(&bundle_path).map_err(|_| {
        CommandError::new(
            "GUI_VOTER_BUNDLE_MALFORMED",
            "INVALID_INPUT",
            "the voter-public transport bundle could not be loaded",
        )
    })?;

    // Confirm the descriptor matches the currently loaded election.
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Err(CommandError::no_session());
    };
    let manifest_hash = session.artifacts().manifest_hash();
    let election_id = session.artifacts().manifest().election_id().as_bytes();
    if bundle.descriptor.election_id() != election_id
        || bundle.descriptor.manifest_hash() != manifest_hash
    {
        return Err(CommandError::new(
            "GUI_VOTER_BUNDLE_WRONG_ELECTION",
            "BINDING_MISMATCH",
            "the voter-public transport bundle is bound to a different election",
        ));
    }

    // Verify the descriptor under the test root before accepting it.
    let roots = TransportAuthorityRootSetV1::new(bundle.root.clone());
    let mut consistency = DescriptorConsistencyStoreV1::default();
    roots
        .verify_and_accept_descriptor(&bundle.descriptor, manifest_hash, &mut consistency)
        .map_err(|_| {
            CommandError::new(
                "GUI_VOTER_BUNDLE_UNTRUSTED",
                "BINDING_MISMATCH",
                "the voter-public transport bundle descriptor does not verify under its test root",
            )
        })?;

    let onion_hostname = bundle.descriptor.onion_endpoints().first().cloned();
    let descriptor_fingerprint = bundle
        .descriptor
        .fingerprint()
        .ok()
        .map(|fp| hex_lower(&fp));

    std::fs::create_dir_all(&tor_data_dir).map_err(|_| CommandError::app_data_unavailable())?;
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_VOTER_SOCKS_PORT));

    let managed_state = ManagedTorTestState {
        controller: None,
        descriptor: bundle.descriptor,
        roots,
        consistency,
        socks_addr,
        tor_exe_path: tor_exe,
        tor_data_dir,
        socks_port: DEFAULT_VOTER_SOCKS_PORT,
    };
    drop(session_guard);
    let mut managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *managed = Some(managed_state);

    let _ = app;
    Ok(ManagedTorTestStatusV1 {
        configured: true,
        tor_running: false,
        socks_ready: false,
        socks_addr: Some(socks_addr.to_string()),
        onion_hostname,
        descriptor_fingerprint,
        message: "Managed Tor test transport configured. Start Tor to submit privately.",
    })
}

/// Starts the managed voter Tor process (direct spawn, no shell) and polls the
/// real SOCKS5 readiness probe. Returns Ready only after valid SOCKS5
/// negotiation. No ballot is released by this command.
#[tauri::command]
pub fn start_managed_tor(
    _app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    let config = {
        let managed = state
            .managed_tor_test
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(m) = managed.as_ref() else {
            return Err(CommandError::new(
                "GUI_TOR_TEST_NOT_CONFIGURED",
                "INVALID_INPUT",
                "configure the managed Tor test transport first",
            ));
        };
        ManagedTorConfigV1 {
            executable: m.tor_exe_path.clone(),
            data_directory: m.tor_data_dir.clone(),
            config_file: m.tor_data_dir.join("voter-torrc"),
            socks_port: m.socks_port,
            startup_timeout: Duration::from_secs(60),
        }
    };
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], config.socks_port));
    let mut probe = SystemManagedTorReadinessProbeV1::new(
        socks_addr,
        Duration::from_secs(10),
        Duration::from_secs(20),
    )
    .map_err(|_| {
        CommandError::new(
            "GUI_TOR_CONFIG_INVALID",
            "INVALID_INPUT",
            "invalid SOCKS endpoint",
        )
    })?;
    let start = Instant::now();
    let controller =
        ManagedTorControllerV1::start(&config, &SystemManagedTorSpawnerV1, &mut probe, || {
            start.elapsed()
        })
        .map_err(|_| {
            CommandError::new(
                "GUI_TOR_START_FAILED",
                "UNAVAILABLE",
                "tor.exe failed to start or the SOCKS5 listener did not become ready",
            )
        })?;

    let mut managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(m) = managed.as_mut() else {
        return Err(CommandError::new(
            "GUI_TOR_TEST_NOT_CONFIGURED",
            "INVALID_INPUT",
            "configure the managed Tor test transport first",
        ));
    };
    m.controller = Some(controller);
    let hostname = m.descriptor.onion_endpoints().first().cloned();
    let fingerprint = m.descriptor.fingerprint().ok().map(|fp| hex_lower(&fp));
    Ok(ManagedTorTestStatusV1 {
        configured: true,
        tor_running: true,
        socks_ready: true,
        socks_addr: Some(m.socks_addr.to_string()),
        onion_hostname: hostname,
        descriptor_fingerprint: fingerprint,
        message: "Managed Tor is ready. You may submit your ballot privately.",
    })
}

/// Stops the managed voter Tor process (bounded). Only the child this
/// application launched is terminated.
#[tauri::command]
pub fn stop_managed_tor(
    state: tauri::State<'_, AppState>,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    let mut managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    if let Some(m) = managed.as_mut() {
        if let Some(controller) = m.controller.as_mut() {
            controller.shutdown();
        }
        m.controller = None;
    }
    Ok(ManagedTorTestStatusV1 {
        configured: managed.is_some(),
        tor_running: false,
        socks_ready: false,
        socks_addr: managed.as_ref().map(|m| m.socks_addr.to_string()),
        onion_hostname: managed
            .as_ref()
            .and_then(|m| m.descriptor.onion_endpoints().first().cloned()),
        descriptor_fingerprint: managed
            .as_ref()
            .and_then(|m| m.descriptor.fingerprint().ok())
            .map(|fp| hex_lower(&fp)),
        message: "Managed Tor stopped.",
    })
}

/// Returns the current managed-Tor test transport status.
///
/// `tor_running` and `socks_ready` reflect CURRENT observations, not merely
/// that a controller object exists. A controller whose child has exited, or
/// whose SOCKS listener no longer responds, never reports ready. Status is
/// read-only: it never creates a PENDING record or changes voter cast state.
#[tauri::command]
pub fn managed_tor_test_status(
    state: tauri::State<'_, AppState>,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    let (descriptor, socks_addr, controller_present, child_alive) = {
        let mut managed = state
            .managed_tor_test
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(m) = managed.as_mut() else {
            return Ok(ManagedTorTestStatusV1::default());
        };
        let controller_present = m.controller.is_some();
        // check_crash is the controller health API (try_wait). It mutates the
        // controller's ready flag only to reflect that the child exited; it
        // does not change voter cast state.
        let child_alive = if let Some(controller) = m.controller.as_mut() {
            controller.check_crash().is_ok()
        } else {
            false
        };
        (
            m.descriptor.clone(),
            m.socks_addr,
            controller_present,
            child_alive,
        )
    };
    // Fresh SOCKS probe OUTSIDE the managed-state lock.
    let socks_ready = if controller_present && child_alive {
        fresh_socks_probe_ok(socks_addr, STATUS_SOCKS_CONNECT, STATUS_SOCKS_HANDSHAKE)
    } else {
        false
    };
    let decision = evaluate_managed_tor_readiness_v1(controller_present, child_alive, socks_ready);
    let message = if decision.is_ready() {
        "Managed Tor is ready. You may submit your ballot privately."
    } else if decision.tor_running {
        "Managed Tor is running but the SOCKS listener is not ready yet."
    } else {
        "Managed Tor test transport is configured but Tor is not running."
    };
    Ok(ManagedTorTestStatusV1 {
        configured: true,
        tor_running: decision.tor_running,
        socks_ready: decision.socks_ready,
        socks_addr: Some(socks_addr.to_string()),
        onion_hostname: descriptor.onion_endpoints().first().cloned(),
        descriptor_fingerprint: descriptor.fingerprint().ok().map(|fp| hex_lower(&fp)),
        message,
    })
}

/// Rewires the private submission through the shared durable release boundary.
/// This is the test-feature implementation of `submit_prepared_voter_ballot_privately`.
///
/// Preconditions enforced (in addition to the release boundary's own checks):
/// the feature is compiled, runtime test mode is configured, the managed Tor
/// controller is alive, SOCKS readiness is good, and the carrier is built from
/// the validated loopback SOCKS endpoint. Then the SHARED RELEASE BOUNDARY
/// (`GuiVoterSessionV1::release_prepared_ballot_via_private_transport`) is
/// invoked — no PENDING logic is duplicated in Tauri.
///
/// The FRESH readiness preflight runs BEFORE the shared release boundary. If
/// Tor has died since initial startup (stale controller) or the SOCKS listener
/// is no longer ready, the preflight fails closed: the release boundary is
/// never entered, no durable PENDING record is created, no bytes are staged,
/// and the voter remains NotCast (choice still changeable).
pub fn submit_prepared_voter_ballot_privately_via_managed_tor(
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiPrivateReleaseResultV1, CommandError> {
    // 1. FRESH readiness preflight (BEFORE the release boundary). Controller
    //    alive is checked under a brief lock (try_wait, no blocking); the SOCKS
    //    probe runs OUTSIDE the managed-state lock so no mutex is held across
    //    the bounded network probe.
    let (descriptor, roots, socks_addr) = {
        let mut managed = state
            .managed_tor_test
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let m = managed.as_mut().ok_or_else(|| {
            CommandError::new(
                "GUI_TOR_TEST_NOT_CONFIGURED",
                "INVALID_INPUT",
                "configure the managed Tor test transport first",
            )
        })?;
        let controller = m.controller.as_mut().ok_or_else(|| {
            CommandError::new(
                "GUI_TOR_NOT_RUNNING",
                "UNAVAILABLE",
                "start the managed Tor transport before submitting privately",
            )
        })?;
        // A. owned Tor child has not exited (uses the controller health API).
        controller.check_crash().map_err(|_| {
            CommandError::new(
                "GUI_TOR_NOT_RUNNING",
                "UNAVAILABLE",
                "the managed Tor process has exited; restart it before submitting privately",
            )
        })?;
        (m.descriptor.clone(), m.roots.clone(), m.socks_addr)
    };
    // B. fresh SOCKS readiness succeeds NOW (not under the managed-state lock).
    fresh_socks_readiness(
        socks_addr,
        PREFLIGHT_SOCKS_CONNECT,
        PREFLIGHT_SOCKS_HANDSHAKE,
    )?;

    // 2. Prepared ballot / NotCast checks + shared release boundary (unchanged).
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

    let cast_locks_dir = cast_locks_directory(app)?;
    let staging_dir = staging_directory(app)?;

    let mut carrier =
        TorSocksPrivateReleaseCarrierV1::new(socks_addr, TorCarrierTimeoutsV1::default()).map_err(
            |_| {
                CommandError::new(
                    "GUI_TOR_CONFIG_INVALID",
                    "INVALID_INPUT",
                    "the loopback SOCKS endpoint is invalid",
                )
            },
        )?;

    // Move the consistency store out of managed state (it is not Clone); it is
    // returned after the release call. Default replaces it meanwhile.
    let mut consistency = {
        let mut managed = state
            .managed_tor_test
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        managed
            .as_mut()
            .map(|m| std::mem::take(&mut m.consistency))
            .unwrap_or_default()
    };

    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };

    // Apply the durable cast-lock state from disk before the gated operation,
    // using the provisioned descriptor so a durably-persisted receipt can
    // promote a PENDING record to CAST on restart.
    let public_key_hex = voter.credential_public_key_hex();
    if let Some(fingerprint) = public_key_hex
        .as_deref()
        .and_then(tari_cc_private_ballot_gui_core::public_credential_fingerprint_hex_v1)
    {
        let manifest_hash_hex =
            tari_cc_private_ballot_gui_core::GuiVoterElectionBindingV1::from_artifacts(&artifacts)
                .manifest_hash_hex;
        let lock_state = resolve_and_recover_private_transport_cast_lock_state_v1(
            &cast_locks_dir,
            &manifest_hash_hex,
            &fingerprint,
            &descriptor,
        )?;
        voter.apply_cast_lock_state(lock_state);
    }

    let result = voter.release_prepared_ballot_via_private_transport(
        &artifacts,
        lifecycle_state,
        &descriptor,
        &roots,
        &mut consistency,
        &cast_locks_dir,
        &staging_dir,
        &mut carrier as &mut dyn tari_cc_private_ballot_gui_core::PrivateReleaseCarrierV1,
    );

    // Return the consistency store to the managed state.
    if let Ok(mut managed) = state.managed_tor_test.lock() {
        if let Some(m) = managed.as_mut() {
            m.consistency = consistency;
        }
    }

    result.map_err(CommandError::from)
}

/// Retries a pending private-transport release with the EXACT staged envelope.
/// Same descriptor, same carrier path, no resealing, no new proof.
///
/// Before retransmitting, a FRESH readiness preflight verifies the controller
/// is alive and the SOCKS listener is ready NOW. If readiness fails, the retry
/// aborts BEFORE the shared retry boundary: the voter remains CastPending, the
/// exact staged envelope is untouched, no carrier is invoked, and no
/// resealing or state rollback occurs. CastPending is never converted back to
/// NotCast.
pub fn retry_private_submission_via_managed_tor(
    app: &AppHandle,
    state: &AppState,
) -> Result<GuiPrivateReleaseResultV1, CommandError> {
    // 1. FRESH readiness preflight (BEFORE the retry boundary). If Tor has
    //    died, remain CastPending without invoking the carrier.
    let (descriptor, roots, socks_addr) = {
        let mut managed = state
            .managed_tor_test
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let m = managed.as_mut().ok_or_else(|| {
            CommandError::new(
                "GUI_TOR_TEST_NOT_CONFIGURED",
                "INVALID_INPUT",
                "configure the managed Tor test transport first",
            )
        })?;
        let controller = m.controller.as_mut().ok_or_else(|| {
            CommandError::new(
                "GUI_TOR_NOT_RUNNING",
                "UNAVAILABLE",
                "start the managed Tor transport before retrying",
            )
        })?;
        controller.check_crash().map_err(|_| {
            CommandError::new(
                "GUI_TOR_NOT_RUNNING",
                "UNAVAILABLE",
                "the managed Tor process has exited; restart it before retrying",
            )
        })?;
        (m.descriptor.clone(), m.roots.clone(), m.socks_addr)
    };
    fresh_socks_readiness(
        socks_addr,
        PREFLIGHT_SOCKS_CONNECT,
        PREFLIGHT_SOCKS_HANDSHAKE,
    )?;

    // 2. Shared retry boundary (unchanged): retransmit the EXACT staged bytes.
    let artifacts = {
        let session_guard = state
            .session
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        let Some(session) = session_guard.as_ref() else {
            return Err(CommandError::no_session());
        };
        session.artifacts().clone()
    };

    let cast_locks_dir = cast_locks_directory(app)?;

    let mut carrier =
        TorSocksPrivateReleaseCarrierV1::new(socks_addr, TorCarrierTimeoutsV1::default()).map_err(
            |_| {
                CommandError::new(
                    "GUI_TOR_CONFIG_INVALID",
                    "INVALID_INPUT",
                    "the loopback SOCKS endpoint is invalid",
                )
            },
        )?;

    let mut consistency = {
        let mut managed = state
            .managed_tor_test
            .lock()
            .map_err(|_| CommandError::state_poisoned())?;
        managed
            .as_mut()
            .map(|m| std::mem::take(&mut m.consistency))
            .unwrap_or_default()
    };

    let mut voter_guard = state
        .voter
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(voter) = voter_guard.as_mut() else {
        return Err(CommandError::no_voter_session());
    };

    let result = voter.retry_pending_private_transport_release(
        &artifacts,
        &descriptor,
        &roots,
        &mut consistency,
        &cast_locks_dir,
        &mut carrier as &mut dyn tari_cc_private_ballot_gui_core::PrivateReleaseCarrierV1,
    );

    if let Ok(mut managed) = state.managed_tor_test.lock() {
        if let Some(m) = managed.as_mut() {
            m.consistency = consistency;
        }
    }

    result.map_err(CommandError::from)
}

/// Tauri command wrapper for retrying a pending private-transport release.
#[tauri::command]
pub fn retry_private_submission(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<GuiPrivateReleaseResultV1, CommandError> {
    retry_private_submission_via_managed_tor(&app, &state)
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

/// Runs a fresh loopback SOCKS5 readiness probe and returns an error if the
/// configured endpoint is not currently accepting SOCKS5 no-auth negotiation.
/// Used by the submit/retry PRE-PENDING preflight. Never holds the
/// managed-state lock (the caller drops it first). The probe is a best-effort
/// local check; it does not guarantee onion reachability or route success.
fn fresh_socks_readiness(
    socks_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<(), CommandError> {
    let mut probe =
        SystemManagedTorReadinessProbeV1::new(socks_addr, connect_timeout, handshake_timeout)
            .map_err(|_| {
                CommandError::new(
                    "GUI_TOR_CONFIG_INVALID",
                    "INVALID_INPUT",
                    "the loopback SOCKS endpoint is invalid",
                )
            })?;
    let ready = probe.ready().map_err(|_| {
        CommandError::new(
            "GUI_TOR_NOT_READY",
            "UNAVAILABLE",
            "the managed Tor SOCKS listener could not be probed",
        )
    })?;
    if !ready {
        return Err(CommandError::new(
            "GUI_TOR_NOT_READY",
            "UNAVAILABLE",
            "the managed Tor SOCKS listener is not currently ready; restart Tor before submitting",
        ));
    }
    Ok(())
}

/// Runs a fresh loopback SOCKS5 readiness probe and returns whether the
/// endpoint is currently ready. Used by the status command (read-only). Any
/// probe construction or negotiation failure is reported as not-ready rather
/// than an error, so status never wedges on a malformed/dead endpoint.
fn fresh_socks_probe_ok(
    socks_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> bool {
    SystemManagedTorReadinessProbeV1::new(socks_addr, connect_timeout, handshake_timeout)
        .ok()
        .and_then(|mut probe| probe.ready().ok())
        .unwrap_or(false)
}

fn staging_directory(app: &AppHandle) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    let staging = app_data_root.join("private-release-staging");
    std::fs::create_dir_all(&staging).map_err(|_| CommandError::app_data_unavailable())?;
    Ok(staging)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
