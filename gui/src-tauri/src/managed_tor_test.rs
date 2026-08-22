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

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tari_cc_private_ballot_gui_core::{
    DescriptorConsistencyStoreV1, GuiPrivateReleaseResultV1, TransportAuthorityRootSetV1,
    TransportAuthorityRootV1, TransportDescriptorV1, ensure_voter_cast_locks_directory_v1,
    resolve_and_recover_private_transport_cast_lock_state_v1, voter_cast_locks_directory_v1,
};
use tari_cc_private_ballot_transport_gateway::load_voter_public_bundle_v1;
use tari_cc_private_ballot_transport_network::{
    ManagedTorConfigV1, ManagedTorControllerV1, ManagedTorReadinessProbeV1, ManagedTorSpawnerV1,
    SystemManagedTorReadinessProbeV1, TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1,
    evaluate_managed_tor_readiness_v1,
};
use tauri::{AppHandle, Manager};

use crate::tor_support::resolve_tor_executable;
use crate::{AppState, CommandError};

/// Backend-controlled directory name for app-owned voter Tor runtime state.
const VOTER_TOR_ROOT_DIRECTORY_NAME: &str = "private-tor-voter";
/// Length in characters of a canonical lowercase Blake3 manifest-hash hex.
const MANIFEST_HASH_HEX_LEN: usize = 64;

/// Reserves a fresh loopback (127.0.0.1) ephemeral TCP port for the voter
/// managed Tor SOCKS listener.
///
/// A fixed global SOCKS port was the root cause of the real one-computer voter
/// Tor failure: an orphaned `tor.exe` from a previous run kept owning that fixed
/// port, so a freshly-spawned child could not bind and exited immediately — yet
/// the readiness probe still reached the ORPHAN on the fixed port and reported
/// "ready" for a child that was already dead (the stale-READY contradiction).
///
/// Binding `127.0.0.1:0` asks the OS for an unused ephemeral port and keeps the
/// binding loopback-only (never a routable interface). The listener is dropped
/// immediately so Tor can bind the same port; a tiny reserve→spawn race is
/// accepted (the readiness probe fails closed if the port was lost), which is far
/// safer than a fixed magic constant that deterministically collides with an
/// orphan. This is NOT a global constant swapped for another global constant:
/// every start reserves a new port.
fn reserve_loopback_socks_port() -> Result<u16, CommandError> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(|_| {
        CommandError::new(
            "GUI_TOR_SOCKS_PORT_UNAVAILABLE",
            "UNAVAILABLE",
            "no loopback SOCKS port could be reserved for the managed Tor connection",
        )
    })?;
    let port = listener
        .local_addr()
        .map_err(|_| {
            CommandError::new(
                "GUI_TOR_SOCKS_PORT_UNAVAILABLE",
                "UNAVAILABLE",
                "the reserved loopback SOCKS port could not be read",
            )
        })?
        .port();
    drop(listener);
    Ok(port)
}

/// Allocates a fresh, app-owned run directory for ONE managed-Tor start under
/// the election-scoped base directory.
///
/// A hard-killed application can leave an orphaned `tor.exe` still holding the
/// lock of the run directory it was using — and the orphan is unowned after the
/// kill (its process handle is gone; a recorded PID could have been reused), so
/// it can neither be proven ours nor safely signalled. Giving every start its
/// OWN fresh run directory makes the next start immune to that stale lock
/// regardless of the orphan: a brand-new directory has no lock. This mirrors the
/// existing dynamic-SOCKS-port defence (a fresh port each start) for the OTHER
/// resource an orphan can hold — the data directory — which was the actual
/// blocker behind the post-hard-kill `GUI_TOR_START_FAILED`.
///
/// The directory name is app-generated (nanoseconds + pid + attempt); no remote
/// value can steer it.
pub(crate) fn fresh_run_directory(base: &Path) -> Result<PathBuf, CommandError> {
    std::fs::create_dir_all(base).map_err(|_| CommandError::app_data_unavailable())?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let pid = u128::from(std::process::id());
    for attempt in 0_u128..1024 {
        let run_dir = base.join(format!("run-{nanos:032x}{pid:08x}{attempt:04x}"));
        match std::fs::create_dir(&run_dir) {
            Ok(()) => return Ok(run_dir),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CommandError::app_data_unavailable()),
        }
    }
    Err(CommandError::new(
        "GUI_TOR_RUN_DIR_COLLISION",
        "UNAVAILABLE",
        "could not allocate a fresh managed-Tor run directory",
    ))
}

/// Best-effort, ownership-scoped cleanup of prior managed-Tor run directories.
///
/// Removes `run-*` subdirectories under the app-owned base that are NOT the
/// current run. A directory still held by an orphaned `tor.exe` (its lock/cache
/// files open) fails to remove and is simply skipped — the orphan is left
/// untouched and no unrelated process, path, or Tor installation is ever
/// signalled or deleted. Only directories this application created under its own
/// election-scoped base are considered.
pub(crate) fn remove_stale_run_directories(base: &Path, keep: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == keep {
            continue;
        }
        let is_owned_run_dir = path.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("run-"));
        if is_owned_run_dir {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// Distinguishable managed-Tor start-failure modes, derived from the child's
/// captured stderr. The user-facing message stays friendly; this classification
/// exists so diagnostics and tests can tell the modes apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedTorStartFailureKind {
    /// Tor could not lock its data directory (another Tor holds it).
    DataDirectoryLock,
    /// Tor could not bind its configured port.
    PortBindFailure,
    /// Tor rejected its configuration.
    ConfigError,
    /// Tor started but exited before the SOCKS listener became ready.
    ExitedEarly,
    /// Tor stayed up but the SOCKS listener never became ready in time.
    ReadinessTimeout,
}

impl ManagedTorStartFailureKind {
    /// Short, bounded, path-free diagnostic label attached to the error context.
    pub(crate) const fn as_context_label(self) -> &'static str {
        match self {
            Self::DataDirectoryLock => "tor-datadir-lock",
            Self::PortBindFailure => "tor-port-bind-failure",
            Self::ConfigError => "tor-config-error",
            Self::ExitedEarly => "tor-exited-early",
            Self::ReadinessTimeout => "tor-socks-readiness-timeout",
        }
    }

    /// Organizer-side variant of [`Self::as_context_label`]. The organizer
    /// intake has no SOCKS listener (it publishes a hidden service), so the
    /// timeout label is worded as a hidden-service readiness timeout. The label
    /// is bounded, path-free, and secret-free.
    pub(crate) const fn as_organizer_context_label(self) -> &'static str {
        match self {
            Self::DataDirectoryLock => "organizer-tor-datadir-lock",
            Self::PortBindFailure => "organizer-tor-port-bind-failure",
            Self::ConfigError => "organizer-tor-config-error",
            Self::ExitedEarly => "organizer-tor-exited-early",
            Self::ReadinessTimeout => "organizer-readiness-timeout",
        }
    }
}

/// Pure classifier over a tail of the managed-Tor child's stderr. Never does
/// I/O, so it is unit-testable without a real Tor binary or network.
pub(crate) fn classify_managed_tor_start_failure(stderr_tail: &str) -> ManagedTorStartFailureKind {
    let lower = stderr_tail.to_ascii_lowercase();
    let has = |needle: &str| lower.contains(needle);
    let datadir_lock = has("could not lock")
        || has("another tor process")
        || has("is another tor")
        || has("lockfile")
        || (has("data directory") && has("lock"));
    let port_bind =
        has("could not bind") || has("address already in use") || has("in use by another");
    let config_error = has("failed to parse")
        || has("unknown option")
        || (has("config") && has("error"))
        || (has("invalid") && has("torrc"));
    if datadir_lock {
        ManagedTorStartFailureKind::DataDirectoryLock
    } else if port_bind {
        ManagedTorStartFailureKind::PortBindFailure
    } else if config_error {
        ManagedTorStartFailureKind::ConfigError
    } else if stderr_tail.trim().is_empty() {
        // No captured output: Tor stayed up (writes nothing on a clean run) but
        // never became ready in time, or exited without a message.
        ManagedTorStartFailureKind::ReadinessTimeout
    } else if has("[err]") || has("exiting") || has("exit") {
        ManagedTorStartFailureKind::ExitedEarly
    } else {
        ManagedTorStartFailureKind::ReadinessTimeout
    }
}

/// Reads the tail of a managed-Tor stderr log and classifies the start failure.
/// Missing/unreadable log ⇒ treated as an empty tail (readiness timeout).
pub(crate) fn classify_start_failure_from_log(stderr_log: &Path) -> ManagedTorStartFailureKind {
    const TAIL_BYTES: usize = 4096;
    let contents = std::fs::read_to_string(stderr_log).unwrap_or_default();
    let tail = if contents.len() > TAIL_BYTES {
        &contents[contents.len() - TAIL_BYTES..]
    } else {
        contents.as_str()
    };
    classify_managed_tor_start_failure(tail)
}

/// GUI-local Tor spawner that is identical to the shared reviewed spawner (an
/// argument-vector spawn, no shell, no PATH resolution) EXCEPT that the child's
/// stderr is redirected to an app-owned per-run log file instead of being
/// discarded, so a start failure can be classified (see
/// [`classify_managed_tor_start_failure`]). Redirecting to a FILE — never a pipe
/// — avoids any pipe-buffer back-pressure on a long-running healthy child.
pub(crate) struct DiagnosticTorSpawnerV1 {
    pub(crate) stderr_log: PathBuf,
}

impl ManagedTorSpawnerV1 for DiagnosticTorSpawnerV1 {
    type Child = Child;

    fn spawn(&self, executable: &Path, config_file: &Path) -> std::io::Result<Child> {
        let log = std::fs::File::create(&self.stderr_log)?;
        Command::new(executable)
            .arg("-f")
            .arg(config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
    }
}

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
    /// The pinned `(key id, public key)` anchor of the configured bundle's
    /// current root, captured at configure time for election-status
    /// authentication.
    root_anchor: (String, [u8; 32]),
    consistency: DescriptorConsistencyStoreV1,
    socks_addr: SocketAddr,
    tor_exe_path: PathBuf,
    tor_data_dir: PathBuf,
    socks_port: u16,
}

pub(crate) fn configured_transport_descriptor(
    state: &AppState,
) -> Result<Option<TransportDescriptorV1>, CommandError> {
    let managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    Ok(managed.as_ref().map(|m| m.descriptor.clone()))
}

/// The pinned transport-authority anchor `(key id, Ed25519 public key)` of the
/// currently configured voter bundle, if any. Election-status statements are
/// authenticated against this SAME trust root that authenticated the transport
/// descriptor.
pub(crate) fn configured_transport_root_anchor(
    state: &AppState,
) -> Result<Option<(String, [u8; 32])>, CommandError> {
    let managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    Ok(managed.as_ref().map(|m| m.root_anchor.clone()))
}

/// The currently configured private-transport endpoint for THIS election:
/// `(loopback SOCKS endpoint, verified descriptor)`. `None` unless a bundle
/// bound to the ACTIVE election has been configured — a connection configured
/// for another election can never be reused here.
pub(crate) fn running_transport_endpoint(
    state: &AppState,
) -> Result<Option<(std::net::SocketAddr, TransportDescriptorV1)>, CommandError> {
    let managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(managed) = managed.as_ref() else {
        return Ok(None);
    };
    let session_guard = state
        .session
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    let Some(session) = session_guard.as_ref() else {
        return Ok(None);
    };
    if managed.descriptor.manifest_hash() != session.artifacts().manifest_hash() {
        return Ok(None);
    }
    Ok(Some((managed.socks_addr, managed.descriptor.clone())))
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

/// Read-only voter Tor availability. `resolved_tor_path` is the path the backend
/// would use (allowlist or remembered/selected); it is a diagnostic only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VoterTorStatusV1 {
    pub tor_found: bool,
    pub resolved_tor_path: Option<String>,
}

/// Pure derivation of the app-owned, election-scoped voter Tor data directory
/// under a given app-data root:
/// `<app-data>/private-tor-voter/election-<manifest-hash>/tor-data`. The hash is
/// the ONLY dynamic path component and is validated as canonical 64-char
/// lowercase hex, so a different election never reuses another election's Tor
/// data directory and no remote value can steer the path.
fn voter_tor_data_subpath(
    app_data_root: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, CommandError> {
    if manifest_hash_hex.len() != MANIFEST_HASH_HEX_LEN
        || !manifest_hash_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommandError::new(
            "GUI_VOTER_TOR_INVALID_ELECTION",
            "INVALID_INPUT",
            "the election manifest hash is not a canonical lowercase hex digest",
        ));
    }
    Ok(app_data_root
        .join(VOTER_TOR_ROOT_DIRECTORY_NAME)
        .join(format!("election-{manifest_hash_hex}"))
        .join("tor-data"))
}

/// Resolves the app-owned, election-scoped voter Tor data directory from the
/// Tauri app-data root (never a remote value).
fn voter_tor_data_dir(app: &AppHandle, manifest_hash_hex: &str) -> Result<PathBuf, CommandError> {
    let app_data_root = app
        .path()
        .app_data_dir()
        .map_err(|_| CommandError::app_data_unavailable())?;
    voter_tor_data_subpath(&app_data_root, manifest_hash_hex)
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
    // Tor executable: an empty path means "auto-detect" — resolve from the
    // reviewed allowlist (or a remembered/selected path when provided). The
    // resolver re-validates (absolute, real regular file, no reparse/control).
    let tor_exe = resolve_tor_executable(if input.tor_exe_path.trim().is_empty() {
        None
    } else {
        Some(input.tor_exe_path.as_str())
    })?;
    let bundle_path = PathBuf::from(&input.voter_public_bundle_path);
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

    // Voter Tor data directory: an empty path means "auto" — an app-owned,
    // election-scoped directory the voter never has to choose. A supplied path is
    // still honoured (absolute) for advanced/manual use.
    let manifest_hash_hex = session.summary().manifest_hash_hex;
    let tor_data_dir = if input.voter_tor_data_dir.trim().is_empty() {
        voter_tor_data_dir(&app, &manifest_hash_hex)?
    } else {
        let dir = PathBuf::from(&input.voter_tor_data_dir);
        if !dir.is_absolute() {
            return Err(CommandError::new(
                "GUI_TOR_DATA_DIR_NOT_ABSOLUTE",
                "INVALID_INPUT",
                "the voter Tor data directory must be an absolute path",
            ));
        }
        dir
    };

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

    // Capture the pinned root anchor (key id + public key) for authenticated
    // election-status verification. The bundle loader guarantees a Pinned root.
    let root_anchor = match &bundle.root {
        TransportAuthorityRootV1::Pinned {
            key_id,
            public_key,
        } => (key_id.clone(), *public_key),
        TransportAuthorityRootV1::ProductionNotProvisioned { .. } => {
            return Err(CommandError::new(
                "GUI_VOTER_BUNDLE_UNTRUSTED",
                "BINDING_MISMATCH",
                "the voter-public transport bundle carries no pinned authority root",
            ));
        }
    };

    std::fs::create_dir_all(&tor_data_dir).map_err(|_| CommandError::app_data_unavailable())?;
    // Reserve a fresh loopback ephemeral SOCKS port now for a truthful initial
    // endpoint; `start_managed_tor` re-reserves a fresh port on every (re)connect
    // so a reconnect after a child exit never reuses a possibly-orphaned port.
    let socks_port = reserve_loopback_socks_port()?;
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], socks_port));

    let managed_state = ManagedTorTestState {
        controller: None,
        descriptor: bundle.descriptor,
        roots,
        root_anchor,
        consistency,
        socks_addr,
        tor_exe_path: tor_exe,
        tor_data_dir,
        socks_port,
    };
    drop(session_guard);
    let mut managed = state
        .managed_tor_test
        .lock()
        .map_err(|_| CommandError::state_poisoned())?;
    *managed = Some(managed_state);

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

/// Read-only voter Tor availability probe. Reports whether a Tor executable can
/// be resolved (from a remembered/selected path or the reviewed allowlist)
/// without starting Tor, provisioning, or mutating any state.
#[tauri::command]
pub fn voter_tor_status(tor_exe_path: Option<String>) -> Result<VoterTorStatusV1, CommandError> {
    match resolve_tor_executable(tor_exe_path.as_deref()) {
        Ok(path) => Ok(VoterTorStatusV1 {
            tor_found: true,
            resolved_tor_path: Some(path.to_string_lossy().into_owned()),
        }),
        Err(_) => Ok(VoterTorStatusV1 {
            tor_found: false,
            resolved_tor_path: None,
        }),
    }
}

/// Starts the managed voter Tor process (direct spawn, no shell) and polls the
/// real SOCKS5 readiness probe. Returns Ready only after valid SOCKS5
/// negotiation. No ballot is released by this command.
#[tauri::command]
pub async fn start_managed_tor(
    app: AppHandle,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        start_managed_tor_blocking(state.inner())
    })
    .await
}

/// Blocking body of [`start_managed_tor`], run on the blocking thread pool.
fn start_managed_tor_blocking(state: &AppState) -> Result<ManagedTorTestStatusV1, CommandError> {
    // Reserve a FRESH loopback ephemeral SOCKS port for this (re)connect and
    // record it as authoritative BEFORE building the Tor config, so a reconnect
    // after a child exit never reuses a possibly-orphaned port.
    let fresh_port = reserve_loopback_socks_port()?;
    // Clone the election-scoped base directory out of the lock so the directory
    // I/O below runs unlocked.
    let base_dir = {
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
        m.tor_data_dir.clone()
    };
    // Allocate a FRESH, app-owned run directory for THIS start so a stale data-
    // directory lock left by an orphaned tor.exe (after a hard kill) can never
    // block the next start — the dynamic SOCKS port alone did not help because
    // the actual blocker was the data-directory lock, not the port. Then clean
    // up prior owned run directories that are no longer locked (best-effort;
    // ownership-scoped; a still-locked orphan directory is simply skipped).
    let run_dir = fresh_run_directory(&base_dir)?;
    remove_stale_run_directories(&base_dir, &run_dir);
    let stderr_log = run_dir.join("tor-stderr.log");
    let config = {
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
        m.socks_port = fresh_port;
        m.socks_addr = SocketAddr::from(([127, 0, 0, 1], fresh_port));
        ManagedTorConfigV1 {
            executable: m.tor_exe_path.clone(),
            data_directory: run_dir.clone(),
            config_file: run_dir.join("voter-torrc"),
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
    let spawner = DiagnosticTorSpawnerV1 {
        stderr_log: stderr_log.clone(),
    };
    let start = Instant::now();
    let controller = ManagedTorControllerV1::start(&config, &spawner, &mut probe, || start.elapsed())
        .map_err(|_| {
            // Classify the failure from the captured child stderr so diagnostics
            // and tests can distinguish spawn/early-exit/lock/bind/config/timeout.
            // The user-facing message stays friendly; the bounded kind label is
            // attached as error context (no path or secret).
            let kind = classify_start_failure_from_log(&stderr_log);
            CommandError::new(
                "GUI_TOR_START_FAILED",
                "UNAVAILABLE",
                "tor.exe failed to start or the SOCKS5 listener did not become ready",
            )
            .with_context(kind.as_context_label().to_owned())
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
pub async fn stop_managed_tor(
    app: AppHandle,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        stop_managed_tor_blocking(state.inner())
    })
    .await
}

/// Blocking body of [`stop_managed_tor`], run on the blocking thread pool.
fn stop_managed_tor_blocking(state: &AppState) -> Result<ManagedTorTestStatusV1, CommandError> {
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

/// Reaps the owned voter Tor child on application teardown so a graceful
/// shutdown never leaks an orphan `tor.exe` that would keep owning a loopback
/// SOCKS port and data-directory lock across the next launch. Idempotent and
/// best-effort; only the child this application launched is touched.
pub(crate) fn shutdown_managed_tor_on_exit(state: &AppState) {
    if let Ok(mut managed) = state.managed_tor_test.lock() {
        if let Some(m) = managed.as_mut() {
            if let Some(controller) = m.controller.as_mut() {
                controller.shutdown();
            }
            m.controller = None;
        }
    }
}

/// Returns the current managed-Tor test transport status.
///
/// `tor_running` and `socks_ready` reflect CURRENT observations, not merely
/// that a controller object exists. A controller whose child has exited, or
/// whose SOCKS listener no longer responds, never reports ready. Status is
/// read-only: it never creates a PENDING record or changes voter cast state.
#[tauri::command]
pub async fn managed_tor_test_status(
    app: AppHandle,
) -> Result<ManagedTorTestStatusV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        managed_tor_test_status_blocking(state.inner())
    })
    .await
}

/// Blocking body of [`managed_tor_test_status`], run on the blocking thread pool
/// so the fresh loopback SOCKS probe never stalls the main UI thread.
fn managed_tor_test_status_blocking(
    state: &AppState,
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

/// Tauri command wrapper for retrying a pending private-transport release. The
/// exact-staged retransmission is a blocking Tor request, so it runs on the
/// blocking thread pool and never freezes the main UI thread.
#[tauri::command]
pub async fn retry_private_submission(
    app: AppHandle,
) -> Result<GuiPrivateReleaseResultV1, CommandError> {
    crate::run_blocking_command(move || {
        let state = app.state::<AppState>();
        retry_private_submission_via_managed_tor(&app, state.inner())
    })
    .await
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

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str =
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const HASH_B: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn app_root() -> PathBuf {
        PathBuf::from(if cfg!(windows) {
            r"C:\app-data-root"
        } else {
            "/app-data-root"
        })
    }

    #[test]
    fn voter_data_dir_is_app_owned_and_election_scoped() {
        let dir = voter_tor_data_subpath(&app_root(), HASH_A).expect("valid hash");
        assert!(dir.starts_with(app_root()));
        assert!(
            dir.to_string_lossy().contains(VOTER_TOR_ROOT_DIRECTORY_NAME),
            "voter data dir must live under the app-owned private-tor-voter directory"
        );
        assert!(
            dir.to_string_lossy().contains(&format!("election-{HASH_A}")),
            "voter data dir must be scoped to the election manifest hash"
        );
    }

    #[test]
    fn different_elections_get_different_voter_data_dirs() {
        let a = voter_tor_data_subpath(&app_root(), HASH_A).expect("a");
        let b = voter_tor_data_subpath(&app_root(), HASH_B).expect("b");
        assert_ne!(a, b, "a different election must never reuse another's data dir");
    }

    #[test]
    fn reserved_socks_port_is_a_fresh_loopback_ephemeral_port() {
        // Regression for the real voter Tor stale-READY root cause: the SOCKS
        // port must be dynamically reserved, never a fixed global constant that a
        // previous run's orphan can keep owning. A reserved port is non-zero and
        // usable as a loopback bind.
        let port = reserve_loopback_socks_port().expect("reserve a loopback port");
        assert_ne!(port, 0, "a reserved SOCKS port is never port 0");
        // It is bindable again on loopback after release (the listener was dropped
        // so Tor can bind it); this also proves it is loopback-only.
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let rebound = TcpListener::bind(addr);
        assert!(rebound.is_ok(), "the reserved loopback port can be bound");
    }

    #[test]
    fn reserved_socks_ports_are_not_a_single_magic_constant() {
        // Reserving several ports should not deterministically yield one fixed
        // value (e.g. 19050); the OS hands out ephemeral ports. We assert the set
        // is not a single constant across a few reservations.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..3 {
            seen.insert(reserve_loopback_socks_port().expect("reserve"));
        }
        assert!(!seen.contains(&0));
        // At least one reservation is outside any single hard-coded default; the
        // OS ephemeral range is well above the old 19050 constant on Windows.
        assert!(seen.iter().any(|&p| p != 19050));
    }

    #[test]
    fn non_hex_manifest_hash_cannot_control_voter_data_dir() {
        for bad in [
            "..",
            "../../secret",
            "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
            "short",
            "aabb/ccdd",
        ] {
            let error =
                voter_tor_data_subpath(&app_root(), bad).expect_err("non-canonical must reject");
            assert_eq!(error.code, "GUI_VOTER_TOR_INVALID_ELECTION");
        }
    }

    // ---------------------------------------------------------------------
    // Hard-kill Tor recovery: fresh per-start run directory + ownership-scoped
    // cleanup + diagnosable start failure (Failure 3).
    // ---------------------------------------------------------------------

    fn temp_base(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "tari-managed-tor-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&base).expect("create temp base");
        base
    }

    #[test]
    fn each_start_gets_an_independent_fresh_run_directory() {
        // The next start must never reuse a data directory whose lock a prior
        // (possibly orphaned) tor.exe could still hold: every start allocates a
        // brand-new, app-owned run directory under the election base.
        let base = temp_base("fresh-run");
        let first = fresh_run_directory(&base).expect("first run dir");
        let second = fresh_run_directory(&base).expect("second run dir");
        assert_ne!(first, second, "each start gets a distinct run directory");
        assert!(first.starts_with(&base) && second.starts_with(&base));
        assert!(first.is_dir() && second.is_dir());
        for dir in [&first, &second] {
            let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            assert!(name.starts_with("run-"), "run dir name is app-generated: {name}");
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn stale_run_directory_cleanup_is_ownership_scoped() {
        // Cleanup removes prior owned `run-*` directories but never the current
        // run and never non-run siblings (e.g. a legacy `tor-data` file or an
        // unrelated directory). It is best-effort: an un-removable directory is
        // skipped without error.
        let base = temp_base("cleanup");
        let keep = fresh_run_directory(&base).expect("current run dir");
        let stale = fresh_run_directory(&base).expect("stale run dir");
        // A non-run sibling that must be preserved.
        let unrelated = base.join("keep-me");
        std::fs::create_dir_all(&unrelated).expect("unrelated dir");
        std::fs::write(base.join("legacy-lock"), b"x").expect("legacy file");

        remove_stale_run_directories(&base, &keep);

        assert!(keep.is_dir(), "the current run directory is never removed");
        assert!(!stale.exists(), "a prior owned run directory is cleaned up");
        assert!(unrelated.is_dir(), "unrelated siblings are never touched");
        assert!(base.join("legacy-lock").exists(), "non-run files are never touched");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn start_failure_modes_are_individually_diagnosable() {
        use ManagedTorStartFailureKind::*;
        // Representative real tor.exe stderr signatures for each mode.
        assert_eq!(
            classify_managed_tor_start_failure(
                "[warn] Could not lock data directory. Is another Tor process running?"
            ),
            DataDirectoryLock,
        );
        assert_eq!(
            classify_managed_tor_start_failure(
                "[warn] Could not bind to 127.0.0.1:9050: Address already in use"
            ),
            PortBindFailure,
        );
        assert_eq!(
            classify_managed_tor_start_failure("[err] Failed to parse/validate config: unknown option"),
            ConfigError,
        );
        assert_eq!(
            classify_managed_tor_start_failure("[err] Something fatal happened; exiting"),
            ExitedEarly,
        );
        // A clean Tor writes nothing to stderr; an empty tail means it stayed up
        // but the SOCKS listener never became ready in time.
        assert_eq!(classify_managed_tor_start_failure(""), ReadinessTimeout);
        assert_eq!(classify_managed_tor_start_failure("   \n  "), ReadinessTimeout);
        // The labels are distinct, bounded, and path-free.
        let labels = [
            DataDirectoryLock,
            PortBindFailure,
            ConfigError,
            ExitedEarly,
            ReadinessTimeout,
        ]
        .map(ManagedTorStartFailureKind::as_context_label);
        let unique: std::collections::BTreeSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "each mode has a distinct label");
        for label in labels {
            assert!(label.starts_with("tor-") && !label.contains('/') && !label.contains('\\'));
        }
    }

    #[test]
    fn classify_from_missing_log_is_a_bounded_readiness_timeout() {
        let base = temp_base("missing-log");
        let missing = base.join("run-x").join("tor-stderr.log");
        assert_eq!(
            classify_start_failure_from_log(&missing),
            ManagedTorStartFailureKind::ReadinessTimeout,
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
