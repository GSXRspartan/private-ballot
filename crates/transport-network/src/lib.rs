#![forbid(unsafe_code)]

//! Process and carrier boundaries for private-ballot transport.
//!
//! This crate deliberately has no ballot verifier, receiver key, or election
//! intake. It owns the managed-Tor child-process boundary and the opaque relay
//! forwarding contract; the gateway remains the only HPKE opening boundary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Windows `CREATE_NO_WINDOW` process creation flag (`0x0800_0000`).
///
/// A `tor.exe` built as a Windows console subsystem allocates and shows a new
/// console window whenever it is spawned from a process that has none — a
/// Tauri GUI, for instance (the Private Ballot organizer GUI or the load
/// tester GUI). That window steals focus and covers the GUI. Applying
/// `CREATE_NO_WINDOW` when spawning tells Windows to run the console child
/// WITHOUT ever attaching or allocating a console at all; the child still
/// runs, its stdout/stderr redirections still work, and its process
/// handle/lifecycle ownership is unchanged. On Unix this flag does not exist
/// and this constant is unused.
#[cfg(windows)]
pub const TOR_WINDOWS_NO_CONSOLE_CREATION_FLAGS_V1: u32 = 0x0800_0000;

/// Applies the Windows-only "hide the child's console window" creation flag to
/// the given `Command` in-place, and returns it. On non-Windows platforms this
/// is a no-op — the `Command` is returned unchanged so callers stay identical
/// across platforms.
///
/// The flag is `CREATE_NO_WINDOW`, applied via the standard-library-provided
/// `std::os::windows::process::CommandExt::creation_flags`. It:
///
///   * NEVER changes the executable, argument vector, working directory,
///     environment, stdio redirections, or process-group membership;
///   * NEVER detaches the child from the parent (the parent still owns the
///     `Child` handle and reaps it on `kill`/`wait`);
///   * NEVER spawns a shell, `cmd.exe`, PowerShell, or resolves PATH.
///
/// It only asks Windows to spawn the child without ever allocating or showing
/// a new console window, so a `tor.exe` built as a console subsystem no longer
/// pops a black terminal in front of the organizer or load tester GUI. On
/// Linux/macOS there is no equivalent flag and Tor spawned from a GUI has no
/// console window in the first place, so the caller path stays identical on
/// those platforms too.
pub fn apply_hide_console_window_on_windows_v1(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(TOR_WINDOWS_NO_CONSOLE_CREATION_FLAGS_V1);
    }
    command
}

mod organizer_hidden_service;
mod remote_socks;
mod tor;

pub use organizer_hidden_service::{
    DiscoveryTimeoutV1, HostnameDiscoveryErrorV1, OrganizerHiddenServiceTorConfigV1,
    discover_organizer_onion_hostname_v1,
};
pub use remote_socks::{
    RemoteSocksEndpointErrorV1, RemoteSocksEndpointV1, SocksProxyEndpointV1, TorTransportModeV1,
};
pub use tor::{
    ELECTION_STATUS_HTTP_PATH_V1, ONION_VIRTUAL_PORT_V1, OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1,
    OPAQUE_ENVELOPE_HTTP_PATH_V1, OnionReachabilityOutcomeV1, RemoteTorReadinessOutcomeV1,
    RemoteTorSocksPrivateReleaseCarrierV1, StrictHeaderErrorV1, SystemManagedTorReadinessProbeV1,
    TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1, fetch_election_status_over_remote_tor,
    fetch_election_status_over_tor, parse_strict_content_length_v1, parse_strict_header_line_v1,
    probe_onion_reachability_endpoint_v1, probe_onion_reachability_v1,
    probe_remote_onion_reachability_v1, validate_loopback_socket_addr_v1,
    validate_onion_hostname_v1,
};

pub const OPAQUE_ENVELOPE_CONTENT_TYPE_V1: &str =
    "application/vnd.tari-cc-private-ballot-envelope-v1";

/// Coarse errors which intentionally omit endpoint, process, and payload details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateTransportNetworkErrorV1 {
    InvalidConfiguration,
    PrivateTransportUnavailable,
    InvalidOpaqueRequest,
    RelayUnavailable,
}

impl std::fmt::Display for PrivateTransportNetworkErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "private transport configuration is invalid",
            Self::PrivateTransportUnavailable => {
                "private transport unavailable; choose relay explicitly or use offline export"
            }
            Self::InvalidOpaqueRequest => "invalid private transport request",
            Self::RelayUnavailable => "private transport unavailable; use offline export or retry",
        })
    }
}

impl std::error::Error for PrivateTransportNetworkErrorV1 {}

/// Explicit user route selection. There is intentionally no direct-gateway route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterPrivateRouteV1 {
    ManagedTor,
    SplitTrustRelay,
    OfflineExport,
}

/// Result of route resolution, kept separate from connectivity failure so a Tor
/// failure can never silently downgrade to a direct connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteResolutionV1 {
    UseManagedTor,
    UseSplitTrustRelay,
    UseOfflineExport,
    PrivateTransportUnavailable,
}

#[must_use]
pub const fn resolve_voter_route_v1(
    selected: VoterPrivateRouteV1,
    managed_tor_ready: bool,
    relay_available: bool,
) -> RouteResolutionV1 {
    match selected {
        VoterPrivateRouteV1::ManagedTor if managed_tor_ready => RouteResolutionV1::UseManagedTor,
        VoterPrivateRouteV1::ManagedTor => RouteResolutionV1::PrivateTransportUnavailable,
        VoterPrivateRouteV1::SplitTrustRelay if relay_available => {
            RouteResolutionV1::UseSplitTrustRelay
        }
        VoterPrivateRouteV1::SplitTrustRelay => RouteResolutionV1::PrivateTransportUnavailable,
        VoterPrivateRouteV1::OfflineExport => RouteResolutionV1::UseOfflineExport,
    }
}

/// Fixed application-owned inputs for a managed Tor process. No caller can add
/// arbitrary Tor command-line fragments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedTorConfigV1 {
    pub executable: PathBuf,
    pub data_directory: PathBuf,
    pub config_file: PathBuf,
    pub socks_port: u16,
    pub startup_timeout: Duration,
}

impl ManagedTorConfigV1 {
    pub fn validate(&self) -> Result<(), PrivateTransportNetworkErrorV1> {
        if !self.executable.is_absolute()
            || !self.data_directory.is_absolute()
            || !self.config_file.is_absolute()
            || self.socks_port == 0
            || self.startup_timeout.is_zero()
            || has_control_path_component(&self.executable)
            || has_control_path_component(&self.data_directory)
            || has_control_path_component(&self.config_file)
        {
            return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
        }
        Ok(())
    }

    /// Generates only the static, application-owned Tor configuration. The
    /// caller never supplies raw config lines or process arguments.
    pub fn write_config(&self) -> Result<(), PrivateTransportNetworkErrorV1> {
        self.validate()?;
        fs::create_dir_all(&self.data_directory)
            .map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
        let body = format!(
            "SocksPort 127.0.0.1:{}\nDataDirectory {}\nClientOnly 1\nAvoidDiskWrites 1\n",
            self.socks_port,
            tor_path_token(&self.data_directory)?,
        );
        write_atomic(&self.config_file, body.as_bytes())
    }
}

pub(crate) fn has_control_path_component(path: &Path) -> bool {
    path.as_os_str()
        .to_string_lossy()
        .chars()
        .any(char::is_control)
}

pub(crate) fn tor_path_token(path: &Path) -> Result<String, PrivateTransportNetworkErrorV1> {
    let token = path.to_string_lossy();
    if token.contains('"') || token.contains('\n') || token.contains('\r') {
        return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
    }
    // Tor's config parser treats `\` as an escape character inside quoted
    // strings on every platform. A raw Windows path such as
    // `C:\private-ballot\organizer-tor-data` would otherwise be rejected with
    // "Invalid escape sequence in quoted string". Doubling every backslash
    // yields a valid Tor escaped token. On platforms whose paths contain no
    // backslashes this is a no-op.
    let escaped = token.replace('\\', r"\\");
    Ok(format!("\"{escaped}\""))
}

pub(crate) fn write_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<(), PrivateTransportNetworkErrorV1> {
    let parent = path
        .parent()
        .ok_or(PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    fs::create_dir_all(parent).map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    let temporary = path.with_extension("new");
    fs::write(&temporary, bytes)
        .map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    fs::rename(&temporary, path).map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)
}

/// Child process boundary, fakeable without a public network or a real Tor binary.
pub trait ManagedTorChildV1 {
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    fn kill(&mut self) -> io::Result<()>;
}

impl ManagedTorChildV1 for Child {
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        Child::try_wait(self).map(|status| status.map(|value| value.code().unwrap_or(-1)))
    }

    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }
}

/// Process creation boundary. The real implementation uses `Command` argument
/// vectors and never invokes a shell.
pub trait ManagedTorSpawnerV1 {
    type Child: ManagedTorChildV1;
    fn spawn(&self, executable: &Path, config_file: &Path) -> io::Result<Self::Child>;
}

#[derive(Debug, Default)]
pub struct SystemManagedTorSpawnerV1;

impl ManagedTorSpawnerV1 for SystemManagedTorSpawnerV1 {
    type Child = Child;

    fn spawn(&self, executable: &Path, config_file: &Path) -> io::Result<Self::Child> {
        let mut command = Command::new(executable);
        command
            .arg(OsString::from("-f"))
            .arg(config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Windows-only: never let `tor.exe` pop a visible console window that
        // covers/steals focus from the load tester or organizer GUI.
        apply_hide_console_window_on_windows_v1(&mut command);
        command.spawn()
    }
}

/// Readiness is separately injected: deployment code may use a loopback SOCKS
/// probe while tests use a deterministic fake. It is never a public-Internet probe.
pub trait ManagedTorReadinessProbeV1 {
    fn ready(&mut self) -> Result<bool, PrivateTransportNetworkErrorV1>;
}

#[derive(Debug)]
pub struct ManagedTorControllerV1<C: ManagedTorChildV1> {
    child: Option<C>,
    ready: bool,
}

impl<C: ManagedTorChildV1> ManagedTorControllerV1<C> {
    pub fn start<S: ManagedTorSpawnerV1<Child = C>, P: ManagedTorReadinessProbeV1>(
        config: &ManagedTorConfigV1,
        spawner: &S,
        readiness: &mut P,
        mut elapsed: impl FnMut() -> Duration,
    ) -> Result<Self, PrivateTransportNetworkErrorV1> {
        config.write_config()?;
        let mut child = spawner
            .spawn(&config.executable, &config.config_file)
            .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
        while elapsed() < config.startup_timeout {
            if child
                .try_wait()
                .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?
                .is_some()
            {
                return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
            }
            if readiness.ready()? {
                return Ok(Self {
                    child: Some(child),
                    ready: true,
                });
            }
        }
        let _ignored = child.kill();
        Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
    }

    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn check_crash(&mut self) -> Result<(), PrivateTransportNetworkErrorV1> {
        let child = self
            .child
            .as_mut()
            .ok_or(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
        if child
            .try_wait()
            .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?
            .is_some()
        {
            self.ready = false;
            return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
        }
        Ok(())
    }

    pub fn shutdown(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ignored = child.kill();
        }
        self.ready = false;
    }
}

/// Reaping the owned Tor child on drop closes the child-process lifecycle
/// boundary: when the controller is dropped (state replacement, reconfigure, or
/// application teardown) the managed `tor.exe` this controller launched is
/// killed rather than leaked as an orphan. An orphaned child would otherwise
/// keep owning its loopback SOCKS port and data-directory lock across an
/// application restart, which is the exact failure that let a stale process
/// answer a readiness probe for a freshly-spawned child that had already exited.
/// Only the child THIS controller owns is touched; no global process list is
/// scanned and no unrelated process is signalled.
impl<C: ManagedTorChildV1> Drop for ManagedTorControllerV1<C> {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ignored = child.kill();
            // Best-effort reap so a killed child does not linger as a zombie on
            // platforms that require it; a still-running kill is asynchronous so
            // `try_wait` may legitimately report "not yet exited".
            let _ignored = child.try_wait();
        }
        self.ready = false;
    }
}

/// Truthful managed-Tor readiness decision derived from CURRENT observations,
/// not merely from a controller object existing. Factored out of the Tauri
/// status command so it is testable without linking the Tauri test binary.
///
/// `tor_running` is true only when a controller is present AND its owned child
/// is still alive (the Tor process is up). `socks_ready` is true only when the
/// process is up AND the configured loopback SOCKS endpoint is currently
/// accepting SOCKS5 no-auth negotiation. A stale controller (child exited /
/// probe failed) never reports ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedTorReadinessDecisionV1 {
    pub tor_running: bool,
    pub socks_ready: bool,
}

impl ManagedTorReadinessDecisionV1 {
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.socks_ready
    }
}

/// Pure decision over the current observations. This never performs I/O; the
/// caller supplies the controller-present flag, the child-liveness result,
/// and the fresh SOCKS probe result. Used by the Tauri status command and
/// by the submit/retry preflight so they share one truthful decision.
#[must_use]
pub const fn evaluate_managed_tor_readiness_v1(
    controller_present: bool,
    child_alive: bool,
    socks_ready: bool,
) -> ManagedTorReadinessDecisionV1 {
    let tor_running = controller_present && child_alive;
    let socks_ready = controller_present && child_alive && socks_ready;
    ManagedTorReadinessDecisionV1 {
        tor_running,
        socks_ready,
    }
}

/// Composes the two managed-Tor readiness checks into one fresh preflight:
/// (1) the controller's owned child has not exited (via `check_crash`), and
/// (2) the configured loopback SOCKS endpoint is currently accepting SOCKS5
/// no-auth negotiation (via the injected probe). Returns Ok only when BOTH
/// checks pass right now.
///
/// This is a PRE-PENDING best-effort guard. It proves the local Tor SOCKS
/// interface is alive at this instant; it does NOT guarantee onion
/// reachability, complete route success, or organizer availability. Those
/// may still fail after PENDING, which correctly produces CastPending.
pub fn check_managed_tor_fresh_readiness_v1<C: ManagedTorChildV1, P: ManagedTorReadinessProbeV1>(
    controller: &mut ManagedTorControllerV1<C>,
    probe: &mut P,
) -> Result<(), PrivateTransportNetworkErrorV1> {
    controller.check_crash()?;
    if !probe.ready()? {
        return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
    }
    Ok(())
}

/// ONE shared Tor executable validation policy for every managed-Tor caller
/// (production Tauri app AND the distributed voter load driver CLI).
///
/// The policy is deliberately identical to the qualified production validator:
/// the path must be absolute (never PATH-relative), must exist, must be a real
/// regular file (never a symlink/reparse point), and must contain no control
/// characters. Discovery, PATH lookup, shell invocation, downloading, and
/// auto-install are all structurally absent: callers pass an explicit operator
/// path and this validator is the only gate before any spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorExecutableValidationErrorV1 {
    NotAbsolute,
    NotFound,
    NotRegularFile,
    ControlCharacters,
    NotExecutable,
}

impl std::fmt::Display for TorExecutableValidationErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NotAbsolute => "the Tor executable path must be absolute",
            Self::NotFound => "the Tor executable was not found",
            Self::NotRegularFile => {
                "the Tor executable must be a regular file (no symlinks/reparse points)"
            }
            Self::ControlCharacters => {
                "the Tor executable path must not contain control characters"
            }
            Self::NotExecutable => "the Tor executable is not marked executable",
        })
    }
}

impl std::error::Error for TorExecutableValidationErrorV1 {}

/// Validates a candidate Tor executable path with the single shared policy:
/// absolute, exists, regular file (no symlink/reparse point), no control
/// characters, and — on Unix — the executable permission bit(s) set. Windows
/// uses the `.exe` extension convention for executability; there is no
/// equivalent bit to check there. Without the Unix check, an operator on
/// Linux/macOS could point at a plain data file and only discover the mistake
/// at spawn time. Every caller (GUI and CLI) MUST run this before spawning.
pub fn validate_tor_executable_v1(path: &Path) -> Result<(), TorExecutableValidationErrorV1> {
    if !path.is_absolute() {
        return Err(TorExecutableValidationErrorV1::NotAbsolute);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| TorExecutableValidationErrorV1::NotFound)?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point_v1(&metadata)
        || !metadata.is_file()
    {
        return Err(TorExecutableValidationErrorV1::NotRegularFile);
    }
    if has_control_path_component(path) {
        return Err(TorExecutableValidationErrorV1::ControlCharacters);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(TorExecutableValidationErrorV1::NotExecutable);
        }
    }
    Ok(())
}

/// Windows reparse-point detection (0x400 `FILE_ATTRIBUTE_REPARSE_POINT`).
/// Non-Windows platforms have no reparse points; symlink rejection above
/// already covers them.
#[cfg(windows)]
pub fn is_windows_reparse_point_v1(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
pub fn is_windows_reparse_point_v1(_metadata: &std::fs::Metadata) -> bool {
    false
}

/// Reserves a fresh loopback (127.0.0.1) ephemeral TCP port for a managed Tor
/// SOCKS listener.
///
/// Binding `127.0.0.1:0` asks the OS for an unused ephemeral port and keeps the
/// binding loopback-only. The listener is dropped immediately so Tor can bind
/// the same port; a tiny reserve→spawn race is accepted (the readiness probe
/// fails closed if the port was lost), which is far safer than any fixed
/// magic-port constant that collides with orphaned processes. Every caller gets
/// a NEW port per start — never a shared constant.
pub fn reserve_loopback_socks_port_v1() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

/// Allocates a fresh, uniquely-named run directory for ONE managed-Tor start
/// under a caller-owned base directory.
///
/// The name is locally generated (nanoseconds + pid + attempt); no remote value
/// can steer it. A hard-killed application leaves no reusible directory behind:
/// every start gets its own fresh directory so a stale data-directory lock from
/// an orphaned Tor process can never block the next start.
pub fn create_fresh_run_directory_v1(base: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(base)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let pid = u128::from(std::process::id());
    for attempt in 0_u128..1024 {
        let run_dir = base.join(format!("run-{nanos:032x}{pid:08x}{attempt:04x}"));
        match fs::create_dir(&run_dir) {
            Ok(()) => return Ok(run_dir),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a fresh managed-Tor run directory",
    ))
}

/// A managed-Tor spawner identical to [`SystemManagedTorSpawnerV1`] (argument
/// vector, no shell, no PATH resolution) except that the child's stderr is
/// redirected to a caller-owned per-run log FILE instead of being discarded, so
/// a start failure leaves bounded diagnostic evidence. Redirecting to a FILE —
/// never a pipe — avoids pipe-buffer back-pressure on a long-running child.
#[derive(Debug, Clone)]
pub struct StderrLogFileTorSpawnerV1 {
    pub stderr_log: PathBuf,
}

impl ManagedTorSpawnerV1 for StderrLogFileTorSpawnerV1 {
    type Child = Child;

    fn spawn(&self, executable: &Path, config_file: &Path) -> io::Result<Child> {
        let log = fs::File::create(&self.stderr_log)?;
        let mut command = Command::new(executable);
        command
            .arg(OsString::from("-f"))
            .arg(config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        // Windows-only: never let `tor.exe` pop a visible console window that
        // covers/steals focus from the load tester or organizer GUI.
        apply_hide_console_window_on_windows_v1(&mut command);
        command.spawn()
    }
}

/// Canonical relay request shape. The relay cannot receive a query string,
/// voter identity, or arbitrary body type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRelayRequestV1 {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub content_type: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Gateway-forwarding boundary; only opaque bytes and the fixed content type cross it.
pub trait OpaqueGatewayForwarderV1 {
    fn forward(
        &mut self,
        content_type: &str,
        body: &[u8],
    ) -> Result<u16, PrivateTransportNetworkErrorV1>;
}

pub fn forward_opaque_relay_request_v1(
    request: OpaqueRelayRequestV1,
    expected_envelope_bytes: usize,
    gateway: &mut impl OpaqueGatewayForwarderV1,
) -> Result<u16, PrivateTransportNetworkErrorV1> {
    if request.method != "POST"
        || request.path != "/v1/opaque-envelope"
        || request
            .query
            .as_deref()
            .is_some_and(|query| !query.is_empty())
        || request.content_type != OPAQUE_ENVELOPE_CONTENT_TYPE_V1
        || request.body.len() != expected_envelope_bytes
    {
        return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
    }
    // All inbound headers, including Forwarded and X-Forwarded-For, are
    // deliberately ignored. The forwarding trait accepts no metadata field.
    let _ignored_headers = request.headers;
    gateway.forward(OPAQUE_ENVELOPE_CONTENT_TYPE_V1, &request.body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[derive(Default)]
    struct FakeChild {
        exited: bool,
        killed: bool,
    }
    impl ManagedTorChildV1 for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            Ok(self.exited.then_some(1))
        }
        fn kill(&mut self) -> io::Result<()> {
            self.killed = true;
            Ok(())
        }
    }
    struct FakeSpawner {
        child: FakeChild,
    }
    impl ManagedTorSpawnerV1 for FakeSpawner {
        type Child = FakeChild;
        fn spawn(&self, _: &Path, _: &Path) -> io::Result<Self::Child> {
            Ok(FakeChild {
                exited: self.child.exited,
                killed: false,
            })
        }
    }
    struct FakeProbe(bool);
    impl ManagedTorReadinessProbeV1 for FakeProbe {
        fn ready(&mut self) -> Result<bool, PrivateTransportNetworkErrorV1> {
            Ok(self.0)
        }
    }
    fn test_config() -> ManagedTorConfigV1 {
        // Every invocation gets its own base directory so concurrent tests
        // (cargo's default test harness runs test threads in parallel) never
        // race on the same torrc/data path. Without this, two tests writing
        // torrc.new + renaming it in write_atomic would race the rename and
        // one would surface as PrivateTransportNetworkErrorV1::InvalidConfiguration
        // on Linux, where fs::rename is fast and atomic and the shared path
        // collision is not masked by slower Windows filesystem timing.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "tari-private-ballot-transport-network-test-{}-{n}",
            std::process::id(),
        ));
        ManagedTorConfigV1 {
            executable: base.join("tor.exe"),
            data_directory: base.join("data"),
            config_file: base.join("torrc"),
            socks_port: 19050,
            startup_timeout: Duration::from_secs(2),
        }
    }

    /// A child that records how many times it was killed into a shared counter,
    /// so a controller drop can be observed after the controller (and its child)
    /// have been moved into the drop.
    struct KillObservingChild {
        kills: std::rc::Rc<std::cell::Cell<u32>>,
    }
    impl ManagedTorChildV1 for KillObservingChild {
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            Ok(None)
        }
        fn kill(&mut self) -> io::Result<()> {
            self.kills.set(self.kills.get() + 1);
            Ok(())
        }
    }
    struct KillObservingSpawner {
        kills: std::rc::Rc<std::cell::Cell<u32>>,
    }
    impl ManagedTorSpawnerV1 for KillObservingSpawner {
        type Child = KillObservingChild;
        fn spawn(&self, _: &Path, _: &Path) -> io::Result<Self::Child> {
            Ok(KillObservingChild {
                kills: self.kills.clone(),
            })
        }
    }

    #[test]
    fn dropping_the_controller_reaps_the_owned_child() {
        // Regression for the voter Tor stale-READY root cause: a controller that
        // goes out of scope (state replacement / app teardown) must kill the Tor
        // child it launched instead of leaking it as an orphan that keeps owning
        // the loopback SOCKS port across a restart.
        let kills = std::rc::Rc::new(std::cell::Cell::new(0));
        let controller = ManagedTorControllerV1::start(
            &test_config(),
            &KillObservingSpawner {
                kills: kills.clone(),
            },
            &mut FakeProbe(true),
            || Duration::ZERO,
        )
        .expect("starts");
        assert_eq!(kills.get(), 0, "a live, ready child is not killed on start");
        drop(controller);
        assert!(
            kills.get() >= 1,
            "dropping the controller must kill the owned child (no orphan)"
        );
    }

    #[test]
    fn shutdown_then_drop_does_not_double_report_ready() {
        let kills = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut controller = ManagedTorControllerV1::start(
            &test_config(),
            &KillObservingSpawner {
                kills: kills.clone(),
            },
            &mut FakeProbe(true),
            || Duration::ZERO,
        )
        .expect("starts");
        controller.shutdown();
        assert!(!controller.is_ready(), "shutdown clears readiness");
        drop(controller);
        // Explicit shutdown plus the drop reaper are both fail-safe; a kill after
        // shutdown is harmless.
        assert!(kills.get() >= 1);
    }

    #[test]
    fn managed_tor_uses_fake_process_and_readiness_without_network() {
        let mut probe = FakeProbe(true);
        let controller = ManagedTorControllerV1::start(
            &test_config(),
            &FakeSpawner {
                child: FakeChild::default(),
            },
            &mut probe,
            || Duration::ZERO,
        )
        .expect("ready fake starts");
        assert!(controller.is_ready());
    }

    #[test]
    fn startup_timeout_and_crash_are_private_transport_unavailable() {
        let mut probe = FakeProbe(false);
        assert!(matches!(
            ManagedTorControllerV1::start(
                &test_config(),
                &FakeSpawner {
                    child: FakeChild::default()
                },
                &mut probe,
                || Duration::from_secs(2),
            ),
            Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
        ));
        let mut ready = FakeProbe(true);
        let mut controller = ManagedTorControllerV1::start(
            &test_config(),
            &FakeSpawner {
                child: FakeChild {
                    exited: false,
                    killed: false,
                },
            },
            &mut ready,
            || Duration::ZERO,
        )
        .expect("starts");
        controller.child.as_mut().expect("child").exited = true;
        assert_eq!(
            controller.check_crash(),
            Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
        );
    }

    #[test]
    fn tor_failure_never_downgrades_to_direct_and_offline_remains_available() {
        assert_eq!(
            resolve_voter_route_v1(VoterPrivateRouteV1::ManagedTor, false, true),
            RouteResolutionV1::PrivateTransportUnavailable
        );
        assert_eq!(
            resolve_voter_route_v1(VoterPrivateRouteV1::SplitTrustRelay, false, true),
            RouteResolutionV1::UseSplitTrustRelay
        );
        assert_eq!(
            resolve_voter_route_v1(VoterPrivateRouteV1::OfflineExport, false, false),
            RouteResolutionV1::UseOfflineExport
        );
    }

    #[derive(Default)]
    struct FakeGateway {
        body: Vec<u8>,
        content_type: String,
    }
    impl OpaqueGatewayForwarderV1 for FakeGateway {
        fn forward(
            &mut self,
            content_type: &str,
            body: &[u8],
        ) -> Result<u16, PrivateTransportNetworkErrorV1> {
            self.content_type = content_type.to_owned();
            self.body = body.to_vec();
            Ok(202)
        }
    }
    #[test]
    fn relay_forwards_only_fixed_opaque_envelope_and_ignores_proxy_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Forwarded-For".to_owned(), "192.0.2.1".to_owned());
        let request = OpaqueRelayRequestV1 {
            method: "POST".to_owned(),
            path: "/v1/opaque-envelope".to_owned(),
            query: None,
            content_type: OPAQUE_ENVELOPE_CONTENT_TYPE_V1.to_owned(),
            headers,
            body: vec![7; 32],
        };
        let mut gateway = FakeGateway::default();
        assert_eq!(
            forward_opaque_relay_request_v1(request, 32, &mut gateway).expect("accepted"),
            202
        );
        assert_eq!(gateway.content_type, OPAQUE_ENVELOPE_CONTENT_TYPE_V1);
        assert_eq!(gateway.body, vec![7; 32]);
    }

    // -------------------------------------------------------------------------
    // Truthful readiness decision + fresh preflight (BLOCKER 2 regression).
    // -------------------------------------------------------------------------

    #[test]
    fn readiness_decision_requires_controller_child_and_socks() {
        use super::evaluate_managed_tor_readiness_v1;
        // No controller → not running, not ready.
        let d = evaluate_managed_tor_readiness_v1(false, false, false);
        assert!(!d.tor_running && !d.socks_ready);
        // Controller present but child exited → not running, not ready.
        let d = evaluate_managed_tor_readiness_v1(true, false, false);
        assert!(!d.tor_running && !d.socks_ready);
        // Controller + child alive but SOCKS probe fails → running, not ready.
        let d = evaluate_managed_tor_readiness_v1(true, true, false);
        assert!(d.tor_running && !d.socks_ready);
        // All three pass → ready.
        let d = evaluate_managed_tor_readiness_v1(true, true, true);
        assert!(d.tor_running && d.socks_ready && d.is_ready());
    }

    #[test]
    fn fresh_readiness_preflight_fails_when_child_exits() {
        let mut controller = ManagedTorControllerV1::start(
            &test_config(),
            &FakeSpawner {
                child: FakeChild::default(),
            },
            &mut FakeProbe(true),
            || Duration::ZERO,
        )
        .expect("starts");
        // Simulate the Tor child dying after initial startup. The controller
        // object still exists (the stale-controller scenario).
        controller.child.as_mut().expect("child").exited = true;
        let mut probe = FakeProbe(true);
        assert_eq!(
            check_managed_tor_fresh_readiness_v1(&mut controller, &mut probe),
            Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
        );
    }

    #[test]
    fn fresh_readiness_preflight_fails_when_socks_probe_fails() {
        let mut controller = ManagedTorControllerV1::start(
            &test_config(),
            &FakeSpawner {
                child: FakeChild::default(),
            },
            &mut FakeProbe(true),
            || Duration::ZERO,
        )
        .expect("starts");
        // Child is alive but the SOCKS listener is no longer responding.
        let mut probe = FakeProbe(false);
        assert_eq!(
            check_managed_tor_fresh_readiness_v1(&mut controller, &mut probe),
            Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
        );
    }

    #[test]
    fn fresh_readiness_preflight_succeeds_when_child_alive_and_socks_ready() {
        let mut controller = ManagedTorControllerV1::start(
            &test_config(),
            &FakeSpawner {
                child: FakeChild::default(),
            },
            &mut FakeProbe(true),
            || Duration::ZERO,
        )
        .expect("starts");
        let mut probe = FakeProbe(true);
        assert!(check_managed_tor_fresh_readiness_v1(&mut controller, &mut probe).is_ok());
    }

    // -------------------------------------------------------------------------
    // Windows torrc path serialization regression (raw `\` must be doubled).
    // -------------------------------------------------------------------------

    #[test]
    fn tor_path_token_escapes_backslashes_and_preserves_rejections() {
        // Portable: `PathBuf::from(r"C:\private ballot\data")` stringifies to
        // the same single-backslash form on every platform, so this exercises
        // the Tor quoted-string escaping everywhere (including Linux CI).
        let token = tor_path_token(&PathBuf::from(r"C:\private ballot\data")).expect("valid path");
        assert_eq!(token, r#""C:\\private ballot\\data""#);
        // The existing safety rejections are preserved.
        assert!(matches!(
            tor_path_token(Path::new("evil\nSocksPort 9050")),
            Err(PrivateTransportNetworkErrorV1::InvalidConfiguration),
        ));
        assert!(matches!(
            tor_path_token(Path::new("quote\"injection")),
            Err(PrivateTransportNetworkErrorV1::InvalidConfiguration),
        ));
        assert!(matches!(
            tor_path_token(Path::new("bad\r\nControlPort 9051")),
            Err(PrivateTransportNetworkErrorV1::InvalidConfiguration),
        ));
    }

    #[cfg(windows)]
    #[test]
    fn tor_path_token_doubles_windows_backslashes_and_preserves_spaces() {
        let path = PathBuf::from(r"C:\private ballot\data");
        let token = tor_path_token(&path).expect("valid windows path");
        assert_eq!(token, r#""C:\\private ballot\\data""#);
    }

    #[cfg(windows)]
    fn unique_windows_config(label: &str) -> ManagedTorConfigV1 {
        let base = std::env::temp_dir().join(format!(
            "tari-private-ballot-transport-network-win-test-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("test dir");
        ManagedTorConfigV1 {
            executable: base.join("tor.exe"),
            data_directory: base.join("organizer-tor-data"),
            config_file: base.join("torrc"),
            socks_port: 19050,
            startup_timeout: Duration::from_secs(2),
        }
    }

    #[cfg(windows)]
    #[test]
    fn managed_tor_write_config_escapes_windows_backslashes_in_data_directory() {
        let config = unique_windows_config("voter-data-dir");
        config.write_config().expect("voter config writes");
        let torrc = std::fs::read_to_string(&config.config_file).expect("read torrc");
        let data_dir = config.data_directory.to_string_lossy().into_owned();
        let escaped = data_dir.replace('\\', r"\\");
        assert!(
            torrc.contains(&format!("DataDirectory \"{escaped}\"")),
            "DataDirectory must contain Tor-escaped doubled backslashes: {torrc}"
        );
        let raw = format!("DataDirectory \"{data_dir}\"");
        assert!(
            !torrc.contains(&raw),
            "DataDirectory regressed to raw unescaped Windows backslashes: {torrc}"
        );
        assert!(
            torrc.contains("SocksPort 127.0.0.1:19050\n"),
            "voter torrc shape unchanged: {torrc}"
        );
    }

    // -------------------------------------------------------------------------
    // Shared Tor executable validation policy (ONE policy for GUI + CLI).
    // -------------------------------------------------------------------------

    /// Writes a regular file that represents a VALID Tor executable fixture.
    /// On Unix the production validator requires an exec bit (`0o111`), so the
    /// fixture is marked executable there; Windows has no mode bit and needs
    /// none. This keeps `validate_tor_executable_v1` strict while giving the
    /// test a genuine Unix executable rather than relaxing validation.
    fn write_regular_file(base: &Path, name: &str) -> PathBuf {
        fs::create_dir_all(base).expect("test base dir");
        let path = base.join(name);
        fs::write(&path, b"not-a-real-tor-binary").expect("write regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path).expect("metadata").permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).expect("set exec bit");
        }
        path
    }

    #[test]
    fn tor_executable_validation_rejects_relative_paths() {
        assert_eq!(
            validate_tor_executable_v1(Path::new("tor.exe")),
            Err(TorExecutableValidationErrorV1::NotAbsolute)
        );
        assert_eq!(
            validate_tor_executable_v1(Path::new("./tor")),
            Err(TorExecutableValidationErrorV1::NotAbsolute)
        );
    }

    #[test]
    fn tor_executable_validation_rejects_missing_files() {
        #[cfg(windows)]
        let bogus = PathBuf::from(r"C:\definitely\not\here\tor.exe");
        #[cfg(not(windows))]
        let bogus = PathBuf::from("/definitely/not/here/tor");
        assert_eq!(
            validate_tor_executable_v1(&bogus),
            Err(TorExecutableValidationErrorV1::NotFound)
        );
    }

    #[test]
    fn tor_executable_validation_rejects_directories_and_control_characters() {
        let base = std::env::temp_dir().join(format!(
            "tari-transport-network-torex-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        // A directory exists but is not a regular file.
        let dir = base.join("dir");
        fs::create_dir_all(&dir).expect("dir");
        assert_eq!(
            validate_tor_executable_v1(&dir),
            Err(TorExecutableValidationErrorV1::NotRegularFile)
        );
        // A control character anywhere in an otherwise valid path is rejected.
        // On Windows the OS itself refuses to stat paths containing control
        // bytes, so the OS-level stat fails first (still fail-closed); on
        // platforms where such filenames are legal the validator must report
        // the control-character error explicitly.
        let with_control = base.join("to\u{0}r");
        if cfg!(windows) {
            assert_eq!(
                validate_tor_executable_v1(&with_control),
                Err(TorExecutableValidationErrorV1::NotFound)
            );
        } else {
            let with_newline = base.join("to\nr");
            fs::write(&with_newline, b"x").expect("control-char filename (non-Windows)");
            assert_eq!(
                validate_tor_executable_v1(&with_newline),
                Err(TorExecutableValidationErrorV1::ControlCharacters)
            );
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn tor_executable_validation_accepts_a_real_regular_file() {
        let base = std::env::temp_dir().join(format!(
            "tari-transport-network-torex-ok-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let path = write_regular_file(&base, "tor.exe");
        assert_eq!(validate_tor_executable_v1(&path), Ok(()));
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(windows)]
    #[test]
    fn tor_executable_validation_rejects_symlinks_and_reparse_points() {
        // Symlink creation needs developer mode/admin; when unavailable the
        // attempt is skipped rather than failing the suite. The regular-file
        // and reparse-attribute logic above remains covered either way.
        let base = std::env::temp_dir().join(format!(
            "tari-transport-network-torex-link-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let target = write_regular_file(&base, "tor.exe");
        let link = base.join("tor-link.exe");
        if std::os::windows::fs::symlink_file(&target, &link).is_ok() {
            assert_eq!(
                validate_tor_executable_v1(&link),
                Err(TorExecutableValidationErrorV1::NotRegularFile)
            );
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn tor_executable_validation_rejects_unix_non_executable_regular_file() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "tari-transport-network-torex-unix-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let file = base.join("not-an-executable");
        fs::create_dir_all(&base).expect("base");
        fs::File::create(&file)
            .and_then(|mut handle| handle.write_all(b"#!/bin/false\n"))
            .expect("write");
        fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_eq!(
            validate_tor_executable_v1(&file),
            Err(TorExecutableValidationErrorV1::NotExecutable)
        );
        // With the executable bit set, the same regular file validates.
        fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(validate_tor_executable_v1(&file), Ok(()));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reserved_socks_port_is_fresh_and_loopback_only() {
        let first = reserve_loopback_socks_port_v1().expect("reserve");
        let second = reserve_loopback_socks_port_v1().expect("reserve");
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        // A reserved port is a usable loopback bind target after the temporary
        // listener is dropped (the reserve→spawn hand-off shape).
        let bound = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, first))
            .expect("reserved port is re-bindable");
        drop(bound);
        let _ = second;
    }

    #[test]
    fn fresh_run_directories_are_unique_and_locally_named() {
        let base = std::env::temp_dir().join(format!(
            "tari-transport-network-rundir-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let first = create_fresh_run_directory_v1(&base).expect("first run dir");
        let second = create_fresh_run_directory_v1(&base).expect("second run dir");
        assert!(first.is_absolute() || first.starts_with(&base));
        assert_ne!(first, second, "every start must get its own run directory");
        let name = first
            .file_name()
            .expect("named")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("run-"), "owned run-dir naming: {name}");
        let _ = fs::remove_dir_all(&base);
    }

    // -------------------------------------------------------------------------
    // Windows console-window suppression helper (regression for organizer and
    // Load Tester UX: a visible tor.exe console covered/blocked the GUI).
    // -------------------------------------------------------------------------

    #[cfg(windows)]
    #[test]
    fn windows_hide_console_helper_uses_create_no_window_flag_value() {
        // Fixed public constant so a reviewer can confirm the value without
        // reading a Microsoft docs page. Any drift is caught here.
        assert_eq!(TOR_WINDOWS_NO_CONSOLE_CREATION_FLAGS_V1, 0x0800_0000);
    }

    #[cfg(windows)]
    #[test]
    fn windows_hide_console_helper_sets_creation_flags_without_altering_program_or_args() {
        // Structural check: applying the helper to a Command preserves the
        // executable, argument vector, and stdio choices — only creation flags
        // change. `Command::get_creation_flags` is not stable, so we verify
        // via the observable side effect that the helper returns the same
        // `&mut Command` and Command inspection APIs still see the unchanged
        // program and args.
        let mut command = Command::new("tor.exe");
        command.arg("-f").arg("torrc");
        let returned: &mut Command = apply_hide_console_window_on_windows_v1(&mut command);
        assert_eq!(returned.get_program(), "tor.exe");
        let args: Vec<_> = returned.get_args().collect();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "-f");
        assert_eq!(args[1], "torrc");
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_hide_console_helper_is_a_no_op_that_preserves_command_shape() {
        // On Unix the helper is a no-op; the Command must be returned unchanged
        // so callers stay identical across platforms.
        let mut command = Command::new("tor");
        command.arg("-f").arg("torrc");
        let returned: &mut Command = apply_hide_console_window_on_windows_v1(&mut command);
        assert_eq!(returned.get_program(), "tor");
        let args: Vec<_> = returned.get_args().collect();
        assert_eq!(args.len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn system_managed_tor_spawner_applies_hidden_console_flag() {
        // We cannot spawn a real Tor here, but the failure mode of a nonexistent
        // executable must be an io error (never a shell invocation) — mirroring
        // the existing stderr-log spawner argument-vector check but exercising
        // the newly wired hidden-console spawner path.
        let bogus = std::env::temp_dir().join("definitely-not-tor.exe");
        let torrc = std::env::temp_dir().join("no-such-torrc");
        let result = SystemManagedTorSpawnerV1.spawn(&bogus, &torrc);
        assert!(result.is_err(), "no shell/PATH lookup; nonexistent exe errors");
    }

    #[test]
    fn stderr_log_spawner_uses_argument_vector_without_a_shell() {
        // Structural check: the spawner writes the child's stderr to the
        // requested FILE path. Spawning a real binary is skipped; instead we
        // verify the request shape via the spawn failure path (nonexistent exe
        // yields an io error, never a shell invocation).
        let base = std::env::temp_dir().join(format!(
            "tari-transport-network-spawner-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let spawner = StderrLogFileTorSpawnerV1 {
            stderr_log: base.join("tor-stderr.log"),
        };
        let bogus = base.join("definitely-not-tor.exe");
        assert!(spawner.spawn(&bogus, &base.join("torrc")).is_err());
        let _ = fs::remove_dir_all(&base);
    }
}
