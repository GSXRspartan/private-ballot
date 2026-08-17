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

mod organizer_hidden_service;
mod tor;

pub use organizer_hidden_service::{
    DiscoveryTimeoutV1, HostnameDiscoveryErrorV1, OrganizerHiddenServiceTorConfigV1,
    discover_organizer_onion_hostname_v1,
};
pub use tor::{
    ONION_VIRTUAL_PORT_V1, OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1, OPAQUE_ENVELOPE_HTTP_PATH_V1,
    StrictHeaderErrorV1, SystemManagedTorReadinessProbeV1, TorCarrierTimeoutsV1,
    TorSocksPrivateReleaseCarrierV1, parse_strict_content_length_v1, parse_strict_header_line_v1,
    validate_loopback_socket_addr_v1, validate_onion_hostname_v1,
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
        Command::new(executable)
            .arg(OsString::from("-f"))
            .arg(config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    }
}

/// Readiness is separately injected: deployment code may use a loopback SOCKS
/// probe while tests use a deterministic fake. It is never a public-Internet probe.
pub trait ManagedTorReadinessProbeV1 {
    fn ready(&mut self) -> Result<bool, PrivateTransportNetworkErrorV1>;
}

#[derive(Debug)]
pub struct ManagedTorControllerV1<C> {
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
        let base = std::env::temp_dir().join("tari-private-ballot-transport-network-test");
        ManagedTorConfigV1 {
            executable: base.join("tor.exe"),
            data_directory: base.join("data"),
            config_file: base.join("torrc"),
            socks_port: 19050,
            startup_timeout: Duration::from_secs(2),
        }
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
}
