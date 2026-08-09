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

pub const OPAQUE_ENVELOPE_CONTENT_TYPE_V1: &str = "application/vnd.tari-cc-private-ballot-envelope-v1";

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
            Self::PrivateTransportUnavailable => "private transport unavailable; choose relay explicitly or use offline export",
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
        VoterPrivateRouteV1::SplitTrustRelay if relay_available => RouteResolutionV1::UseSplitTrustRelay,
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

fn has_control_path_component(path: &Path) -> bool {
    path.as_os_str().to_string_lossy().chars().any(char::is_control)
}

fn tor_path_token(path: &Path) -> Result<String, PrivateTransportNetworkErrorV1> {
    let token = path.to_string_lossy();
    if token.contains('"') || token.contains('\n') || token.contains('\r') {
        return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
    }
    Ok(format!("\"{token}\""))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PrivateTransportNetworkErrorV1> {
    let parent = path.parent().ok_or(PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    fs::create_dir_all(parent).map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    let temporary = path.with_extension("new");
    fs::write(&temporary, bytes).map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
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
                return Ok(Self { child: Some(child), ready: true });
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
        let child = self.child.as_mut().ok_or(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
        if child.try_wait().map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?.is_some() {
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
    fn forward(&mut self, content_type: &str, body: &[u8]) -> Result<u16, PrivateTransportNetworkErrorV1>;
}

pub fn forward_opaque_relay_request_v1(
    request: OpaqueRelayRequestV1,
    expected_envelope_bytes: usize,
    gateway: &mut impl OpaqueGatewayForwarderV1,
) -> Result<u16, PrivateTransportNetworkErrorV1> {
    if request.method != "POST"
        || request.path != "/v1/opaque-envelope"
        || request.query.as_deref().is_some_and(|query| !query.is_empty())
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
    struct FakeChild { exited: bool, killed: bool }
    impl ManagedTorChildV1 for FakeChild {
        fn try_wait(&mut self) -> io::Result<Option<i32>> { Ok(self.exited.then_some(1)) }
        fn kill(&mut self) -> io::Result<()> { self.killed = true; Ok(()) }
    }
    struct FakeSpawner { child: FakeChild }
    impl ManagedTorSpawnerV1 for FakeSpawner {
        type Child = FakeChild;
        fn spawn(&self, _: &Path, _: &Path) -> io::Result<Self::Child> { Ok(FakeChild { exited: self.child.exited, killed: false }) }
    }
    struct FakeProbe(bool);
    impl ManagedTorReadinessProbeV1 for FakeProbe {
        fn ready(&mut self) -> Result<bool, PrivateTransportNetworkErrorV1> { Ok(self.0) }
    }
    fn test_config() -> ManagedTorConfigV1 {
        let base = std::env::temp_dir().join("tari-private-ballot-transport-network-test");
        ManagedTorConfigV1 { executable: base.join("tor.exe"), data_directory: base.join("data"), config_file: base.join("torrc"), socks_port: 19050, startup_timeout: Duration::from_secs(2) }
    }

    #[test]
    fn managed_tor_uses_fake_process_and_readiness_without_network() {
        let mut probe = FakeProbe(true);
        let controller = ManagedTorControllerV1::start(&test_config(), &FakeSpawner { child: FakeChild::default() }, &mut probe, || Duration::ZERO).expect("ready fake starts");
        assert!(controller.is_ready());
    }

    #[test]
    fn startup_timeout_and_crash_are_private_transport_unavailable() {
        let mut probe = FakeProbe(false);
        assert!(matches!(
            ManagedTorControllerV1::start(
                &test_config(),
                &FakeSpawner { child: FakeChild::default() },
                &mut probe,
                || Duration::from_secs(2),
            ),
            Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
        ));
        let mut ready = FakeProbe(true);
        let mut controller = ManagedTorControllerV1::start(&test_config(), &FakeSpawner { child: FakeChild { exited: false, killed: false } }, &mut ready, || Duration::ZERO).expect("starts");
        controller.child.as_mut().expect("child").exited = true;
        assert_eq!(controller.check_crash(), Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable));
    }

    #[test]
    fn tor_failure_never_downgrades_to_direct_and_offline_remains_available() {
        assert_eq!(resolve_voter_route_v1(VoterPrivateRouteV1::ManagedTor, false, true), RouteResolutionV1::PrivateTransportUnavailable);
        assert_eq!(resolve_voter_route_v1(VoterPrivateRouteV1::SplitTrustRelay, false, true), RouteResolutionV1::UseSplitTrustRelay);
        assert_eq!(resolve_voter_route_v1(VoterPrivateRouteV1::OfflineExport, false, false), RouteResolutionV1::UseOfflineExport);
    }

    #[derive(Default)]
    struct FakeGateway { body: Vec<u8>, content_type: String }
    impl OpaqueGatewayForwarderV1 for FakeGateway {
        fn forward(&mut self, content_type: &str, body: &[u8]) -> Result<u16, PrivateTransportNetworkErrorV1> { self.content_type = content_type.to_owned(); self.body = body.to_vec(); Ok(202) }
    }
    #[test]
    fn relay_forwards_only_fixed_opaque_envelope_and_ignores_proxy_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Forwarded-For".to_owned(), "192.0.2.1".to_owned());
        let request = OpaqueRelayRequestV1 { method: "POST".to_owned(), path: "/v1/opaque-envelope".to_owned(), query: None, content_type: OPAQUE_ENVELOPE_CONTENT_TYPE_V1.to_owned(), headers, body: vec![7; 32] };
        let mut gateway = FakeGateway::default();
        assert_eq!(forward_opaque_relay_request_v1(request, 32, &mut gateway).expect("accepted"), 202);
        assert_eq!(gateway.content_type, OPAQUE_ENVELOPE_CONTENT_TYPE_V1);
        assert_eq!(gateway.body, vec![7; 32]);
    }
}
