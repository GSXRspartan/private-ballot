//! Explicit, advanced **Remote SOCKS Tor** transport mode.
//!
//! This module adds a SECOND, deliberately opt-in Tor transport mode alongside
//! the existing (default) managed-local-Tor mode. In remote-SOCKS mode Private
//! Ballot does NOT spawn, validate, own, or stop a Tor process: the operator
//! supplies an already-running Tor SOCKS proxy endpoint (on a trusted LAN, VPN,
//! or tunnelled link) and the application uses it purely as an outbound SOCKS5
//! client for onion traffic.
//!
//! Trust boundary (enforced structurally by the types here and documented for
//! the UI): the application can validate the endpoint syntax, TCP connectivity,
//! the SOCKS5 handshake, and onion reachability THROUGH the proxy. It can NOT
//! validate the remote Tor process identity, binary, version, lifecycle,
//! configuration, host security, or stream isolation — that daemon is
//! externally managed. Nothing in this module ever treats a remote proxy as an
//! owned process.
//!
//! Security invariants preserved from managed-local mode:
//!   * onion destinations remain onion-only (sent as a SOCKS5 `DOMAINNAME`
//!     literal — never resolved through the local OS resolver);
//!   * there is NO clearnet fallback: a proxy or onion failure fails closed;
//!   * no ballot application bytes leave the process during a readiness probe.
//!
//! The one deliberate relaxation relative to managed-local mode is that the
//! SOCKS PROXY endpoint itself may be non-loopback (a LAN/VPN address or a
//! hostname). That is the whole point of the mode, and it is scoped to a
//! DISTINCT type ([`RemoteSocksEndpointV1`]) so the managed-local loopback
//! requirement ([`crate::validate_loopback_socket_addr_v1`]) is never weakened.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::PrivateTransportNetworkErrorV1;

/// Which Tor transport mode the application uses. This is the explicit typed
/// alternative to scattering booleans through the code. `ManagedLocal` is the
/// default and recommended mode (the application owns the Tor process);
/// `RemoteSocks` is the advanced, opt-in mode (an externally managed proxy).
///
/// A missing/legacy persisted value must resolve to [`Self::ManagedLocal`] —
/// see [`Self::default`]. The serde representation is a stable lowercase-kebab
/// string so persisted settings survive a rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TorTransportModeV1 {
    /// Default. The application starts, owns, and stops a local Tor process
    /// with a loopback SOCKS listener (existing managed-Tor behaviour).
    #[default]
    ManagedLocal,
    /// Advanced/opt-in. The application uses an externally managed Tor SOCKS
    /// proxy and never spawns, validates, or stops a Tor process.
    RemoteSocks,
}

impl TorTransportModeV1 {
    /// Stable wire/persistence token. Chosen so a future rename cannot silently
    /// change what a persisted setting resolves to.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::ManagedLocal => "managed-local",
            Self::RemoteSocks => "remote-socks",
        }
    }

    /// Parses a persisted/UI token back into a mode. An unknown or empty token
    /// resolves to the default managed-local mode (fail SAFE toward the
    /// recommended, process-owned path — never silently toward the advanced
    /// remote path).
    #[must_use]
    pub fn from_token_or_default(token: &str) -> Self {
        match token {
            "remote-socks" => Self::RemoteSocks,
            // "managed-local", "", and every unknown legacy value resolve to the
            // recommended default.
            _ => Self::ManagedLocal,
        }
    }
}

/// Why a candidate remote SOCKS endpoint string was rejected. Distinct variants
/// exist so the UI and tests can tell the failures apart; every message is
/// bounded and never echoes the offending value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSocksEndpointErrorV1 {
    /// The host portion was empty.
    EmptyHost,
    /// The port was missing, non-numeric, out of range, or zero.
    InvalidPort,
    /// The host contained a scheme (`://`), path, userinfo (`@`), query,
    /// whitespace, control characters, or was otherwise not a bare
    /// host:port endpoint.
    Malformed,
    /// The host was syntactically a hostname but violated DNS label rules
    /// (length, empty label, illegal character, or leading/trailing hyphen).
    InvalidHost,
}

impl std::fmt::Display for RemoteSocksEndpointErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyHost => "the SOCKS host must not be empty",
            Self::InvalidPort => "the SOCKS port must be a number between 1 and 65535",
            Self::Malformed => {
                "the SOCKS endpoint must be a bare host:port (no scheme, path, or credentials)"
            }
            Self::InvalidHost => "the SOCKS host is not a valid IP address or hostname",
        })
    }
}

impl std::error::Error for RemoteSocksEndpointErrorV1 {}

/// Maximum length of a DNS hostname (RFC 1035). Also the ceiling used to reject
/// absurd inputs before any allocation-heavy work.
const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length of a single DNS label.
const MAX_LABEL_LEN: usize = 63;

/// A validated remote SOCKS proxy endpoint: a bare `host:port`, where `host` is
/// an IPv4 literal, an IPv6 literal (stored WITHOUT brackets), or a DNS
/// hostname, and `port` is non-zero.
///
/// This type intentionally supports ONLY a simple explicit host+port — never an
/// arbitrary URL scheme, path, or userinfo — matching the current transport
/// abstraction, which speaks SOCKS5 to a numeric-or-hostname endpoint. It is a
/// DISTINCT type from the managed-local loopback [`SocketAddr`] so that the
/// managed-local loopback requirement is never relaxed to build this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSocksEndpointV1 {
    host: String,
    port: u16,
    is_ipv6_literal: bool,
}

impl RemoteSocksEndpointV1 {
    /// Parses and validates a `host:port` string. Rejects empty host, missing
    /// or zero port, schemes, paths, userinfo, query strings, whitespace,
    /// control characters, and malformed hostnames/IPs. Surrounding whitespace
    /// is trimmed first; internal whitespace is rejected.
    pub fn parse(raw: &str) -> Result<Self, RemoteSocksEndpointErrorV1> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(RemoteSocksEndpointErrorV1::EmptyHost);
        }
        // Reject anything that is not a bare host:port. A scheme, path,
        // userinfo, query, fragment, backslash, or any whitespace/control byte
        // means this is not the simple endpoint form this mode accepts.
        if trimmed.contains("://")
            || trimmed.contains('/')
            || trimmed.contains('\\')
            || trimmed.contains('@')
            || trimmed.contains('?')
            || trimmed.contains('#')
            || trimmed.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        {
            return Err(RemoteSocksEndpointErrorV1::Malformed);
        }

        // Bracketed IPv6 literal: [addr]:port.
        if let Some(rest) = trimmed.strip_prefix('[') {
            let close = rest
                .find(']')
                .ok_or(RemoteSocksEndpointErrorV1::Malformed)?;
            let host = &rest[..close];
            let after = &rest[close + 1..];
            let port_str = after
                .strip_prefix(':')
                .ok_or(RemoteSocksEndpointErrorV1::InvalidPort)?;
            let port = parse_port(port_str)?;
            if host.parse::<Ipv6Addr>().is_err() {
                return Err(RemoteSocksEndpointErrorV1::InvalidHost);
            }
            return Ok(Self {
                host: host.to_owned(),
                port,
                is_ipv6_literal: true,
            });
        }

        // Unbracketed: split at the LAST colon so IPv4/hostname works. A bare
        // unbracketed IPv6 literal (multiple colons in the host) is rejected —
        // IPv6 must be bracketed so the port is unambiguous.
        let (host, port_str) = trimmed
            .rsplit_once(':')
            .ok_or(RemoteSocksEndpointErrorV1::InvalidPort)?;
        if host.is_empty() {
            return Err(RemoteSocksEndpointErrorV1::EmptyHost);
        }
        let port = parse_port(port_str)?;
        if host.contains(':') {
            // Remaining colon ⇒ an unbracketed IPv6 literal; require brackets.
            return Err(RemoteSocksEndpointErrorV1::Malformed);
        }
        if host.parse::<Ipv4Addr>().is_ok() {
            return Ok(Self {
                host: host.to_owned(),
                port,
                is_ipv6_literal: false,
            });
        }
        validate_hostname(host)?;
        Ok(Self {
            host: host.to_owned(),
            port,
            is_ipv6_literal: false,
        })
    }

    /// Re-validates already-parsed components (used when reloading persisted
    /// settings, which must be validated again and fail closed if malformed).
    pub fn from_parts(host: &str, port: u16) -> Result<Self, RemoteSocksEndpointErrorV1> {
        // Reconstruct the canonical string form and re-run the full parser so a
        // persisted endpoint gets exactly the same strict validation as fresh
        // user input — no shortcut trust path.
        if host.contains(':') && host.parse::<Ipv6Addr>().is_ok() {
            Self::parse(&format!("[{host}]:{port}"))
        } else {
            Self::parse(&format!("{host}:{port}"))
        }
    }

    /// The validated host (IPv6 literals are stored without brackets).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The validated non-zero port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether the endpoint's proxy address is a loopback IP. A hostname (even
    /// `localhost`) is treated as non-loopback because it is not a numeric
    /// loopback literal — the security note about trusting the app↔proxy link
    /// always applies to remote mode regardless.
    #[must_use]
    pub fn is_loopback_ip(&self) -> bool {
        if let Ok(v4) = self.host.parse::<Ipv4Addr>() {
            return v4.is_loopback();
        }
        if let Ok(v6) = self.host.parse::<Ipv6Addr>() {
            return v6.is_loopback();
        }
        false
    }

    /// Canonical display form (`host:port`, bracketing IPv6 literals). Safe to
    /// show and persist — a SOCKS endpoint is not itself secret.
    #[must_use]
    pub fn display(&self) -> String {
        if self.is_ipv6_literal {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Opens a bounded TCP connection to the remote SOCKS proxy.
    ///
    /// Resolving a HOSTNAME here resolves the PROXY's own address only — it
    /// never resolves a `.onion` (onion destinations are always sent to the
    /// proxy as a SOCKS5 `DOMAINNAME` literal). A resolution or connect failure
    /// is a hard, fail-closed error: there is no clearnet fallback.
    pub(crate) fn connect(
        &self,
        connect_timeout: Duration,
    ) -> Result<TcpStream, PrivateTransportNetworkErrorV1> {
        // `to_socket_addrs` on (&str, u16) accepts IPv4 literals, IPv6 literals,
        // and hostnames (proxy resolution only). We try each resolved candidate
        // with a bounded connect and return the first that succeeds.
        let candidates = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
        let mut last_err = PrivateTransportNetworkErrorV1::PrivateTransportUnavailable;
        let mut any = false;
        for addr in candidates {
            any = true;
            match TcpStream::connect_timeout(&addr, connect_timeout) {
                Ok(stream) => return Ok(stream),
                Err(_) => last_err = PrivateTransportNetworkErrorV1::PrivateTransportUnavailable,
            }
        }
        if !any {
            return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
        }
        Err(last_err)
    }
}

fn parse_port(raw: &str) -> Result<u16, RemoteSocksEndpointErrorV1> {
    // Digits only, no sign/whitespace/suffix; non-zero.
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RemoteSocksEndpointErrorV1::InvalidPort);
    }
    let port: u16 = raw
        .parse()
        .map_err(|_| RemoteSocksEndpointErrorV1::InvalidPort)?;
    if port == 0 {
        return Err(RemoteSocksEndpointErrorV1::InvalidPort);
    }
    Ok(port)
}

/// Validates a DNS hostname under conservative RFC 1035-ish rules: total length
/// <= 253, one or more dot-separated labels, each label 1..=63 chars of
/// `[A-Za-z0-9-]`, not starting or ending with a hyphen. A single-label host
/// (e.g. `tor-host`) is permitted for LAN use.
fn validate_hostname(host: &str) -> Result<(), RemoteSocksEndpointErrorV1> {
    if host.is_empty() {
        return Err(RemoteSocksEndpointErrorV1::EmptyHost);
    }
    if host.len() > MAX_HOSTNAME_LEN {
        return Err(RemoteSocksEndpointErrorV1::InvalidHost);
    }
    // A trailing dot (fully-qualified form) is allowed by DNS but we keep the
    // form simple and reject it here to avoid an empty final label.
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(RemoteSocksEndpointErrorV1::InvalidHost);
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(RemoteSocksEndpointErrorV1::InvalidHost);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(RemoteSocksEndpointErrorV1::InvalidHost);
        }
    }
    Ok(())
}

/// A validated SOCKS proxy target for the onion carrier: either the
/// managed-local loopback endpoint (exactly the existing loopback-only policy)
/// or a remote proxy endpoint. This lets the ONE onion-CONNECT + HTTP wire path
/// serve both modes without duplicating (and thus without risking divergence in)
/// the onion-routing / no-clearnet code, while keeping the two endpoint
/// VALIDATION policies strictly separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksProxyEndpointV1 {
    /// Managed-local Tor: a loopback `SocketAddr` (validated exactly by
    /// [`crate::validate_loopback_socket_addr_v1`]).
    ManagedLoopback(SocketAddr),
    /// Remote SOCKS: an externally-managed proxy endpoint.
    Remote(RemoteSocksEndpointV1),
}

impl SocksProxyEndpointV1 {
    /// Validates the endpoint under the policy for its own mode. Managed-local
    /// requires a loopback socket; remote requires a well-formed host:port. The
    /// two policies never mix.
    pub fn validate(&self) -> Result<(), PrivateTransportNetworkErrorV1> {
        match self {
            Self::ManagedLoopback(addr) => {
                crate::validate_loopback_socket_addr_v1(*addr).map(|_| ())
            }
            // A `RemoteSocksEndpointV1` is unconstructible while invalid, so its
            // presence already proves validity; this is a defensive re-check.
            Self::Remote(endpoint) => RemoteSocksEndpointV1::from_parts(endpoint.host(), endpoint.port())
                .map(|_| ())
                .map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration),
        }
    }

    /// Opens a bounded TCP connection to the proxy under its mode's policy.
    /// Managed-local connects to a numeric loopback socket (no DNS whatsoever);
    /// remote may resolve the proxy hostname (proxy address only, never a
    /// `.onion`). Neither path has a clearnet fallback.
    pub(crate) fn connect(
        &self,
        connect_timeout: Duration,
    ) -> Result<TcpStream, PrivateTransportNetworkErrorV1> {
        match self {
            Self::ManagedLoopback(addr) => {
                crate::validate_loopback_socket_addr_v1(*addr)?;
                TcpStream::connect_timeout(addr, connect_timeout)
                    .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
            }
            Self::Remote(endpoint) => endpoint.connect(connect_timeout),
        }
    }

    /// Canonical display form for evidence/metadata (never secret).
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::ManagedLoopback(addr) => addr.to_string(),
            Self::Remote(endpoint) => endpoint.display(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_transport_mode_is_managed_local() {
        assert_eq!(TorTransportModeV1::default(), TorTransportModeV1::ManagedLocal);
    }

    #[test]
    fn legacy_or_unknown_mode_token_resolves_to_managed_local() {
        // A missing/legacy/unknown persisted value must resolve to the
        // recommended managed-local mode, never silently to remote.
        for token in ["", "managed-local", "unknown", "MANAGED", "socks", "true"] {
            assert_eq!(
                TorTransportModeV1::from_token_or_default(token),
                TorTransportModeV1::ManagedLocal,
                "token {token:?}"
            );
        }
        assert_eq!(
            TorTransportModeV1::from_token_or_default("remote-socks"),
            TorTransportModeV1::RemoteSocks
        );
        // Round-trip through the stable token.
        assert_eq!(
            TorTransportModeV1::from_token_or_default(TorTransportModeV1::RemoteSocks.as_token()),
            TorTransportModeV1::RemoteSocks
        );
    }

    #[test]
    fn valid_ipv4_endpoints_are_accepted() {
        for raw in ["127.0.0.1:9050", "192.168.1.50:9050", "10.0.0.12:9050"] {
            let endpoint = RemoteSocksEndpointV1::parse(raw).expect(raw);
            assert_eq!(endpoint.display(), raw);
            assert_eq!(endpoint.port(), 9050);
        }
        assert!(RemoteSocksEndpointV1::parse("127.0.0.1:9050").unwrap().is_loopback_ip());
        assert!(!RemoteSocksEndpointV1::parse("192.168.1.50:9050").unwrap().is_loopback_ip());
    }

    #[test]
    fn valid_hostname_endpoint_is_accepted() {
        let endpoint = RemoteSocksEndpointV1::parse("tor.internal.example:9050").expect("hostname");
        assert_eq!(endpoint.host(), "tor.internal.example");
        assert_eq!(endpoint.port(), 9050);
        // Single-label LAN hostname is fine.
        assert!(RemoteSocksEndpointV1::parse("tor-host:9150").is_ok());
        // A hostname is not treated as a loopback IP even if it is "localhost".
        assert!(!RemoteSocksEndpointV1::parse("localhost:9050").unwrap().is_loopback_ip());
    }

    #[test]
    fn valid_bracketed_ipv6_endpoint_is_accepted() {
        let endpoint = RemoteSocksEndpointV1::parse("[::1]:9050").expect("ipv6");
        assert_eq!(endpoint.host(), "::1");
        assert_eq!(endpoint.port(), 9050);
        assert_eq!(endpoint.display(), "[::1]:9050");
        assert!(endpoint.is_loopback_ip());
    }

    #[test]
    fn invalid_port_is_rejected() {
        for raw in [
            "127.0.0.1:0",
            "127.0.0.1:70000",
            "127.0.0.1:-1",
            "127.0.0.1:99999",
            "127.0.0.1:9050x",
            "127.0.0.1: 9050",
            "127.0.0.1:0x10",
        ] {
            assert!(RemoteSocksEndpointV1::parse(raw).is_err(), "{raw}");
        }
        assert_eq!(
            RemoteSocksEndpointV1::parse("127.0.0.1:0"),
            Err(RemoteSocksEndpointErrorV1::InvalidPort)
        );
    }

    #[test]
    fn empty_host_is_rejected() {
        assert_eq!(
            RemoteSocksEndpointV1::parse(":9050"),
            Err(RemoteSocksEndpointErrorV1::EmptyHost)
        );
        assert_eq!(
            RemoteSocksEndpointV1::parse(""),
            Err(RemoteSocksEndpointErrorV1::EmptyHost)
        );
        assert_eq!(
            RemoteSocksEndpointV1::parse("   "),
            Err(RemoteSocksEndpointErrorV1::EmptyHost)
        );
    }

    #[test]
    fn malformed_endpoints_are_rejected() {
        for raw in [
            "socks5://127.0.0.1:9050", // scheme
            "http://tor:9050",         // scheme
            "127.0.0.1:9050/path",     // path
            "user@127.0.0.1:9050",     // userinfo
            "127.0.0.1:9050?q=1",      // query
            "127.0.0.1",               // no port
            "tor host:9050",           // internal whitespace
            "127.0.0.1:9050:80",       // extra colon (unbracketed)
            "::1:9050",                // unbracketed ipv6
            "tor..example:9050",       // empty label
            "-tor.example:9050",       // leading hyphen
            "tor.example-:9050",       // trailing hyphen
            "tor_host:9050",           // underscore not allowed in hostname
        ] {
            assert!(RemoteSocksEndpointV1::parse(raw).is_err(), "{raw} must reject");
        }
    }

    #[test]
    fn from_parts_revalidates_and_fails_closed_on_malformed() {
        assert!(RemoteSocksEndpointV1::from_parts("192.168.1.50", 9050).is_ok());
        assert!(RemoteSocksEndpointV1::from_parts("::1", 9050).is_ok());
        assert!(RemoteSocksEndpointV1::from_parts("tor.example", 9050).is_ok());
        // A persisted malformed host / zero port must fail closed on reload.
        assert!(RemoteSocksEndpointV1::from_parts("bad host", 9050).is_err());
        assert!(RemoteSocksEndpointV1::from_parts("127.0.0.1", 0).is_err());
        assert!(RemoteSocksEndpointV1::from_parts("", 9050).is_err());
    }

    #[test]
    fn managed_loopback_proxy_endpoint_keeps_loopback_policy() {
        let ok = SocksProxyEndpointV1::ManagedLoopback(SocketAddr::from(([127, 0, 0, 1], 9050)));
        assert!(ok.validate().is_ok());
        // A non-loopback address under the MANAGED policy is still rejected —
        // remote mode does not weaken the managed-local loopback requirement.
        let bad = SocksProxyEndpointV1::ManagedLoopback(SocketAddr::from(([10, 0, 0, 5], 9050)));
        assert!(bad.validate().is_err());
    }

    #[test]
    fn remote_proxy_endpoint_allows_non_loopback() {
        let remote = SocksProxyEndpointV1::Remote(
            RemoteSocksEndpointV1::parse("192.168.1.50:9050").expect("valid"),
        );
        assert!(remote.validate().is_ok());
        assert_eq!(remote.display(), "192.168.1.50:9050");
    }
}
