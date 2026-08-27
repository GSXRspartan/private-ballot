//! Bounded project-owned endpoint configuration for walletd and the indexer
//! (Sections C, E).
//!
//! [`WalletdEndpoint`] and [`IndexerEndpoint`] are bounded, validated endpoint
//! references that carry only the scheme, host, port, and an optional bounded
//! base path. They never store raw secrets, infer a network, perform DNS, or open
//! a connection. Their `Debug` output redacts nothing (endpoints are public
//! locator data, not secrets) but never includes credentials.

use core::fmt;
use core::net::Ipv6Addr;
use core::str::FromStr;

use url::{Host, Url};

/// Maximum byte length of the optional bounded base path.
pub const MAX_ENDPOINT_BASE_PATH_BYTES: usize = 256;

/// Returns whether a parsed URL's host is a loopback address.
///
/// True for the IPv4 loopback block `127.0.0.0/8`, the IPv6 loopback `::1`, and
/// the literal domain `localhost` (case-insensitive). This is the trusted-host
/// predicate the live publish path uses to guarantee the walletd bearer token
/// and every anchor request can only ever reach the organizer's own machine —
/// never an attacker-chosen remote host.
fn url_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        // The whole 127.0.0.0/8 block is loopback (covers 127.0.0.1).
        Some(Host::Ipv4(addr)) => addr.octets()[0] == 127,
        Some(Host::Ipv6(addr)) => addr == Ipv6Addr::LOCALHOST,
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Rejection categories for endpoint configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletdEndpointError {
    /// The endpoint string was empty.
    Empty,
    /// The scheme was missing or not `http` / `https`.
    UnsupportedScheme,
    /// The host was missing or empty.
    EmptyHost,
    /// The endpoint contained embedded credentials (`user:pass@host`).
    EmbeddedCredentials,
    /// The endpoint contained a query string.
    QueryPresent,
    /// The endpoint contained a fragment.
    FragmentPresent,
    /// The base path exceeded the bounded maximum.
    PathTooLong,
    /// The endpoint contained a control character or ambiguous whitespace.
    ForbiddenCharacter,
    /// The port was zero or exceeded 65535.
    PortOutOfRange,
    /// The URL could not be parsed at all.
    Malformed,
}

impl WalletdEndpointError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "ENDPOINT_EMPTY",
            Self::UnsupportedScheme => "ENDPOINT_UNSUPPORTED_SCHEME",
            Self::EmptyHost => "ENDPOINT_EMPTY_HOST",
            Self::EmbeddedCredentials => "ENDPOINT_EMBEDDED_CREDENTIALS",
            Self::QueryPresent => "ENDPOINT_QUERY_PRESENT",
            Self::FragmentPresent => "ENDPOINT_FRAGMENT_PRESENT",
            Self::PathTooLong => "ENDPOINT_PATH_TOO_LONG",
            Self::ForbiddenCharacter => "ENDPOINT_FORBIDDEN_CHARACTER",
            Self::PortOutOfRange => "ENDPOINT_PORT_OUT_OF_RANGE",
            Self::Malformed => "ENDPOINT_MALFORMED",
        }
    }
}

impl fmt::Display for WalletdEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for WalletdEndpointError {}

/// Indexer endpoint errors share the same bounded categories.
pub type IndexerEndpointError = WalletdEndpointError;

/// Validates a raw endpoint string and returns the parsed `Url`.
fn validate_endpoint(raw: &str) -> Result<Url, WalletdEndpointError> {
    if raw.is_empty() {
        return Err(WalletdEndpointError::Empty);
    }

    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(WalletdEndpointError::ForbiddenCharacter);
    }

    let url = Url::parse(raw).map_err(|_error| WalletdEndpointError::Malformed)?;

    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(WalletdEndpointError::UnsupportedScheme),
    }

    if url.username().is_empty() && url.password().is_some() {
        return Err(WalletdEndpointError::EmbeddedCredentials);
    }
    if !url.username().is_empty() {
        return Err(WalletdEndpointError::EmbeddedCredentials);
    }

    let host = url.host_str().unwrap_or("");
    if host.is_empty() {
        return Err(WalletdEndpointError::EmptyHost);
    }

    if let Some(0) = url.port() {
        return Err(WalletdEndpointError::PortOutOfRange);
    }

    if url.query().is_some() {
        return Err(WalletdEndpointError::QueryPresent);
    }
    if url.fragment().is_some() {
        return Err(WalletdEndpointError::FragmentPresent);
    }

    let path = url.path();
    if path.len() > MAX_ENDPOINT_BASE_PATH_BYTES {
        return Err(WalletdEndpointError::PathTooLong);
    }

    Ok(url)
}

/// Bounded walletd endpoint configuration.
///
/// It carries only the scheme, host, port, and an optional base path. It never
/// stores a secret, infers a network, or opens a connection. The endpoint URL
/// never determines the Ootle network: a separate, explicit network identifier
/// is required for every operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WalletdEndpoint {
    url: Url,
}

impl WalletdEndpoint {
    /// Parses and validates a walletd endpoint URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdEndpointError`] if the endpoint is empty,
    /// uses an unsupported scheme, has no host, embeds credentials, carries a
    /// query or fragment, has an over-length path, contains control characters,
    /// or has an out-of-range port.
    pub fn parse(raw: &str) -> Result<Self, WalletdEndpointError> {
        let url = validate_endpoint(raw)?;
        Ok(Self { url })
    }

    /// Returns the scheme (`"http"` or `"https"`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// Returns the host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or("")
    }

    /// Returns the port, if one was specified.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.url.port()
    }

    /// Returns the base path, if one was specified.
    #[must_use]
    pub fn path(&self) -> &str {
        let path = self.url.path();
        if path == "/" { "" } else { path }
    }

    /// Returns the full endpoint URL as a string (no credentials, no query, no
    /// fragment).
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Returns whether this endpoint targets a loopback host (`127.0.0.0/8`,
    /// `::1`, or `localhost`). The live publish path requires this so the
    /// walletd bearer token can never be sent to a non-local host.
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        url_host_is_loopback(&self.url)
    }
}

impl FromStr for WalletdEndpoint {
    type Err = WalletdEndpointError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for WalletdEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.url.as_str())
    }
}

/// Bounded indexer endpoint configuration.
///
/// Shares the same URL-safety rules as [`WalletdEndpoint`]. The indexer endpoint
/// is never silently reused as the walletd endpoint: network binding remains
/// explicit and separate from endpoint location.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IndexerEndpoint {
    url: Url,
}

impl IndexerEndpoint {
    /// Parses and validates an indexer endpoint URL.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`IndexerEndpointError`] for the same URL-safety
    /// violations as [`WalletdEndpoint::parse`].
    pub fn parse(raw: &str) -> Result<Self, IndexerEndpointError> {
        let url = validate_endpoint(raw)?;
        Ok(Self { url })
    }

    /// Returns the scheme (`"http"` or `"https"`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// Returns the host.
    #[must_use]
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or("")
    }

    /// Returns the port, if one was specified.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.url.port()
    }

    /// Returns the base path, if one was specified.
    #[must_use]
    pub fn path(&self) -> &str {
        let path = self.url.path();
        if path == "/" { "" } else { path }
    }

    /// Returns the full endpoint URL as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// Returns whether this endpoint targets a loopback host (`127.0.0.0/8`,
    /// `::1`, or `localhost`).
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        url_host_is_loopback(&self.url)
    }
}

impl FromStr for IndexerEndpoint {
    type Err = IndexerEndpointError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for IndexerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.url.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_loopback_is_accepted() {
        let endpoint = WalletdEndpoint::parse("http://127.0.0.1:12009")
            .unwrap_or_else(|e| panic!("loopback endpoint must be valid: {e:?}"));
        assert_eq!(endpoint.scheme(), "http");
        assert_eq!(endpoint.host(), "127.0.0.1");
        assert_eq!(endpoint.port(), Some(12009));
    }

    #[test]
    fn https_is_accepted() {
        let endpoint = IndexerEndpoint::parse("https://indexer.example.com:443")
            .unwrap_or_else(|e| panic!("https endpoint must be valid: {e:?}"));
        assert_eq!(endpoint.scheme(), "https");
        assert_eq!(endpoint.host(), "indexer.example.com");
    }

    #[test]
    fn base_path_is_accepted() {
        let endpoint = WalletdEndpoint::parse("http://127.0.0.1:12009/api/v1")
            .unwrap_or_else(|e| panic!("base path must be valid: {e:?}"));
        assert_eq!(endpoint.path(), "/api/v1");
    }

    #[test]
    fn empty_endpoint_is_rejected() {
        assert_eq!(
            WalletdEndpoint::parse("")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::Empty
        );
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        assert_eq!(
            WalletdEndpoint::parse("ftp://127.0.0.1")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::UnsupportedScheme
        );
        assert_eq!(
            IndexerEndpoint::parse("file:///tmp")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::UnsupportedScheme
        );
    }

    #[test]
    fn embedded_credentials_are_rejected() {
        assert_eq!(
            WalletdEndpoint::parse("http://user:pass@127.0.0.1")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::EmbeddedCredentials
        );
    }

    #[test]
    fn query_string_is_rejected() {
        assert_eq!(
            WalletdEndpoint::parse("http://127.0.0.1?foo=bar")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::QueryPresent
        );
    }

    #[test]
    fn fragment_is_rejected() {
        assert_eq!(
            IndexerEndpoint::parse("http://127.0.0.1#frag")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::FragmentPresent
        );
    }

    #[test]
    fn control_characters_are_rejected() {
        assert_eq!(
            WalletdEndpoint::parse("http://127.0.0.1\n")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::ForbiddenCharacter
        );
        assert_eq!(
            WalletdEndpoint::parse("http://127.0.0.1\t")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::ForbiddenCharacter
        );
    }

    #[test]
    fn whitespace_is_rejected() {
        assert_eq!(
            WalletdEndpoint::parse(" http://127.0.0.1")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::ForbiddenCharacter
        );
        assert_eq!(
            WalletdEndpoint::parse("http://127.0.0.1 ")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::ForbiddenCharacter
        );
    }

    #[test]
    fn port_zero_is_rejected() {
        assert_eq!(
            WalletdEndpoint::parse("http://127.0.0.1:0")
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            WalletdEndpointError::PortOutOfRange
        );
    }

    #[test]
    fn walletd_and_indexer_are_distinct_types() {
        let w =
            WalletdEndpoint::parse("http://127.0.0.1:12009").unwrap_or_else(|e| panic!("{e:?}"));
        let i =
            IndexerEndpoint::parse("http://127.0.0.1:12500").unwrap_or_else(|e| panic!("{e:?}"));
        assert_ne!(w.as_str(), i.as_str());
    }

    #[test]
    fn loopback_hosts_are_recognized() {
        for raw in [
            "http://127.0.0.1:12009",
            "http://127.5.6.7:1",
            "http://localhost:12009",
            "http://LocalHost:12009",
            "http://[::1]:12009",
        ] {
            let endpoint = WalletdEndpoint::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e:?}"));
            assert!(endpoint.is_loopback(), "{raw} must be loopback");
        }
    }

    #[test]
    fn non_loopback_hosts_are_not_loopback() {
        for raw in [
            "http://10.0.0.5:12009",
            "http://192.168.1.10:12009",
            "https://indexer.example.com:443",
            "http://[2001:db8::1]:12009",
            "http://126.0.0.1:12009",
            "http://128.0.0.1:12009",
        ] {
            let endpoint = IndexerEndpoint::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e:?}"));
            assert!(!endpoint.is_loopback(), "{raw} must not be loopback");
        }
    }
}
