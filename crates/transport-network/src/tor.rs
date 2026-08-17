//! Real (but not yet user-enabled) managed-Tor network primitives.
//!
//! This module provides two production-capable client primitives that speak to
//! a *local* managed Tor SOCKS listener only:
//!
//!   * [`SystemManagedTorReadinessProbeV1`] — proves the configured loopback
//!     SOCKS5 service is actually responding correctly (not merely that a
//!     `tor.exe` process exists), and
//!   * [`TorSocksPrivateReleaseCarrierV1`] — a [`PrivateReleaseCarrierV1`]
//!     implementation that ships an already-authenticated opaque envelope to a
//!     Tor v3 onion collector and returns the raw authenticated receipt bytes.
//!
//! Hard invariants enforced here:
//!
//!   * the SOCKS endpoint must be an IP loopback `SocketAddr` (never `0.0.0.0`,
//!     a LAN address, a public IP, or a resolvable hostname);
//!   * the onion hostname is passed to the proxy as a SOCKS5 `DOMAINNAME`
//!     (`ATYP = 0x03`) literal, so the local OS never resolves `.onion`;
//!   * there is **no** direct/clearnet/relay fallback — Tor or a bounded error;
//!   * ballot bytes never leave the process except through the carrier's single
//!     SOCKS-tunnelled HTTP POST, and never during a readiness probe.
//!
//! State authority (staging, PENDING, cast promotion, receipt verification)
//! stays entirely in gui-core; this module only moves opaque bytes.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use tari_cc_private_ballot_gui_core::{
    GuiCoreError, GuiErrorCategory, MAX_AUTHENTICATED_RECEIPT_BYTES,
    MAX_STAGED_RELEASE_ENVELOPE_BYTES, PrivateReleaseCarrierV1, TransportDescriptorV1,
    TransportRoutePolicyV1,
};

use crate::PrivateTransportNetworkErrorV1;

/// The single collector endpoint path. Nothing else is served or requested.
pub const OPAQUE_ENVELOPE_HTTP_PATH_V1: &str = "/v1/opaque-envelope";
/// The fixed HTTP content type for the opaque envelope body and receipt reply.
pub const OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1: &str = "application/octet-stream";
/// The fixed virtual port a Tor v3 hidden service exposes for this protocol. The
/// descriptor names the destination *host*; the port is a non-configurable
/// protocol constant, so it can never disagree with the verified descriptor.
pub const ONION_VIRTUAL_PORT_V1: u16 = 80;

/// Tor v3 onion hostnames are exactly 56 base32 characters plus the suffix.
const ONION_LABEL_LEN: usize = 56;
const ONION_SUFFIX: &str = ".onion";

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_NO_AUTHENTICATION: u8 = 0x00;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_RESERVED: u8 = 0x00;
const SOCKS_REP_SUCCEEDED: u8 = 0x00;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAINNAME: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// Bounded ceiling on the HTTP response header section. Any collector reply that
/// does not terminate its headers within this many bytes is rejected.
const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;

/// Bounded network timeouts. Every socket operation is time-limited so a hostile
/// or dead peer cannot wedge a submission indefinitely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TorCarrierTimeoutsV1 {
    pub socks_connect: Duration,
    pub socks_handshake: Duration,
    pub http_write: Duration,
    pub http_response: Duration,
}

impl Default for TorCarrierTimeoutsV1 {
    fn default() -> Self {
        Self {
            socks_connect: Duration::from_secs(10),
            socks_handshake: Duration::from_secs(20),
            http_write: Duration::from_secs(30),
            http_response: Duration::from_secs(60),
        }
    }
}

/// Rejects any SOCKS proxy endpoint that is not an IP loopback address with a
/// non-zero port. A `SocketAddr` is already numeric, so accepting one here (and
/// never a hostname) structurally prevents proxy-endpoint DNS resolution.
pub fn validate_loopback_socket_addr_v1(
    addr: SocketAddr,
) -> Result<SocketAddr, PrivateTransportNetworkErrorV1> {
    if addr.ip().is_loopback() && addr.port() != 0 {
        Ok(addr)
    } else {
        Err(PrivateTransportNetworkErrorV1::InvalidConfiguration)
    }
}

/// Strictly validates a canonical Tor v3 onion hostname: exactly 56 lowercase
/// base32 (`a-z2-7`) characters followed by `.onion`, and nothing else.
///
/// This rejects schemes (`://`), paths (`/`), embedded ports (`:`), userinfo
/// (`@`), whitespace, IP addresses, `localhost`, clearnet domains, uppercase,
/// and non-ASCII/Unicode look-alikes — every disallowed byte falls outside the
/// base32 alphabet, and the exact length forbids anything longer or shorter.
pub fn validate_onion_hostname_v1(host: &str) -> Result<(), PrivateTransportNetworkErrorV1> {
    if host.len() != ONION_LABEL_LEN + ONION_SUFFIX.len() {
        return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
    }
    let label = host
        .strip_suffix(ONION_SUFFIX)
        .ok_or(PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    if label.len() != ONION_LABEL_LEN
        || !label
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
    }
    Ok(())
}

/// Real production-capable readiness probe for the local managed Tor SOCKS
/// listener. A "ready" result means the configured loopback endpoint completed a
/// valid SOCKS5 no-authentication method negotiation — never merely that a
/// process exists. The probe never resolves DNS, never reaches clearnet, never
/// opens the onion service, and never releases ballot bytes.
#[derive(Debug, Clone)]
pub struct SystemManagedTorReadinessProbeV1 {
    socks_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

impl SystemManagedTorReadinessProbeV1 {
    /// Builds a probe for a loopback SOCKS endpoint. A non-loopback endpoint is
    /// rejected (fail closed).
    pub fn new(
        socks_addr: SocketAddr,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, PrivateTransportNetworkErrorV1> {
        validate_loopback_socket_addr_v1(socks_addr)?;
        if connect_timeout.is_zero() || handshake_timeout.is_zero() {
            return Err(PrivateTransportNetworkErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            socks_addr,
            connect_timeout,
            handshake_timeout,
        })
    }

    /// The validated loopback SOCKS endpoint this probe targets.
    #[must_use]
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
}

impl crate::ManagedTorReadinessProbeV1 for SystemManagedTorReadinessProbeV1 {
    fn ready(&mut self) -> Result<bool, PrivateTransportNetworkErrorV1> {
        // Re-validate loopback on every probe (defense in depth), then attempt a
        // single SOCKS5 method negotiation. Any connect/handshake problem is
        // reported as "not ready" so a controller keeps polling until timeout.
        validate_loopback_socket_addr_v1(self.socks_addr)?;
        Ok(probe_socks5_ready(
            self.socks_addr,
            self.connect_timeout,
            self.handshake_timeout,
        ))
    }
}

fn probe_socks5_ready(
    socks_addr: SocketAddr,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&socks_addr, connect_timeout) else {
        return false;
    };
    if stream.set_read_timeout(Some(handshake_timeout)).is_err()
        || stream.set_write_timeout(Some(handshake_timeout)).is_err()
    {
        return false;
    }
    // Offer only "no authentication" and require the server to select it. The
    // connection is dropped immediately afterwards: no CONNECT, no ballot bytes.
    if socks5_negotiate_no_auth(&mut stream).is_err() {
        return false;
    }
    true
}

/// Sends the SOCKS5 greeting (`05 01 00`) and requires the server to reply with
/// `05 00` (version 5, no-authentication selected). Any other reply is an error.
fn socks5_negotiate_no_auth(stream: &mut TcpStream) -> Result<(), PrivateTransportNetworkErrorV1> {
    write_all(stream, &[SOCKS_VERSION, 0x01, SOCKS_NO_AUTHENTICATION])?;
    let mut reply = [0u8; 2];
    read_exact(stream, &mut reply)?;
    if reply[0] != SOCKS_VERSION || reply[1] != SOCKS_NO_AUTHENTICATION {
        return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
    }
    Ok(())
}

/// Real private-release carrier that delivers an already-authenticated opaque
/// envelope to a Tor v3 onion collector through a local managed SOCKS5 proxy.
///
/// The carrier holds ONLY a validated loopback SOCKS endpoint and a timeout
/// policy — deliberately **no** ballot destination. The onion route is derived
/// at delivery time from the verified [`TransportDescriptorV1`] the release
/// boundary passes in, so the destination the ciphertext reaches can only ever
/// be the one the verified descriptor names. Route confusion is structurally
/// impossible: there is no independently supplied address to disagree with the
/// descriptor.
///
/// This carrier constructs no ballots, seals no HPKE, writes no PENDING record,
/// mutates no cast state, and never re-generates an envelope on retry. It has no
/// direct/clearnet/relay fallback whatsoever.
#[derive(Debug, Clone)]
pub struct TorSocksPrivateReleaseCarrierV1 {
    socks_addr: SocketAddr,
    timeouts: TorCarrierTimeoutsV1,
}

impl TorSocksPrivateReleaseCarrierV1 {
    /// Builds a carrier for a validated loopback SOCKS endpoint. The carrier
    /// stores no ballot destination; the route is bound per-delivery to the
    /// verified descriptor supplied by the release boundary.
    pub fn new(
        socks_addr: SocketAddr,
        timeouts: TorCarrierTimeoutsV1,
    ) -> Result<Self, PrivateTransportNetworkErrorV1> {
        validate_loopback_socket_addr_v1(socks_addr)?;
        Ok(Self {
            socks_addr,
            timeouts,
        })
    }

    /// The validated loopback SOCKS endpoint.
    #[must_use]
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
}

impl PrivateReleaseCarrierV1 for TorSocksPrivateReleaseCarrierV1 {
    fn deliver_opaque_envelope(
        &mut self,
        descriptor: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<Vec<u8>, GuiCoreError> {
        deliver_over_tor(self.socks_addr, descriptor, &self.timeouts, envelope)
            .map_err(map_carrier_error)
    }
}

/// Coarse voter-facing carrier error. It intentionally reveals only that the
/// private route was unavailable; the release boundary keeps the voter locked.
fn map_carrier_error(_error: PrivateTransportNetworkErrorV1) -> GuiCoreError {
    GuiCoreError::new(
        "GUI_TOR_CARRIER_UNAVAILABLE",
        GuiErrorCategory::Unavailable,
        Some("private-tor-carrier"),
        "private transport delivery failed; the ballot remains locked for retry",
    )
}

/// Derives the Tor onion destination strictly from the verified descriptor. The
/// descriptor's route policy must permit managed Tor, and its first onion
/// endpoint must be a strictly-valid Tor v3 onion hostname. The virtual port is
/// the fixed protocol constant [`ONION_VIRTUAL_PORT_V1`] (the descriptor names
/// the host; the port is not an independently-configurable field). Returns the
/// validated hostname borrowed from the descriptor so no other destination can
/// be substituted.
fn onion_route_from_descriptor_v1(
    descriptor: &TransportDescriptorV1,
) -> Result<(&str, u16), PrivateTransportNetworkErrorV1> {
    if descriptor.route() != TransportRoutePolicyV1::ManagedTorOrOffline {
        return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
    }
    let host = descriptor
        .onion_endpoints()
        .first()
        .map(String::as_str)
        .ok_or(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
    validate_onion_hostname_v1(host)?;
    Ok((host, ONION_VIRTUAL_PORT_V1))
}

/// The whole client wire flow. There is deliberately exactly one path here: the
/// destination is derived from the verified descriptor, then a SOCKS5 CONNECT to
/// that onion service, then a single HTTP POST over that tunnel. No branch
/// reconnects directly, uses a relay, resolves DNS, or uses any destination
/// other than the descriptor's.
fn deliver_over_tor(
    socks_addr: SocketAddr,
    descriptor: &TransportDescriptorV1,
    timeouts: &TorCarrierTimeoutsV1,
    envelope: &[u8],
) -> Result<Vec<u8>, PrivateTransportNetworkErrorV1> {
    if envelope.is_empty() || envelope.len() as u64 > MAX_STAGED_RELEASE_ENVELOPE_BYTES {
        return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
    }
    // Bind the destination to the verified descriptor BEFORE any SOCKS connect
    // or byte transmission.
    let (onion_host, onion_port) = onion_route_from_descriptor_v1(descriptor)?;
    let mut stream = socks5_connect_onion(socks_addr, onion_host, onion_port, timeouts)?;
    http_post_opaque_envelope(&mut stream, onion_host, envelope, timeouts)
}

/// Opens a TCP connection to the loopback SOCKS proxy and performs a strict
/// SOCKS5 `CONNECT` to the onion hostname using `ATYP = DOMAINNAME`. The onion
/// hostname is sent as literal bytes to the proxy; it is never passed to any OS
/// resolver. Returns the established, tunnelled stream on success.
fn socks5_connect_onion(
    socks_addr: SocketAddr,
    onion_host: &str,
    onion_port: u16,
    timeouts: &TorCarrierTimeoutsV1,
) -> Result<TcpStream, PrivateTransportNetworkErrorV1> {
    validate_loopback_socket_addr_v1(socks_addr)?;
    validate_onion_hostname_v1(onion_host)?;

    let mut stream = TcpStream::connect_timeout(&socks_addr, timeouts.socks_connect)
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
    stream
        .set_read_timeout(Some(timeouts.socks_handshake))
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
    stream
        .set_write_timeout(Some(timeouts.socks_handshake))
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;

    socks5_negotiate_no_auth(&mut stream)?;

    // CONNECT: 05 01 00 03 <len> <literal onion host> <port big-endian>.
    let host_bytes = onion_host.as_bytes();
    // The strict validator guarantees a 62-byte hostname, which fits in a u8.
    let host_len = u8::try_from(host_bytes.len())
        .map_err(|_| PrivateTransportNetworkErrorV1::InvalidConfiguration)?;
    let mut request = Vec::with_capacity(4 + 1 + host_bytes.len() + 2);
    request.push(SOCKS_VERSION);
    request.push(SOCKS_CMD_CONNECT);
    request.push(SOCKS_RESERVED);
    request.push(SOCKS_ATYP_DOMAINNAME);
    request.push(host_len);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&onion_port.to_be_bytes());
    write_all(&mut stream, &request)?;

    // Reply: VER REP RSV ATYP <BND.ADDR> <BND.PORT>.
    let mut head = [0u8; 4];
    read_exact(&mut stream, &mut head)?;
    if head[0] != SOCKS_VERSION || head[1] != SOCKS_REP_SUCCEEDED || head[2] != SOCKS_RESERVED {
        return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
    }
    match head[3] {
        SOCKS_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            read_exact(&mut stream, &mut addr)?;
        }
        SOCKS_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            read_exact(&mut stream, &mut addr)?;
        }
        SOCKS_ATYP_DOMAINNAME => {
            let mut len = [0u8; 1];
            read_exact(&mut stream, &mut len)?;
            let mut addr = vec![0u8; usize::from(len[0])];
            read_exact(&mut stream, &mut addr)?;
        }
        _ => return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable),
    }
    let mut port = [0u8; 2];
    read_exact(&mut stream, &mut port)?;
    Ok(stream)
}

/// Writes the single strict HTTP/1.1 POST over an established Tor stream and
/// parses the authenticated-receipt response. No redirects, cookies,
/// compression, chunking, proxy headers, or caller-supplied headers are used.
fn http_post_opaque_envelope(
    stream: &mut TcpStream,
    onion_host: &str,
    envelope: &[u8],
    timeouts: &TorCarrierTimeoutsV1,
) -> Result<Vec<u8>, PrivateTransportNetworkErrorV1> {
    stream
        .set_write_timeout(Some(timeouts.http_write))
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
    stream
        .set_read_timeout(Some(timeouts.http_response))
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;

    let header = format!(
        "POST {OPAQUE_ENVELOPE_HTTP_PATH_V1} HTTP/1.1\r\n\
         Host: {onion_host}\r\n\
         Content-Type: {OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        envelope.len()
    );
    write_all(stream, header.as_bytes())?;
    write_all(stream, envelope)?;
    stream
        .flush()
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;

    read_http_receipt_response(stream)
}

/// Strict, bounded HTTP/1.1 response parser tailored to the single collector
/// endpoint. It requires `200 OK`, a single non-conflicting `Content-Length`, no
/// chunked transfer, a bounded header section, and an exact-length receipt body.
fn read_http_receipt_response(
    stream: &mut TcpStream,
) -> Result<Vec<u8>, PrivateTransportNetworkErrorV1> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 512];
    let header_end = loop {
        if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > MAX_HTTP_HEADER_BYTES {
            return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
        }
        let read = stream
            .read(&mut chunk)
            .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
        if read == 0 {
            return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let header_text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|_| PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?;
    parse_status_line_200(status_line)?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        // No empty line can appear before `\r\n\r\n`; an empty header line is
        // malformed framing.
        let (name, value) = parse_strict_header_line_v1(line)
            .map_err(|_| PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?;
        match name.as_str() {
            "content-length" => {
                // Any duplicate Content-Length (even numerically equal) is
                // rejected: HTTP request-smuggling defense.
                if content_length.is_some() {
                    return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
                }
                content_length = Some(
                    parse_strict_content_length_v1(value)
                        .map_err(|_| PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?,
                );
            }
            // Chunked or any other transfer-encoding (any casing) is refused.
            "transfer-encoding" => {
                return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
            }
            _ => {}
        }
    }

    let length = content_length.ok_or(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?;
    if length > MAX_AUTHENTICATED_RECEIPT_BYTES {
        return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
    }

    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    // Read until the buffer holds at least the promised length. Each read is
    // bounded by `length`: a read that overshoots the declared length (extra
    // bytes bundled with the body tail) is rejected below, never truncated or
    // silently accepted.
    while body.len() < length {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)?;
        if read == 0 {
            // Truncated body: fewer bytes than the promised Content-Length.
            return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    if body.len() != length {
        // More bytes than promised arrived interleaved with the body: reject
        // rather than truncate. This is the request-smuggling / extra-bytes
        // defense (it catches the `abcdEXTRA` case where the surplus arrives in
        // the same read as the declared body).
        return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
    }
    // The authenticated receipt is now complete and canonical: we have read
    // EXACTLY the trusted Content-Length bytes. We deliberately do NOT perform a
    // further blocking read to require an immediate clean EOF.
    //
    // Root cause of the observed real one-computer Tor failure: this is a
    // single-shot request→response client that closes the connection right after
    // returning. Over a real Tor v3 circuit the peer's `Connection: close` does
    // not always surface to this side as a prompt zero-length read — the RELAY_END
    // teardown can arrive as a connection-reset read error, or be delayed until
    // the full `http_response` timeout. A mandatory trailing-EOF read therefore
    // discarded an already-complete, already-authenticated receipt (mapping a
    // reset to `PrivateTransportUnavailable`) or blocked for the whole response
    // timeout, leaving the voter stranded in CAST_PENDING even though delivery had
    // in fact succeeded. Requiring EOF here adds no correctness for a client that
    // reads one bounded response and then closes; every genuine framing defense
    // (single non-conflicting Content-Length, no transfer-encoding, exact-length
    // body, oversize/truncation bounds, 200-only status) is enforced above and is
    // unaffected. Trailing bytes that a hostile peer sends *after* a complete body
    // cannot smuggle a second response into a connection we never reuse.
    Ok(body)
}

fn parse_status_line_200(status_line: &str) -> Result<(), PrivateTransportNetworkErrorV1> {
    let mut parts = status_line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest);
    }
    let code = parts
        .next()
        .ok_or(PrivateTransportNetworkErrorV1::InvalidOpaqueRequest)?;
    // Only 200 is success; every 3xx redirect and every other status is refused.
    if code != "200" {
        return Err(PrivateTransportNetworkErrorV1::PrivateTransportUnavailable);
    }
    Ok(())
}

/// Failure to parse an HTTP header line under strict syntax rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHeaderErrorV1 {
    Malformed,
}

/// Parses one HTTP/1.1 header line under deliberately strict RFC 7230 syntax and
/// returns `(lowercased-field-name, ows-trimmed-value)`.
///
/// This endpoint is intentionally stricter than a general HTTP client. It
/// rejects: obs-fold / continuation lines (leading SP or HTAB), whitespace
/// before the colon, an empty field name, any non-token byte in the field name,
/// and any control byte (including NUL, and a bare LF that survived `\r\n`
/// splitting) in the value. Only optional whitespace immediately around the
/// value is trimmed; the field name is never trimmed into validity.
pub fn parse_strict_header_line_v1(line: &str) -> Result<(String, &str), StrictHeaderErrorV1> {
    // Obs-fold / continuation lines begin with SP or HTAB.
    if line
        .as_bytes()
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        return Err(StrictHeaderErrorV1::Malformed);
    }
    let colon = line.find(':').ok_or(StrictHeaderErrorV1::Malformed)?;
    let name = &line[..colon];
    if name.is_empty() || !name.bytes().all(is_http_token_char) {
        return Err(StrictHeaderErrorV1::Malformed);
    }
    let value = line[colon + 1..].trim_matches(|character| character == ' ' || character == '\t');
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(StrictHeaderErrorV1::Malformed);
    }
    Ok((name.to_ascii_lowercase(), value))
}

/// RFC 7230 `tchar`: the only bytes permitted in an HTTP field name.
fn is_http_token_char(byte: u8) -> bool {
    matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// Strictly parses a `Content-Length` value: one or more ASCII digits only, with
/// no sign, whitespace, comma, or suffix, and within `usize` range.
pub fn parse_strict_content_length_v1(value: &str) -> Result<usize, StrictHeaderErrorV1> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(StrictHeaderErrorV1::Malformed);
    }
    value
        .parse::<usize>()
        .map_err(|_| StrictHeaderErrorV1::Malformed)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_all(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), PrivateTransportNetworkErrorV1> {
    stream
        .write_all(bytes)
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
}

fn read_exact(
    stream: &mut TcpStream,
    buffer: &mut [u8],
) -> Result<(), PrivateTransportNetworkErrorV1> {
    stream
        .read_exact(buffer)
        .map_err(|_| PrivateTransportNetworkErrorV1::PrivateTransportUnavailable)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_socket_addr_validation_is_strict() {
        assert!(
            validate_loopback_socket_addr_v1(SocketAddr::from((Ipv4Addr::LOCALHOST, 9050))).is_ok()
        );
        assert!(
            validate_loopback_socket_addr_v1(SocketAddr::from((Ipv6Addr::LOCALHOST, 9050))).is_ok()
        );
        // Port zero, unspecified, LAN, and public addresses are all rejected.
        assert!(
            validate_loopback_socket_addr_v1(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).is_err()
        );
        assert!(
            validate_loopback_socket_addr_v1(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9050)))
                .is_err()
        );
        assert!(
            validate_loopback_socket_addr_v1(SocketAddr::from((
                Ipv4Addr::new(192, 168, 1, 10),
                9050
            )))
            .is_err()
        );
        assert!(
            validate_loopback_socket_addr_v1(SocketAddr::from((
                Ipv4Addr::new(203, 0, 113, 7),
                9050
            )))
            .is_err()
        );
    }

    #[test]
    fn onion_hostname_validation_is_strict() {
        let good = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        assert_eq!(good.len(), 62);
        assert!(validate_onion_hostname_v1(good).is_ok());

        // Uppercase, clearnet, IP, localhost, embedded port/path/scheme,
        // whitespace, userinfo, wrong length, and non-onion suffix all reject.
        assert!(validate_onion_hostname_v1(&good.to_ascii_uppercase()).is_err());
        assert!(validate_onion_hostname_v1("example.com").is_err());
        assert!(validate_onion_hostname_v1("127.0.0.1").is_err());
        assert!(validate_onion_hostname_v1("localhost").is_err());
        assert!(
            validate_onion_hostname_v1(
                "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:80"
            )
            .is_err()
        );
        assert!(
            validate_onion_hostname_v1(
                "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
            )
            .is_err()
        );
        assert!(
            validate_onion_hostname_v1(
                "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/x"
            )
            .is_err()
        );
        assert!(
            validate_onion_hostname_v1(
                "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53w1d.onion"
            )
            .is_err()
        ); // '1' not in base32
        assert!(validate_onion_hostname_v1("short.onion").is_err());
    }

    #[test]
    fn carrier_construction_only_validates_loopback_endpoint() {
        // The carrier stores no destination; construction validates only the
        // loopback SOCKS endpoint.
        assert!(
            TorSocksPrivateReleaseCarrierV1::new(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 9050)),
                TorCarrierTimeoutsV1::default(),
            )
            .is_ok()
        );
        assert!(
            TorSocksPrivateReleaseCarrierV1::new(
                SocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 9050)),
                TorCarrierTimeoutsV1::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn status_line_parser_accepts_only_200() {
        assert!(parse_status_line_200("HTTP/1.1 200 OK").is_ok());
        assert!(parse_status_line_200("HTTP/1.0 200 OK").is_ok());
        assert!(parse_status_line_200("HTTP/1.1 302 Found").is_err());
        assert!(parse_status_line_200("HTTP/1.1 500 Internal Server Error").is_err());
        assert!(parse_status_line_200("ICY 200 OK").is_err());
        assert!(parse_status_line_200("garbage").is_err());
    }

    #[test]
    fn strict_header_line_parser_rejects_malformed_syntax() {
        assert_eq!(
            parse_strict_header_line_v1("Content-Length: 12"),
            Ok(("content-length".to_owned(), "12")),
        );
        // Case-insensitive name; OWS around the value is trimmed.
        assert_eq!(
            parse_strict_header_line_v1("TrAnSfEr-EnCoDiNg:\tchunked "),
            Ok(("transfer-encoding".to_owned(), "chunked")),
        );
        // Whitespace before the colon, obs-fold, empty/invalid names, NUL, and a
        // control byte in the value are all rejected.
        assert!(parse_strict_header_line_v1("Content-Length : 12").is_err());
        assert!(parse_strict_header_line_v1(" folded").is_err());
        assert!(parse_strict_header_line_v1("\tfolded").is_err());
        assert!(parse_strict_header_line_v1(": novalue-name").is_err());
        assert!(parse_strict_header_line_v1("Bad Name: x").is_err());
        assert!(parse_strict_header_line_v1("X: a\u{0}b").is_err());
    }

    #[test]
    fn strict_content_length_parser_is_digits_only() {
        assert_eq!(parse_strict_content_length_v1("0"), Ok(0));
        assert_eq!(parse_strict_content_length_v1("12345"), Ok(12345));
        for bad in ["", "+1", "-1", "1 2", "0x10", "1,2", " 1", "1 ", "abc"] {
            assert!(
                parse_strict_content_length_v1(bad).is_err(),
                "{bad:?} must reject"
            );
        }
    }
}
