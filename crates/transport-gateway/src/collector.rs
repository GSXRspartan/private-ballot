//! Organizer-side loopback opaque-envelope collector.
//!
//! [`OpaqueEnvelopeCollectorV1`] is a minimal, strict HTTP/1.1 front end that
//! binds **only** to an IP loopback address. It is intended to be placed behind
//! a Tor hidden-service `HiddenServicePort` mapping later; it is never itself a
//! LAN- or public-facing web server. It accepts exactly one request shape —
//! `POST /v1/opaque-envelope` with `Content-Type: application/octet-stream` —
//! and hands the exact opaque body bytes to the existing gateway boundary via a
//! [`OpaqueEnvelopeGatewayHandlerV1`]. It never decrypts, duplicates HPKE, or
//! reimplements admission/intake logic itself.
//!
//! Concurrency: this MVP handles a single connection per [`serve_next`] call
//! (`Connection: close`, no keep-alive). That is intentionally the simplest and
//! safest model sufficient for controlled two-computer testing; batching and
//! throughput are unchanged and out of scope here.
//!
//! [`serve_next`]: OpaqueEnvelopeCollectorV1::serve_next

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use tari_cc_private_ballot_gui_core::{
    AuthenticatedTransportReceiptV1, GuiElectionSessionV1, MAX_STAGED_RELEASE_ENVELOPE_BYTES,
    TransportDescriptorV1, TransportError, VoterReceiptStateV1,
    append_accepted_ballot_package_to_inbox_v1,
};
use tari_cc_private_ballot_transport_network::{
    parse_strict_content_length_v1, parse_strict_header_line_v1,
};

use crate::{GatewayReceiverKeyV1, TransportGatewaySimulatorV1, new_retry_capability_v1};

/// The single accepted request path. Anything else is a 404.
pub const OPAQUE_ENVELOPE_HTTP_PATH_V1: &str = "/v1/opaque-envelope";
/// The single accepted request/response content type.
pub const OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1: &str = "application/octet-stream";

/// Bounded ceiling on the request header section. Headers that do not terminate
/// within this many bytes are rejected before any body is read.
const MAX_HTTP_HEADER_BYTES: usize = 8 * 1024;

const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute wall-clock ceiling on a single request, independent of per-read
/// inactivity timeouts. Because the collector is single-connection-per-serve,
/// this prevents one slow-drip client from holding it far longer than intended.
const DEFAULT_MAX_REQUEST_DURATION: Duration = Duration::from_secs(15);

/// Why the collector could not produce an authenticated receipt for a request.
/// Each maps to a minimal HTTP status with an empty body; no decrypted ballot,
/// key, path, or internal detail is ever reflected to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorRejectionV1 {
    /// Malformed request line, headers, framing, or truncated body (400).
    BadRequest,
    /// Wrong endpoint path (404).
    NotFound,
    /// Wrong method (405).
    MethodNotAllowed,
    /// Body exceeds the configured maximum (413).
    PayloadTooLarge,
    /// Wrong or missing content type (415).
    UnsupportedMediaType,
    /// The request exceeded the absolute per-request time budget (408).
    RequestTimeout,
    /// Admission is closed or the election is not open (503).
    AdmissionUnavailable,
    /// A bounded internal failure (500).
    Internal,
}

impl CollectorRejectionV1 {
    const fn status(self) -> (u16, &'static str) {
        match self {
            Self::BadRequest => (400, "Bad Request"),
            Self::NotFound => (404, "Not Found"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
            Self::PayloadTooLarge => (413, "Payload Too Large"),
            Self::UnsupportedMediaType => (415, "Unsupported Media Type"),
            Self::RequestTimeout => (408, "Request Timeout"),
            Self::AdmissionUnavailable => (503, "Service Unavailable"),
            Self::Internal => (500, "Internal Server Error"),
        }
    }

    /// A bounded, privacy-safe stage label for LOCAL organizer diagnostics. It
    /// carries only the HTTP rejection class — never plaintext, proof, nullifier,
    /// credential, key, envelope, or receipt bytes, and never any client/network
    /// identity.
    #[must_use]
    pub const fn safe_stage(self) -> &'static str {
        match self {
            Self::BadRequest => "HTTP_BAD_REQUEST",
            Self::NotFound => "HTTP_NOT_FOUND",
            Self::MethodNotAllowed => "HTTP_METHOD_NOT_ALLOWED",
            Self::PayloadTooLarge => "HTTP_PAYLOAD_TOO_LARGE",
            Self::UnsupportedMediaType => "HTTP_UNSUPPORTED_MEDIA_TYPE",
            Self::RequestTimeout => "HTTP_REQUEST_TIMEOUT",
            Self::AdmissionUnavailable => "ADMISSION_UNAVAILABLE",
            Self::Internal => "INTERNAL",
        }
    }
}

/// The safe outcome of servicing exactly one collector connection, surfaced to
/// the controlled-test organizer service loop for local operational logging.
///
/// It distinguishes only "an authenticated receipt was written (200)" from "the
/// request was rejected with class X". Whether a 200 corresponds to a NEW
/// acceptance versus a duplicate/authenticated-rejection is derived by the
/// organizer from the separate `accepted_unique_count` delta, never from any
/// receipt contents. No stage carries secret or identifying material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorServeOutcomeV1 {
    /// A `200 OK` with authenticated receipt bytes was written to the caller.
    ReceiptReturned,
    /// The request was rejected before a receipt could be produced.
    Rejected(CollectorRejectionV1),
}

impl CollectorServeOutcomeV1 {
    /// True when a `200` authenticated receipt was written.
    #[must_use]
    pub const fn receipt_returned(self) -> bool {
        matches!(self, Self::ReceiptReturned)
    }

    /// A bounded, privacy-safe stage label for LOCAL organizer diagnostics.
    #[must_use]
    pub const fn safe_stage(self) -> &'static str {
        match self {
            Self::ReceiptReturned => "RECEIPT_RETURNED",
            Self::Rejected(rejection) => rejection.safe_stage(),
        }
    }
}

/// Absolute per-request deadline. It arms each blocking read with the smaller of
/// the per-read inactivity timeout and the time remaining before the total
/// budget elapses, so a slow-drip peer cannot hold the single-connection
/// collector past the budget.
struct RequestDeadlineV1 {
    deadline: Instant,
    per_read: Duration,
}

impl RequestDeadlineV1 {
    fn new(total: Duration, per_read: Duration) -> Self {
        Self {
            deadline: Instant::now() + total,
            per_read,
        }
    }

    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    }

    /// Sets the stream read timeout to `min(per_read, remaining)`, or reports a
    /// timeout if the total budget is already spent.
    fn arm_read(&self, stream: &TcpStream) -> Result<(), CollectorRejectionV1> {
        let remaining = self
            .remaining()
            .ok_or(CollectorRejectionV1::RequestTimeout)?;
        stream
            .set_read_timeout(Some(remaining.min(self.per_read)))
            .map_err(|_| CollectorRejectionV1::Internal)?;
        Ok(())
    }

    /// Classifies a read error as a timeout (budget spent) or malformed request.
    fn classify_read_error(&self) -> CollectorRejectionV1 {
        if self.remaining().is_none() {
            CollectorRejectionV1::RequestTimeout
        } else {
            CollectorRejectionV1::BadRequest
        }
    }
}

/// The gateway handoff boundary. Implementations receive the exact opaque
/// envelope bytes and return canonical authenticated receipt bytes, or a bounded
/// rejection. The collector never opens the envelope itself.
pub trait OpaqueEnvelopeGatewayHandlerV1 {
    fn handle_opaque_envelope(&mut self, envelope: &[u8]) -> Result<Vec<u8>, CollectorRejectionV1>;
}

/// A concrete handler that wires the loopback collector to the existing
/// [`TransportGatewaySimulatorV1`] and signs an authenticated, descriptor-bound
/// receipt with an organizer receipt key.
///
/// It enforces the receipt-key / descriptor consistency required before signing:
/// the receipt signing key MUST be one the descriptor authorizes, the signed
/// descriptor fingerprint IS the descriptor actually serving this collector, and
/// the signed package digest IS the digest the gateway computed for the exact
/// bytes it processed (never a caller-supplied value).
pub struct GatewayCollectorHandlerV1<'a> {
    gateway: &'a mut TransportGatewaySimulatorV1,
    descriptor: &'a TransportDescriptorV1,
    receiver_key: &'a GatewayReceiverKeyV1,
    session: &'a mut GuiElectionSessionV1,
    receipt_signing_key: &'a SigningKey,
    receipt_key_id: String,
    /// Optional app-owned, election-scoped durable hand-off inbox. When set,
    /// every canonical package the session ACCEPTS (including an exact-retry
    /// recovery of a previously accepted delivery) is appended here so the
    /// organizer GUI can ingest it into its authoritative durable workspace.
    /// The append is content-addressed and idempotent; a write failure fails
    /// the request closed so a retry self-heals the durable hand-off.
    accepted_package_inbox: Option<&'a Path>,
}

impl<'a> GatewayCollectorHandlerV1<'a> {
    /// Builds a handler. The receipt signing key must correspond to a receipt
    /// verification key the descriptor authorizes, otherwise construction fails
    /// closed (organizer misconfiguration, never a caller-influenced value).
    pub fn new(
        gateway: &'a mut TransportGatewaySimulatorV1,
        descriptor: &'a TransportDescriptorV1,
        receiver_key: &'a GatewayReceiverKeyV1,
        session: &'a mut GuiElectionSessionV1,
        receipt_signing_key: &'a SigningKey,
        receipt_key_id: String,
    ) -> Result<Self, TransportError> {
        let verifying = receipt_signing_key.verifying_key().to_bytes();
        if !descriptor
            .receipt_verification_keys()
            .iter()
            .any(|authorized| authorized == &verifying)
        {
            return Err(TransportError::WrongGatewayKey);
        }
        if receipt_key_id.is_empty() {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(Self {
            gateway,
            descriptor,
            receiver_key,
            session,
            receipt_signing_key,
            receipt_key_id,
            accepted_package_inbox: None,
        })
    }

    /// Enables durable hand-off of accepted canonical packages into an
    /// app-owned, election-scoped inbox directory (controlled-test intake). The
    /// non-test/offline path leaves this unset and is unchanged.
    #[must_use]
    pub fn with_accepted_package_inbox(mut self, inbox_dir: &'a Path) -> Self {
        self.accepted_package_inbox = Some(inbox_dir);
        self
    }
}

impl OpaqueEnvelopeGatewayHandlerV1 for GatewayCollectorHandlerV1<'_> {
    fn handle_opaque_envelope(&mut self, envelope: &[u8]) -> Result<Vec<u8>, CollectorRejectionV1> {
        // The retry-capability channel is not part of the HTTP MVP; a fresh
        // capability is generated per request. The election-scoped nullifier in
        // the existing intake path remains the authoritative one-vote rule, so a
        // genuine duplicate ballot is still rejected by intake.
        let retry_capability = new_retry_capability_v1();
        let mut next_gateway = self.gateway.clone();
        let mut next_session = self.session.transactional_clone();
        let (voter_receipt, package_digest) = match next_gateway.deliver_and_digest(
            envelope,
            self.descriptor,
            self.receiver_key,
            retry_capability,
            &mut next_session,
        ) {
            Ok(result) => result,
            // Admission closed / election not open is the only "unavailable".
            Err(TransportError::Unavailable) => {
                return Err(CollectorRejectionV1::AdmissionUnavailable);
            }
            // Any decrypt/binding/framing failure is a generic bad request; no
            // internal reason is exposed.
            Err(_) => return Err(CollectorRejectionV1::BadRequest),
        };

        // Durable hand-off: when the session accepted this ballot (a new
        // acceptance OR an exact-retry recovery of a previously accepted
        // delivery), append the exact canonical package bytes to the app-owned
        // inbox so the organizer GUI can ingest them into its authoritative
        // durable workspace. `intake_ballot_package_bytes` pushes the decoded
        // package as the last element, so `packages().last()` is exactly this
        // envelope's canonical package. The inbox is content-addressed, so an
        // exact retry never produces a second file and never double-counts. A
        // genuine different-ballot duplicate returns `Rejected` here and is NOT
        // handed off. A write failure fails the request closed (500) with no
        // receipt, so the voter stays pending and a retry — which is still
        // `Accepted` — re-attempts the durable hand-off (self-healing).
        if let Some(inbox_dir) = self.accepted_package_inbox
            && voter_receipt.state == VoterReceiptStateV1::Accepted
        {
            let Some(package_bytes) = next_session.packages().last() else {
                return Err(CollectorRejectionV1::Internal);
            };
            if append_accepted_ballot_package_to_inbox_v1(inbox_dir, package_bytes).is_err() {
                return Err(CollectorRejectionV1::Internal);
            }
        }

        *self.gateway = next_gateway;
        *self.session = next_session;

        // Sign the SAME authenticated receipt format the release boundary
        // verifies: bound to THIS descriptor's fingerprint and the exact digest
        // the gateway processed. The voter side performs the authoritative
        // cryptographic verification; this response never promotes cast state.
        let fingerprint = self
            .descriptor
            .fingerprint()
            .map_err(|_| CollectorRejectionV1::Internal)?;
        let receipt = AuthenticatedTransportReceiptV1::sign_for_test_or_ceremony(
            voter_receipt,
            fingerprint,
            package_digest,
            None,
            self.receipt_key_id.clone(),
            self.receipt_signing_key,
        );
        receipt
            .to_canonical_cbor()
            .map_err(|_| CollectorRejectionV1::Internal)
    }
}

/// How the collector could fail to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorBindErrorV1 {
    /// The requested bind address is not an IP loopback address.
    NonLoopback,
    /// The OS refused to bind the loopback socket.
    Io,
}

/// The loopback-only opaque-envelope collector.
#[derive(Debug)]
pub struct OpaqueEnvelopeCollectorV1 {
    listener: TcpListener,
    max_body_bytes: usize,
    read_timeout: Duration,
    write_timeout: Duration,
    max_request_duration: Duration,
}

impl OpaqueEnvelopeCollectorV1 {
    /// Binds the collector to a loopback `SocketAddr`. A non-loopback address
    /// (including `0.0.0.0`, any LAN address, or any public IP) is rejected
    /// before the socket is bound, making accidental LAN exposure impossible.
    pub fn bind(addr: SocketAddr) -> Result<Self, CollectorBindErrorV1> {
        if !addr.ip().is_loopback() {
            return Err(CollectorBindErrorV1::NonLoopback);
        }
        let listener = TcpListener::bind(addr).map_err(|_| CollectorBindErrorV1::Io)?;
        Ok(Self {
            listener,
            max_body_bytes: usize::try_from(MAX_STAGED_RELEASE_ENVELOPE_BYTES)
                .unwrap_or(usize::MAX),
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            max_request_duration: DEFAULT_MAX_REQUEST_DURATION,
        })
    }

    /// Convenience: bind `127.0.0.1:<port>` (port `0` selects an ephemeral port).
    pub fn bind_loopback_port(port: u16) -> Result<Self, CollectorBindErrorV1> {
        Self::bind(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    /// Overrides the absolute per-request time budget (primarily for tests).
    #[must_use]
    pub fn with_max_request_duration(mut self, total: Duration) -> Self {
        self.max_request_duration = total;
        self
    }

    /// The actual bound loopback address (useful with an ephemeral port `0`).
    pub fn local_addr(&self) -> Result<SocketAddr, CollectorBindErrorV1> {
        self.listener
            .local_addr()
            .map_err(|_| CollectorBindErrorV1::Io)
    }

    /// Accepts and fully services exactly one connection, then returns. On a
    /// well-formed request the handler's authenticated receipt bytes are written
    /// with `200 OK`; otherwise a minimal error status with an empty body is
    /// written. The result reports whether an authenticated receipt was returned.
    pub fn serve_next(
        &self,
        handler: &mut dyn OpaqueEnvelopeGatewayHandlerV1,
    ) -> Result<bool, CollectorBindErrorV1> {
        let (mut stream, _peer) = self
            .listener
            .accept()
            .map_err(|_| CollectorBindErrorV1::Io)?;
        // Bound the response write; reads are bounded per-read AND by an absolute
        // total deadline armed inside `read_and_dispatch`.
        let _ = stream.set_write_timeout(Some(self.write_timeout));
        let deadline = RequestDeadlineV1::new(self.max_request_duration, self.read_timeout);
        let outcome = match read_and_dispatch(&mut stream, self.max_body_bytes, &deadline, handler)
        {
            Ok(receipt_bytes) => {
                write_response(&mut stream, 200, "OK", &receipt_bytes);
                true
            }
            Err(rejection) => {
                let (code, reason) = rejection.status();
                write_response(&mut stream, code, reason, &[]);
                false
            }
        };
        // Best-effort orderly close; `Connection: close` is always used.
        let _ = stream.flush();
        Ok(outcome)
    }

    /// Stoppable single-serve variant for the controlled-test organizer service
    /// loop. It polls the loopback listener in non-blocking mode every
    /// `poll_interval`, returning `Ok(None)` as soon as `stop` is set, or
    /// servicing exactly one connection otherwise. `Ok(Some(true))` means an
    /// authenticated receipt was returned; `Ok(Some(false))` means a request
    /// was serviced but rejected. Never blocks longer than `poll_interval`
    /// while waiting, so shutdown is bounded.
    #[cfg(feature = "managed-tor-test")]
    pub fn serve_next_or_stop(
        &self,
        handler: &mut dyn OpaqueEnvelopeGatewayHandlerV1,
        stop: &std::sync::atomic::AtomicBool,
        poll_interval: std::time::Duration,
    ) -> Result<Option<CollectorServeOutcomeV1>, CollectorBindErrorV1> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_| CollectorBindErrorV1::Io)?;
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(None);
            }
            match self.listener.accept() {
                Ok((mut stream, _peer)) => {
                    // A real connection arrived; restore blocking mode on the
                    // listener for the next accept poll.
                    let _ = self.listener.set_nonblocking(false);
                    // CRITICAL (Windows root cause of the real one-computer Tor
                    // failure): the socket returned by `accept()` INHERITS the
                    // listener's non-blocking flag on Windows, so the
                    // non-blocking accept-poll above leaves THIS accepted stream
                    // non-blocking. On a non-blocking stream `set_read_timeout`
                    // (SO_RCVTIMEO) is ignored and the very first `read()` in
                    // `read_and_dispatch` returns `WouldBlock` whenever the
                    // request bytes have not arrived yet — which is ALWAYS the
                    // case over a real Tor v3 circuit, where the request reaches
                    // this loopback collector a full circuit round-trip AFTER
                    // `accept()` returns. `read_and_dispatch`/`classify_read_error`
                    // then map that `WouldBlock` to `BadRequest` (400) and reject
                    // every genuine Tor ballot BEFORE intake (accepted count
                    // stays 0; the voter falls to CAST_PENDING). It also explains
                    // the manual GET route probe returning 400 instead of the 405
                    // a correctly-blocking collector gives. Deterministic loopback
                    // tests never reproduced it because the client writes the whole
                    // request before the worker's first read, so the bytes are
                    // already buffered and `read()` returns them immediately even
                    // on a non-blocking socket. Force blocking mode here so the
                    // bounded read timeouts actually govern each read; fail closed
                    // (500) if the OS refuses rather than risk a spurious 400.
                    if stream.set_nonblocking(false).is_err() {
                        write_response(&mut stream, 500, "Internal Server Error", &[]);
                        let _ = stream.flush();
                        return Ok(Some(CollectorServeOutcomeV1::Rejected(
                            CollectorRejectionV1::Internal,
                        )));
                    }
                    let _ = stream.set_write_timeout(Some(self.write_timeout));
                    let deadline =
                        RequestDeadlineV1::new(self.max_request_duration, self.read_timeout);
                    let outcome = match read_and_dispatch(
                        &mut stream,
                        self.max_body_bytes,
                        &deadline,
                        handler,
                    ) {
                        Ok(receipt_bytes) => {
                            write_response(&mut stream, 200, "OK", &receipt_bytes);
                            CollectorServeOutcomeV1::ReceiptReturned
                        }
                        Err(rejection) => {
                            let (code, reason) = rejection.status();
                            write_response(&mut stream, code, reason, &[]);
                            CollectorServeOutcomeV1::Rejected(rejection)
                        }
                    };
                    let _ = stream.flush();
                    return Ok(Some(outcome));
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    std::thread::sleep(poll_interval);
                }
                Err(_) => {
                    let _ = self.listener.set_nonblocking(false);
                    return Err(CollectorBindErrorV1::Io);
                }
            }
        }
    }
}

fn read_and_dispatch(
    stream: &mut TcpStream,
    max_body_bytes: usize,
    deadline: &RequestDeadlineV1,
    handler: &mut dyn OpaqueEnvelopeGatewayHandlerV1,
) -> Result<Vec<u8>, CollectorRejectionV1> {
    let (request, mut body) = read_request_head(stream, deadline)?;

    // Validation order: method, path, framing, content type, length.
    if request.method != "POST" {
        return Err(CollectorRejectionV1::MethodNotAllowed);
    }
    if request.path != OPAQUE_ENVELOPE_HTTP_PATH_V1 {
        return Err(CollectorRejectionV1::NotFound);
    }
    if request.transfer_encoding_present {
        return Err(CollectorRejectionV1::BadRequest);
    }
    match request.content_type.as_deref() {
        Some(value) if value.eq_ignore_ascii_case(OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1) => {}
        _ => return Err(CollectorRejectionV1::UnsupportedMediaType),
    }
    let length = request
        .content_length
        .ok_or(CollectorRejectionV1::BadRequest)?;
    if length > max_body_bytes {
        return Err(CollectorRejectionV1::PayloadTooLarge);
    }

    // Read exactly `length` body bytes. Already-buffered bytes are reused; the
    // read is bounded by `length`, never by EOF alone, and by the absolute
    // request deadline.
    if body.len() > length {
        return Err(CollectorRejectionV1::BadRequest);
    }
    let mut chunk = [0u8; 512];
    while body.len() < length {
        deadline.arm_read(stream)?;
        let read = stream
            .read(&mut chunk)
            .map_err(|_| deadline.classify_read_error())?;
        if read == 0 {
            return Err(CollectorRejectionV1::BadRequest);
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > length {
            return Err(CollectorRejectionV1::BadRequest);
        }
    }

    handler.handle_opaque_envelope(&body)
}

struct ParsedRequest {
    method: String,
    path: String,
    content_length: Option<usize>,
    content_type: Option<String>,
    transfer_encoding_present: bool,
}

fn read_request_head(
    stream: &mut TcpStream,
    deadline: &RequestDeadlineV1,
) -> Result<(ParsedRequest, Vec<u8>), CollectorRejectionV1> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 512];
    let header_end = loop {
        if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
            break position;
        }
        if buffer.len() > MAX_HTTP_HEADER_BYTES {
            return Err(CollectorRejectionV1::BadRequest);
        }
        deadline.arm_read(stream)?;
        let read = stream
            .read(&mut chunk)
            .map_err(|_| deadline.classify_read_error())?;
        if read == 0 {
            return Err(CollectorRejectionV1::BadRequest);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HTTP_HEADER_BYTES {
            return Err(CollectorRejectionV1::BadRequest);
        }
    };

    let header_text =
        std::str::from_utf8(&buffer[..header_end]).map_err(|_| CollectorRejectionV1::BadRequest)?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or(CollectorRejectionV1::BadRequest)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(CollectorRejectionV1::BadRequest)?;
    let path = parts.next().ok_or(CollectorRejectionV1::BadRequest)?;
    let version = parts.next().ok_or(CollectorRejectionV1::BadRequest)?;
    if parts.next().is_some() {
        return Err(CollectorRejectionV1::BadRequest);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(CollectorRejectionV1::BadRequest);
    }

    let mut content_length: Option<usize> = None;
    let mut content_type: Option<String> = None;
    let mut transfer_encoding_present = false;
    for line in lines {
        // Strict RFC 7230 header syntax: rejects whitespace-before-colon,
        // obs-fold, NUL/control bytes, and non-token field names. No empty line
        // can appear before the `\r\n\r\n` terminator.
        let (name, value) =
            parse_strict_header_line_v1(line).map_err(|_| CollectorRejectionV1::BadRequest)?;
        match name.as_str() {
            "content-length" => {
                // Any duplicate Content-Length (even numerically equal) is
                // rejected as a request-smuggling defense.
                if content_length.is_some() {
                    return Err(CollectorRejectionV1::BadRequest);
                }
                content_length = Some(
                    parse_strict_content_length_v1(value)
                        .map_err(|_| CollectorRejectionV1::BadRequest)?,
                );
            }
            // Any casing of Transfer-Encoding is refused (name is lowercased).
            "transfer-encoding" => transfer_encoding_present = true,
            "content-type" => content_type = Some(value.to_owned()),
            _ => {}
        }
    }

    let request = ParsedRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        content_length,
        content_type,
        transfer_encoding_present,
    };
    let body = buffer[header_end + 4..].to_vec();
    Ok((request, body))
}

fn write_response(stream: &mut TcpStream, code: u16, reason: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {OPAQUE_ENVELOPE_HTTP_CONTENT_TYPE_V1}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    if !body.is_empty() {
        let _ = stream.write_all(body);
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
