//! Organizer collector service-loop liveness tests (managed-tor only).
//!
//! These prove the dedicated worker remains alive after start, services
//! requests, and exits cleanly on stop. They would FAIL under the old
//! inverted loop condition (`while stop.load(...)` with stop starting false),
//! which dropped the listener immediately and let the worker exit.
//!
//! No real Tor, no network beyond loopback sockets.

#![cfg(feature = "managed-tor")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, PaddingPolicyV1, PrivateBallotEnvelopeV1, TransportDescriptorV1,
    TransportRoutePolicyV1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, OpaqueEnvelopeCollectorV1, OrganizerCollectorServiceLoopV1,
    ThreadSafeCollectorHandlerV1, TransportGatewaySimulatorV1,
};

type Kem = X25519HkdfSha256;

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

fn descriptor_with(receiver_public: [u8; 32]) -> TransportDescriptorV1 {
    let manifest = common::manifest();
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("hash");
    let authority = SigningKey::from_bytes(&[71; 32]);
    let receipt_key = SigningKey::from_bytes(&[72; 32]);
    TransportDescriptorV1::sign_for_test_or_ceremony(
        manifest.election_id().as_bytes().to_vec(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![TEST_ONION.to_owned()],
        Vec::new(),
        receiver_public,
        "service-loop-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "fixed-loop".to_owned(),
            padded_bytes: 65_536,
        },
        BatchPolicyV1 {
            id: "accepted-1".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        "service-loop-root".to_owned(),
        &authority,
    )
    .expect("descriptor")
}

struct LoopFixture {
    service_loop: OrganizerCollectorServiceLoopV1,
    addr: SocketAddr,
    descriptor: TransportDescriptorV1,
}

fn start_loop() -> LoopFixture {
    start_loop_with_inbox(None)
}

fn start_loop_with_inbox(inbox: Option<PathBuf>) -> LoopFixture {
    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut gateway_public = [0u8; 32];
    gateway_public.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(receiver_secret.to_bytes().as_slice());
    let descriptor = descriptor_with(gateway_public);
    let receiver_key = GatewayReceiverKeyV1::from_secret_bytes(secret).expect("receiver key");

    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind collector");
    let addr = collector.local_addr().expect("addr");

    let gateway = std::sync::Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    let session = std::sync::Arc::new(Mutex::new(common::open_session()));
    let descriptor_arc = std::sync::Arc::new(descriptor.clone());
    let receiver_key_arc = std::sync::Arc::new(receiver_key);
    let receipt_key_arc = std::sync::Arc::new(SigningKey::from_bytes(&[72; 32]));
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway.clone(),
        descriptor_arc,
        receiver_key_arc,
        session,
        receipt_key_arc,
        "service-loop-receipt".to_owned(),
    );
    let handler = match inbox.as_ref() {
        Some(inbox) => handler.with_accepted_package_inbox(inbox.clone()),
        None => handler,
    };
    let service_loop =
        OrganizerCollectorServiceLoopV1::start(collector, handler, Duration::from_millis(20))
            .expect("start service loop");
    LoopFixture {
        service_loop,
        addr,
        descriptor,
    }
}

fn temp_path(label: &str) -> PathBuf {
    let unique = format!(
        "{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
    );
    std::env::temp_dir().join(unique)
}

/// POSTs one opaque envelope to the loopback collector and returns the HTTP
/// status code plus the exact response body.
fn post_envelope(addr: SocketAddr, envelope: &[u8]) -> (u16, Vec<u8>) {
    let mut request = format!(
        "POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        envelope.len()
    )
    .into_bytes();
    request.extend_from_slice(envelope);
    let mut stream = TcpStream::connect(addr).expect("connect collector");
    stream.write_all(&request).expect("write request");
    stream.flush().expect("flush");
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).expect("read response");
    let split = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response header terminator");
    let status = std::str::from_utf8(&buffer[..split])
        .ok()
        .and_then(|head| head.lines().next())
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status code");
    (status, buffer[split + 4..].to_vec())
}

#[test]
fn worker_remains_alive_after_start() {
    let fixture = start_loop();
    // Under the old inverted condition, the worker exited immediately. Give it
    // a short bounded window to (wrongly) terminate, then assert it is alive.
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        fixture.service_loop.worker_is_alive(),
        "worker must remain alive after start until stop is requested"
    );
    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded stop");
}

#[test]
fn worker_services_a_request_then_stops_cleanly() {
    let fixture = start_loop();
    let addr = fixture.addr;
    // Prove the loop is actually servicing connections: send a malformed
    // request and expect a bounded HTTP error (not a connection refused / hang).
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).expect("connect collector");
        let _ = stream.write_all(b"POST /v1/opaque-envelope HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        buf
    });
    let response = client.join().expect("client thread");
    // The gateway rejects malformed envelope bytes with 400; the important
    // invariant is that the listener was actually serving (not dropped).
    let status_line = std::str::from_utf8(&response)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("");
    assert!(
        status_line.starts_with("HTTP/1.1 4") || status_line.starts_with("HTTP/1.1 200"),
        "collector must produce an HTTP response, got: {status_line}"
    );
    assert!(
        fixture.service_loop.worker_is_alive(),
        "worker still alive after servicing one request"
    );
    // stop() consumes the service loop and joins the worker; returning Ok proves
    // a bounded clean exit (the worker was alive and observed stop).
    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

/// The live-observability primitive the controlled intake CLI polls: the
/// aggregate accepted-ballot count advances when a valid ballot is accepted and
/// stays STABLE when the SAME exact envelope is retried (the organizer
/// idempotency fix), all through the real service loop. This is what lets the
/// operator see "Accepted ballots: N" advance for real deliveries only.
#[test]
fn accepted_count_advances_on_accept_and_is_stable_on_exact_retry() {
    let fixture = start_loop();
    let addr = fixture.addr;

    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        0,
        "no ballots accepted before any submission",
    );

    // Seal a valid ballot package to the SAME descriptor the loop verifies.
    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");

    // First delivery: accepted → count becomes 1.
    let (code1, body1) = post_envelope(addr, &envelope);
    assert_eq!(code1, 200);
    assert!(!body1.is_empty(), "an authenticated receipt is returned");
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        1,
        "accepted count advances to 1 on a valid new ballot",
    );

    // EXACT retry of the SAME envelope: still 200 with a receipt, but the count
    // does NOT advance (idempotent previous-delivery recovery, no double vote).
    let (code2, body2) = post_envelope(addr, &envelope);
    assert_eq!(code2, 200);
    assert!(!body2.is_empty(), "the retry also returns a receipt");
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        1,
        "an exact retry never inflates the accepted count",
    );

    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

#[test]
fn accepted_receipt_is_returned_only_after_inbox_package_exists() {
    let inbox = temp_path("service-loop-inbox-success");
    let fixture = start_loop_with_inbox(Some(inbox.clone()));
    let addr = fixture.addr;

    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");

    let (code, body) = post_envelope(addr, &envelope);
    assert_eq!(code, 200);
    assert!(!body.is_empty(), "an authenticated receipt is returned");
    assert!(
        inbox
            .read_dir()
            .expect("inbox exists before receipt is visible to caller")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().ends_with(".package")),
        "the durable inbox package must exist before the accepted receipt is made available",
    );
    assert_eq!(fixture.service_loop.accepted_unique_count(), 1);

    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

#[test]
fn inbox_persistence_failure_emits_no_receipt_and_does_not_report_accepted() {
    let inbox = temp_path("service-loop-inbox-failure");
    std::fs::write(&inbox, b"not-a-directory").expect("file blocks inbox directory");
    let fixture = start_loop_with_inbox(Some(inbox.clone()));
    let addr = fixture.addr;

    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");

    let (code, body) = post_envelope(addr, &envelope);
    assert_eq!(code, 500, "durable inbox failure must fail closed");
    assert!(
        body.is_empty(),
        "no authenticated receipt bytes are emitted"
    );
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        0,
        "worker accepted count must not advance before the durable inbox commit",
    );

    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

/// Connects, waits `delay` BEFORE writing the request, then reads the response.
/// This models a real Tor v3 circuit, where the request bytes reach the loopback
/// collector a full circuit round-trip AFTER `accept()` returns — so the worker's
/// FIRST read runs on an empty receive buffer. The existing `post_envelope`
/// helper writes the whole request before the worker reads, so on loopback the
/// bytes are already buffered and it never reproduces the accept-before-data gap.
fn post_envelope_delayed(addr: SocketAddr, envelope: &[u8], delay: Duration) -> (u16, Vec<u8>) {
    let mut request = format!(
        "POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        envelope.len()
    )
    .into_bytes();
    request.extend_from_slice(envelope);
    let mut stream = TcpStream::connect(addr).expect("connect collector");
    // The connection is established (accept() returns on the worker) but NO data
    // is sent yet: the worker's first read must block for real data, not fail.
    std::thread::sleep(delay);
    stream.write_all(&request).expect("write request");
    stream.flush().expect("flush");
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).expect("read response");
    let split = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response header terminator");
    let status = std::str::from_utf8(&buffer[..split])
        .ok()
        .and_then(|head| head.lines().next())
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status code");
    (status, buffer[split + 4..].to_vec())
}

/// Regression for the REAL one-computer Tor submission failure. When the request
/// bytes arrive AFTER `accept()` returns (as they always do over a Tor circuit),
/// the collector must still block for the data and accept a valid ballot — never
/// misclassify the accept-before-data window as a 400 Bad Request.
///
/// Before the fix, `serve_next_or_stop` left the accepted stream in the
/// listener's non-blocking mode on Windows, so the worker's first `read()`
/// returned `WouldBlock` and was mapped to `BadRequest` (400): the organizer
/// showed `Accepted ballots: 0` and the voter fell to CAST_PENDING even though
/// the onion route was reachable. This test exercises the real full stack
/// (staged envelope encode → collector HTTP parser → gateway → HPKE open → core
/// intake → authenticated receipt) through the service loop with a delay that
/// guarantees the worker reads before any data has arrived.
#[test]
fn delayed_first_read_still_accepts_a_valid_ballot() {
    let fixture = start_loop();
    let addr = fixture.addr;

    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");

    // 300ms is far longer than the loopback accept latency and far shorter than
    // the collector's 15s absolute request deadline: the worker WILL call its
    // first read before this client writes.
    let (code, body) = post_envelope_delayed(addr, &envelope, Duration::from_millis(300));
    assert_eq!(
        code, 200,
        "a ballot whose bytes arrive after accept() must still be accepted, not rejected 400",
    );
    assert!(!body.is_empty(), "an authenticated receipt is returned");
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        1,
        "the delayed-delivery ballot advances the accepted count to 1",
    );

    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

/// Waits (bounded) for the service loop to record at least `expected` serviced
/// requests. The worker updates the observation just AFTER the client receives
/// the response (it loops back after `serve_next_or_stop` returns), so a test
/// that read the observation immediately would race; the organizer CLI polls
/// every 250ms and is unaffected by this small lag.
fn wait_for_serviced(loop_ref: &OrganizerCollectorServiceLoopV1, expected: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while loop_ref.serviced_request_count() < expected {
        if std::time::Instant::now() >= deadline {
            panic!(
                "service loop did not record {expected} serviced request(s) in time (saw {})",
                loop_ref.serviced_request_count()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Phase C organizer observability: a REJECTED request (one the accepted count
/// never reflects) must still be visible to the organizer with a safe stage, so
/// the operator learns on the FIRST attempt that a request reached the collector
/// and was rejected — not just silence with `Accepted ballots: 0`.
#[test]
fn rejected_request_is_observable_with_safe_stage() {
    let fixture = start_loop();
    let addr = fixture.addr;

    assert_eq!(fixture.service_loop.serviced_request_count(), 0);

    // A well-formed HTTP POST whose body is NOT a canonical opaque envelope: the
    // gateway rejects it (400) and the accepted count never advances.
    let (code, _body) = post_envelope(addr, b"not-a-canonical-envelope");
    assert_eq!(code, 400, "a malformed envelope is a bad request");
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        0,
        "a rejected request never advances the accepted count",
    );

    wait_for_serviced(&fixture.service_loop, 1);
    let observation = fixture.service_loop.last_request_observation();
    assert_eq!(
        observation.serviced_count, 1,
        "the rejected request is counted as serviced",
    );
    assert!(
        !observation.last_receipt_returned,
        "no authenticated receipt was returned for the rejected request",
    );
    assert_eq!(
        observation.last_stage, "HTTP_BAD_REQUEST",
        "the safe organizer stage reflects the bad-request rejection",
    );

    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

/// The accepted path is also observable: an ACCEPTED ballot advances the
/// serviced counter and records the `RECEIPT_RETURNED` stage.
#[test]
fn accepted_request_is_observable_as_receipt_returned() {
    let fixture = start_loop();
    let addr = fixture.addr;

    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let (code, _body) = post_envelope(addr, &envelope);
    assert_eq!(code, 200);

    wait_for_serviced(&fixture.service_loop, 1);
    let observation = fixture.service_loop.last_request_observation();
    assert_eq!(observation.serviced_count, 1);
    assert!(observation.last_receipt_returned);
    assert_eq!(observation.last_stage, "RECEIPT_RETURNED");
    assert_eq!(fixture.service_loop.accepted_unique_count(), 1);

    fixture
        .service_loop
        .stop(Duration::from_secs(2))
        .expect("bounded clean stop");
}

/// A bound collector with NO service loop must not serve requests. This proves
/// the phase boundary for the intake startup reorder: before the service loop
/// starts (i.e. before runtime hostname verification), a local caller cannot
/// cause gateway intake. The connection is accepted by the OS backlog but
/// never serviced, so it must time out rather than receive a gateway response.
#[test]
fn bound_collector_without_service_loop_does_not_serve() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let addr = collector.local_addr().expect("addr");
    // The listener is bound but no worker is servicing it. A connect may
    // succeed (OS backlog) but no gateway response can ever be produced.
    let client = std::thread::spawn(move || {
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) else {
            return Vec::new();
        };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
        let _ = stream.write_all(b"POST /v1/opaque-envelope HTTP/1.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        buf
    });
    let response = client.join().expect("client thread");
    let status_line = std::str::from_utf8(&response)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("");
    assert!(
        !status_line.starts_with("HTTP/1.1 4") && !status_line.starts_with("HTTP/1.1 200"),
        "no gateway response may be produced without a service loop, got: {status_line}"
    );
    // The collector remains bound for the test duration (retained-listener
    // behavior during the pre-verification phase).
    drop(collector);
}
