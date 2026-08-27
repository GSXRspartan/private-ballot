//! Loopback opaque-envelope collector tests, plus two composition integration
//! tests that wire the real carrier and collector together. No installed Tor, no
//! internet, no DNS; loopback sockets only.

#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

#[path = "../../transport-network/tests/fake_socks/mod.rs"]
mod fake_socks;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};

use tari_cc_private_ballot_gui_core::{
    AuthenticatedTransportReceiptV1, BatchPolicyV1, PaddingPolicyV1, PrivateBallotEnvelopeV1,
    PrivateReleaseCarrierV1, RetryStatusV1, TransportDescriptorV1, TransportRoutePolicyV1,
    VoterReceiptStateV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashDomain, hash_domain_separated};
use tari_cc_private_ballot_transport_gateway::{
    CollectorBindErrorV1, CollectorRejectionV1, GatewayCollectorHandlerV1, GatewayReceiverKeyV1,
    OpaqueEnvelopeCollectorV1, OpaqueEnvelopeGatewayHandlerV1, TransportGatewaySimulatorV1,
};
use tari_cc_private_ballot_transport_network::{
    TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1,
};

type Kem = X25519HkdfSha256;

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

// =========================================================================
// Raw HTTP client + collector driver.
// =========================================================================

fn parse_response(bytes: &[u8]) -> (u16, Vec<u8>) {
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response header terminator");
    let head = std::str::from_utf8(&bytes[..split]).expect("utf8 head");
    let status_line = head.split("\r\n").next().expect("status line");
    let code = status_line
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .expect("status code");
    (code, bytes[split + 4..].to_vec())
}

fn http_post(addr: SocketAddr, request: Vec<u8>) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect collector");
    stream.write_all(&request).expect("write request");
    stream.flush().expect("flush");
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).expect("read response");
    parse_response(&buffer)
}

/// Runs the collector for exactly one connection driven by a raw client request.
fn drive_once(
    collector: &OpaqueEnvelopeCollectorV1,
    handler: &mut dyn OpaqueEnvelopeGatewayHandlerV1,
    request: Vec<u8>,
) -> (u16, Vec<u8>) {
    let addr = collector.local_addr().expect("addr");
    let client = std::thread::spawn(move || http_post(addr, request));
    collector.serve_next(handler).expect("serve one");
    client.join().expect("client thread")
}

fn octet_post(path: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

// =========================================================================
// Fake handler — isolates the HTTP request layer from the gateway.
// =========================================================================

struct FakeHandler {
    seen: Vec<Vec<u8>>,
    response: Result<Vec<u8>, CollectorRejectionV1>,
}

impl FakeHandler {
    fn accepting(receipt: Vec<u8>) -> Self {
        Self {
            seen: Vec::new(),
            response: Ok(receipt),
        }
    }
    fn rejecting(rejection: CollectorRejectionV1) -> Self {
        Self {
            seen: Vec::new(),
            response: Err(rejection),
        }
    }
}

impl OpaqueEnvelopeGatewayHandlerV1 for FakeHandler {
    fn handle_opaque_envelope(&mut self, envelope: &[u8]) -> Result<Vec<u8>, CollectorRejectionV1> {
        self.seen.push(envelope.to_vec());
        self.response.clone()
    }
}

// =========================================================================
// 24/25/26. Collector request tests + loopback bind enforcement.
// =========================================================================

#[test]
fn collector_binds_only_loopback_and_reports_addr() {
    // 0.0.0.0 and LAN addresses are refused before binding; 127.0.0.1 is allowed.
    assert_eq!(
        OpaqueEnvelopeCollectorV1::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).err(),
        Some(CollectorBindErrorV1::NonLoopback),
    );
    assert_eq!(
        OpaqueEnvelopeCollectorV1::bind(SocketAddr::from((Ipv4Addr::new(192, 168, 1, 5), 0))).err(),
        Some(CollectorBindErrorV1::NonLoopback),
    );
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("loopback bind");
    assert!(collector.local_addr().expect("addr").ip().is_loopback());
}

#[test]
fn valid_post_reaches_handler_with_exact_bytes_and_returns_200() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![1, 2, 3, 4]);
    let body = b"exact-opaque-envelope-bytes".to_vec();
    let (code, response) = drive_once(
        &collector,
        &mut handler,
        octet_post("/v1/opaque-envelope", &body),
    );
    assert_eq!(code, 200);
    assert_eq!(response, vec![1, 2, 3, 4], "exact handler receipt returned");
    assert_eq!(
        handler.seen,
        vec![body],
        "exact opaque bytes reached the handler"
    );
}

#[test]
fn wrong_method_is_405_and_handler_not_called() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"GET /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 405);
    assert!(handler.seen.is_empty());
}

#[test]
fn wrong_path_is_404() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let (code, _) = drive_once(&collector, &mut handler, octet_post("/v1/other", b"abc"));
    assert_eq!(code, 404);
    assert!(handler.seen.is_empty());
}

#[test]
fn wrong_content_type_is_415() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 415);
    assert!(handler.seen.is_empty());
}

#[test]
fn missing_content_length_is_400() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 400);
    assert!(handler.seen.is_empty());
}

#[test]
fn duplicate_content_length_is_400() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\nab".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 400);
    assert!(handler.seen.is_empty());
}

#[test]
fn chunked_request_is_400() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nab".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 400);
    assert!(handler.seen.is_empty());
}

#[test]
fn oversized_body_is_413_before_handler() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    // Advertise a length beyond the maximum; the collector rejects on the value
    // before reading (or reserving for) the body.
    let request = b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 99999999\r\nConnection: close\r\n\r\n".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 413);
    assert!(handler.seen.is_empty());
}

#[test]
fn malformed_request_line_is_400() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"GARBAGE-REQUEST-LINE\r\nContent-Length: 0\r\n\r\n".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 400);
}

#[test]
fn handler_admission_unavailable_is_503() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::rejecting(CollectorRejectionV1::AdmissionUnavailable);
    let (code, _) = drive_once(
        &collector,
        &mut handler,
        octet_post("/v1/opaque-envelope", b"x"),
    );
    assert_eq!(code, 503);
}

#[test]
fn handler_internal_failure_is_500() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::rejecting(CollectorRejectionV1::Internal);
    let (code, _) = drive_once(
        &collector,
        &mut handler,
        octet_post("/v1/opaque-envelope", b"x"),
    );
    assert_eq!(code, 500);
}

// -------------------------------------------------------------------------
// Strict HTTP request header syntax — malformed request never reaches gateway.
// -------------------------------------------------------------------------

/// Drives a raw request whose headers are malformed; asserts 400 and that the
/// gateway handler was never invoked.
fn assert_malformed_request(request: Vec<u8>) {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 400, "malformed request must be 400");
    assert!(handler.seen.is_empty(), "gateway must not be invoked");
}

#[test]
fn whitespace_before_colon_request_header_is_400() {
    assert_malformed_request(b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Length : 2\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\nab".to_vec());
}

#[test]
fn obs_fold_request_header_is_400() {
    assert_malformed_request(b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n \tfolded\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec());
}

#[test]
fn nul_in_request_header_is_400() {
    assert_malformed_request(b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nX-Evil: a\0b\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec());
}

#[test]
fn non_token_field_name_request_is_400() {
    assert_malformed_request(b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nBad Header: y\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec());
}

#[test]
fn signed_content_length_request_is_400() {
    assert_malformed_request(b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: +2\r\nConnection: close\r\n\r\nab".to_vec());
}

#[test]
fn mixed_case_transfer_encoding_request_is_rejected_before_gateway() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut handler = FakeHandler::accepting(vec![0]);
    let request = b"POST /v1/opaque-envelope HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\ntRaNsFeR-EnCoDiNg: chunked\r\nConnection: close\r\n\r\nab".to_vec();
    let (code, _) = drive_once(&collector, &mut handler, request);
    assert_eq!(code, 400);
    assert!(handler.seen.is_empty());
}

// -------------------------------------------------------------------------
// §24 Absolute request deadline — a slow-drip client cannot hold the collector.
// -------------------------------------------------------------------------

#[test]
fn slow_client_is_bounded_by_absolute_request_deadline() {
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0)
        .expect("bind")
        .with_max_request_duration(Duration::from_millis(500));
    let addr = collector.local_addr().expect("addr");
    let mut handler = FakeHandler::accepting(vec![0]);

    // The client sends only a partial header, then stalls well past the budget.
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(addr).expect("connect");
        let _ = stream.write_all(b"POST /v1/opaque-envelope HTTP/1.1\r\nContent-Length: 10\r\n");
        std::thread::sleep(Duration::from_secs(2));
        drop(stream);
    });

    let start = Instant::now();
    collector.serve_next(&mut handler).expect("serve one");
    let elapsed = start.elapsed();

    assert!(
        handler.seen.is_empty(),
        "gateway must not be invoked for a stalled request",
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "collector must abort within the request budget, took {elapsed:?}",
    );
    let _ = client.join();
}

// =========================================================================
// Real gateway handler: exact gateway handoff + authenticated receipt.
// =========================================================================

struct GatewayFixture {
    descriptor: TransportDescriptorV1,
    receiver_key: GatewayReceiverKeyV1,
    receipt_key: SigningKey,
    package: Vec<u8>,
}

fn gateway_fixture() -> GatewayFixture {
    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut gateway_public = [0u8; 32];
    gateway_public.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(receiver_secret.to_bytes().as_slice());

    let manifest = common::manifest();
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("hash");
    let authority = SigningKey::from_bytes(&[71; 32]);
    let receipt_key = SigningKey::from_bytes(&[72; 32]);
    let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        manifest.election_id().as_bytes().to_vec(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![TEST_ONION.to_owned()],
        Vec::new(),
        gateway_public,
        "collector-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "collector-fixed".to_owned(),
            padded_bytes: 65_536,
        },
        BatchPolicyV1 {
            id: "accepted-1".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        "collector-root".to_owned(),
        &authority,
    )
    .expect("descriptor");
    GatewayFixture {
        descriptor,
        receiver_key: GatewayReceiverKeyV1::from_secret_bytes(secret).expect("receiver key"),
        receipt_key,
        package: common::triptych_package_bytes(0, &[b"candidate-a"]),
    }
}

fn sealed_envelope(fixture: &GatewayFixture) -> Vec<u8> {
    PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &fixture.package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode")
}

#[test]
fn real_gateway_handler_returns_authenticated_receipt_for_exact_package() {
    let fixture = gateway_fixture();
    let encoded = sealed_envelope(&fixture);
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();
    let mut handler = GatewayCollectorHandlerV1::new(
        &mut gateway,
        &fixture.descriptor,
        &fixture.receiver_key,
        &mut session,
        &fixture.receipt_key,
        "collector-receipt-key".to_owned(),
    )
    .expect("handler constructs");

    let (code, response) = drive_once(
        &collector,
        &mut handler,
        octet_post("/v1/opaque-envelope", &encoded),
    );
    assert_eq!(code, 200);

    let receipt = AuthenticatedTransportReceiptV1::from_canonical_cbor(&response)
        .expect("canonical authenticated receipt");
    receipt
        .verify_for_descriptor(&fixture.descriptor)
        .expect("receipt is descriptor-authorized");
    let expected_digest = hash_domain_separated(
        &Blake3HashProviderV1,
        HashDomain::BallotPackageV1,
        &fixture.package,
    );
    assert_eq!(
        receipt.package_digest(),
        expected_digest,
        "digest binds exact package"
    );
    assert_eq!(receipt.receipt().state, VoterReceiptStateV1::Accepted);
}

// Idempotent exact-retry recovery (the second real-test root cause): the voter's
// authenticated receipt for a delivery that WAS accepted can be lost to a
// delayed/reset Tor close, leaving it CAST_PENDING. Retrying the EXACT staged
// envelope must recover the prior acceptance (so the voter reaches CAST) without
// counting a second vote, while a genuinely different ballot under the same
// credential/nullifier stays rejected. All three go through the real gateway.
#[test]
fn exact_retry_recovers_previous_acceptance_and_distinct_ballot_is_rejected() {
    let fixture = gateway_fixture();
    let encoded = sealed_envelope(&fixture);
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();

    // A distinct ballot from the SAME credential (member 0) but a DIFFERENT choice:
    // same election nullifier, different package, sealed to the same descriptor.
    let distinct_package = common::triptych_package_bytes(0, &[b"candidate-b"]);
    let distinct_encoded = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &distinct_package)
        .expect("seal distinct")
        .to_canonical_cbor()
        .expect("encode distinct");

    {
        let mut handler = GatewayCollectorHandlerV1::new(
            &mut gateway,
            &fixture.descriptor,
            &fixture.receiver_key,
            &mut session,
            &fixture.receipt_key,
            "collector-receipt-key".to_owned(),
        )
        .expect("handler");

        // 1. First exact delivery: accepted (new).
        let (code1, resp1) = drive_once(
            &collector,
            &mut handler,
            octet_post("/v1/opaque-envelope", &encoded),
        );
        assert_eq!(code1, 200);
        let r1 = AuthenticatedTransportReceiptV1::from_canonical_cbor(&resp1).expect("receipt 1");
        r1.verify_for_descriptor(&fixture.descriptor)
            .expect("auth 1");
        assert_eq!(r1.receipt().state, VoterReceiptStateV1::Accepted);
        assert_eq!(r1.receipt().retry_status, RetryStatusV1::NewDelivery);

        // 2. EXACT retry of the SAME envelope: recovers the prior acceptance
        //    (Accepted / PreviousDeliveryAccepted) so the voter can reach CAST.
        let (code2, resp2) = drive_once(
            &collector,
            &mut handler,
            octet_post("/v1/opaque-envelope", &encoded),
        );
        assert_eq!(code2, 200);
        let r2 = AuthenticatedTransportReceiptV1::from_canonical_cbor(&resp2).expect("receipt 2");
        r2.verify_for_descriptor(&fixture.descriptor)
            .expect("auth 2");
        assert_eq!(
            r2.receipt().state,
            VoterReceiptStateV1::Accepted,
            "an exact retry of an accepted ballot recovers to Accepted (voter can promote to CAST)",
        );
        assert_eq!(
            r2.receipt().retry_status,
            RetryStatusV1::PreviousDeliveryAccepted,
        );
        assert_eq!(
            r1.package_digest(),
            r2.package_digest(),
            "the same package is acknowledged",
        );

        // 3. A DIFFERENT ballot from the same credential/nullifier is rejected.
        let (code3, resp3) = drive_once(
            &collector,
            &mut handler,
            octet_post("/v1/opaque-envelope", &distinct_encoded),
        );
        assert_eq!(code3, 200);
        let r3 = AuthenticatedTransportReceiptV1::from_canonical_cbor(&resp3).expect("receipt 3");
        r3.verify_for_descriptor(&fixture.descriptor)
            .expect("auth 3");
        assert_eq!(
            r3.receipt().state,
            VoterReceiptStateV1::Rejected,
            "a different ballot under the same nullifier is a genuine double-vote and rejected",
        );
        assert_eq!(r3.receipt().retry_status, RetryStatusV1::GenericDuplicate);
    }

    // Exactly one unique ballot was accepted across the retry and the double-vote.
    assert_eq!(
        gateway.accepted_unique_count(),
        1,
        "retry and double-vote never inflate the accepted count",
    );
}

#[test]
fn handler_construction_rejects_unauthorized_receipt_key() {
    let fixture = gateway_fixture();
    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();
    let unauthorized = SigningKey::from_bytes(&[201; 32]);
    assert!(
        GatewayCollectorHandlerV1::new(
            &mut gateway,
            &fixture.descriptor,
            &fixture.receiver_key,
            &mut session,
            &unauthorized,
            "k".to_owned(),
        )
        .is_err(),
        "a receipt key the descriptor does not authorize must be refused",
    );
}

#[test]
fn closed_admission_returns_503() {
    let fixture = gateway_fixture();
    let encoded = sealed_envelope(&fixture);
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();
    // Drive the election to CLOSED via the admission gate before serving.
    gateway.begin_close(&mut session).expect("begin close");
    gateway.expire_close_drain(&mut session).expect("drain");

    let mut handler = GatewayCollectorHandlerV1::new(
        &mut gateway,
        &fixture.descriptor,
        &fixture.receiver_key,
        &mut session,
        &fixture.receipt_key,
        "collector-receipt-key".to_owned(),
    )
    .expect("handler");
    let (code, body) = drive_once(
        &collector,
        &mut handler,
        octet_post("/v1/opaque-envelope", &encoded),
    );
    assert_eq!(code, 503, "a closed election rejects delivery");
    assert!(body.is_empty(), "no receipt when admission is closed");
}

#[test]
fn malformed_envelope_bytes_are_400_not_leaked() {
    let fixture = gateway_fixture();
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();
    let mut handler = GatewayCollectorHandlerV1::new(
        &mut gateway,
        &fixture.descriptor,
        &fixture.receiver_key,
        &mut session,
        &fixture.receipt_key,
        "collector-receipt-key".to_owned(),
    )
    .expect("handler");
    let (code, body) = drive_once(
        &collector,
        &mut handler,
        octet_post("/v1/opaque-envelope", b"not-a-canonical-envelope"),
    );
    assert_eq!(code, 400);
    assert!(body.is_empty(), "no internal detail is reflected");
}

// -------------------------------------------------------------------------
// Durable hand-off: an ACCEPTED delivery is written to the app-owned inbox,
// a rejected one is not, and an exact retry never writes a second file.
// -------------------------------------------------------------------------

#[test]
fn accepted_delivery_is_handed_off_to_inbox_and_retry_is_deduped() {
    let fixture = gateway_fixture();
    let encoded = sealed_envelope(&fixture);
    let dir = common::TestDir::new("collector-inbox");
    let inbox = dir.join("inbox");
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();

    let count_packages = || {
        std::fs::read_dir(&inbox)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".package"))
                    .count()
            })
            .unwrap_or(0)
    };

    // A rejected (malformed) delivery hands nothing off.
    {
        let mut handler = GatewayCollectorHandlerV1::new(
            &mut gateway,
            &fixture.descriptor,
            &fixture.receiver_key,
            &mut session,
            &fixture.receipt_key,
            "collector-receipt-key".to_owned(),
        )
        .expect("handler")
        .with_accepted_package_inbox(&inbox);
        let (code, _) = drive_once(
            &collector,
            &mut handler,
            octet_post("/v1/opaque-envelope", b"not-a-canonical-envelope"),
        );
        assert_eq!(code, 400);
    }
    assert_eq!(count_packages(), 0, "a rejected delivery is not handed off");

    // A genuine acceptance is handed off exactly once.
    {
        let mut handler = GatewayCollectorHandlerV1::new(
            &mut gateway,
            &fixture.descriptor,
            &fixture.receiver_key,
            &mut session,
            &fixture.receipt_key,
            "collector-receipt-key".to_owned(),
        )
        .expect("handler")
        .with_accepted_package_inbox(&inbox);
        let (code, _) = drive_once(
            &collector,
            &mut handler,
            octet_post("/v1/opaque-envelope", &encoded),
        );
        assert_eq!(code, 200);
    }
    assert_eq!(
        count_packages(),
        1,
        "an accepted delivery is handed off once"
    );

    // An EXACT retry recovers the acceptance (still 200) but is content-addressed:
    // it never writes a second file and never inflates the accepted count.
    {
        let mut handler = GatewayCollectorHandlerV1::new(
            &mut gateway,
            &fixture.descriptor,
            &fixture.receiver_key,
            &mut session,
            &fixture.receipt_key,
            "collector-receipt-key".to_owned(),
        )
        .expect("handler")
        .with_accepted_package_inbox(&inbox);
        let (code, _) = drive_once(
            &collector,
            &mut handler,
            octet_post("/v1/opaque-envelope", &encoded),
        );
        assert_eq!(code, 200);
    }
    assert_eq!(
        count_packages(),
        1,
        "an exact retry never writes a second file"
    );
    assert_eq!(gateway.accepted_unique_count(), 1);
}

// =========================================================================
// 33. End-to-end: real carrier -> fake SOCKS tunnel -> real collector.
// =========================================================================

#[test]
fn carrier_through_fake_socks_to_real_collector_round_trips_receipt() {
    let fixture = gateway_fixture();
    let encoded = sealed_envelope(&fixture);
    let expected_digest = hash_domain_separated(
        &Blake3HashProviderV1,
        HashDomain::BallotPackageV1,
        &fixture.package,
    );

    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");
    let collector_addr = collector.local_addr().expect("addr");

    // Fake SOCKS proxy tunnels the established stream straight to the collector.
    let socks =
        fake_socks::FakeSocks5Server::start(fake_socks::FakeSocks5Config::tunnel(collector_addr));
    let socks_addr = socks.addr();

    // The carrier runs on another thread; the collector serves on this one. The
    // carrier holds no destination — it derives the onion route from the same
    // verified descriptor the envelope was sealed to.
    let carrier_descriptor = fixture.descriptor.clone();
    let carrier_thread = std::thread::spawn(move || {
        let mut carrier =
            TorSocksPrivateReleaseCarrierV1::new(socks_addr, TorCarrierTimeoutsV1::default())
                .expect("carrier");
        carrier.deliver_opaque_envelope(&carrier_descriptor, &encoded)
    });

    let mut gateway = TransportGatewaySimulatorV1::default();
    let mut session = common::open_session();
    let mut handler = GatewayCollectorHandlerV1::new(
        &mut gateway,
        &fixture.descriptor,
        &fixture.receiver_key,
        &mut session,
        &fixture.receipt_key,
        "collector-receipt-key".to_owned(),
    )
    .expect("handler");
    collector.serve_next(&mut handler).expect("serve one");

    let receipt_bytes = carrier_thread
        .join()
        .expect("carrier thread")
        .expect("carrier obtains a receipt");
    let _ = socks.join();

    let receipt = AuthenticatedTransportReceiptV1::from_canonical_cbor(&receipt_bytes)
        .expect("authenticated receipt");
    receipt
        .verify_for_descriptor(&fixture.descriptor)
        .expect("receipt verifies for descriptor");
    assert_eq!(receipt.package_digest(), expected_digest);
    assert_eq!(receipt.receipt().state, VoterReceiptStateV1::Accepted);
}

// =========================================================================
// 32. Release boundary -> real carrier: PENDING exists when bytes leave.
// =========================================================================

mod release_boundary;

#[test]
fn release_boundary_reaches_carrier_only_after_durable_pending() {
    release_boundary::run_release_boundary_to_carrier_test();
}
