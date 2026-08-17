//! Real Tor SOCKS carrier + readiness probe tests over a deterministic loopback
//! fake SOCKS5 server. No installed Tor, no internet, no DNS, no onion service.
//!
//! The carrier holds no ballot destination: the onion route is derived from the
//! verified `TransportDescriptorV1` passed at delivery, so these tests also prove
//! the destination on the wire comes from the descriptor, never from independent
//! carrier configuration.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fake_socks;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use fake_socks::{
    FakeSocks5Config, FakeSocks5Server, http_ok, http_response, success_connect_reply,
};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, PaddingPolicyV1, PrivateReleaseCarrierV1, TransportDescriptorV1,
    TransportRoutePolicyV1,
};
use tari_cc_private_ballot_protocol::ManifestHash;
use tari_cc_private_ballot_transport_network::{
    ManagedTorReadinessProbeV1, ONION_VIRTUAL_PORT_V1, SystemManagedTorReadinessProbeV1,
    TorCarrierTimeoutsV1, TorSocksPrivateReleaseCarrierV1,
};

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
// A second, distinct, strictly-valid Tor v3 onion hostname.
const TEST_ONION_B: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

fn fast_timeouts() -> TorCarrierTimeoutsV1 {
    TorCarrierTimeoutsV1 {
        socks_connect: Duration::from_secs(2),
        socks_handshake: Duration::from_secs(2),
        http_write: Duration::from_secs(2),
        http_response: Duration::from_secs(2),
    }
}

fn carrier_to(addr: SocketAddr) -> TorSocksPrivateReleaseCarrierV1 {
    TorSocksPrivateReleaseCarrierV1::new(addr, fast_timeouts()).expect("carrier constructs")
}

fn descriptor_with_onion(onion: &str, route: TransportRoutePolicyV1) -> TransportDescriptorV1 {
    descriptor_from_endpoints(vec![onion.to_owned()], route)
}

fn descriptor_from_endpoints(
    onion_endpoints: Vec<String>,
    route: TransportRoutePolicyV1,
) -> TransportDescriptorV1 {
    let signing = SigningKey::from_bytes(&[13; 32]);
    TransportDescriptorV1::sign_for_test_or_ceremony(
        b"tor-carrier-test-election".to_vec(),
        ManifestHash::new([5; 32]),
        1,
        route,
        onion_endpoints,
        Vec::new(),
        [7; 32],
        "gw".to_owned(),
        Vec::new(),
        PaddingPolicyV1 {
            id: "p".to_owned(),
            padded_bytes: 4096,
        },
        BatchPolicyV1 {
            id: "b".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        "root".to_owned(),
        &signing,
    )
    .expect("descriptor signs")
}

/// A valid managed-Tor descriptor pointing at [`TEST_ONION`].
fn tor_descriptor() -> TransportDescriptorV1 {
    descriptor_with_onion(TEST_ONION, TransportRoutePolicyV1::ManagedTorOrOffline)
}

/// A loopback address where nothing is listening (bind, capture, drop).
fn closed_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

fn http_body(request: &[u8]) -> Vec<u8> {
    let position = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("request has header terminator");
    request[position + 4..].to_vec()
}

/// Asserts `descriptor` produces zero network activity: a real loopback listener
/// is armed non-blocking, delivery must error, and no connection is accepted.
fn assert_zero_network(descriptor: &TransportDescriptorV1) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let mut carrier = carrier_to(addr);
    assert!(
        carrier
            .deliver_opaque_envelope(descriptor, b"envelope")
            .is_err(),
        "delivery must be refused before any network",
    );
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("a connection was made before route validation: {other:?}"),
    }
}

// =========================================================================
// Happy path + descriptor-derived route (positive proof).
// =========================================================================

#[test]
fn carrier_sends_literal_onion_connect_and_exact_envelope_then_returns_receipt() {
    let receipt = vec![0xAB, 0xCD, 0xEF, 0x01];
    let server = FakeSocks5Server::start(FakeSocks5Config::success(http_ok(&receipt)));
    let addr = server.addr();

    let envelope = b"opaque-encrypted-ballot-envelope-bytes".to_vec();
    let mut carrier = carrier_to(addr);
    let returned = carrier
        .deliver_opaque_envelope(&tor_descriptor(), &envelope)
        .expect("carrier delivers");
    assert_eq!(returned, receipt, "carrier returns exact receipt bytes");

    let capture = server.join();

    // SOCKS CONNECT wire: 05 01 00 03 <len> <literal onion> <port BE>.
    let connect = capture.connect_request;
    assert_eq!(connect[0], 0x05, "SOCKS version 5");
    assert_eq!(connect[1], 0x01, "CONNECT command");
    assert_eq!(connect[2], 0x00, "reserved");
    assert_eq!(connect[3], 0x03, "ATYP = DOMAINNAME (no OS DNS)");
    assert_eq!(usize::from(connect[4]), TEST_ONION.len(), "hostname length");
    let host = &connect[5..5 + TEST_ONION.len()];
    assert_eq!(
        host,
        TEST_ONION.as_bytes(),
        "literal onion hostname on the wire"
    );
    let port = &connect[5 + TEST_ONION.len()..];
    assert_eq!(
        port,
        &ONION_VIRTUAL_PORT_V1.to_be_bytes(),
        "onion port big-endian",
    );

    // HTTP request: exact endpoint, exact Content-Length, exact body.
    let request = String::from_utf8_lossy(&capture.http_request).to_string();
    assert!(
        request.starts_with("POST /v1/opaque-envelope HTTP/1.1\r\n"),
        "request line: {request}"
    );
    assert!(request.contains(&format!("Content-Length: {}\r\n", envelope.len())));
    assert!(request.contains("Content-Type: application/octet-stream\r\n"));
    assert!(request.contains(&format!("Host: {TEST_ONION}\r\n")));
    assert_eq!(
        http_body(&capture.http_request),
        envelope,
        "exact envelope body, unmutated"
    );
}

// The SAME carrier, given two different verified descriptors, sends to the onion
// each descriptor names — proving the wire route is descriptor-derived, not
// carrier-configured.
#[test]
fn carrier_route_is_derived_from_the_verified_descriptor() {
    for onion in [TEST_ONION, TEST_ONION_B] {
        let server = FakeSocks5Server::start(FakeSocks5Config::success(http_ok(&[1])));
        let addr = server.addr();
        let mut carrier = carrier_to(addr);
        let descriptor = descriptor_with_onion(onion, TransportRoutePolicyV1::ManagedTorOrOffline);
        let _ = carrier.deliver_opaque_envelope(&descriptor, b"envelope");
        let capture = server.join();
        assert_eq!(capture.connect_request[3], 0x03, "ATYP DOMAINNAME");
        let host = &capture.connect_request[5..5 + onion.len()];
        assert_eq!(host, onion.as_bytes(), "wire hostname == descriptor onion");
    }
}

// A descriptor that does not name a usable Tor onion route causes zero network.
#[test]
fn clearnet_onion_endpoint_is_rejected_before_any_network() {
    assert_zero_network(&descriptor_with_onion(
        "example.com",
        TransportRoutePolicyV1::ManagedTorOrOffline,
    ));
}

#[test]
fn ip_literal_onion_endpoint_is_rejected_before_any_network() {
    assert_zero_network(&descriptor_with_onion(
        "127.0.0.1",
        TransportRoutePolicyV1::ManagedTorOrOffline,
    ));
}

#[test]
fn missing_onion_endpoint_is_rejected_before_any_network() {
    assert_zero_network(&descriptor_from_endpoints(
        Vec::new(),
        TransportRoutePolicyV1::ManagedTorOrOffline,
    ));
}

#[test]
fn non_tor_route_policy_is_rejected_before_any_network() {
    assert_zero_network(&descriptor_with_onion(
        TEST_ONION,
        TransportRoutePolicyV1::OfflineOnly,
    ));
}

#[test]
fn non_loopback_socks_endpoint_is_rejected_at_construction() {
    assert!(
        TorSocksPrivateReleaseCarrierV1::new(
            SocketAddr::from((Ipv4Addr::new(192, 168, 0, 2), 9050)),
            fast_timeouts(),
        )
        .is_err()
    );
}

// =========================================================================
// SOCKS failure cases: always a bounded error, never a direct fallback.
// =========================================================================

fn deliver_against(config: FakeSocks5Config, envelope: &[u8]) -> Result<Vec<u8>, ()> {
    let server = FakeSocks5Server::start(config);
    let addr = server.addr();
    let mut carrier = carrier_to(addr);
    let result = carrier
        .deliver_opaque_envelope(&tor_descriptor(), envelope)
        .map_err(|_| ());
    let _ = server.join();
    result
}

fn stop_after_method(method_reply: Vec<u8>) -> FakeSocks5Config {
    FakeSocks5Config {
        method_reply,
        stop_after_method: true,
        connect_reply: Vec::new(),
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    }
}

#[test]
fn socks_listener_unavailable_is_bounded_error() {
    let addr = closed_loopback_addr();
    let mut carrier = carrier_to(addr);
    assert!(
        carrier
            .deliver_opaque_envelope(&tor_descriptor(), b"envelope")
            .is_err()
    );
}

#[test]
fn malformed_socks_method_reply_fails() {
    assert!(deliver_against(stop_after_method(vec![0x04, 0x00]), b"envelope").is_err());
}

#[test]
fn unsupported_socks_auth_selection_fails() {
    assert!(deliver_against(stop_after_method(vec![0x05, 0x02]), b"envelope").is_err());
}

#[test]
fn socks_connect_rep_failure_fails() {
    let config = FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: vec![0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    };
    assert!(deliver_against(config, b"envelope").is_err());
}

#[test]
fn truncated_socks_connect_reply_fails() {
    let config = FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: vec![0x05],
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    };
    assert!(deliver_against(config, b"envelope").is_err());
}

#[test]
fn unexpected_socks_connect_atyp_fails() {
    let config = FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: vec![0x05, 0x00, 0x00, 0x09, 0, 0],
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    };
    assert!(deliver_against(config, b"envelope").is_err());
}

// =========================================================================
// No-local-DNS behavioral proof.
// =========================================================================

#[test]
fn onion_hostname_travels_as_socks_domainname_never_resolved_locally() {
    let server = FakeSocks5Server::start(FakeSocks5Config::success(http_ok(&[0x01])));
    let addr = server.addr();
    let mut carrier = carrier_to(addr);
    let _ = carrier.deliver_opaque_envelope(&tor_descriptor(), b"envelope");
    let capture = server.join();
    assert_eq!(capture.connect_request[3], 0x03, "ATYP must be DOMAINNAME");
    let host = &capture.connect_request[5..5 + TEST_ONION.len()];
    assert_eq!(host, TEST_ONION.as_bytes());
}

// =========================================================================
// HTTP response parser tests (including strict header syntax).
// =========================================================================

fn deliver_with_response(response: Vec<u8>) -> Result<Vec<u8>, ()> {
    deliver_against(FakeSocks5Config::success(response), b"envelope")
}

#[test]
fn valid_200_returns_exact_receipt() {
    let receipt = vec![9, 8, 7, 6, 5];
    assert_eq!(deliver_with_response(http_ok(&receipt)), Ok(receipt));
}

// Regression for the real one-computer managed-Tor failure: a complete,
// exact-length authenticated receipt must be returned as soon as its bytes are
// read, WITHOUT waiting for the peer to close the connection. Over a real Tor
// circuit the collector's `Connection: close` teardown can be delayed (or arrive
// as a reset); a mandatory trailing-EOF read previously blocked here for the full
// response timeout (or errored), discarding a receipt that had in fact been
// delivered and stranding the voter in CAST_PENDING. If a trailing-EOF read is
// ever reintroduced, this test blocks until the (short) response timeout and then
// fails both assertions.
#[test]
fn complete_receipt_returns_without_waiting_for_peer_close() {
    use std::time::Instant;

    let receipt = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let server = FakeSocks5Server::start(FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: success_connect_reply(),
        stop_after_connect: false,
        // Send the full 200 + receipt, then hold the socket open for far longer
        // than the carrier's response timeout below.
        behavior: fake_socks::HttpBehavior::RespondThenHold(
            http_ok(&receipt),
            Duration::from_secs(5),
        ),
    });
    let addr = server.addr();

    // A short response timeout is the discriminator: with the fix, delivery
    // returns in a few milliseconds; a reintroduced trailing-EOF read would block
    // until this elapses.
    let mut carrier = TorSocksPrivateReleaseCarrierV1::new(
        addr,
        TorCarrierTimeoutsV1 {
            socks_connect: Duration::from_secs(2),
            socks_handshake: Duration::from_secs(2),
            http_write: Duration::from_secs(2),
            http_response: Duration::from_millis(800),
        },
    )
    .expect("carrier constructs");

    let start = Instant::now();
    let returned = carrier
        .deliver_opaque_envelope(&tor_descriptor(), b"envelope")
        .expect("a complete receipt is returned even though the peer has not closed");
    let elapsed = start.elapsed();

    assert_eq!(returned, receipt, "exact receipt bytes are returned");
    assert!(
        elapsed < Duration::from_millis(700),
        "a complete exact-length receipt must return immediately, not wait for the \
         peer close or the response timeout (took {elapsed:?})",
    );
    // Deliberately do not join: the fake peer is still holding the socket open.
    drop(server);
}

#[test]
fn non_200_status_is_rejected() {
    assert!(
        deliver_with_response(http_response("HTTP/1.1 500 Internal Server Error", &[1, 2]))
            .is_err()
    );
}

#[test]
fn redirect_is_not_followed() {
    let response = b"HTTP/1.1 302 Found\r\nLocation: http://evil.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn missing_content_length_is_rejected() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\nabcd".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn conflicting_content_length_is_rejected() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcd".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn oversized_receipt_length_is_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\nshort".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn truncated_body_is_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nabcd".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn extra_trailing_body_bytes_are_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcdEXTRA".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn malformed_status_line_is_rejected() {
    let response = b"NOT-HTTP 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn whitespace_before_colon_header_is_rejected() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Length : 2\r\nConnection: close\r\n\r\nok".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn obs_fold_header_is_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n \tfolded\r\nConnection: close\r\n\r\nok"
            .to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn nul_in_header_is_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Evil: a\0b\r\nConnection: close\r\n\r\nok"
            .to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn non_token_field_name_is_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\nBad Header: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            .to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn mixed_case_transfer_encoding_response_is_rejected() {
    let response =
        b"HTTP/1.1 200 OK\r\ntRaNsFeR-EnCoDiNg: chunked\r\nConnection: close\r\n\r\n".to_vec();
    assert!(deliver_with_response(response).is_err());
}

#[test]
fn signed_or_junk_content_length_is_rejected() {
    for value in [
        "+1",
        "-1",
        "1 2",
        "0x10",
        "1,2",
        "  ",
        "99999999999999999999999999",
    ] {
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\nConnection: close\r\n\r\nab")
                .into_bytes();
        assert!(
            deliver_with_response(response).is_err(),
            "value {value:?} must reject"
        );
    }
}

// =========================================================================
// Readiness probe tests.
// =========================================================================

fn probe_to(addr: SocketAddr) -> SystemManagedTorReadinessProbeV1 {
    SystemManagedTorReadinessProbeV1::new(addr, Duration::from_secs(2), Duration::from_secs(2))
        .expect("probe constructs")
}

fn readiness_server(method_reply: Vec<u8>) -> FakeSocks5Server {
    FakeSocks5Server::start(stop_after_method(method_reply))
}

#[test]
fn readiness_ready_on_valid_negotiation() {
    let server = readiness_server(vec![0x05, 0x00]);
    let addr = server.addr();
    let mut probe = probe_to(addr);
    assert_eq!(probe.ready(), Ok(true));
    let _ = server.join();
}

#[test]
fn readiness_not_ready_when_port_closed() {
    let addr = closed_loopback_addr();
    let mut probe = probe_to(addr);
    assert_eq!(probe.ready(), Ok(false));
}

#[test]
fn readiness_not_ready_on_wrong_socks_version() {
    let server = readiness_server(vec![0x04, 0x00]);
    let addr = server.addr();
    let mut probe = probe_to(addr);
    assert_eq!(probe.ready(), Ok(false));
    let _ = server.join();
}

#[test]
fn readiness_not_ready_on_unsupported_auth_method() {
    let server = readiness_server(vec![0x05, 0xFF]);
    let addr = server.addr();
    let mut probe = probe_to(addr);
    assert_eq!(probe.ready(), Ok(false));
    let _ = server.join();
}

#[test]
fn readiness_not_ready_on_truncated_reply() {
    let server = readiness_server(vec![0x05]);
    let addr = server.addr();
    let mut probe = probe_to(addr);
    assert_eq!(probe.ready(), Ok(false));
    let _ = server.join();
}

#[test]
fn readiness_rejects_non_loopback_endpoint() {
    assert!(
        SystemManagedTorReadinessProbeV1::new(
            SocketAddr::from((Ipv4Addr::new(10, 1, 2, 3), 9050)),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err()
    );
}

#[test]
fn success_connect_reply_is_well_formed() {
    assert_eq!(success_connect_reply()[0], 0x05);
    assert_eq!(success_connect_reply()[1], 0x00);
}
