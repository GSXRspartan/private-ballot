//! Remote SOCKS Tor carrier + readiness probe tests over the deterministic
//! loopback fake SOCKS5 server. No installed Tor, no internet, no DNS, no onion
//! service.
//!
//! These prove the ADVANCED remote-SOCKS path shares the managed-local path's
//! hard guarantees: the onion destination is derived from the verified
//! descriptor and sent as a SOCKS5 DOMAINNAME literal (never DNS-resolved),
//! there is no clearnet fallback, and a readiness probe sends zero application
//! bytes.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fake_socks;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use fake_socks::{FakeSocks5Config, FakeSocks5Server, http_ok};
use tari_cc_private_ballot_gui_core::{
    BatchPolicyV1, PaddingPolicyV1, PrivateReleaseCarrierV1, TransportDescriptorV1,
    TransportRoutePolicyV1,
};
use tari_cc_private_ballot_protocol::ManifestHash;
use tari_cc_private_ballot_transport_network::{
    RemoteSocksEndpointV1, RemoteTorReadinessOutcomeV1, RemoteTorSocksPrivateReleaseCarrierV1,
    TorCarrierTimeoutsV1, probe_remote_onion_reachability_v1,
};

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

fn fast_timeouts() -> TorCarrierTimeoutsV1 {
    TorCarrierTimeoutsV1 {
        socks_connect: Duration::from_secs(2),
        socks_handshake: Duration::from_secs(2),
        http_write: Duration::from_secs(2),
        http_response: Duration::from_secs(2),
    }
}

/// A remote endpoint pointing at the given loopback address. `127.0.0.1:PORT`
/// is an explicitly supported remote SOCKS endpoint form; using loopback here
/// keeps the test hermetic (no LAN, no external proxy) while exercising the
/// remote carrier's own code path end to end.
fn remote_endpoint(addr: SocketAddr) -> RemoteSocksEndpointV1 {
    RemoteSocksEndpointV1::parse(&addr.to_string()).expect("valid remote endpoint")
}

fn remote_carrier(addr: SocketAddr) -> RemoteTorSocksPrivateReleaseCarrierV1 {
    RemoteTorSocksPrivateReleaseCarrierV1::new(remote_endpoint(addr), fast_timeouts())
}

fn descriptor_with_route(route: TransportRoutePolicyV1) -> TransportDescriptorV1 {
    let signing = SigningKey::from_bytes(&[19; 32]);
    TransportDescriptorV1::sign_for_test_or_ceremony(
        b"remote-tor-carrier-test-election".to_vec(),
        ManifestHash::new([9; 32]),
        1,
        route,
        vec![TEST_ONION.to_owned()],
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

fn tor_descriptor() -> TransportDescriptorV1 {
    descriptor_with_route(TransportRoutePolicyV1::ManagedTorOrOffline)
}

fn closed_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

// =========================================================================
// Test 13: .onion destination remains routed through SOCKS as a DOMAINNAME
// literal — the remote carrier delivers the exact envelope and returns the
// exact receipt.
// =========================================================================

#[test]
fn remote_carrier_sends_literal_onion_connect_and_exact_envelope_then_returns_receipt() {
    let receipt = vec![0x11, 0x22, 0x33, 0x44];
    let server = FakeSocks5Server::start(FakeSocks5Config::success(http_ok(&receipt)));
    let addr = server.addr();

    let envelope = b"opaque-encrypted-remote-ballot-envelope".to_vec();
    let mut carrier = remote_carrier(addr);
    let returned = carrier
        .deliver_opaque_envelope(&tor_descriptor(), &envelope)
        .expect("remote carrier delivers");
    assert_eq!(returned, receipt, "remote carrier returns exact receipt bytes");

    let capture = server.join();
    let connect = capture.connect_request;
    assert_eq!(connect[0], 0x05, "SOCKS version 5");
    assert_eq!(connect[1], 0x01, "CONNECT command");
    assert_eq!(connect[3], 0x03, "ATYP = DOMAINNAME — .onion never OS-resolved");
    assert_eq!(usize::from(connect[4]), TEST_ONION.len(), "onion hostname length");
    let host = &connect[5..5 + TEST_ONION.len()];
    assert_eq!(host, TEST_ONION.as_bytes(), "literal onion host on the wire");

    // The exact envelope bytes were the HTTP POST body (no re-seal, no mutation).
    let request = capture.http_request;
    let position = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("request terminator");
    assert_eq!(&request[position + 4..], envelope.as_slice());
}

// =========================================================================
// Test 12: SOCKS failure does not fall back to clearnet — a closed proxy
// yields a bounded error, not a direct connection.
// =========================================================================

#[test]
fn remote_carrier_closed_proxy_fails_closed_without_clearnet_fallback() {
    let addr = closed_loopback_addr();
    let mut carrier = remote_carrier(addr);
    let result = carrier.deliver_opaque_envelope(&tor_descriptor(), b"envelope");
    assert!(
        result.is_err(),
        "a dead SOCKS proxy must fail closed, never reach the onion another way"
    );
}

// =========================================================================
// No-clearnet / route binding: a descriptor whose route policy does not permit
// managed Tor must produce ZERO network activity from the remote carrier.
// =========================================================================

#[test]
fn remote_carrier_refuses_non_tor_route_before_any_network() {
    let descriptor = descriptor_with_route(TransportRoutePolicyV1::RelayOrOffline);
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let mut carrier = remote_carrier(addr);
    assert!(
        carrier.deliver_opaque_envelope(&descriptor, b"envelope").is_err(),
        "a non-Tor route must be refused before any connection"
    );
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("remote carrier connected before route validation: {other:?}"),
    }
}

// =========================================================================
// Test 10: the readiness probe performs no ballot submission (zero app bytes)
// and reports Ready on a fully successful SOCKS5 CONNECT.
// =========================================================================

#[test]
fn remote_readiness_probe_reports_ready_and_sends_zero_application_bytes() {
    // A fake server that would fail the test if ANY HTTP request byte arrived:
    // the probe must close right after the SOCKS CONNECT reply.
    let server = FakeSocks5Server::start(FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: fake_socks::success_connect_reply(),
        stop_after_connect: false,
        behavior: fake_socks::HttpBehavior::Respond(http_ok(b"unused")),
    });
    let addr = server.addr();
    let outcome = probe_remote_onion_reachability_v1(
        &remote_endpoint(addr),
        &tor_descriptor(),
        &fast_timeouts(),
    );
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::Ready);
    assert_eq!(outcome.code(), "REMOTE_TOR_READY");
    assert!(outcome.is_ready());

    let capture = server.join();
    assert!(
        capture.http_request.is_empty(),
        "the readiness probe must send ZERO application (HTTP) bytes"
    );
}

// =========================================================================
// Readiness failure classification: distinguishable states with stable codes.
// =========================================================================

#[test]
fn remote_readiness_probe_unreachable_on_closed_proxy() {
    let addr = closed_loopback_addr();
    let outcome =
        probe_remote_onion_reachability_v1(&remote_endpoint(addr), &tor_descriptor(), &fast_timeouts());
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::Unreachable);
    assert_eq!(outcome.code(), "REMOTE_TOR_UNREACHABLE");
    assert!(!outcome.is_ready());
}

#[test]
fn remote_readiness_probe_handshake_failed_when_proxy_rejects_method() {
    // The peer answers the TCP connect but refuses SOCKS5 no-auth negotiation.
    let server = FakeSocks5Server::start(FakeSocks5Config {
        method_reply: vec![0x05, 0xFF], // no acceptable method
        stop_after_method: true,
        connect_reply: Vec::new(),
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    });
    let addr = server.addr();
    let outcome =
        probe_remote_onion_reachability_v1(&remote_endpoint(addr), &tor_descriptor(), &fast_timeouts());
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::SocksHandshakeFailed);
    assert_eq!(outcome.code(), "REMOTE_TOR_SOCKS_HANDSHAKE_FAILED");
    let _ = server.join();
}

#[test]
fn remote_readiness_probe_onion_unreachable_when_connect_refused() {
    // SOCKS5 negotiation succeeds but the CONNECT reply is a failure (0x04 =
    // host unreachable), which models Tor failing to reach the hidden service.
    let server = FakeSocks5Server::start(FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: vec![0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    });
    let addr = server.addr();
    let outcome =
        probe_remote_onion_reachability_v1(&remote_endpoint(addr), &tor_descriptor(), &fast_timeouts());
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::OnionUnreachable);
    assert_eq!(outcome.code(), "REMOTE_TOR_ONION_UNREACHABLE");
    let _ = server.join();
}

#[test]
fn remote_readiness_probe_endpoint_invalid_on_non_tor_route() {
    // A descriptor that does not permit managed Tor yields EndpointInvalid
    // (a configuration problem), and never opens a connection.
    let descriptor = descriptor_with_route(TransportRoutePolicyV1::RelayOrOffline);
    let outcome = probe_remote_onion_reachability_v1(
        &RemoteSocksEndpointV1::parse("127.0.0.1:9").expect("valid"),
        &descriptor,
        &fast_timeouts(),
    );
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::EndpointInvalid);
    assert_eq!(outcome.code(), "REMOTE_TOR_ENDPOINT_INVALID");
}
