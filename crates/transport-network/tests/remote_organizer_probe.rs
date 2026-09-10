//! Remote ORGANIZER onion readiness tests over the deterministic loopback fake
//! SOCKS5 server. These cover the explicit-hostname remote organizer probe:
//! the supplied onion is sent as a SOCKS5 DOMAINNAME literal (never
//! OS-resolved), the probe sends zero application bytes, a malformed onion is
//! rejected BEFORE any connection, and failures are classified fail-closed.
//! No installed Tor, no internet, no DNS, no onion service.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fake_socks;

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use fake_socks::{FakeSocks5Config, FakeSocks5Server, http_ok};
use tari_cc_private_ballot_transport_network::{
    RemoteSocksEndpointV1, RemoteTorReadinessOutcomeV1, TorCarrierTimeoutsV1,
    fetch_election_status_over_remote_tor_onion, probe_remote_onion_hostname_v1,
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

fn remote_endpoint(addr: SocketAddr) -> RemoteSocksEndpointV1 {
    RemoteSocksEndpointV1::parse(&addr.to_string()).expect("valid remote endpoint")
}

fn closed_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

#[test]
fn organizer_probe_sends_literal_onion_connect_and_zero_application_bytes() {
    let server = FakeSocks5Server::start(FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: fake_socks::success_connect_reply(),
        stop_after_connect: false,
        behavior: fake_socks::HttpBehavior::Respond(http_ok(b"unused")),
    });
    let outcome = probe_remote_onion_hostname_v1(
        &remote_endpoint(server.addr()),
        TEST_ONION,
        &fast_timeouts(),
    );
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::Ready);
    assert!(outcome.is_ready());

    let capture = server.join();
    let connect = capture.connect_request;
    assert_eq!(connect[0], 0x05, "SOCKS version 5");
    assert_eq!(connect[1], 0x01, "CONNECT command");
    assert_eq!(connect[3], 0x03, "ATYP = DOMAINNAME — onion never OS-resolved");
    assert_eq!(usize::from(connect[4]), TEST_ONION.len());
    assert_eq!(
        &connect[5..5 + TEST_ONION.len()],
        TEST_ONION.as_bytes(),
        "the operator-supplied onion goes on the wire as a literal"
    );
    assert!(
        capture.http_request.is_empty(),
        "the organizer readiness probe must send ZERO application (HTTP) bytes"
    );
}

#[test]
fn organizer_probe_rejects_malformed_onion_before_any_connection() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    listener
        .set_nonblocking(true)
        .expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let outcome = probe_remote_onion_hostname_v1(
        &remote_endpoint(addr),
        "example.com",
        &fast_timeouts(),
    );
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::EndpointInvalid);
    // A malformed onion must be a configuration error, not a network attempt.
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("malformed onion reached the network layer: {other:?}"),
    }
}

#[test]
fn organizer_probe_fails_closed_on_closed_proxy() {
    let outcome = probe_remote_onion_hostname_v1(
        &remote_endpoint(closed_loopback_addr()),
        TEST_ONION,
        &fast_timeouts(),
    );
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::Unreachable);
}

#[test]
fn organizer_probe_classifies_onion_unreachable_on_connect_failure() {
    let server = FakeSocks5Server::start(FakeSocks5Config {
        method_reply: vec![0x05, 0x00],
        stop_after_method: false,
        connect_reply: vec![0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        stop_after_connect: true,
        behavior: fake_socks::HttpBehavior::Respond(Vec::new()),
    });
    let outcome = probe_remote_onion_hostname_v1(
        &remote_endpoint(server.addr()),
        TEST_ONION,
        &fast_timeouts(),
    );
    assert_eq!(outcome, RemoteTorReadinessOutcomeV1::OnionUnreachable);
    let _ = server.join();
}

#[test]
fn organizer_status_fetch_returns_the_body_over_the_remote_route() {
    let body = b"signed-election-status-statement";
    let server = FakeSocks5Server::start(FakeSocks5Config::success(http_ok(body)));
    let fetched = fetch_election_status_over_remote_tor_onion(
        &remote_endpoint(server.addr()),
        TEST_ONION,
        &fast_timeouts(),
    )
    .expect("status fetch");
    assert_eq!(fetched, body.to_vec());

    let capture = server.join();
    let request = String::from_utf8_lossy(&capture.http_request).into_owned();
    assert!(
        request.starts_with("GET /v1/election-status"),
        "the readiness fetch is the public credential-free status GET: {request}"
    );
    let connect = capture.connect_request;
    assert_eq!(connect[3], 0x03, "onion stays a DOMAINNAME literal");
    let _ = server;
}

#[test]
fn organizer_status_fetch_rejects_malformed_onion_fail_closed() {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("addr");
    let result =
        fetch_election_status_over_remote_tor_onion(&remote_endpoint(addr), "bad-host", &fast_timeouts());
    assert!(result.is_err(), "a malformed onion must fail closed");
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => panic!("malformed onion reached the network layer: {other:?}"),
    }
}
