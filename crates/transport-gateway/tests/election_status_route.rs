//! Authenticated election-status route + authoritative lifecycle fencing
//! tests (managed-tor-test only).
//!
//! These prove the two distributed-lifecycle guarantees added to the
//! organizer collector:
//!
//! 1. `GET /v1/election-status` answers with canonical bytes of one
//!    AUTHENTICATED, election-bound status statement whose state and
//!    generation come from the AUTHORITATIVE lifecycle fence â€” never from the
//!    worker session's own substrate.
//! 2. Ballot admission is FENCED by that same fence: a FROZEN or CLOSED
//!    organizer election refuses envelopes with 503 BEFORE any decryption,
//!    intake, or durable work, so no receipt can ever claim acceptance
//!    outside the authoritative open state.
//!
//! No real Tor, no internet; loopback sockets only.

#![cfg(feature = "managed-tor-test")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};

use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;
use tari_cc_private_ballot_gui_core::{
    AuthenticatedElectionStatusStatementV1, AuthoritativeLifecycleFenceV1,
    ElectionStatusKnowledgeV1, GuiElectionSessionV1, BatchPolicyV1, PaddingPolicyV1,
    PrivateBallotEnvelopeV1, TransportAuthorityRootSetV1, TransportAuthorityRootV1,
    TransportDescriptorV1, TransportRoutePolicyV1, verify_and_apply_election_status_statement_v1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1};
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, OpaqueEnvelopeCollectorV1, OpaqueEnvelopeGatewayHandlerV1,
    ThreadSafeCollectorHandlerV1, TransportGatewaySimulatorV1,
};

type Kem = X25519HkdfSha256;

const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
const ROOT_KEY_ID: &str = "status-route-root";

// =========================================================================
// Raw HTTP client + single-serve driver.
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

fn http_exchange(addr: SocketAddr, request: Vec<u8>) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("connect collector");
    stream.write_all(&request).expect("write request");
    stream.flush().expect("flush");
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).expect("read response");
    parse_response(&buffer)
}

fn drive_once(
    collector: &OpaqueEnvelopeCollectorV1,
    handler: &mut dyn OpaqueEnvelopeGatewayHandlerV1,
    request: Vec<u8>,
) -> (u16, Vec<u8>) {
    let addr = collector.local_addr().expect("addr");
    let client = std::thread::spawn(move || http_exchange(addr, request));
    collector.serve_next(handler).expect("serve one");
    client.join().expect("client thread")
}

fn http_get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").into_bytes()
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
// Fixtures.
// =========================================================================

struct HandlerFixture {
    descriptor: TransportDescriptorV1,
    receiver_secret: [u8; 32],
    receipt_key: SigningKey,
    root_signing_key: SigningKey,
    roots: TransportAuthorityRootSetV1,
    package: Vec<u8>,
}

fn handler_fixture() -> HandlerFixture {
    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut gateway_public = [0u8; 32];
    gateway_public.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(receiver_secret.to_bytes().as_slice());

    let manifest = common::manifest();
    let manifest_hash = manifest.canonical_hash(&Blake3HashProviderV1).expect("hash");
    // The SAME root key signs the descriptor AND the status statements.
    let root_signing_key = SigningKey::from_bytes(&[81; 32]);
    let receipt_key = SigningKey::from_bytes(&[82; 32]);
    let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        manifest.election_id().as_bytes().to_vec(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![TEST_ONION.to_owned()],
        Vec::new(),
        gateway_public,
        "status-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "status-fixed".to_owned(),
            padded_bytes: 65_536,
        },
        BatchPolicyV1 {
            id: "accepted-1".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        ROOT_KEY_ID.to_owned(),
        &root_signing_key,
    )
    .expect("descriptor");
    let roots =
        TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
            key_id: ROOT_KEY_ID.to_owned(),
            public_key: root_signing_key.verifying_key().to_bytes(),
        });
    HandlerFixture {
        descriptor,
        receiver_secret: secret,
        receipt_key,
        root_signing_key,
        roots,
        package: common::triptych_package_bytes(0, &[b"candidate-a"]),
    }
}

/// Builds the thread-safe production-intake handler shape: OPEN worker session
/// substrate + fence + status signer. Admission must follow the FENCE, never
/// the substrate session's own OPEN state.
fn fenced_handler(
    fixture: &HandlerFixture,
    fence: AuthoritativeLifecycleFenceV1,
) -> (
    Arc<Mutex<TransportGatewaySimulatorV1>>,
    Arc<Mutex<tari_cc_private_ballot_gui_core::GuiElectionSessionV1>>,
    ThreadSafeCollectorHandlerV1,
) {
    let gateway = Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    // Substrate session is OPEN on purpose: fencing must come from the fence.
    let session = Arc::new(Mutex::new(common::open_session()));
    let receiver_key = GatewayReceiverKeyV1::from_secret_bytes(fixture.receiver_secret)
        .expect("receiver key");
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway.clone(),
        Arc::new(fixture.descriptor.clone()),
        Arc::new(receiver_key),
        session.clone(),
        Arc::new(fixture.receipt_key.clone()),
        "status-receipt-key".to_owned(),
    )
    .with_lifecycle_fence(fence.clone())
    .with_election_status_signer(
        Arc::new(fixture.root_signing_key.clone()),
        ROOT_KEY_ID.to_owned(),
    );
    (gateway, session, handler)
}

fn verify_statement(
    fixture: &HandlerFixture,
    body: &[u8],
) -> AuthenticatedElectionStatusStatementV1 {
    let statement = AuthenticatedElectionStatusStatementV1::from_canonical_cbor(body)
        .expect("canonical authenticated statement");
    let artifacts = common::artifacts();
    statement
        .verify(
            &fixture.roots,
            artifacts.manifest().election_id().as_bytes(),
            artifacts.manifest_hash(),
            artifacts.registry_commitment(),
        )
        .expect("statement authenticates under pinned root");
    statement
}

// =========================================================================
// Tests.
// =========================================================================

#[test]
fn get_election_status_returns_authenticated_authoritative_open() {
    let fixture = handler_fixture();
    // Authoritative truth: voting IS open (generation continues an issuance
    // counter at 4).
    let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Open, 4);
    let (_gateway, _session, mut handler) = fenced_handler(&fixture, fence.clone());
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let (code, body) = drive_once(&collector, &mut handler, http_get("/v1/election-status"));
    assert_eq!(code, 200, "status route answers 200");

    let statement = verify_statement(&fixture, &body);
    assert_eq!(statement.state(), ElectionLifecycleStateV1::Open);
    assert_eq!(statement.generation(), 4);
    assert_eq!(statement.root_key_id(), ROOT_KEY_ID);
}

#[test]
fn get_election_status_reflects_committed_close_monotonically() {
    let fixture = handler_fixture();
    // Start FROZEN at generation 3, then commit open and close through the
    // authoritative fence exactly as GUI transitions would publish them.
    let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 3);
    let (_gateway, _session, mut handler) = fenced_handler(&fixture, fence.clone());
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let (frozen_code, frozen_body) =
        drive_once(&collector, &mut handler, http_get("/v1/election-status"));
    assert_eq!(frozen_code, 200);
    let frozen = verify_statement(&fixture, &frozen_body);
    assert_eq!(frozen.state(), ElectionLifecycleStateV1::Frozen);

    fence.observe(ElectionLifecycleStateV1::Open, None);
    fence.observe(ElectionLifecycleStateV1::Closed, None);

    let (closed_code, closed_body) =
        drive_once(&collector, &mut handler, http_get("/v1/election-status"));
    assert_eq!(closed_code, 200);
    let closed = verify_statement(&fixture, &closed_body);
    assert_eq!(closed.state(), ElectionLifecycleStateV1::Closed);
    // Generations advance monotonically across observed transitions.
    assert_eq!(frozen.generation(), 3);
    assert_eq!(closed.generation(), 5);
}

#[test]
fn closed_fence_refuses_valid_envelopes_before_any_acceptance() {
    let fixture = handler_fixture();
    // Authoritative truth: voting has CLOSED. The substrate worker session is
    // still OPEN â€” the fence, not the substrate, decides.
    let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Open, 9);
    fence.observe(ElectionLifecycleStateV1::Closed, None);
    let (gateway, session, mut handler) = fenced_handler(&fixture, fence.clone());
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let encoded = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &fixture.package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let (code, body) = drive_once(&collector, &mut handler, octet_post("/v1/opaque-envelope", &encoded));
    assert_eq!(code, 503, "closed election fences ballots with 503");
    assert!(body.is_empty(), "rejections carry no receipt bytes");

    // Nothing was accepted anywhere: no gateway count, no durable packages.
    assert_eq!(
        gateway.lock().expect("gateway").accepted_unique_count(),
        0,
        "no ballot may be accepted after close"
    );
    assert!(
        session.lock().expect("session").packages().is_empty(),
        "no package may enter the intake session after close"
    );
}

#[test]
fn open_fence_admits_and_status_stays_truthful() {
    let fixture = handler_fixture();
    let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 2);
    let (gateway, _session, mut handler) = fenced_handler(&fixture, fence.clone());
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    // While FROZEN the exact same valid envelope is refused...
    let encoded = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &fixture.package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let (frozen_code, _) =
        drive_once(&collector, &mut handler, octet_post("/v1/opaque-envelope", &encoded));
    assert_eq!(frozen_code, 503, "pre-open election fences ballots");

    // ...and once the organizer commits OPEN, admission proceeds.
    fence.observe(ElectionLifecycleStateV1::Open, None);
    let (open_code, open_body) =
        drive_once(&collector, &mut handler, octet_post("/v1/opaque-envelope", &encoded));
    assert_eq!(open_code, 200, "open election admits a valid ballot");
    let receipt =
        tari_cc_private_ballot_gui_core::AuthenticatedTransportReceiptV1::from_canonical_cbor(&open_body)
            .expect("authenticated receipt");
    assert_eq!(
        receipt.receipt().state,
        tari_cc_private_ballot_gui_core::VoterReceiptStateV1::Accepted
    );
    assert_eq!(gateway.lock().expect("gateway").accepted_unique_count(), 1);
}

#[test]
fn status_route_requires_signer_and_exact_path() {
    let fixture = handler_fixture();
    // A handler WITHOUT fence/signer keeps the trait default: 404.
    let bare_session = Arc::new(Mutex::new(common::open_session()));
    let bare_receiver =
        GatewayReceiverKeyV1::from_secret_bytes(fixture.receiver_secret).expect("receiver key");
    let mut bare = ThreadSafeCollectorHandlerV1::new(
        Arc::new(Mutex::new(TransportGatewaySimulatorV1::default())),
        Arc::new(fixture.descriptor.clone()),
        Arc::new(bare_receiver),
        bare_session,
        Arc::new(fixture.receipt_key.clone()),
        "status-receipt-key".to_owned(),
    );
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    let (missing_code, missing_body) =
        drive_once(&collector, &mut bare, http_get("/v1/election-status"));
    assert_eq!(missing_code, 404, "unsigned/unfenced handler refuses");
    assert!(missing_body.is_empty());

    // GET to any other path is a plain 404 as well.
    let (wrong_path_code, _) = drive_once(&collector, &mut bare, http_get("/v1/other"));
    assert_eq!(wrong_path_code, 404);

    // POST to the status path is NOT the envelope endpoint either.
    let (post_status_code, _) = drive_once(
        &collector,
        &mut bare,
        octet_post("/v1/election-status", b"junk"),
    );
    assert_ne!(post_status_code, 200);
}

#[test]
fn physical_regression_frozen_then_open_on_one_running_collector_with_voter_apply() {
    // Reproduces the two-computer physical failure (`lifecycle-auto-refresh-01`)
    // end to end at the wire level, under the ROOT-CAUSE fix's generation
    // semantics: the intake fence seed is durably RESERVED like any other
    // issuance, so a served statement's generation is never re-minted by a
    // later transition.
    //
    // 1. The ballot-office status source starts FROZEN at its reserved seed.
    // 2. A voter fetches and APPLIES that FROZEN statement (monotonic knowledge).
    // 3. The organizer authoritative lifecycle advances to OPEN (generation 2).
    // 4. The SAME already-running collector is queried and MUST return a newly
    //    valid signed OPEN statement — never a snapshot frozen at start time.
    // 5. The voter private-fetch apply path accepts it and advances FROZEN ->
    //    OPEN (this exact apply failed with ConflictingGeneration before the
    //    fix, because the served OPEN repeated generation 1).
    // 6. OPEN -> CLOSED while the service keeps running stays monotonic.
    let fixture = handler_fixture();
    let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Frozen, 1);
    let (_gateway, _session, mut handler) = fenced_handler(&fixture, fence.clone());
    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(0).expect("bind");

    // Steps 1+2: startup truth — signed FROZEN@1, consumed by the voter.
    let (frozen_code, frozen_body) =
        drive_once(&collector, &mut handler, http_get("/v1/election-status"));
    assert_eq!(frozen_code, 200);
    let frozen = verify_statement(&fixture, &frozen_body);
    assert_eq!(frozen.state(), ElectionLifecycleStateV1::Frozen);
    assert_eq!(frozen.generation(), 1);
    let mut knowledge =
        ElectionStatusKnowledgeV1::from_accepted(frozen.state(), frozen.generation());
    let mut voter = GuiElectionSessionV1::new(common::artifacts()).expect("frozen voter session");
    verify_and_apply_election_status_statement_v1(
        &frozen_body,
        &fixture.roots,
        &mut knowledge,
        &mut voter,
    )
    .expect("startup FROZEN statement applies");

    // Step 3: the organizer commits OPEN; publication continues the ledger.
    fence.observe(ElectionLifecycleStateV1::Open, Some(2));

    // Step 4: the SAME already-running collector answers with NEW signed truth
    // (no restart of the collector, handler, or worker).
    let (open_code, open_body) =
        drive_once(&collector, &mut handler, http_get("/v1/election-status"));
    assert_eq!(open_code, 200);
    let open = verify_statement(&fixture, &open_body);
    assert_eq!(open.state(), ElectionLifecycleStateV1::Open);
    assert_eq!(open.generation(), 2);

    // Step 5: the previously-FROZEN voter applies the OPEN answer.
    let applied = verify_and_apply_election_status_statement_v1(
        &open_body,
        &fixture.roots,
        &mut knowledge,
        &mut voter,
    )
    .expect("voter that consumed FROZEN must accept the newer OPEN statement");
    assert_eq!(applied.effective_state, ElectionLifecycleStateV1::Open);
    assert!(applied.advanced, "the voter must actually advance to OPEN");
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Open);

    // Step 6: OPEN -> CLOSED on the still-running service stays monotonic and
    // remains applicable by the same voter knowledge.
    fence.observe(ElectionLifecycleStateV1::Closed, Some(3));
    let (closed_code, closed_body) =
        drive_once(&collector, &mut handler, http_get("/v1/election-status"));
    assert_eq!(closed_code, 200);
    let closed = verify_statement(&fixture, &closed_body);
    assert_eq!(closed.state(), ElectionLifecycleStateV1::Closed);
    assert_eq!(closed.generation(), 3);
    let applied_closed = verify_and_apply_election_status_statement_v1(
        &closed_body,
        &fixture.roots,
        &mut knowledge,
        &mut voter,
    )
    .expect("voter must learn the close through the same live endpoint");
    assert_eq!(applied_closed.effective_state, ElectionLifecycleStateV1::Closed);
}
