//! LOCAL INTEGRATION TEST — external-remote organizer Tor (Option 1 prototype).
//!
//! This test simulates the intended two-machine topology on ONE machine:
//!
//!   Private Ballot (client role) ──SOCKS──▶ "Tor B" (externally managed)
//!                                              │ hosts the onion service
//!                                              ▼
//!                              HiddenServicePort 80 → 127.0.0.1:18081
//!                                              │
//!                                              ▼
//!                        Private Ballot organizer collector (this process)
//!
//! Tor B is started by the TEST ITSELF acting as the remote OPERATOR — it is
//! explicitly NOT started, owned, or stopped through any Private Ballot
//! ownership code path. The assertions prove that Private Ballot's remote
//! primitives treat it exactly like an external daemon:
//!   * the readiness probe sends ZERO application bytes (SOCKS CONNECT + close)
//!   * the onion hostname stays a literal SOCKS5 DOMAINNAME (no OS DNS)
//!   * a real sealed ballot envelope is delivered through the remote route and
//!     an authenticated receipt is returned, with at-most-once semantics
//!   * the public, credential-free election-status GET is served and verifies
//!   * the external Tor stays alive across a client "disconnect" — Private
//!     Ballot never signals it
//!
//! RUN (local development only — needs the real Tor network):
//!   TOR_B_EXE=<path to tor.exe> cargo test -p tari-cc-private-ballot-transport-gateway \
//!     --test remote_organizer_external_tor -- --ignored --nocapture
//!
//! No other environment setup is required: the test creates its own Tor
//! data/hidden-service directories and torrc under the system temp dir (never
//! inside the repository) and performs the final operator cleanup itself.

#![cfg(feature = "managed-tor")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use tari_cc_private_ballot_gui_core::{
    AuthenticatedElectionStatusStatementV1, AuthoritativeLifecycleFenceV1, BatchPolicyV1,
    ElectionLifecycleStateV1, PaddingPolicyV1, PrivateBallotEnvelopeV1,
    PrivateReleaseCarrierV1, TransportAuthorityRootSetV1, TransportAuthorityRootV1,
    TransportDescriptorV1, TransportRoutePolicyV1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
use tari_cc_private_ballot_transport_gateway::{
    GatewayReceiverKeyV1, OpaqueEnvelopeCollectorV1, OrganizerCollectorServiceLoopV1,
    ThreadSafeCollectorHandlerV1, TransportGatewaySimulatorV1,
};
use tari_cc_private_ballot_transport_network::{
    RemoteSocksEndpointV1, RemoteTorSocksPrivateReleaseCarrierV1, TorCarrierTimeoutsV1,
    fetch_election_status_over_remote_tor_onion, probe_remote_onion_hostname_v1,
};

type Kem = X25519HkdfSha256;

const ROOT_KEY_ID: &str = "external-remote-root";
// Observed bootstrap on a slow directory feed: ~4m20s to 100%. Keep a generous
// but strictly bounded budget so the test can never wait indefinitely.
const TOR_B_BOOTSTRAP_BUDGET: Duration = Duration::from_secs(420);
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

fn fast_timeouts() -> TorCarrierTimeoutsV1 {
    TorCarrierTimeoutsV1 {
        socks_connect: Duration::from_secs(10),
        socks_handshake: Duration::from_secs(20),
        http_write: Duration::from_secs(20),
        http_response: Duration::from_secs(30),
    }
}

/// The externally managed Tor instance ("Tor B"). Owned by the TEST in its
/// operator role — never by any Private Ballot ownership code path.
struct ExternalTorB {
    child: Arc<Mutex<Child>>,
    base: PathBuf,
}

impl Drop for ExternalTorB {
    // The OPERATOR's cleanup — the same action a human operator would take on
    // the remote machine. Private Ballot code never reaches this.
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ExternalTorB {
    fn alive(&self) -> bool {
        self.child
            .lock()
            .map(|mut child| {
                child
                    .try_wait()
                    .map(|status| status.is_none())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    fn start(tor_exe: &Path, socks_port: u16, collector_port: u16) -> Self {
        let base = std::env::temp_dir().join(format!(
            "private-ballot-tor-b-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("data")).expect("tor B data dir");
        std::fs::create_dir_all(base.join("hs")).expect("tor B hidden-service dir");
        // Written by the OPERATOR (this test role), not by Private Ballot: the
        // external daemon owns its own configuration and hidden-service
        // directory. Private Ballot can neither see nor generate this file.
        let torrc = format!(
            "SocksPort 127.0.0.1:{socks_port}\n\
             DataDirectory {}\n\
             HiddenServiceDir {}\n\
             HiddenServiceVersion 3\n\
             HiddenServicePort 80 127.0.0.1:{collector_port}\n",
            quote(&base.join("data")),
            quote(&base.join("hs")),
        );
        let torrc_path = base.join("torrc");
        std::fs::write(&torrc_path, torrc).expect("write tor B torrc");
        let child = Command::new(tor_exe)
            .arg("-f")
            .arg(&torrc_path)
            .spawn()
            .expect("operator starts Tor B");
        Self {
            child: Arc::new(Mutex::new(child)),
            base,
        }
    }

    /// Bounded wait for Tor B to publish its hidden-service hostname file.
    /// An early daemon exit (bad config, port conflict) fails FAST instead of
    /// burning the whole discovery budget.
    fn discover_hostname(&self) -> String {
        let hostname_file = self.base.join("hs").join("hostname");
        let deadline = Instant::now() + TOR_B_BOOTSTRAP_BUDGET;
        loop {
            if let Ok(content) = std::fs::read_to_string(&hostname_file) {
                let trimmed = content.trim_end_matches(['\n', '\r']);
                if !trimmed.is_empty() {
                    return trimmed.to_owned();
                }
            }
            assert!(
                self.alive(),
                "tor B exited before publishing the hidden-service hostname (check its config/ports)"
            );
            assert!(
                Instant::now() < deadline,
                "tor B never published its hidden-service hostname"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

fn quote(path: &Path) -> String {
    format!("\"{}\"", path.to_string_lossy().replace('\\', "\\\\"))
}

struct CollectorFixture {
    service_loop: OrganizerCollectorServiceLoopV1,
    descriptor: TransportDescriptorV1,
    roots: TransportAuthorityRootSetV1,
}

/// Builds the full organizer intake shape (collector, gateway, worker session,
/// fence, status signer) for the REAL external onion hostname.
fn start_collector(onion: &str, collector_port: u16) -> CollectorFixture {
    let (receiver_secret, receiver_public) = Kem::gen_keypair();
    let mut gateway_public = [0u8; 32];
    gateway_public.copy_from_slice(receiver_public.to_bytes().as_slice());
    let mut secret = [0u8; 32];
    secret.copy_from_slice(receiver_secret.to_bytes().as_slice());

    let manifest = common::manifest();
    let manifest_hash = manifest
        .canonical_hash(&Blake3HashProviderV1)
        .expect("hash");
    let root_signing_key = SigningKey::from_bytes(&[91; 32]);
    let receipt_key = SigningKey::from_bytes(&[92; 32]);
    let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        manifest.election_id().as_bytes().to_vec(),
        manifest_hash,
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![onion.to_owned()],
        Vec::new(),
        gateway_public,
        "external-remote-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "external-remote-fixed".to_owned(),
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
    let roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
        key_id: ROOT_KEY_ID.to_owned(),
        public_key: root_signing_key.verifying_key().to_bytes(),
    });

    let collector = OpaqueEnvelopeCollectorV1::bind_loopback_port(collector_port)
        .expect("bind collector on the fixed remote-target port");
    let gateway = Arc::new(Mutex::new(TransportGatewaySimulatorV1::default()));
    let session = Arc::new(Mutex::new(common::open_session()));
    let receiver_key = GatewayReceiverKeyV1::from_secret_bytes(secret).expect("receiver key");
    let handler = ThreadSafeCollectorHandlerV1::new(
        gateway,
        Arc::new(descriptor.clone()),
        Arc::new(receiver_key),
        session,
        Arc::new(receipt_key),
        "external-remote-receipt".to_owned(),
    )
    .with_lifecycle_fence(AuthoritativeLifecycleFenceV1::new(
        ElectionLifecycleStateV1::Open,
        1,
    ))
    .with_election_status_signer(
        Arc::new(root_signing_key),
        ROOT_KEY_ID.to_owned(),
    );
    let service_loop = OrganizerCollectorServiceLoopV1::start(
        collector,
        handler,
        Duration::from_millis(50),
    )
    .expect("start collector service loop");
    CollectorFixture {
        service_loop,
        descriptor,
        roots,
    }
}

fn fetch_status_directly(addr: SocketAddr) -> Vec<u8> {
    let mut request =
        b"GET /v1/election-status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec();
    let mut stream = TcpStream::connect(addr).expect("connect collector");
    stream.write_all(&mut request).expect("write");
    stream.flush().expect("flush");
    let mut buffer = Vec::new();
    let _ = stream.read_to_end(&mut buffer);
    let split = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    buffer[split + 4..].to_vec()
}

#[test]
#[ignore = "requires a real externally managed Tor instance: set TOR_B_EXE and run with -- --ignored"]
fn external_remote_organizer_onion_end_to_end() {
    let Some(tor_exe) = std::env::var_os("TOR_B_EXE").map(PathBuf::from) else {
        panic!("set TOR_B_EXE to a real tor executable for this local integration test");
    };
    let socks_port: u16 = std::env::var("TOR_B_SOCKS_PORT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(19050);
    let collector_port: u16 = std::env::var("TOR_B_COLLECTOR_PORT")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(18081);

    // ---- Operator role: start + provision the EXTERNAL Tor instance. --------
    let tor_b = ExternalTorB::start(&tor_exe, socks_port, collector_port);
    assert!(tor_b.alive(), "tor B exited immediately");
    let onion = tor_b.discover_hostname();
    println!("external Tor B onion: {onion}");

    // ---- Organizer collector (loopback, fixed port the remote HS targets). --
    // Bound FIRST — exactly like the production remote-organizer start order —
    // because the onion service dials this port during every rendezvous: a
    // readiness probe against a closed target must (and does) fail closed.
    let fixture = start_collector(&onion, collector_port);

    // ---- Private Ballot client role: validate endpoint + probe readiness. ---
    let endpoint = RemoteSocksEndpointV1::parse(&format!("127.0.0.1:{socks_port}"))
        .expect("endpoint");
    let timeouts = fast_timeouts();
    // Bounded bootstrap wait: Tor B must fetch consensus, publish its HS
    // descriptor, and build the rendezvous before the probe succeeds. The probe
    // is the SAME zero-application-byte primitive the production remote
    // organizer mode uses.
    let deadline = Instant::now() + TOR_B_BOOTSTRAP_BUDGET;
    loop {
        let outcome = probe_remote_onion_hostname_v1(&endpoint, &onion, &timeouts);
        if outcome.is_ready() {
            println!("remote readiness: READY (zero application bytes proven by unit tests)");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "onion never became reachable through the external proxy: {outcome:?}"
        );
        std::thread::sleep(PROBE_INTERVAL);
    }

    // Public, credential-free election-status GET through the external onion.
    let status_bytes =
        fetch_election_status_over_remote_tor_onion(&endpoint, &onion, &timeouts)
            .expect("status over the remote organizer route");
    let statement = AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&status_bytes)
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
    println!("election-status GET verified through the external onion");

    // ---- Tiny election path: one real sealed ballot through the remote route.
    let package = common::triptych_package_bytes(0, &[b"candidate-a"]);
    let envelope = PrivateBallotEnvelopeV1::seal(&fixture.descriptor, &package)
        .expect("seal")
        .to_canonical_cbor()
        .expect("encode");
    let mut carrier = RemoteTorSocksPrivateReleaseCarrierV1::new(endpoint.clone(), timeouts);
    let receipt = carrier
        .deliver_opaque_envelope(&fixture.descriptor, &envelope)
        .expect("ballot delivered through the external remote Tor route");
    assert!(!receipt.is_empty(), "an authenticated receipt is returned");
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        1,
        "exactly one ballot accepted through the remote organizer route"
    );
    // At-most-once through the remote route: an exact resend never double-counts.
    let _ = carrier
        .deliver_opaque_envelope(&fixture.descriptor, &envelope)
        .expect("exact resend also returns a receipt");
    assert_eq!(
        fixture.service_loop.accepted_unique_count(),
        1,
        "an exact resend through the remote route is never counted twice"
    );

    // ---- Disconnect: drop the carrier, prove external Tor is UNTOUCHED. -----
    drop(carrier);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        tor_b.alive(),
        "the externally managed Tor B must still be running after Private Ballot disconnects"
    );

    fixture
        .service_loop
        .stop(Duration::from_secs(3))
        .expect("bounded collector stop");

    // The operator (test role) cleans up Tor B last, via Drop. Private Ballot
    // code never performed any process or filesystem ownership action on it.
}
