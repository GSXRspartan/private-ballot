//! Organizer-side live Ootle anchor publish facade tests.
//!
//! These exercise the gui-core publish boundary up to the live-network edge
//! using scripted transports (no socket is opened, no real walletd or indexer
//! is contacted). The privacy floor, archive binding, decision parsing, auth
//! resolution, and full scripted accept round-trip are all covered here.

#![allow(clippy::expect_used)]

mod common;

use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorLogPayloadV1, AnchorTransactionId,
};
use tari_cc_private_ballot_archive::{
    ArchiveHashV1, TransportArchiveBatchV1, TransportArchiveBindingV1,
};
use tari_cc_private_ballot_gui_core::{
    GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1, GuiCoreError, parse_decision,
    run_step_with_transports,
};
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorLiveApprovalFactsV1, OperatorDecision,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerResponse, ScriptedIndexerTransport,
    ScriptedWalletdResponse, ScriptedWalletdTransport, TransportError, TransportErrorCategory,
    WalletdAnchorNetworkAdapter, WalletdWireTransport,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1;
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use common::{
    TestDir, anchor_network, network_adapter_config, open_session, triptych_package_bytes,
};

const DECLARED_SEAL_PUBLIC_KEY: &str = "seal-public-key-attested";

/// Counting walletd transport that records every call and always reports
/// service unavailable. Used to prove the privacy floor and binding gates
/// reject *before* any network action.
#[derive(Debug, Default)]
struct RefusingWalletdCounters {
    detect: AtomicU64,
    dry_run: AtomicU64,
    create: AtomicU64,
    approve: AtomicU64,
    reject: AtomicU64,
    get: AtomicU64,
    submit: AtomicU64,
}

struct RefusingWalletdTransport {
    counters: Arc<RefusingWalletdCounters>,
}

impl RefusingWalletdTransport {
    fn new(counters: Arc<RefusingWalletdCounters>) -> Self {
        Self { counters }
    }

    fn unavailable() -> TransportError {
        TransportError::from_category(TransportErrorCategory::ServiceUnavailable)
    }
}

impl WalletdWireTransport for RefusingWalletdTransport {
    fn detect_transaction_inputs(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionDetectInputsRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionDetectInputsResponse,
        TransportError,
    > {
        self.counters.detect.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn submit_transaction_dry_run_fee(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionSubmitDryRunRequest,
    ) -> Result<u64, TransportError> {
        // Refuses like every other call so tests can prove the privacy floor
        // and binding gates reject BEFORE any network probe — including the
        // dry-run fee estimate — is issued.
        self.counters.dry_run.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn create_transaction_request(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestCreateRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestCreateResponse,
        TransportError,
    > {
        self.counters.create.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn approve_transaction_request(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionResponse,
        TransportError,
    > {
        self.counters.approve.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn reject_transaction_request(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionResponse,
        TransportError,
    > {
        self.counters.reject.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn get_transaction_request(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestGetRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestGetResponse,
        TransportError,
    > {
        self.counters.get.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn submit_transaction_request(
        &mut self,
        _request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestSubmitRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestSubmitResponse,
        TransportError,
    > {
        self.counters.submit.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }
}

fn refusing_walletd_adapter(
    counters: Arc<RefusingWalletdCounters>,
) -> WalletdAnchorNetworkAdapter<RefusingWalletdTransport> {
    WalletdAnchorNetworkAdapter::new(RefusingWalletdTransport::new(counters), anchor_network())
}

fn not_found_indexer() -> IndexerReceiptNetworkAdapter<ScriptedIndexerTransport> {
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::NotFound);
    IndexerReceiptNetworkAdapter::new(transport)
}

fn live_config(
    dir: &TestDir,
    manifest_hash: tari_cc_private_ballot_protocol::ManifestHash,
    archive_hash: ArchiveHashV1,
    accepted_ballot_count: u64,
    floor: u64,
) -> AnchorAppConfig {
    let facts = AnchorLiveApprovalFactsV1::new(
        accepted_ballot_count,
        floor,
        false,
        false,
        DECLARED_SEAL_PUBLIC_KEY.to_owned(),
        true,
        true,
    )
    .expect("live approval facts must construct");
    let account =
        AnchorAccountReference::new("fee-account".to_owned()).expect("account must construct");
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter_config(),
        account,
        manifest_hash,
        archive_hash,
        anchor_network(),
        dir.join("snapshot.cbor"),
        dir.join("evidence.cbor"),
        1,
        1,
        None,
        facts,
    )
    .with_event_template_binding(
        common::scenario_event_template(),
        common::SCENARIO_MAX_EPOCH_DELTA,
    )
    .expect("event template binding must attach")
}

fn assert_code(error: GuiCoreError, code: &str) {
    assert_eq!(error.code(), code, "unexpected error: {}", error.message());
}

#[test]
fn publish_refuses_floor_below_two_before_any_transport_use() {
    let dir = TestDir::new("publish-floor-below-two");
    let config = live_config(
        &dir,
        common::anchor_manifest_hash(),
        common::anchor_archive_hash(),
        1,
        1,
    );
    let counters = Arc::new(RefusingWalletdCounters::default());

    let error = run_step_with_transports(
        config,
        std::path::Path::new(&format!("{}/nonexistent", dir.path().display())),
        OperatorDecision::Approve,
        refusing_walletd_adapter(counters.clone()),
        not_found_indexer(),
        None,
    )
    .expect_err("floor below minimum must be rejected");

    assert_code(error, "GUI_ANCHOR_PUBLISH_PRIVACY_FLOOR");
    assert_eq!(counters.create.load(Ordering::SeqCst), 0);
    assert_eq!(counters.submit.load(Ordering::SeqCst), 0);
}

#[test]
fn publish_refuses_config_without_live_facts() {
    let dir = TestDir::new("publish-no-live-facts");
    let account =
        AnchorAccountReference::new("fee-account".to_owned()).expect("account must construct");
    let config = AnchorAppConfig::new_archive_verified(
        network_adapter_config(),
        account,
        common::anchor_manifest_hash(),
        common::anchor_archive_hash(),
        anchor_network(),
        dir.join("snapshot.cbor"),
        dir.join("evidence.cbor"),
        1,
        1,
        None,
    );
    let counters = Arc::new(RefusingWalletdCounters::default());

    let error = run_step_with_transports(
        config,
        std::path::Path::new(&format!("{}/nonexistent", dir.path().display())),
        OperatorDecision::Approve,
        refusing_walletd_adapter(counters.clone()),
        not_found_indexer(),
        None,
    )
    .expect_err("missing live facts must be rejected");

    assert_code(error, "GUI_ANCHOR_PUBLISH_LIVE_FACTS_MISSING");
    assert_eq!(counters.create.load(Ordering::SeqCst), 0);
}

#[test]
fn publish_decision_is_validated() {
    assert!(parse_decision("bogus").is_err());
    assert_eq!(
        parse_decision("approve").unwrap(),
        OperatorDecision::Approve
    );
    assert_eq!(
        parse_decision(" REJECT ").unwrap(),
        OperatorDecision::Reject
    );
    assert_eq!(
        parse_decision("none").unwrap(),
        OperatorDecision::NoDecision
    );
}

#[test]
fn publish_minimum_floor_is_two() {
    // The privacy floor must be at least two so a one-voter aggregate anchor
    // can never be casually published through the GUI boundary.
    assert_eq!(GUI_OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1, 2);
}

#[test]
fn publish_archive_binding_mismatch_blocks_prepare() {
    let dir = TestDir::new("publish-binding-mismatch");
    let session = finalized_session_with_two_ballots();
    let archive_dir = write_finalized_bound_archive(&dir, &session);
    // Config deliberately anchored to a DIFFERENT archive hash.
    let config = live_config(
        &dir,
        session.artifacts().manifest_hash(),
        ArchiveHashV1::new([0xA5; 32]),
        2,
        2,
    );
    let counters = Arc::new(RefusingWalletdCounters::default());

    let error = run_step_with_transports(
        config,
        &archive_dir,
        OperatorDecision::Approve,
        refusing_walletd_adapter(counters.clone()),
        not_found_indexer(),
        None,
    )
    .expect_err("archive mismatch must be rejected before publishing");

    assert_code(error, "ANCHOR_PUBLISH_ARCHIVE_BINDING_MISMATCH");
    assert_eq!(counters.create.load(Ordering::SeqCst), 0);
}

#[test]
fn publish_scripted_round_trip_reaches_finalized_accept() {
    let dir = TestDir::new("publish-round-trip");
    let session = finalized_session_with_two_ballots();
    let archive_dir = write_finalized_bound_archive(&dir, &session);
    let archive_hash = read_archive_hash(&archive_dir);
    let manifest_hash = session.artifacts().manifest_hash();
    let config = live_config(&dir, manifest_hash, archive_hash, 2, 2);

    let tx = common::anchor_transaction_id();
    let anchor_digest = OotleAnchorRecordV1::new(anchor_network(), manifest_hash, archive_hash)
        .canonical_hash(&Blake3HashProviderV1)
        .expect("anchor digest must derive");
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);
    let expected_digest_hex = lower_hex(anchor_digest.as_bytes());
    let terminal_root = dir.join("terminal-index");
    let _ = std::fs::create_dir_all(&terminal_root);

    let mut last = None;
    for _ in 0..16 {
        let result = run_step_with_transports(
            config.clone(),
            &archive_dir,
            OperatorDecision::Approve,
            WalletdAnchorNetworkAdapter::new(clone_scripted_walletd(&tx), anchor_network()),
            IndexerReceiptNetworkAdapter::new(clone_scripted_indexer(&payload, &tx)),
            Some(&terminal_root),
        )
        .expect("step must succeed");
        last = Some(result.clone());
        if result.phase_is_terminal_success {
            break;
        }
    }
    let result = last.expect("must reach a terminal result");
    assert!(result.phase_is_terminal_success);
    assert_eq!(result.machine_code, "ANCHOR_APP_FINALIZED_ACCEPT");
    assert!(result.evidence_written);
    assert_eq!(result.anchor_digest_hex, expected_digest_hex);
    assert_eq!(result.transaction_id.as_deref(), Some(tx.as_str()));
}

// ---------------------------------------------------------------------------
// HIGH-1 — concurrent publish serialization
// ---------------------------------------------------------------------------

/// Shared, cross-thread call counters for the walletd transport.
#[derive(Debug, Default)]
struct SharedWalletdCounters {
    create: AtomicU64,
    approve: AtomicU64,
    submit: AtomicU64,
}

/// A happy-path walletd transport that increments SHARED counters so a
/// concurrency test can prove exactly one create/submit occurs across all racing
/// steps for the same anchor.
struct CountingWalletdTransport {
    inner: ScriptedWalletdTransport,
    counters: Arc<SharedWalletdCounters>,
}

impl WalletdWireTransport for CountingWalletdTransport {
    fn detect_transaction_inputs(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionDetectInputsRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionDetectInputsResponse,
        TransportError,
    > {
        self.inner.detect_transaction_inputs(request)
    }

    fn submit_transaction_dry_run_fee(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionSubmitDryRunRequest,
    ) -> Result<u64, TransportError> {
        // Delegates to the underlying scripted transport. The concurrency
        // gates the test proves — exactly-once create/submit under the
        // two-layer publish lock — do not apply to dry-run fee estimation,
        // so no additional shared counter is needed here.
        self.inner.submit_transaction_dry_run_fee(request)
    }

    fn create_transaction_request(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestCreateRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestCreateResponse,
        TransportError,
    > {
        self.counters.create.fetch_add(1, Ordering::SeqCst);
        self.inner.create_transaction_request(request)
    }

    fn approve_transaction_request(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionResponse,
        TransportError,
    > {
        self.counters.approve.fetch_add(1, Ordering::SeqCst);
        self.inner.approve_transaction_request(request)
    }

    fn reject_transaction_request(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestDecisionResponse,
        TransportError,
    > {
        self.inner.reject_transaction_request(request)
    }

    fn get_transaction_request(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestGetRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestGetResponse,
        TransportError,
    > {
        self.inner.get_transaction_request(request)
    }

    fn submit_transaction_request(
        &mut self,
        request: &tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestSubmitRequest,
    ) -> Result<
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransactionRequestSubmitResponse,
        TransportError,
    > {
        self.counters.submit.fetch_add(1, Ordering::SeqCst);
        self.inner.submit_transaction_request(request)
    }
}

#[test]
fn concurrent_publish_steps_for_same_anchor_create_and_submit_exactly_once() {
    let dir = TestDir::new("publish-concurrent-same-anchor");
    let session = finalized_session_with_two_ballots();
    let archive_dir = write_finalized_bound_archive(&dir, &session);
    let archive_hash = read_archive_hash(&archive_dir);
    let manifest_hash = session.artifacts().manifest_hash();
    let config = live_config(&dir, manifest_hash, archive_hash, 2, 2);

    let tx = common::anchor_transaction_id();
    let anchor_digest = OotleAnchorRecordV1::new(anchor_network(), manifest_hash, archive_hash)
        .canonical_hash(&Blake3HashProviderV1)
        .expect("anchor digest must derive");
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);
    let terminal_root = dir.join("terminal-index");
    let _ = std::fs::create_dir_all(&terminal_root);
    let counters = Arc::new(SharedWalletdCounters::default());

    // Several rounds; each round races multiple threads that each perform ONE
    // step for the SAME anchor. The two-layer lock serializes them, so the
    // lifecycle advances one transition per winning step and never double-drives
    // a transition (never a second create/submit).
    let mut reached_terminal = false;
    'rounds: for _round in 0..24 {
        let mut handles = Vec::new();
        for _ in 0..4 {
            let config = config.clone();
            let archive_dir = archive_dir.clone();
            let terminal_root = terminal_root.clone();
            let counters = Arc::clone(&counters);
            let tx = tx.clone();
            let payload = payload.clone();
            handles.push(std::thread::spawn(move || {
                let walletd = CountingWalletdTransport {
                    inner: clone_scripted_walletd(&tx),
                    counters,
                };
                let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, anchor_network());
                let indexer_adapter =
                    IndexerReceiptNetworkAdapter::new(clone_scripted_indexer(&payload, &tx));
                // A lock-busy error is an acceptable non-terminal outcome; the
                // next round retries. A duplicate create/submit is what the lock
                // must prevent, and the shared counters would catch it.
                run_step_with_transports(
                    config,
                    &archive_dir,
                    OperatorDecision::Approve,
                    walletd_adapter,
                    indexer_adapter,
                    Some(&terminal_root),
                )
                .map(|result| result.phase_is_terminal_success)
                .unwrap_or(false)
            }));
        }
        for handle in handles {
            if handle.join().unwrap_or(false) {
                reached_terminal = true;
            }
        }
        if reached_terminal {
            break 'rounds;
        }
    }

    assert!(
        reached_terminal,
        "the concurrent lifecycle must reach FinalizedAccept"
    );
    assert_eq!(
        counters.create.load(Ordering::SeqCst),
        1,
        "exactly one walletd create across all concurrent steps"
    );
    assert_eq!(
        counters.submit.load(Ordering::SeqCst),
        1,
        "exactly one walletd submit across all concurrent steps"
    );
}

#[test]
fn publish_output_inside_archive_is_rejected_before_any_transport() {
    let dir = TestDir::new("publish-output-within-archive");
    let session = finalized_session_with_two_ballots();
    let archive_dir = write_finalized_bound_archive(&dir, &session);
    let archive_hash = read_archive_hash(&archive_dir);
    let manifest_hash = session.artifacts().manifest_hash();
    // A config whose snapshot/evidence paths are INSIDE the finalized archive.
    let facts = AnchorLiveApprovalFactsV1::new(
        2,
        2,
        false,
        false,
        DECLARED_SEAL_PUBLIC_KEY.to_owned(),
        true,
        true,
    )
    .expect("facts must construct");
    let account =
        AnchorAccountReference::new("fee-account".to_owned()).expect("account must construct");
    let config = AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter_config(),
        account,
        manifest_hash,
        archive_hash,
        anchor_network(),
        archive_dir.join("anchor-snapshot.cbor"),
        archive_dir.join("anchor-evidence.cbor"),
        1,
        1,
        None,
        facts,
    )
    .with_event_template_binding(
        common::scenario_event_template(),
        common::SCENARIO_MAX_EPOCH_DELTA,
    )
    .expect("event template binding must attach");
    let counters = Arc::new(RefusingWalletdCounters::default());
    let terminal_root = dir.join("terminal-index");
    let _ = std::fs::create_dir_all(&terminal_root);

    let error = run_step_with_transports(
        config,
        &archive_dir,
        OperatorDecision::Approve,
        refusing_walletd_adapter(counters.clone()),
        not_found_indexer(),
        Some(&terminal_root),
    )
    .expect_err("an output inside the archive must be rejected");

    assert_code(error, "ANCHOR_PUBLISH_OUTPUT_WITHIN_ARCHIVE");
    assert_eq!(counters.create.load(Ordering::SeqCst), 0);
    assert_eq!(counters.submit.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Helpers mirroring the live-driver integration fixtures.
// ---------------------------------------------------------------------------

fn lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn finalized_session_with_two_ballots() -> tari_cc_private_ballot_gui_core::GuiElectionSessionV1 {
    let mut session = open_session();
    for package in [
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(0, &[b"candidate-c"]),
    ] {
        session
            .intake_ballot(&package)
            .expect("ballot package must intake");
    }
    session.close().expect("session must close");
    session.mark_verified().expect("session must verify");
    session.finalize().expect("session must finalize");
    assert_eq!(session.lifecycle_state(), "FINALIZED");
    session
}

fn live_transport_binding(
    session: &tari_cc_private_ballot_gui_core::GuiElectionSessionV1,
) -> TransportArchiveBindingV1 {
    TransportArchiveBindingV1::new(
        session
            .artifacts()
            .manifest()
            .election_id()
            .as_bytes()
            .to_vec(),
        session.artifacts().manifest_hash(),
        [8; 32],
        4,
        vec![TransportArchiveBatchV1::new(
            1,
            [1; 32],
            session.transcript().accepted_count() as u64,
            false,
        )],
    )
    .expect("transport binding must construct")
}

fn write_finalized_bound_archive(
    dir: &TestDir,
    session: &tari_cc_private_ballot_gui_core::GuiElectionSessionV1,
) -> PathBuf {
    let target = dir.join("archive");
    tari_cc_private_ballot_gui_core::write_finalized_archive_v1_with_transport_binding(
        session,
        &target,
        &live_transport_binding(session),
    )
    .expect("finalized bound archive must write");
    target
}

fn read_archive_hash(archive_dir: &std::path::Path) -> ArchiveHashV1 {
    let verification = tari_cc_private_ballot_gui_core::verify_archive_directory_v1(archive_dir)
        .expect("archive must verify");
    let hex = verification
        .archive_hash_hex
        .as_deref()
        .expect("verified archive must expose its hash");
    let mut bytes = [0u8; 32];
    let src = hex.as_bytes();
    assert_eq!(src.len(), 64);
    for i in 0..32 {
        bytes[i] = (hex_value(src[i * 2]) << 4) | hex_value(src[i * 2 + 1]);
    }
    ArchiveHashV1::new(bytes)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid archive hash hex"),
    }
}

fn clone_scripted_walletd(tx: &AnchorTransactionId) -> ScriptedWalletdTransport {
    let mut walletd = ScriptedWalletdTransport::new();
    walletd.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 1,
        expires_at: 0,
    });
    walletd.set_approve_response(ScriptedWalletdResponse::Approve {
        request_id: 1,
        status: WalletdEffectiveStatusV1::Approved,
    });
    walletd.set_reject_response(ScriptedWalletdResponse::Reject {
        request_id: 1,
        status: WalletdEffectiveStatusV1::Rejected,
    });
    walletd.set_get_response(ScriptedWalletdResponse::Get {
        request_id: 1,
        status: WalletdEffectiveStatusV1::Submitted,
        transaction_id: Some(tx.clone()),
    });
    walletd.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: tx.clone(),
    });
    walletd
}

fn clone_scripted_indexer(
    payload: &AnchorLogPayloadV1,
    tx: &AnchorTransactionId,
) -> ScriptedIndexerTransport {
    let mut indexer = ScriptedIndexerTransport::new();
    indexer.set_response(ScriptedIndexerResponse::Finalized(
        receipt_scenarios::accepted_receipt(tx, &anchor_network(), payload),
    ));
    indexer
}
