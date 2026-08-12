//! Real archive-directory integration for the Ootle anchor app live driver.

#![allow(clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tari_cc_private_ballot_anchor_transport::AnchorAccountReference;
use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveHashV1, TransportArchiveBatchV1,
    TransportArchiveBindingV1,
};
use tari_cc_private_ballot_gui_core::GuiElectionSessionV1;
use tari_cc_private_ballot_gui_core::archive_writer::{
    write_archive_directory_v1_with_transport_binding,
    write_finalized_archive_v1_with_transport_binding,
};
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, AnchorLiveApprovalFactsV1, DriverError,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerTransport, TransactionRequestCreateRequest,
    TransactionRequestCreateResponse, TransactionRequestDecisionRequest,
    TransactionRequestDecisionResponse, TransactionRequestGetRequest,
    TransactionRequestGetResponse, TransactionRequestSubmitRequest,
    TransactionRequestSubmitResponse, TransportError, TransportErrorCategory,
    WalletdAnchorNetworkAdapter, WalletdWireTransport,
};

use common::{TestDir, open_session, triptych_package_bytes};

#[derive(Debug, Default)]
struct WalletdCallCounters {
    create: AtomicU64,
    approve: AtomicU64,
    reject: AtomicU64,
    get: AtomicU64,
    submit: AtomicU64,
}

impl WalletdCallCounters {
    fn create_calls(&self) -> u64 {
        self.create.load(Ordering::SeqCst)
    }

    fn submit_calls(&self) -> u64 {
        self.submit.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
struct CountingWalletdTransport {
    counters: Arc<WalletdCallCounters>,
}

impl CountingWalletdTransport {
    fn new(counters: Arc<WalletdCallCounters>) -> Self {
        Self { counters }
    }

    fn unavailable() -> TransportError {
        TransportError::from_category(TransportErrorCategory::ServiceUnavailable)
    }
}

impl WalletdWireTransport for CountingWalletdTransport {
    fn create_transaction_request(
        &mut self,
        _request: &TransactionRequestCreateRequest,
    ) -> Result<TransactionRequestCreateResponse, TransportError> {
        self.counters.create.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn approve_transaction_request(
        &mut self,
        _request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError> {
        self.counters.approve.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn reject_transaction_request(
        &mut self,
        _request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError> {
        self.counters.reject.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn get_transaction_request(
        &mut self,
        _request: &TransactionRequestGetRequest,
    ) -> Result<TransactionRequestGetResponse, TransportError> {
        self.counters.get.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }

    fn submit_transaction_request(
        &mut self,
        _request: &TransactionRequestSubmitRequest,
    ) -> Result<TransactionRequestSubmitResponse, TransportError> {
        self.counters.submit.fetch_add(1, Ordering::SeqCst);
        Err(Self::unavailable())
    }
}

fn closed_session_with_ballots() -> GuiElectionSessionV1 {
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
    session
}

fn finalized_session_with_ballots() -> GuiElectionSessionV1 {
    let mut session = closed_session_with_ballots();
    session.mark_verified().expect("session must verify");
    session.finalize().expect("session must finalize");
    assert_eq!(session.lifecycle_state(), "FINALIZED");
    session
}

fn live_transport_binding(session: &GuiElectionSessionV1) -> TransportArchiveBindingV1 {
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

fn live_config_for_archive(
    dir: &TestDir,
    session: &GuiElectionSessionV1,
    archive_hash: ArchiveHashV1,
) -> AnchorAppConfig {
    let accepted_ballot_count = session.transcript().accepted_count() as u64;
    let facts = AnchorLiveApprovalFactsV1::new(
        accepted_ballot_count,
        accepted_ballot_count,
        false,
        false,
        "seal-public-key-attested".to_owned(),
        true,
        true,
    )
    .expect("live approval facts must construct");
    let account =
        AnchorAccountReference::new("fee-account".to_owned()).expect("account must construct");
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        common::network_adapter_config(),
        account,
        session.artifacts().manifest_hash(),
        archive_hash,
        common::anchor_network(),
        dir.join("snapshot.cbor"),
        dir.join("evidence.cbor"),
        1,
        2,
        None,
        facts,
    )
}

fn write_finalized_bound_archive(
    dir: &TestDir,
    session: &GuiElectionSessionV1,
) -> (PathBuf, ArchiveHashV1) {
    let target = dir.join("archive");
    let written = write_finalized_archive_v1_with_transport_binding(
        session,
        &target,
        &live_transport_binding(session),
    )
    .expect("finalized bound archive must write");
    (target, archive_hash_from_hex(&written.archive_hash_hex))
}

fn write_legacy_bound_archive(
    dir: &TestDir,
    session: &GuiElectionSessionV1,
) -> (PathBuf, ArchiveHashV1) {
    let target = dir.join("archive");
    let written = write_archive_directory_v1_with_transport_binding(
        session,
        &target,
        &live_transport_binding(session),
    )
    .expect("legacy bound archive must write");
    (target, archive_hash_from_hex(&written.archive_hash_hex))
}

fn archive_hash_from_hex(hex: &str) -> ArchiveHashV1 {
    ArchiveHashV1::new(hash_from_hex(hex))
}

fn hash_from_hex(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        bytes[index] = (hex_value(chunk[0]) << 4) | hex_value(chunk[1]);
    }
    bytes
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("archive writer emitted invalid hex"),
    }
}

fn counted_walletd_adapter(
    counters: Arc<WalletdCallCounters>,
) -> WalletdAnchorNetworkAdapter<CountingWalletdTransport> {
    WalletdAnchorNetworkAdapter::new(
        CountingWalletdTransport::new(counters),
        common::anchor_network(),
    )
}

fn indexer_adapter() -> IndexerReceiptNetworkAdapter<ScriptedIndexerTransport> {
    IndexerReceiptNetworkAdapter::new(ScriptedIndexerTransport::new())
}

fn expect_new_live_error(
    config: AnchorAppConfig,
    archive_dir: &Path,
) -> (DriverError, Arc<WalletdCallCounters>) {
    let counters = Arc::new(WalletdCallCounters::default());
    let result: Result<
        AnchorAppDriver<CountingWalletdTransport, ScriptedIndexerTransport>,
        DriverError,
    > = AnchorAppDriver::new_live(
        config,
        counted_walletd_adapter(counters.clone()),
        indexer_adapter(),
        archive_dir,
    );
    let error = match result {
        Ok(_) => panic!("live driver construction must fail"),
        Err(error) => error,
    };
    (error, counters)
}

fn flip_first_byte(path: &Path) {
    let mut bytes = std::fs::read(path).expect("archive file must read");
    bytes[0] ^= 1;
    std::fs::write(path, bytes).expect("archive file mutation must write");
}

#[test]
fn matching_finalized_archive_allows_live_driver_construction() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("live-driver-finalized-match");
    let (archive_dir, archive_hash) = write_finalized_bound_archive(&dir, &session);

    let counters = Arc::new(WalletdCallCounters::default());
    let driver = AnchorAppDriver::new_live(
        live_config_for_archive(&dir, &session, archive_hash),
        counted_walletd_adapter(counters.clone()),
        indexer_adapter(),
        &archive_dir,
    )
    .expect("matching finalized archive must construct live driver");

    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
    assert_eq!(counters.create_calls(), 0);
    assert_eq!(counters.submit_calls(), 0);

    let restore_counters = Arc::new(WalletdCallCounters::default());
    let restored = AnchorAppDriver::restore_live(
        live_config_for_archive(&dir, &session, archive_hash),
        counted_walletd_adapter(restore_counters.clone()),
        indexer_adapter(),
        &archive_dir,
    )
    .expect("matching finalized archive must restore live driver");

    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
    assert_eq!(restore_counters.create_calls(), 0);
    assert_eq!(restore_counters.submit_calls(), 0);
}

#[test]
fn mismatched_archive_hash_rejects_before_prepare() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("live-driver-archive-mismatch");
    let (archive_dir, _archive_hash) = write_finalized_bound_archive(&dir, &session);
    let config = live_config_for_archive(&dir, &session, ArchiveHashV1::new([0xA5; 32]));

    let (error, counters) = expect_new_live_error(config, &archive_dir);

    assert_eq!(error, DriverError::RuntimeArchiveBindingMismatch);
    assert_eq!(counters.create_calls(), 0);
    assert_eq!(counters.submit_calls(), 0);
}

#[test]
fn legacy_archive_rejects_before_prepare() {
    let session = closed_session_with_ballots();
    let dir = TestDir::new("live-driver-legacy-archive");
    let (archive_dir, archive_hash) = write_legacy_bound_archive(&dir, &session);
    let config = live_config_for_archive(&dir, &session, archive_hash);

    let (error, counters) = expect_new_live_error(config, &archive_dir);

    assert_eq!(error, DriverError::RuntimeArchiveVerificationFailed);
    assert_eq!(counters.create_calls(), 0);
    assert_eq!(counters.submit_calls(), 0);
}

#[test]
fn mutated_archive_rejects_before_prepare() {
    let session = finalized_session_with_ballots();
    let dir = TestDir::new("live-driver-mutated-archive");
    let (archive_dir, archive_hash) = write_finalized_bound_archive(&dir, &session);
    let config = live_config_for_archive(&dir, &session, archive_hash);
    flip_first_byte(&archive_dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH));

    let (error, counters) = expect_new_live_error(config, &archive_dir);

    assert_eq!(error, DriverError::RuntimeArchiveVerificationFailed);
    assert_eq!(counters.create_calls(), 0);
    assert_eq!(counters.submit_calls(), 0);
}
