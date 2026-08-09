//! Shared deterministic fixtures for the gui-core test suite.
//!
//! Every helper is offline and deterministic. Real Triptych proofs are built
//! from fixed scalar fixtures, exactly as the existing CLI integration tests
//! do. Unused-helper warnings are allowed, matching the workspace test
//! convention.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use curve25519_dalek_v4::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_v4::scalar::Scalar;
use tari_cc_private_ballot_anchor::{OotleAnchorRecordV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorRequestId,
    AnchorTransactionId,
};
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, AnchorEvidenceRecordV1, ArchiveProofInputs,
    DriverRunOutcome, OperatorDecision, TerminalEvidenceInputs, write_evidence_atomic,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleRecoverySnapshot, PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, IndexerReceiptNetworkAdapter, NetworkAdapterConfig,
    ScriptedIndexerResponse, ScriptedIndexerTransport, ScriptedWalletdResponse,
    ScriptedWalletdTransport, WalletdAnchorNetworkAdapter, WalletdEndpoint,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, AnchorReceiptQueryV1,
    receipt_scenarios,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdAnchorBindingV1, WalletdAnchorSnapshotV1,
    WalletdEffectiveStatusV1, WalletdFeeComponentRef, WalletdRequestDecisionV1, WalletdRequestId,
    WalletdSealSignerRef, WalletdSubmissionStateV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, ManifestHash, PROTOCOL_VERSION_V1};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
};

pub const SECRET_SCALARS: [u64; 3] = [7, 11, 13];

/// One deterministic voter keypair fixture (secret scalar + public point).
pub struct VoterFixture {
    pub secret_bytes: [u8; 32],
    pub public_bytes: [u8; 32],
}

pub fn voter(scalar: u64) -> VoterFixture {
    let scalar_value = Scalar::from(scalar);
    let public = (RISTRETTO_BASEPOINT_POINT * scalar_value)
        .compress()
        .to_bytes();
    VoterFixture {
        secret_bytes: scalar_value.to_bytes(),
        public_bytes: public,
    }
}

pub fn voters() -> Vec<VoterFixture> {
    SECRET_SCALARS.iter().map(|scalar| voter(*scalar)).collect()
}

/// Canonical registry bytes for the three deterministic voters.
pub fn registry_bytes() -> Vec<u8> {
    let mut writer = tari_cc_private_ballot_protocol::CanonicalCborWriter::new();
    let mut keys: Vec<[u8; 32]> = voters().iter().map(|voter| voter.public_bytes).collect();
    keys.sort_unstable();
    assert!(writer.write_array_len(keys.len()).is_ok());
    for key in keys {
        assert!(writer.write_byte_string(&key).is_ok());
    }
    writer.into_bytes()
}

pub fn registry() -> RegistrySnapshot {
    match RegistrySnapshot::from_canonical_cbor(&registry_bytes()) {
        Ok(registry) => registry,
        Err(_) => panic!("fixture registry must decode"),
    }
}

pub fn candidate_id(bytes: &[u8]) -> CandidateId {
    match CandidateId::new(bytes.to_vec()) {
        Ok(id) => id,
        Err(_) => panic!("fixture candidate ID must be valid"),
    }
}

pub fn candidate_set() -> CandidateSet {
    let definitions = vec![
        CandidateDefinition::new(candidate_id(b"candidate-a"), "Candidate A".to_owned()),
        CandidateDefinition::new(candidate_id(b"candidate-b"), "Candidate B".to_owned()),
        CandidateDefinition::new(candidate_id(b"candidate-c"), "Candidate C".to_owned()),
    ];
    let definitions: Vec<CandidateDefinition> = definitions
        .into_iter()
        .map(|candidate| match candidate {
            Ok(candidate) => candidate,
            Err(_) => panic!("fixture candidate must be valid"),
        })
        .collect();
    match CandidateSet::new(definitions) {
        Ok(candidates) => candidates,
        Err(_) => panic!("fixture candidate set must be valid"),
    }
}

pub fn candidate_bytes() -> Vec<u8> {
    match candidate_set().to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("fixture candidate set must encode"),
    }
}

pub fn approval_limits() -> ApprovalLimits {
    match ApprovalLimits::new(1, 2, false) {
        Ok(limits) => limits,
        Err(_) => panic!("fixture approval limits must be valid"),
    }
}

/// Builds a manifest bound to the canonical registry and candidate set.
pub fn manifest_with(
    election_id: &[u8],
    proof_suite_id: &str,
    limits: ApprovalLimits,
) -> ElectionManifestV1 {
    let provider = Blake3HashProviderV1;
    let registry = registry();
    let candidates = candidate_set();
    let registry_commitment = match registry.canonical_commitment(&provider) {
        Ok(commitment) => commitment,
        Err(_) => panic!("fixture registry commitment must derive"),
    };
    let candidate_set_commitment = match candidates.canonical_commitment(&provider) {
        Ok(commitment) => commitment,
        Err(_) => panic!("fixture candidate commitment must derive"),
    };
    let election_id = match ElectionId::new(election_id.to_vec()) {
        Ok(id) => id,
        Err(_) => panic!("fixture election ID must be valid"),
    };
    match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: proof_suite_id.to_owned(),
        approval_limits: limits,
        governance_source_revision: "gui-core-test-revision-1".to_owned(),
    }) {
        Ok(manifest) => manifest,
        Err(_) => panic!("fixture manifest must be valid"),
    }
}

pub fn manifest() -> ElectionManifestV1 {
    manifest_with(
        b"gui-core-test-election",
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        approval_limits(),
    )
}

/// Builds a manifest bound to the canonical registry and candidate set with a
/// custom governance source revision (Slice 5A8 voter-confirmation fixtures).
pub fn manifest_with_revision(revision: &str) -> ElectionManifestV1 {
    let provider = Blake3HashProviderV1;
    let registry = registry();
    let candidates = candidate_set();
    let registry_commitment = match registry.canonical_commitment(&provider) {
        Ok(commitment) => commitment,
        Err(_) => panic!("fixture registry commitment must derive"),
    };
    let candidate_set_commitment = match candidates.canonical_commitment(&provider) {
        Ok(commitment) => commitment,
        Err(_) => panic!("fixture candidate commitment must derive"),
    };
    let election_id = match ElectionId::new(b"gui-core-test-election".to_vec()) {
        Ok(id) => id,
        Err(_) => panic!("fixture election ID must be valid"),
    };
    match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: revision.to_owned(),
    }) {
        Ok(manifest) => manifest,
        Err(_) => panic!("fixture manifest with revision must be valid"),
    }
}

/// Loads the canonical validated artifact triple with a custom governance
/// source revision (Slice 5A8 voter-confirmation fixtures).
pub fn artifacts_with_revision(
    revision: &str,
) -> tari_cc_private_ballot_gui_core::GuiElectionArtifactsV1 {
    let manifest = manifest_with_revision(revision);
    let manifest_bytes = match manifest.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("fixture manifest with revision must encode"),
    };
    match tari_cc_private_ballot_gui_core::GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes,
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(artifacts) => artifacts,
        Err(error) => panic!("fixture artifacts with revision must load: {error}"),
    }
}

pub fn manifest_bytes() -> Vec<u8> {
    match manifest().to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("fixture manifest must encode"),
    }
}

/// Loads the canonical validated artifact triple.
pub fn artifacts() -> tari_cc_private_ballot_gui_core::GuiElectionArtifactsV1 {
    match tari_cc_private_ballot_gui_core::GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes(),
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(artifacts) => artifacts,
        Err(error) => panic!("fixture artifacts must load: {error}"),
    }
}

/// Returns an opened organizer session over the canonical election.
pub fn open_session() -> tari_cc_private_ballot_gui_core::GuiElectionSessionV1 {
    let session = tari_cc_private_ballot_gui_core::GuiElectionSessionV1::new(artifacts());
    let mut session = match session {
        Ok(session) => session,
        Err(error) => panic!("fixture session must construct: {error}"),
    };
    if let Err(error) = session.open() {
        panic!("fixture session must open: {error}");
    }
    session
}

/// Returns an opened organizer session over the canonical election with a
/// custom governance source revision (Slice 5A8 archive governance tests).
pub fn open_session_with_revision(
    revision: &str,
) -> tari_cc_private_ballot_gui_core::GuiElectionSessionV1 {
    let session = tari_cc_private_ballot_gui_core::GuiElectionSessionV1::new(
        artifacts_with_revision(revision),
    );
    let mut session = match session {
        Ok(session) => session,
        Err(error) => panic!("fixture session must construct: {error}"),
    };
    if let Err(error) = session.open() {
        panic!("fixture session must open: {error}");
    }
    session
}

/// Builds a real Triptych ballot package for `voter_index` selecting
/// `selections` under the canonical manifest.
pub fn triptych_package_bytes(voter_index: usize, selections: &[&[u8]]) -> Vec<u8> {
    package_bytes_for(&manifest(), voter_index, selections)
}

pub fn package_bytes_for(
    manifest: &ElectionManifestV1,
    voter_index: usize,
    selections: &[&[u8]],
) -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let candidates = candidate_set();
    let registry = registry();
    let selection_ids: Vec<CandidateId> = selections.iter().map(|id| candidate_id(id)).collect();
    let payload =
        match ApprovalBallotPayload::new(selection_ids, &candidates, manifest.approval_limits()) {
            Ok(payload) => payload,
            Err(_) => panic!("fixture payload must be valid"),
        };
    let verifier = match build_tari_triptych_verifier_from_registry_v1(&registry, &provider) {
        Ok(verifier) => verifier,
        Err(_) => panic!("fixture verifier must construct"),
    };
    let statement = match reconstruct_approval_proof_statement(manifest, &payload, &provider) {
        Ok(statement) => statement,
        Err(_) => panic!("fixture statement must reconstruct"),
    };
    let secret =
        match TariTriptychSecretKeyV1::from_canonical_bytes(voters()[voter_index].secret_bytes) {
            Ok(secret) => secret,
            Err(_) => panic!("fixture secret must be canonical"),
        };
    let proof = match prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) {
        Ok(proof) => proof,
        Err(_) => panic!("fixture proof must construct"),
    };
    let manifest_hash = match manifest.canonical_hash(&provider) {
        Ok(hash) => hash,
        Err(_) => panic!("fixture manifest hash must derive"),
    };
    let package = match BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: manifest.proof_suite_id().to_owned(),
        proof,
        payload,
    }) {
        Ok(package) => package,
        Err(_) => panic!("fixture package must be valid"),
    };
    match package.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("fixture package must encode"),
    }
}

/// A unique temporary directory that is removed on drop.
pub struct TestDir {
    path: PathBuf,
}

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TestDir {
    pub fn new(label: &str) -> Self {
        let id = UNIQUE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("gui-core-test-{}-{label}-{id}", std::process::id()));
        if let Err(error) = std::fs::create_dir_all(&path) {
            panic!("test temp dir must be creatable: {error}");
        }
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Anchor artifact fixtures (mirror the anchor-app test constructors, which
// use only public APIs).
// ---------------------------------------------------------------------------

pub const ANCHOR_MANIFEST_BYTE: u8 = 0x11;
pub const ANCHOR_ARCHIVE_BYTE: u8 = 0x22;
pub const ANCHOR_TX_HEX: &str = "4444444444444444444444444444444444444444444444444444444444444444";

pub fn anchor_network() -> OotleNetworkIdV1 {
    match OotleNetworkIdV1::new("esmeralda".to_owned()) {
        Ok(network) => network,
        Err(_) => panic!("fixture network must be valid"),
    }
}

pub fn anchor_manifest_hash() -> ManifestHash {
    ManifestHash::new([ANCHOR_MANIFEST_BYTE; 32])
}

pub fn anchor_archive_hash() -> ArchiveHashV1 {
    ArchiveHashV1::new([ANCHOR_ARCHIVE_BYTE; 32])
}

pub fn anchor_digest() -> tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1 {
    let record = OotleAnchorRecordV1::new(
        anchor_network(),
        anchor_manifest_hash(),
        anchor_archive_hash(),
    );
    match record.canonical_hash(&Blake3HashProviderV1) {
        Ok(digest) => digest,
        Err(_) => panic!("fixture anchor digest must derive"),
    }
}

pub fn anchor_transaction_id() -> AnchorTransactionId {
    match AnchorTransactionId::new(ANCHOR_TX_HEX.to_owned()) {
        Ok(id) => id,
        Err(_) => panic!("fixture transaction id must be valid"),
    }
}

pub fn anchor_binding() -> WalletdAnchorBindingV1 {
    let account = match AnchorAccountReference::new("fee-account".to_owned()) {
        Ok(account) => account,
        Err(_) => panic!("fixture account must be valid"),
    };
    WalletdAnchorBindingV1::new(
        anchor_network(),
        account,
        anchor_digest(),
        AnchorLogPayloadV1::from_digest(anchor_digest()),
        AnchorMaxFeeV1::from_units(1_000),
        OotleAnchorInspectionFingerprintV1::new([0x55; 32]),
    )
}

pub fn anchor_request_id() -> AnchorRequestId {
    match AnchorRequestId::new("anchor-request-001".to_owned()) {
        Ok(id) => id,
        Err(_) => panic!("fixture request id must be valid"),
    }
}

pub fn walletd_snapshot(
    decision: WalletdRequestDecisionV1,
    submission: WalletdSubmissionStateV1,
    transaction_id: Option<AnchorTransactionId>,
    status: Option<WalletdEffectiveStatusV1>,
) -> WalletdAnchorSnapshotV1 {
    WalletdAnchorSnapshotV1::new(
        anchor_request_id(),
        WalletdRequestId::from_walletd(1),
        anchor_binding(),
        decision,
        submission,
        transaction_id,
        status,
        0,
        1,
        None,
    )
}

pub fn submitted_handle() -> SubmittedWalletdAnchorRequestV1 {
    SubmittedWalletdAnchorRequestV1::new(
        anchor_request_id(),
        WalletdRequestId::from_walletd(1),
        anchor_transaction_id(),
        anchor_binding(),
    )
}

/// A valid `Prepared`-phase recovery snapshot.
pub fn prepared_snapshot() -> AnchorLifecycleRecoverySnapshot {
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snapshot(
            WalletdRequestDecisionV1::Prepared,
            WalletdSubmissionStateV1::NotSubmitted,
            None,
            None,
        )],
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::Prepared,
        None,
    )
}

/// A valid `FinalizedAccept`-phase recovery snapshot.
pub fn finalized_accept_snapshot() -> AnchorLifecycleRecoverySnapshot {
    let query = AnchorReceiptQueryV1::from_submitted(&submitted_handle());
    let receipt = AnchorReceiptQuerySnapshotV1::new(
        query,
        AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
        Some(tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1::Accepted),
        true,
        1,
        None,
    );
    AnchorLifecycleRecoverySnapshot::new(
        vec![walletd_snapshot(
            WalletdRequestDecisionV1::Approved,
            WalletdSubmissionStateV1::Submitted,
            Some(anchor_transaction_id()),
            Some(WalletdEffectiveStatusV1::Submitted),
        )],
        vec![receipt],
        Some(submitted_handle()),
        PollingPolicy::from_consumed(8, 5),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    )
}

/// A semantically impossible snapshot: terminal phase with no content.
pub fn impossible_snapshot() -> AnchorLifecycleRecoverySnapshot {
    AnchorLifecycleRecoverySnapshot::new(
        Vec::new(),
        Vec::new(),
        None,
        PollingPolicy::new(8),
        UnifiedAnchorLifecyclePhase::FinalizedAccept,
        None,
    )
}

pub fn network_adapter_config() -> NetworkAdapterConfig {
    let walletd_endpoint = match WalletdEndpoint::parse("http://127.0.0.1:12009") {
        Ok(endpoint) => endpoint,
        Err(_) => panic!("fixture walletd endpoint must parse"),
    };
    let indexer_endpoint = match IndexerEndpoint::parse("http://127.0.0.1:12500") {
        Ok(endpoint) => endpoint,
        Err(_) => panic!("fixture indexer endpoint must parse"),
    };
    let fee_component_raw = "component_".to_owned() + &"11".repeat(32);
    let fee_component = match WalletdFeeComponentRef::parse(&fee_component_raw) {
        Ok(component) => component,
        Err(_) => panic!("fixture fee component must parse"),
    };
    match NetworkAdapterConfig::new(
        anchor_network(),
        walletd_endpoint,
        indexer_endpoint,
        fee_component,
        WalletdSealSignerRef::AccountKey { index: 0 },
        AnchorMaxFeeV1::from_units(1_000),
        Some(30),
        8,
        None,
    ) {
        Ok(config) => config,
        Err(_) => panic!("fixture network adapter config must construct"),
    }
}

/// Writes a valid canonical anchor config into `dir` and returns its path.
pub fn write_anchor_config(dir: &Path) -> PathBuf {
    let snapshot_path = dir.join("snapshot.cbor");
    let evidence_path = dir.join("evidence.cbor");
    let account = match AnchorAccountReference::new("fee-account".to_owned()) {
        Ok(account) => account,
        Err(_) => panic!("fixture account must be valid"),
    };
    let config = AnchorAppConfig::new(
        network_adapter_config(),
        account,
        anchor_manifest_hash(),
        anchor_archive_hash(),
        anchor_network(),
        snapshot_path,
        evidence_path,
        1,
        2,
        None,
    );
    let path = dir.join("config.cbor");
    if config.write_canonical_file(&path).is_err() {
        panic!("fixture config must write");
    }
    path
}

/// Writes a valid terminal evidence record into `dir` and returns its path.
pub fn write_anchor_evidence(dir: &Path) -> PathBuf {
    let inputs = ArchiveProofInputs::new(
        anchor_network(),
        anchor_manifest_hash(),
        anchor_archive_hash(),
        anchor_digest(),
    );
    let record = match AnchorEvidenceRecordV1::from_terminal_outcome(
        &inputs,
        TerminalEvidenceInputs::RejectedByApprover,
        &[0x66; 32],
    ) {
        Ok(record) => record,
        Err(_) => panic!("fixture evidence must construct"),
    };
    let path = dir.join("evidence.cbor");
    if write_evidence_atomic(&path, &record).is_err() {
        panic!("fixture evidence must write");
    }
    path
}

/// Creates genuine deterministic `FINALIZED_ACCEPT` Phase 4 evidence for the
/// supplied exact archive binding. The scripted adapters never contact a
/// network; they exercise the existing Phase 4 driver and evidence constructor.
pub fn write_accepted_anchor_evidence_for(
    dir: &Path,
    manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
) -> PathBuf {
    let anchor_digest = OotleAnchorRecordV1::new(anchor_network(), manifest_hash, archive_hash)
        .canonical_hash(&Blake3HashProviderV1)
        .unwrap_or_else(|_| panic!("anchor digest must derive"));
    let account = AnchorAccountReference::new("fee-account".to_owned())
        .unwrap_or_else(|_| panic!("anchor account must construct"));
    let config = AnchorAppConfig::new(
        network_adapter_config(),
        account,
        manifest_hash,
        archive_hash,
        anchor_network(),
        dir.join("accepted-snapshot.cbor"),
        dir.join("accepted-evidence.cbor"),
        1,
        1,
        None,
    );
    let transaction_id = anchor_transaction_id();
    let mut walletd = ScriptedWalletdTransport::new();
    walletd.set_create_response(ScriptedWalletdResponse::Create { request_id: 1, expires_at: 0 });
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
        transaction_id: Some(transaction_id.clone()),
    });
    walletd.set_submit_response(ScriptedWalletdResponse::Submit { transaction_id: transaction_id.clone() });
    let payload = AnchorLogPayloadV1::from_digest(anchor_digest);
    let mut indexer = ScriptedIndexerTransport::new();
    indexer.set_response(ScriptedIndexerResponse::Finalized(receipt_scenarios::accepted_receipt(
        &transaction_id,
        &anchor_network(),
        &payload,
    )));
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, anchor_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = AnchorAppDriver::new(config, walletd_adapter, indexer_adapter)
        .unwrap_or_else(|_| panic!("anchor driver must construct"));
    let evidence = match driver.run(OperatorDecision::Approve) {
        Ok(DriverRunOutcome::FinalizedAccept(evidence)) => evidence,
        _ => panic!("scripted accepted anchor must finalize"),
    };
    let path = driver.evidence_path().to_owned();
    write_evidence_atomic(&path, &evidence)
        .unwrap_or_else(|_| panic!("accepted evidence must write"));
    path
}
