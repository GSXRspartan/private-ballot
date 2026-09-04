//! Scripted V2 live-lifecycle tests (manual approval, submit, receipt polling,
//! recovery, and failure evidence).
//!
//! These drive [`run_v2_live_anchor_step_with_transports`] with the offline
//! [`ScriptedWalletdTransport`]/[`ScriptedIndexerTransport`] seams — no socket
//! is opened and nothing is published. Each test advances one durable step at a
//! time (the sidecar is reloaded from disk on every call), reconfiguring the
//! scripted responses between steps exactly as a real walletd/indexer would
//! change state.

#![allow(clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_DIGEST_KEY_V2, ANCHOR_EVENT_ELECTION_ID_KEY_V2, ANCHOR_EVENT_NETWORK_KEY_V2,
    ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V2, ANCHOR_TEMPLATE_MODULE_V2,
    AnchorEventPayloadV3, AnchorEventProofV2, AnchorFinalStatusV1, AnchorReceiptSourceKindV1,
    AnchorReceiptV1, AnchorTemplateBindingV2, AnchorTransactionId,
};
use tari_cc_private_ballot_archive::{TransportArchiveBatchV1, TransportArchiveBindingV1};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiLiveAnchorV2RequestV1, GuiV2LiveAnchorStepRequestV1,
    GuiV2LiveAnchorStepResultV1, __set_v2_anchor_sidecar_root_test_override,
    build_v2_public_payload_from_verified_archive_v1, inspect_v2_live_anchor_state,
    read_v2_public_anchor_evidence_file, run_v2_live_anchor_recovery_step_with_indexer,
    run_v2_live_anchor_step_with_transports, v2_evidence_sidecar_path, v2_failure_sidecar_path,
    v2_lifecycle_sidecar_path,
};
use tari_cc_private_ballot_ootle_anchor_adapter::inspect_detected_fee_bearing_v2_anchor_transaction;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerResponse, ScriptedIndexerTransport,
    ScriptedWalletdResponse, ScriptedWalletdTransport, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1;

use common::{TestDir, open_session, triptych_package_bytes};

const V2_ARTIFACT_DIGEST: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const REQUEST_ID: i32 = 42;
/// A deterministic 64-lowercase-hex Ootle transaction id for the sealed submit.
const TX_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn finalized_bound_archive(dir: &TestDir) -> PathBuf {
    ensure_test_sidecar_root();
    let session = finalized_session();
    let target = dir.join("archive");
    tari_cc_private_ballot_gui_core::write_finalized_archive_v1_with_transport_binding(
        &session,
        &target,
        &live_transport_binding(&session),
    )
    .expect("finalized bound archive must write");
    target
}

fn finalized_session() -> GuiElectionSessionV1 {
    let mut session = open_session();
    for package in [
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(2, &[b"candidate-a"]),
    ] {
        session.intake_ballot(&package).expect("intake");
    }
    session.close().expect("close");
    session.mark_verified().expect("verify");
    session.finalize().expect("finalize");
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
    .expect("binding")
}

fn v2_request(archive: &Path) -> GuiLiveAnchorV2RequestV1 {
    GuiLiveAnchorV2RequestV1 {
        archive_directory: archive.to_string_lossy().into_owned(),
        network: "esmeralda".to_owned(),
        template_address: format!("template_{}", "44".repeat(32)),
        template_module: "tari_private_ballot_anchor_v2".to_owned(),
        template_function: "publish_anchor_v2".to_owned(),
        template_event_topic:
            "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2".to_owned(),
        template_artifact_digest_hex: V2_ARTIFACT_DIGEST.to_owned(),
    }
}

fn decode32(hex: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    <[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes")
}

fn network() -> OotleNetworkIdV1 {
    OotleNetworkIdV1::new("esmeralda".to_owned()).expect("network")
}

/// A test harness holding the archive, the verified public payload, the exact V2
/// deployment binding, and the two scripted adapters.
struct Harness {
    _dir: TestDir,
    archive: PathBuf,
    built: tari_cc_private_ballot_gui_core::GuiLiveAnchorV2ResultV1,
    binding: AnchorTemplateBindingV2,
    walletd: WalletdAnchorNetworkAdapter<ScriptedWalletdTransport>,
    indexer: IndexerReceiptNetworkAdapter<ScriptedIndexerTransport>,
}

impl Harness {
    fn new(label: &str) -> Self {
        ensure_test_sidecar_root();
        let dir = TestDir::new(label);
        let archive = finalized_bound_archive(&dir);
        let built = build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive))
            .expect("V2 build");
        let binding = AnchorTemplateBindingV2::new(
            built.template_address.clone(),
            built.template_module.clone(),
            built.template_function.clone(),
            built.template_event_topic.clone(),
            decode32(&built.template_artifact_digest_hex),
        )
        .expect("V2 binding");
        let walletd = WalletdAnchorNetworkAdapter::new(ScriptedWalletdTransport::new(), network());
        let indexer = IndexerReceiptNetworkAdapter::new(ScriptedIndexerTransport::new());
        Self {
            _dir: dir,
            archive,
            built,
            binding,
            walletd,
            indexer,
        }
    }

    fn request(&self, decision: &str) -> GuiV2LiveAnchorStepRequestV1 {
        GuiV2LiveAnchorStepRequestV1 {
            archive_directory: self.archive.to_string_lossy().into_owned(),
            payload_hex: self.built.payload_hex.clone(),
            expected_digest_hex: self.built.v2_anchor_digest_hex.clone(),
            fee_component: format!("component_{}", "11".repeat(32)),
            seal_signer_kind: "account".to_owned(),
            seal_signer_id: "0".to_owned(),
            max_fee: 1000,
            max_epoch_delta: 10,
            walletd_endpoint: "http://127.0.0.1:5100".to_owned(),
            indexer_endpoint: "http://127.0.0.1:18300".to_owned(),
            use_walletd_auth: false,
            decision: decision.to_owned(),
        }
    }

    fn step(&mut self, decision: &str) -> GuiV2LiveAnchorStepResultV1 {
        run_v2_live_anchor_step_with_transports(
            &self.request(decision),
            &self.binding,
            &mut self.walletd,
            &mut self.indexer,
        )
        .expect("lifecycle step")
    }

    fn set_get(
        &mut self,
        status: WalletdEffectiveStatusV1,
        transaction_id: Option<AnchorTransactionId>,
    ) {
        self.walletd
            .transport_mut()
            .set_get_response(ScriptedWalletdResponse::Get {
                request_id: REQUEST_ID,
                status,
                transaction_id,
            });
    }

    /// Runs the offline prepare step and asserts it created a WAITING snapshot.
    fn prepare(&mut self) -> GuiV2LiveAnchorStepResultV1 {
        self.walletd
            .transport_mut()
            .set_dry_run_response(ScriptedWalletdResponse::DryRun {
                required_fees: 1_110,
            });
        self.walletd
            .transport_mut()
            .set_create_response(ScriptedWalletdResponse::Create {
                request_id: REQUEST_ID,
                expires_at: 0,
            });
        let result = self.step("none");
        assert_eq!(result.phase, "WAITING_FOR_WALLET_APPROVAL");
        assert!(result.waiting_for_wallet_approval);
        assert_eq!(result.estimated_required_fee, Some(1_110));
        assert_eq!(result.selected_max_fee, Some(1_221));
        assert_eq!(self.walletd.transport().create_calls(), 1);
        assert!(lifecycle_sidecar(&self.archive).exists());
        result
    }

    /// The verified, finalized receipt that matches the built payload exactly.
    fn finalized_receipt(&self) -> AnchorReceiptV1 {
        self.finalized_receipt_with_topic(self.binding.canonical_receipt_event_topic())
    }

    fn finalized_receipt_with_topic(&self, topic: String) -> AnchorReceiptV1 {
        let payload = AnchorEventPayloadV3::new(
            decode32(&self.built.v2_anchor_digest_hex),
            self.built.network.clone(),
            self.built.election_id.clone(),
            self.built.public_summary_json.clone(),
        )
        .expect("event payload");
        let proof = AnchorEventProofV2::new(
            self.binding.template_address().to_owned(),
            topic,
            vec![
                (ANCHOR_EVENT_DIGEST_KEY_V2.to_owned(), payload.digest_hex()),
                (
                    ANCHOR_EVENT_NETWORK_KEY_V2.to_owned(),
                    payload.network().to_owned(),
                ),
                (
                    ANCHOR_EVENT_ELECTION_ID_KEY_V2.to_owned(),
                    payload.election_id().to_owned(),
                ),
                (
                    ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2.to_owned(),
                    payload.public_summary().to_owned(),
                ),
            ],
            0,
            1,
            [0; 32],
        )
        .expect("event proof");
        AnchorReceiptV1::new(
            AnchorTransactionId::new(TX_HEX.to_owned()).expect("tx id"),
            network(),
            AnchorFinalStatusV1::Accepted,
            vec![],
            None,
            Some(1),
            AnchorReceiptSourceKindV1::Walletd,
        )
        .with_event_proofs_v2(vec![proof])
    }

    /// Advances a WAITING snapshot through manual approval to APPROVED.
    fn approve(&mut self) -> GuiV2LiveAnchorStepResultV1 {
        self.set_get(WalletdEffectiveStatusV1::Pending, None);
        self.walletd
            .transport_mut()
            .set_approve_response(ScriptedWalletdResponse::Approve {
                request_id: REQUEST_ID,
                status: WalletdEffectiveStatusV1::Approved,
            });
        let result = self.step("approve");
        assert_eq!(result.phase, "APPROVED");
        result
    }

    /// Advances an APPROVED snapshot through submit to POLLING_RECEIPT.
    fn submit(&mut self) -> GuiV2LiveAnchorStepResultV1 {
        self.set_get(WalletdEffectiveStatusV1::Approved, None);
        self.walletd
            .transport_mut()
            .set_submit_response(ScriptedWalletdResponse::Submit {
                transaction_id: AnchorTransactionId::new(TX_HEX.to_owned()).expect("tx id"),
            });
        let result = self.step("none");
        assert_eq!(result.phase, "POLLING_RECEIPT");
        assert_eq!(result.transaction_id.as_deref(), Some(TX_HEX));
        result
    }
}

/// Redirects the app-owned V2 sidecar root to a per-process temp directory so
/// integration tests never touch the real `%LOCALAPPDATA%\Private Ballot\...`
/// storage. The redirect is registered once for the lifetime of the test
/// binary through the process-wide `OnceLock` in production code; each test's
/// archive path is unique, so their sanitized sidecar keys never collide
/// within that shared root.
fn ensure_test_sidecar_root() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir()
            .join(format!("gui-core-test-v2-sidecars-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        __set_v2_anchor_sidecar_root_test_override(root);
    });
}

fn lifecycle_sidecar(archive: &Path) -> PathBuf {
    ensure_test_sidecar_root();
    v2_lifecycle_sidecar_path(archive).expect("lifecycle path")
}

fn evidence_sidecar(archive: &Path) -> PathBuf {
    ensure_test_sidecar_root();
    v2_evidence_sidecar_path(archive).expect("evidence path")
}

fn failure_sidecar(archive: &Path) -> PathBuf {
    ensure_test_sidecar_root();
    v2_failure_sidecar_path(archive).expect("failure path")
}

#[test]
fn read_v2_evidence_file_projects_valid_public_json() {
    let mut h = Harness::new("v2life-read-evidence");
    h.finalize_to_verified();

    let evidence =
        read_v2_public_anchor_evidence_file(&evidence_sidecar(&h.archive)).expect("read evidence");

    assert_eq!(
        evidence.schema,
        "TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_EVIDENCE_V1"
    );
    assert_eq!(
        evidence.archive_directory,
        h.archive.to_string_lossy().into_owned()
    );
    assert_eq!(evidence.transaction_id, TX_HEX);
    assert_eq!(evidence.network, "esmeralda");
    assert_eq!(evidence.template_address, h.built.template_address);
    assert_eq!(evidence.template_module, h.built.template_module);
    assert_eq!(evidence.template_function, h.built.template_function);
    assert_eq!(evidence.template_topic, h.built.template_event_topic);
    assert_eq!(
        evidence.template_artifact_digest_hex,
        h.built.template_artifact_digest_hex
    );
    assert_eq!(evidence.anchor_digest_hex, h.built.v2_anchor_digest_hex);
    assert_eq!(evidence.payload_hex, h.built.payload_hex);
}

#[test]
fn read_v2_evidence_file_rejects_malformed_json() {
    let dir = TestDir::new("v2life-read-malformed-json");
    let path = dir.join("bad.v2-anchor-evidence.json");
    std::fs::write(&path, b"{not valid json").expect("write malformed json");

    let error =
        read_v2_public_anchor_evidence_file(&path).expect_err("malformed JSON must fail closed");

    assert_eq!(error.code(), "GUI_ANCHOR_V2_EVIDENCE_INVALID");
}

#[test]
fn read_v2_evidence_file_rejects_unsupported_schema() {
    let mut h = Harness::new("v2life-read-unsupported-schema");
    h.finalize_to_verified();
    let path = evidence_sidecar(&h.archive);
    let text = std::fs::read_to_string(&path).expect("read evidence");
    let tampered = text.replace(
        "TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_EVIDENCE_V1",
        "TARI_CC_PRIVATE_BALLOT_V2_ANCHOR_EVIDENCE_V999",
    );
    assert_ne!(text, tampered, "schema must be present");
    std::fs::write(&path, tampered).expect("write unsupported schema");

    let error = read_v2_public_anchor_evidence_file(&path)
        .expect_err("unsupported schema must fail closed");

    assert_eq!(error.code(), "GUI_ANCHOR_V2_EVIDENCE_SCHEMA_UNSUPPORTED");
}

#[test]
fn read_v2_evidence_file_rejects_malformed_payload_hex() {
    let mut h = Harness::new("v2life-read-bad-payload-hex");
    h.finalize_to_verified();
    let path = evidence_sidecar(&h.archive);
    let text = std::fs::read_to_string(&path).expect("read evidence");
    let tampered = text.replace(
        &format!("\"payload_hex\": \"{}\"", h.built.payload_hex),
        "\"payload_hex\": \"not-hex\"",
    );
    assert_ne!(text, tampered, "payload_hex must be present");
    std::fs::write(&path, tampered).expect("write malformed payload_hex");

    let error = read_v2_public_anchor_evidence_file(&path)
        .expect_err("malformed payload hex must fail closed");

    assert_eq!(error.code(), "GUI_ANCHOR_V2_EVIDENCE_HEX_INVALID");
}

#[test]
fn prepare_creates_waiting_snapshot_and_never_approves() {
    let mut h = Harness::new("v2life-prepare");
    h.prepare();
    // Preparation must not approve or submit — the wallet gate is untouched.
    assert_eq!(h.walletd.transport().approve_calls(), 0);
    assert_eq!(h.walletd.transport().submit_calls(), 0);
    // No success or failure evidence exists yet.
    assert!(!evidence_sidecar(&h.archive).exists());
    assert!(!failure_sidecar(&h.archive).exists());
}

#[test]
fn dry_run_fee_1110_never_creates_request_with_1000() {
    let mut h = Harness::new("v2life-fee-1110");
    let result = h.prepare();
    assert_eq!(result.estimated_required_fee, Some(1_110));
    assert_eq!(result.selected_max_fee, Some(1_221));
    assert_eq!(h.walletd.transport().dry_run_calls(), 1);
    assert_eq!(h.walletd.transport().detect_calls(), 2);

    let created = h
        .walletd
        .transport()
        .captured_create()
        .expect("create request captured");
    let max_epoch = created.transaction.max_epoch().as_u64();
    let payload = AnchorEventPayloadV3::new(
        decode32(&h.built.v2_anchor_digest_hex),
        h.built.network.clone(),
        h.built.election_id.clone(),
        h.built.public_summary_json.clone(),
    )
    .expect("event payload");
    let selected_fee_check = inspect_detected_fee_bearing_v2_anchor_transaction(
        &created.transaction,
        &network(),
        max_epoch,
        format!("component_{}", "11".repeat(32))
            .parse()
            .expect("fee component"),
        tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1::from_units(1_221),
        &h.binding,
        &payload,
    );
    assert!(
        selected_fee_check.is_ok(),
        "selected fee inspection failed: {selected_fee_check:?}"
    );
    assert!(
        inspect_detected_fee_bearing_v2_anchor_transaction(
            &created.transaction,
            &network(),
            max_epoch,
            format!("component_{}", "11".repeat(32))
                .parse()
                .expect("fee component"),
            tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1::from_units(1_000),
            &h.binding,
            &payload,
        )
        .is_err(),
        "the frozen create request must not retain the stale 1000 fee"
    );
}

#[test]
fn sidecars_live_outside_the_archive_tree_under_the_app_owned_root() {
    let h = Harness::new("v2life-app-owned");
    for sidecar in [
        lifecycle_sidecar(&h.archive),
        evidence_sidecar(&h.archive),
        failure_sidecar(&h.archive),
    ] {
        // Never inside the archive directory itself.
        assert!(
            !sidecar.starts_with(&h.archive),
            "sidecar must not resolve inside the authoritative archive tree: {}",
            sidecar.display()
        );
        assert_ne!(sidecar, h.archive);
        // Landed under the deterministic app-owned root (env-overridden to a
        // per-process temp dir by `ensure_test_sidecar_root`).
        let text = sidecar.to_string_lossy();
        assert!(
            text.contains("gui-core-test-v2-sidecars-"),
            "sidecar must land under the app-owned sidecar root, got {text}"
        );
    }
}

#[test]
fn sidecars_are_deterministic_and_non_colliding_for_arbitrary_archives() {
    ensure_test_sidecar_root();
    // Two arbitrary, unrelated production-shaped archive paths — no folder
    // name is treated specially by the shipping product.
    let a = PathBuf::from(r"D:\Elections\September Council Vote");
    let b = PathBuf::from(r"E:\Ballots\Community Election 2027");
    let a_lifecycle = v2_lifecycle_sidecar_path(&a).expect("a lifecycle");
    let a_evidence = v2_evidence_sidecar_path(&a).expect("a evidence");
    let a_failure = v2_failure_sidecar_path(&a).expect("a failure");
    let b_lifecycle = v2_lifecycle_sidecar_path(&b).expect("b lifecycle");

    // Deterministic: the same input yields the same output every time.
    assert_eq!(a_lifecycle, v2_lifecycle_sidecar_path(&a).expect("a rederive"));

    // Every sidecar lands outside the archive tree.
    for sidecar in [&a_lifecycle, &a_evidence, &a_failure, &b_lifecycle] {
        assert!(
            !sidecar.starts_with(&a) && !sidecar.starts_with(&b),
            "sidecar must not resolve inside any authoritative archive tree: {}",
            sidecar.display()
        );
    }
    // Different archive paths derive different sidecar directories.
    assert_ne!(
        a_lifecycle.parent(),
        b_lifecycle.parent(),
        "distinct archives must not collide on the same sidecar directory"
    );
    // Lifecycle/evidence/failure for the same archive share the same
    // parent directory so rediscovery is a single directory read.
    assert_eq!(a_lifecycle.parent(), a_evidence.parent());
    assert_eq!(a_lifecycle.parent(), a_failure.parent());
}

#[test]
fn production_source_has_no_test_archive_special_case() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/live_anchor_v2_lifecycle.rs",
    ))
    .expect("read production source");
    assert!(
        !src.contains("PRESERVED_500_VOTER_ARCHIVE_NAME"),
        "production source must not name the historical preserved-archive constant"
    );
    assert!(
        !src.contains("500 Voter Test VPS and Desktop"),
        "production source must not branch on the historical archive folder name"
    );
}

#[test]
fn existing_500_voter_archive_naturally_maps_to_its_existing_sidecar_path() {
    // Regression-safety only: the historical physical `C:\500 Voter Test VPS
    // and Desktop` archive already has evidence saved on the operator's disk
    // at `%LOCALAPPDATA%\Private Ballot\v2-anchor-sidecars\
    // C__500_Voter_Test_VPS_and_Desktop\C__500_Voter_Test_VPS_and_Desktop
    // .v2-anchor-evidence.json`. The generic app-owned derivation must
    // reproduce that legacy layout naturally so the existing evidence
    // remains auto-discoverable without any migration or special-case in
    // the shipping product.
    //
    // This test asserts the deterministic tail of the derived path (the
    // sanitized-key directory plus filename) matches the historical layout.
    // It never mutates env vars — the shared app-owned root is picked up
    // from whatever `ensure_test_sidecar_root` set for this test binary.
    ensure_test_sidecar_root();
    let historical_archive = PathBuf::from(r"C:\500 Voter Test VPS and Desktop");
    let evidence =
        v2_evidence_sidecar_path(&historical_archive).expect("historical evidence path");
    let expected_key = "C__500_Voter_Test_VPS_and_Desktop";
    let expected_tail = PathBuf::from(expected_key)
        .join(format!("{expected_key}.v2-anchor-evidence.json"));
    assert!(
        evidence.ends_with(&expected_tail),
        "generic derivation must reproduce the pre-existing 500-voter sidecar layout \
         (`.../{}`) without a special case, got {}",
        expected_tail.display(),
        evidence.display()
    );
}

#[test]
fn poll_while_pending_is_a_noop_without_approving() {
    let mut h = Harness::new("v2life-poll-pending");
    h.prepare();
    h.set_get(WalletdEffectiveStatusV1::Pending, None);
    let result = h.step("none");
    assert_eq!(result.phase, "WAITING_FOR_WALLET_APPROVAL");
    assert_eq!(h.walletd.transport().approve_calls(), 0);
    assert_eq!(h.walletd.transport().submit_calls(), 0);
}

#[test]
fn manual_approval_submit_then_verified_receipt_writes_evidence() {
    let mut h = Harness::new("v2life-happy");
    h.prepare();
    h.approve();
    assert_eq!(h.walletd.transport().approve_calls(), 1);
    h.submit();
    assert_eq!(h.walletd.transport().submit_calls(), 1);

    // Receipt is finalized and verifies against the locked V2 deployment.
    let receipt = h.finalized_receipt();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(receipt));
    let result = h.step("none");
    assert_eq!(result.phase, "RECEIPT_VERIFIED");
    assert!(result.receipt_verified);
    assert!(result.failure_reason.is_none());
    // Only a verified receipt writes the immutable success-evidence sidecar.
    assert!(evidence_sidecar(&h.archive).exists());
    assert!(!failure_sidecar(&h.archive).exists());
}

#[test]
fn wallet_rejection_is_terminal_and_writes_failure_evidence() {
    let mut h = Harness::new("v2life-reject");
    h.prepare();
    h.set_get(WalletdEffectiveStatusV1::Rejected, None);
    let result = h.step("approve");
    assert_eq!(result.phase, "REJECTED");
    assert_eq!(result.wallet_request_status, "rejected");
    assert!(result.retry_required);
    assert!(
        result
            .rejection_reason
            .expect("reason")
            .contains("Transaction rejected")
    );
    // Never approved a rejected request.
    assert_eq!(h.walletd.transport().approve_calls(), 0);
    assert!(failure_sidecar(&h.archive).exists());
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn insufficient_fees_paid_is_classified_as_rejection_with_details() {
    let mut h = Harness::new("v2life-low-fee");
    h.prepare();
    h.approve();
    h.set_get(WalletdEffectiveStatusV1::Approved, None);
    h.walletd.transport_mut().set_submit_response(ScriptedWalletdResponse::SubmitError(
        tari_cc_private_ballot_ootle_anchor_network_adapters::TransportError::insufficient_fees_paid(
            1_000, 1_110,
        ),
    ));
    let result = h.step("none");
    assert_eq!(result.phase, "REJECTED");
    assert_eq!(result.transaction_id, None);
    assert!(!result.receipt_verified);
    assert!(result.retry_required);
    assert_eq!(
        result.rejection_reason.as_deref(),
        Some(
            "Transaction rejected. Fee too low: paid 1000, required 1110. Prepare a new transaction with an updated fee."
        )
    );
    assert!(failure_sidecar(&h.archive).exists());
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn rejected_request_allows_one_fresh_request_without_resubmitting_old_id() {
    let mut h = Harness::new("v2life-retry");
    h.prepare();
    let first_create = h
        .walletd
        .transport()
        .captured_create()
        .expect("first create")
        .transaction
        .clone();
    let first_payload = inspect_detected_fee_bearing_v2_anchor_transaction(
        &first_create,
        &network(),
        first_create.max_epoch().as_u64(),
        format!("component_{}", "11".repeat(32))
            .parse()
            .expect("fee component"),
        tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1::from_units(1_221),
        &h.binding,
        &AnchorEventPayloadV3::new(
            decode32(&h.built.v2_anchor_digest_hex),
            h.built.network.clone(),
            h.built.election_id.clone(),
            h.built.public_summary_json.clone(),
        )
        .expect("event payload"),
    )
    .expect("first payload");
    h.set_get(WalletdEffectiveStatusV1::Rejected, None);
    let rejected = h.step("approve");
    assert_eq!(rejected.walletd_request_id, Some(REQUEST_ID));
    let submits_before_retry = h.walletd.transport().submit_calls();

    h.walletd
        .transport_mut()
        .set_dry_run_response(ScriptedWalletdResponse::DryRun {
            required_fees: 1_110,
        });
    h.walletd
        .transport_mut()
        .set_create_response(ScriptedWalletdResponse::Create {
            request_id: REQUEST_ID + 1,
            expires_at: 0,
        });
    let retry = h.step("none");
    assert_eq!(retry.phase, "WAITING_FOR_WALLET_APPROVAL");
    assert_eq!(retry.walletd_request_id, Some(REQUEST_ID + 1));
    assert_eq!(h.walletd.transport().submit_calls(), submits_before_retry);
    let second_create = h
        .walletd
        .transport()
        .captured_create()
        .expect("second create")
        .transaction
        .clone();
    let second_payload = inspect_detected_fee_bearing_v2_anchor_transaction(
        &second_create,
        &network(),
        second_create.max_epoch().as_u64(),
        format!("component_{}", "11".repeat(32))
            .parse()
            .expect("fee component"),
        tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1::from_units(1_221),
        &h.binding,
        &AnchorEventPayloadV3::new(
            decode32(&h.built.v2_anchor_digest_hex),
            h.built.network.clone(),
            h.built.election_id.clone(),
            h.built.public_summary_json.clone(),
        )
        .expect("event payload"),
    )
    .expect("second payload");
    assert_eq!(second_payload, first_payload);
    let snapshot = std::fs::read_to_string(lifecycle_sidecar(&h.archive)).expect("snapshot");
    assert!(snapshot.contains("\"walletd_request_id\": 43"));
    assert!(snapshot.contains("\"prior_rejected_walletd_request_ids\""));
    assert!(snapshot.contains("42"));
}

#[test]
fn approval_window_expiry_maps_to_failed() {
    let mut h = Harness::new("v2life-expired");
    h.prepare();
    h.set_get(WalletdEffectiveStatusV1::Expired, None);
    let result = h.step("approve");
    assert_eq!(result.phase, "FAILED");
    assert!(result.failure_reason.expect("reason").contains("expired"));
    assert_eq!(h.walletd.transport().approve_calls(), 0);
    assert!(failure_sidecar(&h.archive).exists());
}

#[test]
fn recovery_adopts_a_sealed_transaction_without_resubmitting() {
    let mut h = Harness::new("v2life-recover");
    h.prepare();
    h.approve();
    // Simulate a crash after walletd sealed the submit but before the snapshot
    // recorded POLLING_RECEIPT: the request is already Submitted with an id.
    h.set_get(
        WalletdEffectiveStatusV1::Submitted,
        Some(AnchorTransactionId::new(TX_HEX.to_owned()).expect("tx id")),
    );
    let result = h.step("none");
    assert_eq!(result.phase, "POLLING_RECEIPT");
    assert_eq!(result.transaction_id.as_deref(), Some(TX_HEX));
    // The sealed id was adopted; submit was never called from the APPROVED state.
    assert_eq!(h.walletd.transport().submit_calls(), 0);
}

#[test]
fn receipt_verifier_failure_writes_failure_evidence_and_no_success() {
    let mut h = Harness::new("v2life-badreceipt");
    h.prepare();
    h.approve();
    h.submit();

    // A finalized receipt whose public summary is not the exact string that
    // the caller re-derived off-chain must fail the V2 receipt verifier and
    // never produce success evidence.
    let mut receipt = h.finalized_receipt();
    let tampered_summary = h
        .built
        .public_summary_json
        .replace("\"accepted_ballots\":3", "\"accepted_ballots\":4");
    assert_ne!(tampered_summary, h.built.public_summary_json);
    let tampered_payload = AnchorEventPayloadV3::new(
        decode32(&h.built.v2_anchor_digest_hex),
        h.built.network.clone(),
        h.built.election_id.clone(),
        tampered_summary,
    )
    .expect("payload");
    let tampered_proof = AnchorEventProofV2::new(
        h.binding.template_address().to_owned(),
        h.binding.full_event_topic(),
        vec![
            (
                ANCHOR_EVENT_DIGEST_KEY_V2.to_owned(),
                tampered_payload.digest_hex(),
            ),
            (
                ANCHOR_EVENT_NETWORK_KEY_V2.to_owned(),
                tampered_payload.network().to_owned(),
            ),
            (
                ANCHOR_EVENT_ELECTION_ID_KEY_V2.to_owned(),
                tampered_payload.election_id().to_owned(),
            ),
            (
                ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2.to_owned(),
                tampered_payload.public_summary().to_owned(),
            ),
        ],
        0,
        1,
        [0; 32],
    )
    .expect("proof");
    receipt = receipt.with_event_proofs_v2(vec![tampered_proof]);
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(receipt));

    let result = h.step("none");
    assert_eq!(result.phase, "FAILED");
    assert!(!result.receipt_verified);
    assert!(!evidence_sidecar(&h.archive).exists());
    assert!(failure_sidecar(&h.archive).exists());

    // A subsequent step stays terminally FAILED and never produces success.
    let again = h.step("none");
    assert_eq!(again.phase, "FAILED");
    assert!(!again.receipt_verified);
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn wrong_topic_failure_can_recover_existing_accepted_transaction_without_new_request() {
    let mut h = Harness::new("v2life-topic-recover");
    h.prepare();
    h.approve();
    h.submit();
    let creates = h.walletd.transport().create_calls();
    let submits = h.walletd.transport().submit_calls();

    let old_snake_topic = format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}");
    let wrong_topic_receipt = h.finalized_receipt_with_topic(old_snake_topic);
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(wrong_topic_receipt));
    let failed = h.step("none");
    assert_eq!(failed.phase, "FAILED");
    assert!(matches!(
        failed.failure_reason.as_deref(),
        Some("ANCHOR_RECEIPT_WRONG_EVENT_TOPIC")
    ));
    assert!(!evidence_sidecar(&h.archive).exists());
    assert!(failure_sidecar(&h.archive).exists());

    let recovered_receipt = h.finalized_receipt();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(recovered_receipt));
    let recovered = h.step("none");
    assert_eq!(recovered.phase, "RECEIPT_VERIFIED");
    assert!(recovered.receipt_verified);
    assert!(recovered.failure_reason.is_none());
    assert_eq!(recovered.transaction_id.as_deref(), Some(TX_HEX));
    assert_eq!(h.walletd.transport().create_calls(), creates);
    assert_eq!(h.walletd.transport().submit_calls(), submits);
    assert!(evidence_sidecar(&h.archive).exists());
}

#[test]
fn rejected_transaction_receipt_is_terminal() {
    let mut h = Harness::new("v2life-txrejected");
    h.prepare();
    h.approve();
    h.submit();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Rejected {
            reason: Some("aborted".to_owned()),
        });
    let result = h.step("none");
    assert_eq!(result.phase, "FAILED");
    assert!(failure_sidecar(&h.archive).exists());
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn pending_receipt_keeps_polling() {
    let mut h = Harness::new("v2life-pending-receipt");
    h.prepare();
    h.approve();
    h.submit();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Pending);
    let result = h.step("none");
    assert_eq!(result.phase, "POLLING_RECEIPT");
    assert!(!result.receipt_verified);
    assert!(!evidence_sidecar(&h.archive).exists());

    // Once the receipt finalizes and verifies, it advances to verified.
    let receipt = h.finalized_receipt();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(receipt));
    let done = h.step("none");
    assert_eq!(done.phase, "RECEIPT_VERIFIED");
    assert!(done.receipt_verified);
}

#[test]
fn not_found_receipt_keeps_polling_without_failing() {
    let mut h = Harness::new("v2life-notfound-receipt");
    h.prepare();
    h.approve();
    h.submit();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::NotFound);
    let result = h.step("none");
    assert_eq!(result.phase, "POLLING_RECEIPT");
    assert!(!result.receipt_verified);
    assert!(!failure_sidecar(&h.archive).exists());
}

#[test]
fn changed_request_binding_after_prepare_is_rejected() {
    let mut h = Harness::new("v2life-binding");
    h.prepare();
    // Tamper the request payload after the snapshot is bound; the reload must
    // detect the divergence rather than continue with a mismatched request.
    let mut bad = h.request("approve");
    bad.expected_digest_hex = "00".repeat(32);
    let error =
        run_v2_live_anchor_step_with_transports(&bad, &h.binding, &mut h.walletd, &mut h.indexer)
            .expect_err("binding mismatch must fail");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_LIFECYCLE_BINDING_MISMATCH");
}

impl Harness {
    /// Drives the full happy path to a verified receipt with evidence written.
    fn finalize_to_verified(&mut self) {
        self.prepare();
        self.approve();
        self.submit();
        let receipt = self.finalized_receipt();
        self.indexer
            .transport_mut()
            .set_response(ScriptedIndexerResponse::Finalized(receipt));
        let done = self.step("none");
        assert_eq!(done.phase, "RECEIPT_VERIFIED");
        assert!(evidence_sidecar(&self.archive).exists());
    }
}

#[test]
fn missing_snapshot_with_valid_evidence_recovers_as_success_without_republishing() {
    let mut h = Harness::new("v2life-recover-evidence");
    h.finalize_to_verified();
    let creates = h.walletd.transport().create_calls();
    let submits = h.walletd.transport().submit_calls();

    // Simulate a crash that lost the lifecycle snapshot after the successful
    // publish and evidence write (the indexer still returns the verified receipt).
    std::fs::remove_file(lifecycle_sidecar(&h.archive)).expect("remove snapshot");
    assert!(!lifecycle_sidecar(&h.archive).exists());
    assert!(evidence_sidecar(&h.archive).exists());

    let recovered = h.step("none");
    assert_eq!(recovered.phase, "RECEIPT_VERIFIED");
    assert!(recovered.receipt_verified);
    // Recovery adopted the existing evidence; it never created or submitted a new
    // walletd request (no double publish).
    assert_eq!(h.walletd.transport().create_calls(), creates);
    assert_eq!(h.walletd.transport().submit_calls(), submits);
    // The terminal snapshot was rebuilt.
    assert!(lifecycle_sidecar(&h.archive).exists());
}

#[test]
fn missing_snapshot_with_mismatched_evidence_fails_closed() {
    let mut h = Harness::new("v2life-recover-conflict");
    h.finalize_to_verified();
    std::fs::remove_file(lifecycle_sidecar(&h.archive)).expect("remove snapshot");

    // Corrupt the evidence binding: a different anchor digest than the request.
    let path = evidence_sidecar(&h.archive);
    let text = std::fs::read_to_string(&path).expect("read evidence");
    let real = &h.built.v2_anchor_digest_hex;
    let tampered = text.replace(real.as_str(), &"00".repeat(32));
    assert_ne!(tampered, text, "digest must be present to tamper");
    std::fs::write(&path, tampered).expect("write tampered evidence");

    let error = run_v2_live_anchor_step_with_transports(
        &h.request("none"),
        &h.binding,
        &mut h.walletd,
        &mut h.indexer,
    )
    .expect_err("mismatched evidence must fail closed");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_EVIDENCE_CONFLICT");
    // No new walletd request was created during the fail-closed recovery.
    assert_eq!(h.walletd.transport().create_calls(), 1);
}

#[test]
fn missing_snapshot_with_only_failure_sidecar_is_not_treated_as_success() {
    let mut h = Harness::new("v2life-recover-failure");
    h.prepare();
    h.approve();
    h.submit();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Rejected {
            reason: Some("aborted".to_owned()),
        });
    let failed = h.step("none");
    assert_eq!(failed.phase, "FAILED");
    assert!(failure_sidecar(&h.archive).exists());
    assert!(!evidence_sidecar(&h.archive).exists());

    // Lose the snapshot: only the failure sidecar remains. Recovery must never
    // read the failure artifact as success.
    std::fs::remove_file(lifecycle_sidecar(&h.archive)).expect("remove snapshot");
    let after = h.step("none");
    assert_ne!(after.phase, "RECEIPT_VERIFIED");
    assert!(!after.receipt_verified);
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn crash_after_evidence_before_snapshot_adopts_without_overwriting() {
    let mut h = Harness::new("v2life-adopt-evidence");
    h.finalize_to_verified();
    let evidence_path = evidence_sidecar(&h.archive);
    let before = std::fs::read(&evidence_path).expect("read evidence");

    // Simulate the exact reported crash: evidence written, but the snapshot phase
    // was not advanced to RECEIPT_VERIFIED (rewind it to POLLING_RECEIPT).
    let snap_path = lifecycle_sidecar(&h.archive);
    let snap = std::fs::read_to_string(&snap_path).expect("read snapshot");
    let rewound = snap.replace(
        "\"phase\": \"RECEIPT_VERIFIED\"",
        "\"phase\": \"POLLING_RECEIPT\"",
    );
    assert_ne!(rewound, snap, "phase must be present to rewind");
    std::fs::write(&snap_path, rewound).expect("write rewound snapshot");

    // The receipt still verifies; re-polling must adopt the identical existing
    // evidence idempotently instead of failing closed on EVIDENCE_EXISTS.
    let result = h.step("none");
    assert_eq!(result.phase, "RECEIPT_VERIFIED");
    assert!(result.receipt_verified);
    // The existing valid evidence was not overwritten.
    let after = std::fs::read(&evidence_path).expect("re-read evidence");
    assert_eq!(before, after, "valid evidence must not be overwritten");
}

#[test]
fn crash_recovery_with_conflicting_evidence_fails_closed() {
    let mut h = Harness::new("v2life-adopt-conflict");
    h.finalize_to_verified();

    // Rewind the snapshot to POLLING_RECEIPT and tamper the evidence so it no
    // longer matches what the verified snapshot would write.
    let snap_path = lifecycle_sidecar(&h.archive);
    let snap = std::fs::read_to_string(&snap_path).expect("read snapshot");
    std::fs::write(
        &snap_path,
        snap.replace(
            "\"phase\": \"RECEIPT_VERIFIED\"",
            "\"phase\": \"POLLING_RECEIPT\"",
        ),
    )
    .expect("rewind snapshot");
    let evidence_path = evidence_sidecar(&h.archive);
    let text = std::fs::read_to_string(&evidence_path).expect("read evidence");
    std::fs::write(&evidence_path, text.replace(TX_HEX, &"bb".repeat(32)))
        .expect("tamper evidence");

    let error = run_v2_live_anchor_step_with_transports(
        &h.request("none"),
        &h.binding,
        &mut h.walletd,
        &mut h.indexer,
    )
    .expect_err("conflicting evidence must fail closed");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_EVIDENCE_CONFLICT");
}

// -----------------------------------------------------------------------------
// Recovery hydration/UI regression tests
//
// These tests reproduce the exact 500-voter physical-load state where the
// walletd-submitted V2 anchor transaction was accepted but the receipt event
// topic did not match the verifier, producing a persisted FAILED lifecycle
// carrying transaction_id, walletd_request_id, and payload_hex. After an
// application restart the organizer UI must:
//   1. Hydrate the persisted FAILED sidecar (read-only), not fall back to
//      Build/Prepare/Submit.
//   2. Classify the state as recoverable and expose the existing transaction
//      hash.
//   3. Advance recovery through the walletd-free indexer poll path so no
//      duplicate wallet request or transaction can be created.
//   4. Verify the canonical Ootle receipt topic and the preserved payload_hex
//      byte-for-byte on success.
// -----------------------------------------------------------------------------

/// Drives the harness to the exact FAILED shape observed on the preserved
/// 500-voter archive: a walletd-approved transaction whose accepted receipt
/// carried the legacy snake-case event topic and therefore failed the V2
/// verifier. Leaves the sidecars persisted for the following tests.
fn drive_to_wrong_topic_failure(h: &mut Harness) {
    h.prepare();
    h.approve();
    h.submit();
    let legacy_topic = format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}");
    let wrong_topic_receipt = h.finalized_receipt_with_topic(legacy_topic);
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(wrong_topic_receipt));
    let failed = h.step("none");
    assert_eq!(failed.phase, "FAILED");
    assert_eq!(
        failed.failure_reason.as_deref(),
        Some("ANCHOR_RECEIPT_WRONG_EVENT_TOPIC")
    );
    assert_eq!(failed.transaction_id.as_deref(), Some(TX_HEX));
    assert!(failure_sidecar(&h.archive).exists());
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn persisted_failed_lifecycle_hydrates_after_application_restart() {
    let mut h = Harness::new("v2life-hydrate-failed");
    drive_to_wrong_topic_failure(&mut h);

    // Simulate a full application restart: nothing but the persisted sidecars
    // remain on disk. The read-only inspect never contacts walletd or the
    // indexer, so it can be exercised in isolation.
    let hydrated = inspect_v2_live_anchor_state(&h.archive).expect("inspect");
    assert!(hydrated.lifecycle_present);
    assert!(hydrated.failure_present);
    assert!(!hydrated.evidence_present);
    assert_eq!(hydrated.phase.as_deref(), Some("FAILED"));
    assert_eq!(hydrated.transaction_id.as_deref(), Some(TX_HEX));
    assert_eq!(
        hydrated.failure_reason.as_deref(),
        Some("ANCHOR_RECEIPT_WRONG_EVENT_TOPIC")
    );
    assert_eq!(hydrated.walletd_request_id, Some(REQUEST_ID));
    // Preserved public summary bytes survive verbatim through the sidecar.
    assert_eq!(
        hydrated.payload_hex.as_deref(),
        Some(h.built.payload_hex.as_str())
    );
    assert_eq!(
        hydrated.expected_digest_hex.as_deref(),
        Some(h.built.v2_anchor_digest_hex.as_str())
    );
    // Sidecar paths must resolve outside the authoritative archive tree.
    let lifecycle_path = Path::new(&hydrated.lifecycle_path);
    assert!(
        !lifecycle_path.starts_with(&h.archive),
        "lifecycle path must not resolve inside the authoritative archive: {}",
        lifecycle_path.display()
    );
    // Hand-crafted persisted-shape check: the exact walletd_request_id and
    // failure_reason strings recovered from disk match the on-disk JSON.
    let raw = std::fs::read_to_string(lifecycle_sidecar(&h.archive)).expect("read");
    assert!(raw.contains("\"walletd_request_id\": 42"));
    assert!(raw.contains("\"failure_reason\": \"ANCHOR_RECEIPT_WRONG_EVENT_TOPIC\""));
    assert!(raw.contains("\"transaction_id\": \"aaaaaaaaaaaaaaaa"));
}

#[test]
fn hydrated_failed_lifecycle_is_classified_recoverable_and_blocks_fresh_publish() {
    let mut h = Harness::new("v2life-hydrate-recoverable");
    drive_to_wrong_topic_failure(&mut h);

    let hydrated = inspect_v2_live_anchor_state(&h.archive).expect("inspect");
    assert!(
        hydrated.recoverable,
        "FAILED with ANCHOR_RECEIPT_WRONG_EVENT_TOPIC and a submitted transaction must be recoverable"
    );
    assert!(
        hydrated.blocks_fresh_publish,
        "an already-submitted transaction must suppress the fresh Build/Prepare/Submit path"
    );
    assert!(!hydrated.receipt_verified);
    // The transaction hash is what the recovery panel surfaces to the operator.
    assert_eq!(hydrated.transaction_id.as_deref(), Some(TX_HEX));
}

#[test]
fn recovery_uses_existing_transaction_and_never_creates_a_wallet_request() {
    let mut h = Harness::new("v2life-recovery-no-walletd");
    drive_to_wrong_topic_failure(&mut h);
    let creates_before = h.walletd.transport().create_calls();
    let submits_before = h.walletd.transport().submit_calls();
    let approves_before = h.walletd.transport().approve_calls();

    // The indexer now returns the correctly-topic'd (canonical PascalCase)
    // receipt for the SAME transaction id. Recovery must adopt it without
    // touching walletd.
    let recovered_receipt = h.finalized_receipt();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(recovered_receipt));

    let recovered =
        run_v2_live_anchor_recovery_step_with_indexer(&h.archive, &h.binding, &mut h.indexer)
            .expect("recovery");
    assert_eq!(recovered.phase, "RECEIPT_VERIFIED");
    assert!(recovered.receipt_verified);
    assert!(recovered.failure_reason.is_none());
    // The submitted transaction id is unchanged: recovery never mints a new tx.
    assert_eq!(recovered.transaction_id.as_deref(), Some(TX_HEX));
    // Architectural guarantee: recovery does not accept a walletd transport, so
    // no new wallet request could have been created and no submit could occur.
    assert_eq!(h.walletd.transport().create_calls(), creates_before);
    assert_eq!(h.walletd.transport().submit_calls(), submits_before);
    assert_eq!(h.walletd.transport().approve_calls(), approves_before);
    // Success evidence is written beside the archive (never inside it), and the
    // failure sidecar from the earlier wrong-topic attempt is preserved for
    // audit history.
    let evidence = evidence_sidecar(&h.archive);
    assert!(evidence.exists());
    assert!(
        !evidence.starts_with(&h.archive),
        "evidence must not resolve inside the authoritative archive: {}",
        evidence.display()
    );
    assert!(failure_sidecar(&h.archive).exists());

    // Post-recovery hydration reflects the terminal verified state.
    let hydrated = inspect_v2_live_anchor_state(&h.archive).expect("inspect");
    assert!(hydrated.receipt_verified);
    assert_eq!(hydrated.phase.as_deref(), Some("RECEIPT_VERIFIED"));
    assert!(
        !hydrated.recoverable,
        "verified receipts are not recoverable again"
    );
    assert!(hydrated.blocks_fresh_publish);
}

#[test]
fn recovery_preserves_payload_hex_and_digest_byte_for_byte() {
    let mut h = Harness::new("v2life-recovery-preserves-payload");
    drive_to_wrong_topic_failure(&mut h);

    // Capture the persisted payload_hex/digest BEFORE recovery so we can prove
    // recovery uses them verbatim and never regenerates a replacement.
    let raw_before = std::fs::read_to_string(lifecycle_sidecar(&h.archive)).expect("read");
    let hydrated_before = inspect_v2_live_anchor_state(&h.archive).expect("inspect");
    let payload_before = hydrated_before.payload_hex.clone().expect("payload");
    let digest_before = hydrated_before.expected_digest_hex.clone().expect("digest");

    let receipt = h.finalized_receipt();
    h.indexer
        .transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(receipt));
    let recovered =
        run_v2_live_anchor_recovery_step_with_indexer(&h.archive, &h.binding, &mut h.indexer)
            .expect("recovery");
    assert!(recovered.receipt_verified);

    // The persisted payload_hex/digest are byte-for-byte unchanged.
    let hydrated_after = inspect_v2_live_anchor_state(&h.archive).expect("inspect");
    assert_eq!(
        hydrated_after.payload_hex.as_deref(),
        Some(payload_before.as_str())
    );
    assert_eq!(
        hydrated_after.expected_digest_hex.as_deref(),
        Some(digest_before.as_str())
    );
    // The exact preserved payload_hex substring is still present in the raw
    // lifecycle file on disk (the sidecar was rewritten during poll but the
    // payload_hex field itself is copied through unchanged).
    let raw_after = std::fs::read_to_string(lifecycle_sidecar(&h.archive)).expect("read");
    assert!(raw_after.contains(&payload_before));
    // The success-evidence sidecar records the same payload_hex.
    let evidence_raw = std::fs::read_to_string(evidence_sidecar(&h.archive)).expect("read");
    assert!(evidence_raw.contains(&payload_before));
    assert!(evidence_raw.contains(&digest_before));
    // The lifecycle's transaction id must survive verbatim in the raw file.
    assert!(raw_before.contains(TX_HEX));
    assert!(raw_after.contains(TX_HEX));
}

#[test]
fn recovery_rejects_a_deployment_binding_that_does_not_match_the_persisted_lifecycle() {
    let mut h = Harness::new("v2life-recovery-binding-mismatch");
    drive_to_wrong_topic_failure(&mut h);

    // Construct a foreign V2 binding (different template address). Recovery
    // must fail closed rather than silently poll against a mismatched verifier.
    let foreign = AnchorTemplateBindingV2::new(
        format!("template_{}", "77".repeat(32)),
        h.binding.module().to_owned(),
        h.binding.function().to_owned(),
        h.binding.full_event_topic(),
        decode32(V2_ARTIFACT_DIGEST),
    )
    .expect("foreign binding");

    let error = run_v2_live_anchor_recovery_step_with_indexer(&h.archive, &foreign, &mut h.indexer)
        .expect_err("binding mismatch must fail closed");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_LIFECYCLE_BINDING_MISMATCH");
    // No new evidence was written under a mismatched binding.
    assert!(!evidence_sidecar(&h.archive).exists());
}

#[test]
fn recovery_without_a_persisted_lifecycle_is_inapplicable() {
    let dir = TestDir::new("v2life-recovery-empty");
    let archive = finalized_bound_archive(&dir);
    let binding = AnchorTemplateBindingV2::new(
        format!("template_{}", "44".repeat(32)),
        "tari_private_ballot_anchor_v2".to_owned(),
        "publish_anchor_v2".to_owned(),
        "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2".to_owned(),
        decode32(V2_ARTIFACT_DIGEST),
    )
    .expect("binding");
    let mut indexer = IndexerReceiptNetworkAdapter::new(ScriptedIndexerTransport::new());

    let error = run_v2_live_anchor_recovery_step_with_indexer(&archive, &binding, &mut indexer)
        .expect_err("no lifecycle must be inapplicable");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_RECOVERY_LIFECYCLE_MISSING");

    // The read-only inspect on the same directory returns an empty projection
    // (no lifecycle, no evidence, no failure) and does not error.
    let hydrated = inspect_v2_live_anchor_state(&archive).expect("inspect");
    assert!(!hydrated.lifecycle_present);
    assert!(!hydrated.evidence_present);
    assert!(!hydrated.failure_present);
    assert!(!hydrated.recoverable);
    assert!(!hydrated.blocks_fresh_publish);
    assert!(hydrated.transaction_id.is_none());
    assert!(hydrated.phase.is_none());
}

#[test]
fn hydration_reports_written_paths_outside_the_archive_directory() {
    let mut h = Harness::new("v2life-hydrate-paths");
    drive_to_wrong_topic_failure(&mut h);
    let hydrated = inspect_v2_live_anchor_state(&h.archive).expect("inspect");
    let expected_lifecycle = v2_lifecycle_sidecar_path(&h.archive).expect("lifecycle");
    let expected_evidence = v2_evidence_sidecar_path(&h.archive).expect("evidence");
    let expected_failure = v2_failure_sidecar_path(&h.archive).expect("failure");
    assert_eq!(Path::new(&hydrated.lifecycle_path), expected_lifecycle);
    assert_eq!(Path::new(&hydrated.evidence_path), expected_evidence);
    assert_eq!(Path::new(&hydrated.failure_path), expected_failure);
}
