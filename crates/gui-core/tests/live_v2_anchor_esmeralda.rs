//! Live Esmeralda V2 anchor smoke test (fee-bearing).
//!
//! This is the repository-native, one-command live qualification harness for
//! the already-published `TariPrivateBallotAnchorV2` template. It drives the
//! **production** V2 path end to end and re-implements none of it:
//!
//!   lock_trusted_ootle_deployment_v2            (temp, create-new)
//!   build_v2_public_payload_from_verified_archive_v1
//!   run_v2_live_anchor_step_with_transports     with the real
//!     RealWalletdTransport + RealIndexerTransport
//!
//! Phases: prepare (walletd dry-run + fee estimate) -> approve -> submit ->
//! indexer receipt verification -> evidence write. It fails closed on every
//! step and asserts that a terminal `RECEIPT_VERIFIED` phase carries the
//! expected anchor digest.
//!
//! # Running
//!
//! The test is `#[ignore]`d so an ordinary `cargo test` never spends money.
//! Run it explicitly:
//!
//! ```text
//! cargo test -p tari-cc-private-ballot-gui-core --test live_v2_anchor_esmeralda \
//!   -- --ignored --nocapture
//! ```
//!
//! # Configuration (all optional except in practice)
//!
//! | Variable | Default | Meaning |
//! | --- | --- | --- |
//! | `PRIVATE_BALLOT_V2_TEMPLATE_ADDRESS` | the reviewed Esmeralda deployment | template under test |
//! | `PRIVATE_BALLOT_V2_WALLETD` | `http://127.0.0.1:5100` | walletd base URL (must be loopback) |
//! | `PRIVATE_BALLOT_V2_INDEXER` | trusted Esmeralda indexer | indexer base URL |
//! | `PRIVATE_BALLOT_V2_FEE_COMPONENT` | operator must set | fee-paying account component |
//! | `WALLETD_AUTH_TOKEN` | unset = no bearer | walletd bearer token; omit for an unauthenticated daemon |
//!
//! No secret is ever printed, and no secret is written to any sidecar.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use tari_cc_private_ballot_anchor::OotleAnchorPublicPayloadV2;
use tari_cc_private_ballot_anchor_transport::OotleNetworkIdV1;
use tari_cc_private_ballot_archive::{TransportArchiveBatchV1, TransportArchiveBindingV1};
use tari_cc_private_ballot_gui_core::{
    TRUSTED_OOTLE_DEPLOYMENT_V2_ARTIFACT_DIGEST_HEX, GuiElectionSessionV1,
    GuiLiveAnchorV2RequestV1, GuiTrustedOotleDeploymentLockRequestV2,
    GuiV2AnchorPublishPreparationRequestV1, GuiV2LiveAnchorStepRequestV1,
    build_v2_public_payload_from_verified_archive_v1,
    load_trusted_ootle_deployment_v2, lock_trusted_ootle_deployment_v2,
    prepare_v2_anchor_publish_from_verified_evidence_v1,
    read_v2_public_anchor_evidence_file, run_v2_live_anchor_step_with_transports,
    trusted_ootle_deployment_to_live_anchor_v2_request_v1,
    trusted_ootle_deployment_v2_binding, unlock_trusted_ootle_deployment_v2,
    write_finalized_archive_v1_with_transport_binding,
};
use tari_cc_private_ballot_ootle_anchor_app::TokioBlockingExecutor;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, IndexerReceiptNetworkAdapter, RealIndexerTransport, RealWalletdTransport,
    TRUSTED_ESMERALDA_INDEXER_ENDPOINT_V1, WalletdAnchorNetworkAdapter, WalletdAuthSecret,
    WalletdEndpoint, indexer_endpoint_allowed_for_network_v1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use common::{TestDir, open_session, triptych_package_bytes};

const DEFAULT_TEMPLATE_ADDRESS: &str =
    "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee";
const DEFAULT_WALLETD: &str = "http://127.0.0.1:5100";
const DEFAULT_NETWORK: &str = "esmeralda";
const REQUEST_TIMEOUT_SECS: u64 = 30;
const MAX_EPOCH_DELTA: u64 = 12;
const POLL_ATTEMPTS: usize = 240;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Operator-authorized maximum fee for the Esmeralda v0.42 controlled-alpha
/// configuration, in raw fee units. This is an AUTHORIZED MAXIMUM, not an
/// estimate: the network only ever burns the fee the committed transaction
/// actually requires, which is always bounded by this cap.
///
/// The same value is the production GUI default. Live qualification measured
/// real requirements of 1143 (against a 761 cap -> Abort/InsufficientFeesPaid)
/// and a dry-run requirement of 3324 (against a 2500 cap -> stopped at
/// preflight), so the authorized ceiling is set generously while the actual
/// charge remains the network's true requirement. Overridable with
/// `PRIVATE_BALLOT_V2_MAX_FEE`; the production hard ceiling
/// (`OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1` = 10_000_000) is enforced by the
/// lifecycle and is never bypassed here.
const DEFAULT_MAX_FEE: u64 = 100_000;

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// A disposable, synthetic, test-only finalized election: three ballots over the
/// canonical `gui-core` fixture vectors, no real voter data and no production
/// material. The fixture election id is `gui-core-test-election`, so the anchor
/// this produces is self-identifying as a smoke test on-chain. Deterministic
/// given the fixed fixture vectors, so the resulting anchor digest is
/// reproducible.
fn synthetic_finalized_session() -> GuiElectionSessionV1 {
    let mut session = open_session();
    for package in [
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(2, &[b"candidate-a"]),
    ] {
        session.intake_ballot(&package).expect("synthetic ballot intake");
    }
    session.close().expect("close");
    session.mark_verified().expect("mark verified");
    session.finalize().expect("finalize");
    session
}

fn synthetic_transport_binding(
    session: &GuiElectionSessionV1,
) -> TransportArchiveBindingV1 {
    TransportArchiveBindingV1::new(
        session
            .artifacts()
            .manifest()
            .election_id()
            .as_bytes()
            .to_vec(),
        session.artifacts().manifest_hash(),
        [9; 32],
        4,
        vec![TransportArchiveBatchV1::new(
            1,
            [9; 32],
            session.transcript().accepted_count() as u64,
            false,
        )],
    )
    .expect("synthetic transport binding")
}

fn write_synthetic_archive(session: &GuiElectionSessionV1, dir: &TestDir) -> PathBuf {
    let target = dir.join("archive");
    write_finalized_archive_v1_with_transport_binding(
        session,
        &target,
        &synthetic_transport_binding(session),
    )
    .expect("synthetic finalized archive must write");
    target
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("lowercase hex"))
        .collect()
}

fn line(key: &str, value: &str) {
    println!("{key:<24} {value}");
}

#[test]
#[ignore = "fee-bearing live Esmeralda publication; run explicitly with --ignored"]
fn live_v2_anchor_smoke_test() {
    let template_address = env_or("PRIVATE_BALLOT_V2_TEMPLATE_ADDRESS", DEFAULT_TEMPLATE_ADDRESS);
    let walletd_base = env_or("PRIVATE_BALLOT_V2_WALLETD", DEFAULT_WALLETD);
    let indexer_base =
        env_or("PRIVATE_BALLOT_V2_INDEXER", TRUSTED_ESMERALDA_INDEXER_ENDPOINT_V1);
    let network_id = env_or("PRIVATE_BALLOT_V2_NETWORK", DEFAULT_NETWORK);
    // Never echoed. Absent means "no bearer token", which is correct for a
    // daemon started with `--authentication none` on older builds.
    let auth_token = std::env::var("WALLETD_AUTH_TOKEN").ok().filter(|t| !t.trim().is_empty());
    let fee_component = std::env::var("PRIVATE_BALLOT_V2_FEE_COMPONENT")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .expect("PRIVATE_BALLOT_V2_FEE_COMPONENT must name the fee-paying account component");
    let max_fee = env_or("PRIVATE_BALLOT_V2_MAX_FEE", &DEFAULT_MAX_FEE.to_string())
        .parse::<u64>()
        .expect("PRIVATE_BALLOT_V2_MAX_FEE must be a positive integer");

    println!("== LIVE V2 ANCHOR SMOKE TEST ==");
    line("TEMPLATE ADDRESS:", &template_address);
    line("WALLETD:", &walletd_base);
    line("INDEXER:", &indexer_base);
    line("NETWORK:", &network_id);
    line("MAX FEE (authorized cap):", &max_fee.to_string());
    line(
        "AUTH:",
        if auth_token.is_some() {
            "bearer token supplied (value never printed)"
        } else {
            "none"
        },
    );

    // ---- PHASE 4: disposable synthetic anchor -------------------------------
    let dir = TestDir::new("live-v2-esmeralda");
    let session = synthetic_finalized_session();
    let archive = write_synthetic_archive(&session, &dir);

    // Sidecars are app-owned; redirect them beside this test's temp dir so no
    // real per-user state is read or written.
    let sidecar_root = dir.join("sidecars");
    std::fs::create_dir_all(&sidecar_root).expect("sidecar root");
    tari_cc_private_ballot_gui_core::__set_v2_anchor_sidecar_root_test_override(sidecar_root);

    // ---- PHASE 5: temporary trusted deployment (create-new, never overwrites) --
    let app_data = dir.join("appdata");
    let locked = lock_trusted_ootle_deployment_v2(
        &app_data,
        &GuiTrustedOotleDeploymentLockRequestV2 {
            network: network_id.clone(),
            template_address: template_address.clone(),
            template_artifact_digest_hex: TRUSTED_OOTLE_DEPLOYMENT_V2_ARTIFACT_DIGEST_HEX
                .to_owned(),
        },
    )
    .expect("temporary trusted V2 deployment lock");
    let deployment = locked.deployment.expect("locked deployment");
    assert_eq!(deployment.template_address, template_address);

    let binding = trusted_ootle_deployment_v2_binding(&deployment).expect("V2 template binding");
    let network = OotleNetworkIdV1::new(deployment.network.clone()).expect("network id");

    // Endpoint policy, identical to the Tauri command.
    let walletd_endpoint = WalletdEndpoint::parse(&walletd_base).expect("walletd endpoint");
    let indexer_endpoint = IndexerEndpoint::parse(&indexer_base).expect("indexer endpoint");
    assert!(walletd_endpoint.is_loopback(), "walletd must be loopback");
    assert!(
        indexer_endpoint_allowed_for_network_v1(&network, &indexer_endpoint),
        "indexer endpoint must be loopback or the trusted esmeralda remote"
    );

    let request = trusted_ootle_deployment_to_live_anchor_v2_request_v1(
        GuiLiveAnchorV2RequestV1 {
            archive_directory: archive.to_string_lossy().into_owned(),
            network: network_id.clone(),
            template_address: template_address.clone(),
            template_module: "tari_private_ballot_anchor_v2".to_owned(),
            template_function: "publish_anchor_v2".to_owned(),
            template_event_topic: String::new(),
            template_artifact_digest_hex: String::new(),
        },
        &deployment,
    )
    .expect("stamp deployment onto live anchor request");

    let built = build_v2_public_payload_from_verified_archive_v1(&request)
        .expect("build V2 public payload from verified archive");

    println!();
    println!("== SYNTHETIC ANCHOR (non-sensitive) ==");
    line("ELECTION ID:", &built.election_id);
    line("NETWORK:", &built.network);
    line("ACCEPTED BALLOTS:", &built.accepted_ballot_count.to_string());
    line("ELIGIBLE VOTERS:", &built.eligible_voter_count.to_string());
    line("TEMPLATE ADDRESS:", &built.template_address);
    line("ARTIFACT BLAKE3:", &built.template_artifact_digest_hex);
    line("ANCHOR DIGEST:", &built.v2_anchor_digest_hex);
    line("PUBLIC SUMMARY BYTES:", &built.public_summary_json.len().to_string());
    println!();
    println!("PUBLIC SUMMARY:");
    println!("{}", built.public_summary_json);
    println!();

    // Exact publish_anchor_v2 arguments, straight from the production preparer.
    let preview = prepare_v2_anchor_publish_from_verified_evidence_v1(
        &GuiV2AnchorPublishPreparationRequestV1 {
            archive_directory: archive.to_string_lossy().into_owned(),
            payload_hex: built.payload_hex.clone(),
            expected_digest_hex: built.v2_anchor_digest_hex.clone(),
        },
        &binding,
    )
    .expect("prepare V2 anchor publish");
    assert_eq!(preview.template_function, "publish_anchor_v2");
    assert_eq!(preview.arguments.len(), 4, "V2 ABI must take exactly four arguments");
    assert_eq!(preview.arguments[0], built.v2_anchor_digest_hex);
    assert_eq!(preview.arguments[1], built.network);
    assert_eq!(preview.arguments[2], built.election_id);
    assert_eq!(preview.arguments[3], built.public_summary_json);
    println!("== publish_anchor_v2 ARGUMENTS ({}) ==", preview.arguments.len());
    for (i, arg) in preview.arguments.iter().enumerate() {
        let shown = if arg.len() > 96 {
            format!("{}...", &arg[..96])
        } else {
            arg.clone()
        };
        println!("  arg[{i}] {shown}");
    }
    println!();

    // ---- shared lifecycle driver -------------------------------------------
    let step = |decision: &str| -> tari_cc_private_ballot_gui_core::GuiV2LiveAnchorStepResultV1 {
        let req = GuiV2LiveAnchorStepRequestV1 {
            archive_directory: archive.to_string_lossy().into_owned(),
            payload_hex: built.payload_hex.clone(),
            expected_digest_hex: built.v2_anchor_digest_hex.clone(),
            fee_component: fee_component.clone(),
            seal_signer_kind: "account".to_owned(),
            seal_signer_id: "0".to_owned(),
            max_fee,
            max_epoch_delta: MAX_EPOCH_DELTA,
            walletd_endpoint: walletd_base.clone(),
            indexer_endpoint: indexer_base.clone(),
            use_walletd_auth: auth_token.is_some(),
            decision: decision.to_owned(),
        };
        let auth = auth_token
            .as_ref()
            .map(|t| WalletdAuthSecret::new(t.clone()))
            .transpose()
            .expect("bearer token shape");
        let executor = TokioBlockingExecutor::new_current_thread().expect("blocking executor");
        let walletd = RealWalletdTransport::new(
            &walletd_endpoint,
            auth.as_ref(),
            Some(Duration::from_secs(REQUEST_TIMEOUT_SECS)),
            executor.clone(),
        )
        .expect("real walletd transport");
        let indexer = RealIndexerTransport::new(
            &indexer_endpoint,
            Some(Duration::from_secs(REQUEST_TIMEOUT_SECS)),
            executor,
        )
        .expect("real indexer transport");
        let mut walletd = WalletdAnchorNetworkAdapter::new(walletd, network.clone());
        let mut indexer = IndexerReceiptNetworkAdapter::new(indexer);
        run_v2_live_anchor_step_with_transports(&req, &binding, &mut walletd, &mut indexer)
            .unwrap_or_else(|e| panic!("lifecycle step (decision={decision}) failed: {e:?}"))
    };

    // ---- PHASE 6: dry run ---------------------------------------------------
    let prepared = step("none");
    println!("== DRY RUN ==");
    line("PHASE:", &prepared.phase);
    line("ESTIMATED FEE:", &format!("{:?}", prepared.estimated_required_fee));
    line("SELECTED MAX FEE:", &format!("{:?}", prepared.selected_max_fee));
    line("WALLETD REQUEST ID:", &format!("{:?}", prepared.walletd_request_id));
    assert_eq!(
        prepared.phase, "WAITING_FOR_WALLET_APPROVAL",
        "dry run must stop at wallet approval and never submit"
    );
    assert!(
        prepared.transaction_id.is_none(),
        "dry run must not produce a transaction id"
    );
    let estimated = prepared
        .estimated_required_fee
        .expect("dry run must yield a fee estimate");
    assert!(estimated > 0, "fee estimate must be positive");
    assert!(
        estimated <= max_fee,
        "dry-run estimate {estimated} exceeds the authorized maximum fee {max_fee}; \
         raise PRIVATE_BALLOT_V2_MAX_FEE rather than letting the network reject it"
    );
    assert_eq!(
        prepared.selected_max_fee,
        Some(max_fee),
        "the final transaction fee must be the operator-authorized cap, not the estimate"
    );
    println!();

    // ---- PHASE 7: approve + submit ----------------------------------------
    // The production state machine only submits from the APPROVED arm once
    // walletd reports the request as `Approved`; between the approve decision and
    // that readiness the request is still sealing. Poll until the transaction id
    // appears, then keep polling to a terminal state.
    let mut state = step("approve");
    assert_eq!(state.phase, "APPROVED", "approve must not itself fail");
    println!();
    println!("== SUBMISSION ==");
    line("PHASE AFTER APPROVE:", &state.phase);

    let mut tx_id: Option<String> = None;
    for attempt in 1..=POLL_ATTEMPTS {
        if attempt > 1 {
            std::thread::sleep(POLL_INTERVAL);
            state = step("none");
        }
        if let Some(id) = state.transaction_id.clone() {
            tx_id = Some(id);
        }
        line(&format!("POLL {attempt}:"), &state.phase);
        match state.phase.as_str() {
            "RECEIPT_VERIFIED" | "FAILED" | "REJECTED" => {
                println!("(terminal after {attempt} step(s))");
                break;
            }
            "APPROVED" | "POLLING_RECEIPT" => {}
            other => panic!("unexpected V2 lifecycle phase {other}"),
        }
        if tx_id.is_some() && state.phase == "RECEIPT_VERIFIED" {
            break;
        }
    }
    line("TERMINAL PHASE:", &state.phase);
    line("RECEIPT VERIFIED:", &state.receipt_verified.to_string());
    assert_eq!(
        state.phase, "RECEIPT_VERIFIED",
        "transaction did not reach a committed, receipt-verified terminal state"
    );
    assert!(state.receipt_verified);
    let tx_id = tx_id.unwrap_or_else(|| {
        state
            .transaction_id
            .clone()
            .expect("a verified receipt must carry a transaction id")
    });
    assert_eq!(state.transaction_id.as_deref(), Some(tx_id.as_str()));
    println!();

    // ---- PHASE 8: readback + independent digest oracle ---------------------
    let evidence = read_v2_public_anchor_evidence_file(Path::new(&state.evidence_path))
        .expect("read back V2 anchor evidence");
    println!("== READBACK ==");
    line("TX ID:", &evidence.transaction_id);
    line("TEMPLATE ADDRESS:", &evidence.template_address);
    line("EVENT TOPIC:", &evidence.template_topic);
    line("OBSERVED ANCHOR DIGEST:", &evidence.anchor_digest_hex);
    assert_eq!(evidence.transaction_id, tx_id);
    assert_eq!(evidence.network, network_id);
    assert_eq!(evidence.template_address, template_address);

    // Independent recomputation from the original synthetic inputs: decode the
    // exact on-chain bytes and re-derive the digest from scratch.
    let payload_bytes = decode_hex(&evidence.payload_hex);
    assert_eq!(
        payload_bytes,
        built.public_summary_json.as_bytes(),
        "read-back payload must equal the submitted public summary byte-for-byte"
    );
    let reparsed = OotleAnchorPublicPayloadV2::from_canonical_json_bytes(&payload_bytes)
        .expect("decode read-back payload");
    let recomputed = reparsed
        .canonical_digest(&Blake3HashProviderV1)
        .expect("recompute V2 anchor digest");
    let recomputed_hex: String = recomputed.iter().map(|b| format!("{b:02x}")).collect();
    line("RECOMPUTED DIGEST:", &recomputed_hex);
    line("EXPECTED DIGEST:", &built.v2_anchor_digest_hex);
    assert_eq!(
        recomputed_hex, built.v2_anchor_digest_hex,
        "independently recomputed digest must equal the expected digest"
    );
    assert_eq!(
        evidence.anchor_digest_hex, recomputed_hex,
        "observed on-chain anchor digest must equal the independently recomputed digest"
    );

    // ---- PHASE 9: cleanup ---------------------------------------------------
    let _ = unlock_trusted_ootle_deployment_v2(&app_data, true);
    assert!(
        !load_trusted_ootle_deployment_v2(&app_data)
            .expect("reload after unlock")
            .locked,
        "temporary trusted deployment must be removed"
    );

    println!();
    println!("== FINAL VERDICT ==");
    line("DRY RUN:", "PASS");
    line("SUBMISSION:", "COMMITTED");
    line("TX ID:", &tx_id);
    line("READBACK:", "PASS");
    line("DIGEST MATCH:", "PASS");
    line("TEMP CLEANUP:", "PASS");
    println!();
    println!("LIVE V2 ANCHOR: PASS");
}