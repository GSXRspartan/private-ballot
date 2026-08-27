//! Shared-layer live-publication security tests (Codex remediation).
//!
//! These prove the SHARED [`AnchorAppDriver`] enforces, before ANY walletd or
//! indexer transport call, the privacy floor (HIGH-4), the loopback endpoint
//! policy (HIGH-3), and the archive-containment guard (HIGH-2); that the
//! walletd bearer token never lands in any persisted artifact (HIGH-3); and
//! that stepped receipt polling honors the same persisted backoff as the looped
//! driver across immediate re-calls and a restart (MEDIUM-1). Every scenario is
//! offline and deterministic (scripted transports, no socket).

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(feature = "test-support")]

mod common;

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use tari_cc_private_ballot_anchor::OotleAnchorRecordV1;
use tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1;
use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, AnchorLiveApprovalFactsV1, DriverError, OperatorDecision,
    VerifiedRuntimeArchiveFactsV1, create_intent,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerEndpoint, IndexerReceiptNetworkAdapter, NetworkAdapterConfig, ScriptedIndexerTransport,
    ScriptedWalletdResponse, ScriptedWalletdTransport, TransportError, TransportErrorCategory,
    WalletdAnchorNetworkAdapter, WalletdAuthSecret, WalletdEndpoint,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use common::*;

const LOOPBACK_WALLETD: &str = "http://127.0.0.1:12009";
const LOOPBACK_INDEXER: &str = "http://127.0.0.1:12500";

#[allow(clippy::too_many_arguments)]
fn live_config_with(
    accepted: u64,
    floor: u64,
    walletd_ep: &str,
    indexer_ep: &str,
    snapshot: PathBuf,
    evidence: PathBuf,
    backoff_base: u64,
    backoff_cap: u64,
) -> AnchorAppConfig {
    let facts = AnchorLiveApprovalFactsV1::new(
        accepted,
        floor,
        false,
        false,
        DECLARED_SEAL_PUBLIC_KEY.to_owned(),
        true,
        true,
    )
    .expect("live approval facts must construct");
    let adapter = NetworkAdapterConfig::new(
        canonical_network(),
        WalletdEndpoint::parse(walletd_ep).expect("walletd endpoint must parse"),
        IndexerEndpoint::parse(indexer_ep).expect("indexer endpoint must parse"),
        fee_component(),
        seal_signer(),
        max_fee(),
        Some(30),
        8,
        None,
    )
    .expect("network adapter must construct");
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        adapter,
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snapshot,
        evidence,
        backoff_base,
        backoff_cap,
        None,
        facts,
    )
    .with_event_template_binding(template_binding(), SCENARIO_MAX_EPOCH_DELTA)
    .expect("event template binding must attach")
}

fn scripted_driver(
    config: AnchorAppConfig,
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("runtime facts must derive from live config");
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    AnchorAppDriver::new(config, walletd_adapter, indexer_adapter)
        .expect("driver must construct")
        .with_runtime_archive_for_test(runtime)
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn config_with_fee(fee: u64) -> AnchorAppConfig {
    let facts = AnchorLiveApprovalFactsV1::new(
        2,
        2,
        false,
        false,
        DECLARED_SEAL_PUBLIC_KEY.to_owned(),
        true,
        true,
    )
    .expect("facts");
    let adapter = NetworkAdapterConfig::new(
        canonical_network(),
        WalletdEndpoint::parse(LOOPBACK_WALLETD).expect("walletd"),
        IndexerEndpoint::parse(LOOPBACK_INDEXER).expect("indexer"),
        fee_component(),
        seal_signer(),
        AnchorMaxFeeV1::from_units(fee),
        Some(30),
        8,
        None,
    )
    .expect("adapter");
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        adapter,
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_network(),
        snapshot_path(),
        evidence_path(),
        1,
        1,
        None,
        facts,
    )
    .with_event_template_binding(template_binding(), SCENARIO_MAX_EPOCH_DELTA)
    .expect("event template binding must attach")
}

fn anchor_digest(config: &AnchorAppConfig) -> [u8; 32] {
    *OotleAnchorRecordV1::new(
        config.anchor_record_network().clone(),
        config.archive_manifest_hash(),
        config.archive_hash(),
    )
    .canonical_hash(&Blake3HashProviderV1)
    .expect("anchor digest must derive")
    .as_bytes()
}

// ---------------------------------------------------------------------------
// MEDIUM-3 — the fee policy does not affect the canonical anchor digest
// ---------------------------------------------------------------------------

#[test]
fn max_fee_does_not_alter_the_anchor_digest() {
    let low = config_with_fee(1_000);
    let high = config_with_fee(5_000_000);
    assert_ne!(
        low.network_adapter().max_fee().value(),
        high.network_adapter().max_fee().value()
    );
    // The anchor-record digest commits to network + manifest hash + archive
    // hash only, so a different (but valid) fee budget yields the SAME digest.
    assert_eq!(anchor_digest(&low), anchor_digest(&high));
}

// ---------------------------------------------------------------------------
// HIGH-4 — shared privacy floor
// ---------------------------------------------------------------------------

#[test]
fn shared_privacy_floor_blocks_below_two_step_with_zero_transport() {
    let config = live_config_with(
        1,
        1,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    );
    let error = driver
        .run_single_step(OperatorDecision::Approve)
        .expect_err("a one-ballot cohort must be blocked");
    assert_eq!(error, DriverError::PrivacyFloorNotMet);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
    assert_eq!(driver.walletd_adapter().transport().submit_calls(), 0);
}

#[test]
fn shared_privacy_floor_blocks_below_two_run_with_zero_transport() {
    // The looped `run` entry point (used by the CLI) is bound identically.
    let config = live_config_with(
        1,
        1,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    );
    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("CLI run path must be blocked below the floor");
    assert_eq!(error, DriverError::PrivacyFloorNotMet);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
}

#[test]
fn two_accepted_ballots_pass_the_floor_and_prepare() {
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config.clone(),
        happy_walletd_transport(),
        not_found_indexer_transport(),
    );
    driver
        .run_single_step(OperatorDecision::Approve)
        .expect("a two-ballot cohort must pass the floor and prepare");
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 1);
    assert!(
        !create_intent::exists(config.snapshot_path()).expect("intent path must be readable"),
        "the intent clears only after the prepared snapshot is durable"
    );
}

// ---------------------------------------------------------------------------
// HIGH-3 — loopback endpoint policy
// ---------------------------------------------------------------------------

#[test]
fn non_loopback_walletd_endpoint_blocks_before_transport() {
    let config = live_config_with(
        2,
        2,
        "http://10.0.0.5:12009",
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    );
    let error = driver
        .run_single_step(OperatorDecision::Approve)
        .expect_err("a remote walletd endpoint must be rejected");
    assert_eq!(error, DriverError::NonLoopbackEndpoint);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
}

#[test]
fn non_loopback_indexer_endpoint_blocks_before_transport() {
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        "https://indexer.example.com:443",
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    );
    let error = driver
        .run_single_step(OperatorDecision::Approve)
        .expect_err("a remote indexer endpoint must be rejected");
    assert_eq!(error, DriverError::NonLoopbackEndpoint);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
}

// ---------------------------------------------------------------------------
// HIGH-2 — archive containment
// ---------------------------------------------------------------------------

#[test]
fn snapshot_inside_archive_blocks_before_transport() {
    let archive = tmp_path(&format!("contain-archive-{}", unique_id()));
    let snapshot_inside = archive.join("anchor-snapshot.cbor");
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_inside,
        evidence_path(),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    )
    .with_archive_dir_for_test(archive);
    let error = driver
        .run_single_step(OperatorDecision::Approve)
        .expect_err("an output inside the archive must be rejected");
    assert_eq!(error, DriverError::OutputPathWithinArchive);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
}

#[test]
fn evidence_inside_archive_blocks_before_transport() {
    let archive = tmp_path(&format!("contain-archive-ev-{}", unique_id()));
    let evidence_inside = archive.join("sub").join("anchor-evidence.cbor");
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_inside,
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    )
    .with_archive_dir_for_test(archive);
    let error = driver
        .run_single_step(OperatorDecision::Approve)
        .expect_err("nested evidence inside the archive must be rejected");
    assert_eq!(error, DriverError::OutputPathWithinArchive);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
}

#[test]
fn sibling_outputs_next_to_archive_are_accepted() {
    // The default detached sidecar layout writes siblings NEXT TO the archive
    // directory; these must pass containment and proceed to prepare.
    let base = tmp_path(&format!("contain-sibling-{}", unique_id()));
    let archive = base.join("archive");
    std::fs::create_dir_all(&archive).expect("archive dir must create");
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        base.join("archive-anchor-snapshot.cbor"),
        base.join("archive-anchor-evidence.cbor"),
        1,
        1,
    );
    let mut driver = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    )
    .with_archive_dir_for_test(archive);
    driver
        .run_single_step(OperatorDecision::Approve)
        .expect("sibling outputs must be accepted and prepare");
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 1);
}

// ---------------------------------------------------------------------------
// HIGH-3 — walletd bearer secret is never persisted
// ---------------------------------------------------------------------------

#[test]
fn walletd_bearer_token_never_persisted_in_any_artifact() {
    const TOKEN: &str = "super-secret-walletd-bearer-token-DO-NOT-LEAK-9f8e7d6c";
    let base = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let snapshot = base.snapshot_path().to_path_buf();
    let evidence = base.evidence_path().to_path_buf();
    let config = base
        .with_walletd_auth(Some(
            WalletdAuthSecret::new(TOKEN.to_owned()).expect("auth secret must construct"),
        ))
        .expect("config with auth must reconstruct");

    let mut driver = scripted_driver(
        config.clone(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&canonical_transaction_id())),
    );
    let mut reached_terminal = false;
    for _ in 0..12 {
        let step = driver
            .run_single_step(OperatorDecision::Approve)
            .expect("scripted step must succeed");
        if step.outcome.is_some() {
            reached_terminal = true;
            break;
        }
    }
    assert!(reached_terminal, "scripted lifecycle must terminate");

    // The canonical config never serializes auth.
    let config_bytes = config.to_canonical_bytes().expect("config bytes");
    assert!(!bytes_contain(&config_bytes, TOKEN.as_bytes()));
    // Neither the durable snapshot nor the terminal evidence carries the token.
    let snapshot_bytes = std::fs::read(&snapshot).expect("snapshot file must read");
    assert!(!bytes_contain(&snapshot_bytes, TOKEN.as_bytes()));
    let evidence_bytes = std::fs::read(&evidence).expect("evidence file must read");
    assert!(!bytes_contain(&evidence_bytes, TOKEN.as_bytes()));

    // The secret redacts its Debug and does not leak through error Display.
    let secret = WalletdAuthSecret::new(TOKEN.to_owned()).expect("auth secret must construct");
    assert!(!format!("{secret:?}").contains(TOKEN));
    for error in [
        DriverError::PrivacyFloorNotMet,
        DriverError::NonLoopbackEndpoint,
        DriverError::OutputPathWithinArchive,
        DriverError::PublishLockBusy,
    ] {
        assert!(!error.to_string().contains(TOKEN));
    }
}

// ---------------------------------------------------------------------------
// HIGH-1 — walletd create is fail-closed after an uncertain response
// ---------------------------------------------------------------------------

#[test]
fn uncertain_create_response_persists_intent_and_restart_never_creates_again() {
    let terminal_root = tmp_path(&format!("create-unknown-lock-{}", unique_id()));
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut lost_response = happy_walletd_transport();
    // The scripted transport records the create call, then deliberately loses
    // the response exactly like a side effect followed by a timeout.
    lost_response.set_create_response(ScriptedWalletdResponse::CreateError(
        TransportError::from_category(TransportErrorCategory::Timeout),
    ));
    let mut first = scripted_driver(config.clone(), lost_response, not_found_indexer_transport())
        .with_terminal_index_root_for_test(terminal_root.clone());

    let error = first
        .run_single_step(OperatorDecision::Approve)
        .expect_err("lost create response must not look retryable");
    assert_eq!(error.as_str(), "WALLETD_SUBMIT_TIMEOUT");
    assert_eq!(first.walletd_adapter().transport().create_calls(), 1);
    assert!(
        create_intent::exists(config.snapshot_path()).expect("intent path must be readable"),
        "intent must survive before the create response is known"
    );
    let intent = std::fs::read(create_intent::create_intent_path(config.snapshot_path()))
        .expect("durable intent must read");
    let intent_text = String::from_utf8(intent).expect("intent is bounded UTF-8 metadata");
    for required in [
        "project_request_id=",
        "manifest_hash=",
        "archive_hash=",
        "anchor_digest=",
        "transaction_fingerprint=",
        "max_fee_units=",
    ] {
        assert!(
            intent_text.contains(required),
            "intent must retain {required}"
        );
    }

    // Process-equivalent reconstruction starts from the same durable intent.
    // It never reaches the new transport's create counter.
    let mut restarted = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(terminal_root);
    let restart_error = restarted
        .run_single_step(OperatorDecision::Approve)
        .expect_err("unknown create must require operator reconciliation");
    assert_eq!(restart_error, DriverError::CreateRecoveryRequired);
    assert_eq!(restarted.walletd_adapter().transport().create_calls(), 0);
}

#[test]
fn explicit_create_noncreation_error_clears_intent_and_allows_one_safe_retry() {
    let terminal_root = tmp_path(&format!("create-rejected-lock-{}", unique_id()));
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut refused = happy_walletd_transport();
    // A server NotFound response is an explicit non-creation outcome, unlike a
    // timeout or connection loss. It is safe to clear the intent and retry.
    refused.set_create_response(ScriptedWalletdResponse::CreateError(
        TransportError::from_category(TransportErrorCategory::NotFound),
    ));
    let mut first = scripted_driver(config.clone(), refused, not_found_indexer_transport())
        .with_terminal_index_root_for_test(terminal_root.clone());
    let error = first
        .run_single_step(OperatorDecision::Approve)
        .expect_err("explicit refusal must surface");
    assert_eq!(error.as_str(), "WALLETD_REQUEST_NOT_FOUND");
    assert_eq!(first.walletd_adapter().transport().create_calls(), 1);
    assert!(
        !create_intent::exists(config.snapshot_path()).expect("intent path must be readable"),
        "a proven non-creation must leave retry possible"
    );

    let mut retried = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(terminal_root);
    retried
        .run_single_step(OperatorDecision::Approve)
        .expect("a proven non-creation must permit a normal retry");
    assert_eq!(retried.walletd_adapter().transport().create_calls(), 1);
}

#[test]
fn concurrent_retry_after_uncertain_create_cannot_issue_a_second_create() {
    let terminal_root = tmp_path(&format!("create-concurrent-lock-{}", unique_id()));
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut uncertain = happy_walletd_transport();
    uncertain.set_create_response(ScriptedWalletdResponse::CreateError(
        TransportError::from_category(TransportErrorCategory::Timeout),
    ));
    let mut first = scripted_driver(config.clone(), uncertain, not_found_indexer_transport())
        .with_terminal_index_root_for_test(terminal_root.clone());
    let _ = first.run_single_step(OperatorDecision::Approve);
    assert_eq!(first.walletd_adapter().transport().create_calls(), 1);

    let mut racing_retry = scripted_driver(
        config,
        happy_walletd_transport(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(terminal_root);
    assert_eq!(
        racing_retry.run_single_step(OperatorDecision::Approve),
        Err(DriverError::CreateRecoveryRequired)
    );
    assert_eq!(racing_retry.walletd_adapter().transport().create_calls(), 0);
}

// ---------------------------------------------------------------------------
// MEDIUM-1 — stepped receipt-poll backoff is enforced and persisted
// ---------------------------------------------------------------------------

fn poll_calls(driver: &AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport>) -> u64 {
    driver.indexer_adapter().transport().receipt_calls()
        + driver.indexer_adapter().transport().result_calls()
}

#[test]
fn stepped_poll_honors_persisted_backoff_across_immediate_calls_and_restart() {
    let terminal_root = tmp_path(&format!("mediumone-termroot-{}", unique_id()));
    // A 30s backoff makes the gate reliably active for the immediate re-call.
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        30,
        30,
    );

    let mut driver = scripted_driver(
        config.clone(),
        happy_walletd_transport(),
        pending_indexer_transport(),
    )
    .with_terminal_index_root_for_test(terminal_root.clone());

    // prepare, approve, submit
    for _ in 0..3 {
        driver
            .run_single_step(OperatorDecision::Approve)
            .expect("lifecycle step must advance");
    }
    // First poll: consumes one receipt attempt and arms the backoff gate.
    let first_poll = driver
        .run_single_step(OperatorDecision::Approve)
        .expect("first poll must run");
    assert!(first_poll.outcome.is_none());
    assert!(first_poll.next_backoff_secs.is_some());
    let after_first = poll_calls(&driver);
    assert!(after_first >= 1, "the first poll must reach the indexer");

    // Immediate re-call: the gate returns a bounded retry-after WITHOUT polling
    // and WITHOUT consuming another attempt.
    let gated = driver
        .run_single_step(OperatorDecision::Approve)
        .expect("gated step must succeed");
    assert!(gated.outcome.is_none());
    assert!(gated.next_backoff_secs.is_some());
    assert_eq!(
        poll_calls(&driver),
        after_first,
        "a premature step must not poll the transport"
    );

    // Restart: a brand-new driver with a FRESH transport still respects the
    // persisted deadline and does not poll.
    let mut restarted = scripted_driver(
        config.clone(),
        happy_walletd_transport(),
        pending_indexer_transport(),
    )
    .with_terminal_index_root_for_test(terminal_root);
    let after_restart_step = restarted
        .run_single_step(OperatorDecision::Approve)
        .expect("restart step must succeed");
    assert!(after_restart_step.outcome.is_none());
    assert!(after_restart_step.next_backoff_secs.is_some());
    assert_eq!(
        poll_calls(&restarted),
        0,
        "a restart must honor the persisted backoff and not poll"
    );
}

#[test]
fn looped_run_waits_for_a_gate_persisted_by_single_step_before_polling() {
    let terminal_root = tmp_path(&format!("mediumone-cross-mode-{}", unique_id()));
    // One second keeps the wall-clock assertion bounded while making an early
    // poll distinguishable from honoring the persisted not-before deadline.
    let config = live_config_with(
        2,
        2,
        LOOPBACK_WALLETD,
        LOOPBACK_INDEXER,
        snapshot_path(),
        evidence_path(),
        1,
        1,
    );
    let mut stepped = scripted_driver(
        config.clone(),
        happy_walletd_transport(),
        pending_indexer_transport(),
    )
    .with_terminal_index_root_for_test(terminal_root.clone());
    for _ in 0..3 {
        stepped
            .run_single_step(OperatorDecision::Approve)
            .expect("prepare, approve, and submit must advance");
    }
    stepped
        .run_single_step(OperatorDecision::Approve)
        .expect("first poll must persist the gate");
    let attempts_before = stepped.snapshot().policy().attempts_consumed();
    assert_eq!(attempts_before, 1);

    // A reconstructed looped caller receives a final receipt after the gate.
    // It must wait first, then consume exactly the next receipt attempt.
    let mut restarted = scripted_driver(
        config,
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&canonical_transaction_id())),
    )
    .with_terminal_index_root_for_test(terminal_root);
    let started = Instant::now();
    let outcome = restarted
        .run(OperatorDecision::Approve)
        .expect("looped run must honor then pass the persisted gate");
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "run() must not issue its first post-restart poll before the gate"
    );
    assert!(matches!(
        outcome,
        tari_cc_private_ballot_ootle_anchor_app::DriverRunOutcome::FinalizedAccept(_)
    ));
    assert_eq!(restarted.snapshot().policy().attempts_consumed(), 2);
}
