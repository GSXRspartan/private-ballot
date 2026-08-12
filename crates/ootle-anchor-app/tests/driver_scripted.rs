//! Driver scripted integration tests (Slice 4A10 §16.4).
//!
//! Every scenario drives [`AnchorAppDriver`] through the Slice 4A9 scripted
//! transports. No socket is opened, no real walletd or indexer is contacted,
//! and no transaction is submitted to a live network.

mod common;

use tari_cc_private_ballot_ootle_anchor_app::{
    AnchorAppConfig, AnchorAppDriver, AnchorConfigInputProvenanceV1, AnchorEvidenceRecordV1,
    AnchorLiveApprovalFactsV1, ArchiveProofInputs, DriverError, DriverRunOutcome,
    FEE_COMPONENT_ASSURANCE_VERIFIED, LiveEvidenceApprovalFactsV1, OperatorDecision,
    SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED, SnapshotFileError, TerminalEvidenceInputs,
    TerminalIndexError, VerifiedRuntimeArchiveFactsV1, read_snapshot, terminal_index_path,
    write_snapshot_atomic,
};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerTransport, ScriptedWalletdResponse,
    ScriptedWalletdTransport, TransportError, TransportErrorCategory, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdSubmissionStateV1;

use common::*;

fn build_driver(
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let config = live_config();
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver.with_runtime_archive_for_test(runtime),
        Err(error) => panic!("driver construction failed: {error}"),
    }
}

fn build_driver_with_config(
    config: AnchorAppConfig,
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config).ok();
    match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => match runtime {
            Some(runtime) => driver.with_runtime_archive_for_test(runtime),
            None => driver,
        },
        Err(error) => panic!("driver construction failed: {error}"),
    }
}

fn build_driver_without_runtime(
    config: AnchorAppConfig,
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver,
        Err(error) => panic!("driver construction failed: {error}"),
    }
}

fn config_for_archive(archive_byte: u8) -> AnchorAppConfig {
    AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter(),
        canonical_account(),
        canonical_manifest_hash(),
        archive_hash(archive_byte),
        canonical_network(),
        snapshot_path(),
        evidence_path(),
        1,
        1,
        None,
        live_approval_facts(),
    )
}

fn terminal_index_root(name: &str) -> std::path::PathBuf {
    let root = tmp_path(&format!("terminal-index-{name}-{}", unique_id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("terminal-index test root");
    root
}

#[cfg(any(unix, windows))]
fn symlink_file_for_test(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
}

fn run(
    walletd: ScriptedWalletdTransport,
    indexer: ScriptedIndexerTransport,
    decision: OperatorDecision,
) -> (
    AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport>,
    DriverRunOutcome,
) {
    let mut driver = build_driver(walletd, indexer);
    let outcome = match driver.run(decision) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    (driver, outcome)
}

#[cfg(feature = "offline-test-raw-hashes")]
#[test]
fn offline_test_raw_hashes_config_rejected_before_prepare() {
    let config =
        tari_cc_private_ballot_ootle_anchor_app::AnchorAppConfig::new_offline_test_raw_hashes(
            network_adapter(),
            canonical_account(),
            canonical_manifest_hash(),
            canonical_archive_hash(),
            canonical_network(),
            snapshot_path(),
            evidence_path(),
            1,
            1,
            None,
        );
    let walletd_adapter =
        WalletdAnchorNetworkAdapter::new(happy_walletd_transport(), canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(finalized_indexer_transport(
        accepted_receipt(&canonical_transaction_id()),
    ));
    let mut driver =
        AnchorAppDriver::new(config, walletd_adapter, indexer_adapter).expect("driver constructs");

    let error = driver
        .run(OperatorDecision::NoDecision)
        .expect_err("raw-hash config must be rejected");

    assert_eq!(error, DriverError::OfflineTestRawHashesNotLiveApproved);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
}

#[test]
fn happy_path_finalized_accept() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    match outcome {
        DriverRunOutcome::FinalizedAccept(evidence) => {
            assert_eq!(evidence.final_status(), "ACCEPTED");
            assert_eq!(evidence.receipt_source(), "INDEPENDENT_INDEXER");
        }
        other => panic!("expected FinalizedAccept, got {other:?}"),
    }
}

#[test]
fn live_evidence_binds_approval_facts_and_assurance_levels() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("live-evidence-facts");
    let mut driver = build_driver_with_config(
        live_config(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(root);

    let outcome = driver
        .run(OperatorDecision::Approve)
        .expect("live terminal accept");
    let DriverRunOutcome::FinalizedAccept(evidence) = outcome else {
        panic!("expected finalized accept");
    };
    let facts = evidence
        .live_approval_facts()
        .expect("live evidence must bind approval facts");

    assert_eq!(
        facts.input_provenance(),
        AnchorConfigInputProvenanceV1::ArchiveVerified
    );
    assert!(facts.finalized_archive());
    assert_eq!(facts.accepted_ballot_count(), 2);
    assert_eq!(facts.required_accepted_ballot_floor(), 2);
    assert!(!facts.reduced_anonymity());
    assert!(!facts.reduced_anonymity_acknowledged());
    assert_eq!(facts.fee_component(), fee_component().display_string());
    assert_eq!(
        facts.fee_component_assurance(),
        FEE_COMPONENT_ASSURANCE_VERIFIED
    );
    assert_eq!(facts.declared_seal_public_key(), DECLARED_SEAL_PUBLIC_KEY);
    assert_eq!(
        facts.seal_public_key_assurance(),
        SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED
    );
    assert_ne!(facts.seal_public_key_assurance(), "VERIFIED");
    assert!(facts.dedicated_organizer_wallet_attested());
    let expected_fingerprint = *driver
        .snapshot()
        .walletd_snapshots()
        .first()
        .expect("walletd snapshot")
        .binding()
        .fingerprint()
        .as_bytes();
    assert_eq!(facts.transaction_fingerprint(), expected_fingerprint);

    let summary = evidence.human_review_summary();
    assert!(summary.contains("fee_component_assurance=VERIFIED"));
    assert!(summary.contains("seal_public_key_assurance=ATTESTED"));
    assert!(!summary.contains("seal_public_key_assurance=VERIFIED"));

    let canonical_text =
        String::from_utf8_lossy(evidence.canonical_bytes().as_ref()).to_lowercase();
    assert!(!canonical_text.contains("voter"));
    assert!(!canonical_text.contains("nullifier"));
    assert!(!canonical_text.contains("registry"));
    assert!(!canonical_text.contains("secret"));
}

#[test]
fn v2_archive_verified_config_without_runtime_archive_rejected_before_prepare() {
    let tx = canonical_transaction_id();
    let mut driver = build_driver_with_config(
        base_config(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(terminal_index_root("missing-live-facts"));
    let prepares_before = driver.walletd_adapter().transport().create_calls();
    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("archive-verified V2 config must require runtime archive facts");
    let prepares_after = driver.walletd_adapter().transport().create_calls();

    assert_eq!(prepares_before, prepares_after);
    assert_eq!(error, DriverError::RuntimeArchiveRequired);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
}

#[test]
fn live_config_without_runtime_archive_rejected_before_prepare() {
    let tx = canonical_transaction_id();
    let mut driver = build_driver_without_runtime(
        live_config(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    );
    let prepares_before = driver.walletd_adapter().transport().create_calls();
    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("live config must require runtime archive facts");
    let prepares_after = driver.walletd_adapter().transport().create_calls();

    assert_eq!(prepares_before, prepares_after);
    assert_eq!(error, DriverError::RuntimeArchiveRequired);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
}

#[test]
fn self_consistent_archive_verified_config_without_archive_cannot_prepare() {
    let tx = canonical_transaction_id();
    let mut driver = build_driver_without_runtime(
        config_for_archive(0x99),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    );
    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("hand-authored live config without archive must fail closed");

    assert_eq!(error, DriverError::RuntimeArchiveRequired);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
}

#[test]
fn runtime_archive_config_swap_mismatch_rejected_before_prepare() {
    let tx = canonical_transaction_id();
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&live_config())
        .expect("canonical runtime facts");
    let mut driver = build_driver_without_runtime(
        config_for_archive(0x99),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_runtime_archive_for_test(runtime);
    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("runtime facts must match config exactly");

    assert_eq!(error, DriverError::RuntimeArchiveBindingMismatch);
    assert_eq!(driver.walletd_adapter().transport().create_calls(), 0);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
}

#[test]
fn live_approval_facts_reject_missing_policy_acknowledgements() {
    assert!(matches!(
        AnchorLiveApprovalFactsV1::new(
            2,
            2,
            false,
            false,
            DECLARED_SEAL_PUBLIC_KEY.to_owned(),
            false,
            true,
        ),
        Err(tari_cc_private_ballot_ootle_anchor_app::ConfigFileError::InvalidData)
    ));
    assert!(matches!(
        AnchorLiveApprovalFactsV1::new(
            2,
            2,
            true,
            false,
            DECLARED_SEAL_PUBLIC_KEY.to_owned(),
            true,
            true,
        ),
        Err(tari_cc_private_ballot_ootle_anchor_app::ConfigFileError::InvalidData)
    ));
}

#[test]
fn mutating_live_approval_facts_changes_evidence_digest() {
    let archive = ArchiveProofInputs::new(
        canonical_network(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        canonical_anchor_digest(),
    );
    let snapshot_digest = [0x66; 32];
    let first_facts = LiveEvidenceApprovalFactsV1::from_config(
        AnchorConfigInputProvenanceV1::ArchiveVerified,
        &live_approval_facts(),
        fee_component().display_string(),
        [FINGERPRINT_BYTE; 32],
    )
    .expect("first facts");
    let second_facts = LiveEvidenceApprovalFactsV1::from_config(
        AnchorConfigInputProvenanceV1::ArchiveVerified,
        &reduced_live_approval_facts(),
        fee_component().display_string(),
        [FINGERPRINT_BYTE; 32],
    )
    .expect("second facts");

    let first = AnchorEvidenceRecordV1::from_terminal_outcome_with_live_approval_facts(
        &archive,
        TerminalEvidenceInputs::RejectedByApprover,
        &snapshot_digest,
        first_facts,
    )
    .expect("first evidence");
    let second = AnchorEvidenceRecordV1::from_terminal_outcome_with_live_approval_facts(
        &archive,
        TerminalEvidenceInputs::RejectedByApprover,
        &snapshot_digest,
        second_facts,
    )
    .expect("second evidence");

    assert_ne!(first.digest(), second.digest());
    let decoded = AnchorEvidenceRecordV1::from_canonical_bytes(first.canonical_bytes().as_ref())
        .expect("live evidence must decode");
    assert_eq!(decoded, first);
}

#[test]
fn terminal_index_same_anchor_accept_is_idempotent_without_new_prepare() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("same-anchor");
    let config = live_config();
    let original_evidence_path = config.evidence_path().to_owned();
    let mut first = build_driver_with_config(
        config,
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(root.clone());
    let first_outcome = first
        .run(OperatorDecision::Approve)
        .expect("first terminal accept");
    assert!(matches!(
        first_outcome,
        DriverRunOutcome::FinalizedAccept(_)
    ));
    assert!(original_evidence_path.exists());

    let second_config = live_config();
    let changed_evidence_path = second_config.evidence_path().to_owned();
    let mut second = build_driver_with_config(
        second_config,
        ScriptedWalletdTransport::new(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(root);
    let prepares_before = second.walletd_adapter().transport().create_calls();
    let submits_before = second.walletd_adapter().transport().submit_calls();
    let second_outcome = second
        .run(OperatorDecision::Approve)
        .expect("same anchor accepted from terminal index");
    let prepares_after = second.walletd_adapter().transport().create_calls();
    let submits_after = second.walletd_adapter().transport().submit_calls();

    assert_eq!(prepares_before, prepares_after);
    assert_eq!(submits_before, submits_after);
    assert_eq!(second.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
    match second_outcome {
        DriverRunOutcome::FinalizedAccept(evidence) => {
            assert_eq!(evidence.final_status(), "ACCEPTED");
            assert_eq!(evidence.anchor_digest(), canonical_anchor_digest());
        }
        other => panic!("expected terminal-index accept, got {other:?}"),
    }
    assert!(
        !changed_evidence_path.exists(),
        "changed evidence path must not receive copied terminal evidence"
    );
}

#[test]
fn terminal_index_same_anchor_accept_is_idempotent_with_different_cwd() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("different-cwd");
    let mut first = build_driver_with_config(
        live_config(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(root.clone());
    first
        .run(OperatorDecision::Approve)
        .expect("first terminal accept");

    let new_cwd = tmp_path(&format!("cwd-{}", unique_id()));
    let original_cwd = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(&new_cwd).expect("set test cwd");
    let mut second = build_driver_with_config(
        live_config(),
        ScriptedWalletdTransport::new(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(root);
    let prepares_before = second.walletd_adapter().transport().create_calls();
    let outcome = second.run(OperatorDecision::Approve);
    let prepares_after = second.walletd_adapter().transport().create_calls();
    std::env::set_current_dir(original_cwd).expect("restore cwd");

    let outcome = outcome.expect("same anchor accepted from terminal index");
    assert_eq!(prepares_before, prepares_after);
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
}

#[test]
fn terminal_index_conflicting_archive_rejected_before_prepare_even_with_new_paths() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("conflict");
    let mut first = build_driver_with_config(
        live_config(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(root.clone());
    first
        .run(OperatorDecision::Approve)
        .expect("first terminal accept");

    let mut conflicting = build_driver_with_config(
        config_for_archive(0x77),
        ScriptedWalletdTransport::new(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(root);
    let prepares_before = conflicting.walletd_adapter().transport().create_calls();
    let error = conflicting
        .run(OperatorDecision::Approve)
        .expect_err("conflicting archive must fail before prepare");
    let prepares_after = conflicting.walletd_adapter().transport().create_calls();

    assert_eq!(prepares_before, prepares_after);
    assert_eq!(
        conflicting.phase(),
        UnifiedAnchorLifecyclePhase::NotPrepared
    );
    assert_eq!(
        error,
        DriverError::TerminalIndex(TerminalIndexError::Conflict)
    );
}

#[test]
fn corrupted_terminal_index_fails_closed_before_prepare() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("corrupt");
    let mut first = build_driver_with_config(
        live_config(),
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(root.clone());
    first
        .run(OperatorDecision::Approve)
        .expect("first terminal accept");

    let path = terminal_index_path(&root, canonical_manifest_hash());
    let mut bytes = std::fs::read(&path).expect("index exists");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).expect("corrupt index");

    let mut second = build_driver_with_config(
        live_config(),
        ScriptedWalletdTransport::new(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(root);
    let prepares_before = second.walletd_adapter().transport().create_calls();
    let error = second
        .run(OperatorDecision::Approve)
        .expect_err("corrupt terminal index must fail closed");
    let prepares_after = second.walletd_adapter().transport().create_calls();

    assert_eq!(prepares_before, prepares_after);
    assert_eq!(second.phase(), UnifiedAnchorLifecyclePhase::NotPrepared);
    assert!(matches!(error, DriverError::TerminalIndex(_)));
}

#[cfg(any(unix, windows))]
#[test]
fn terminal_index_bound_evidence_symlink_fails_closed_before_prepare() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("evidence-symlink");
    let config = live_config();
    let original_evidence_path = config.evidence_path().to_owned();
    let mut first = build_driver_with_config(
        config,
        happy_walletd_transport(),
        finalized_indexer_transport(accepted_receipt(&tx)),
    )
    .with_terminal_index_root_for_test(root.clone());
    first
        .run(OperatorDecision::Approve)
        .expect("first terminal accept");

    let target_path = original_evidence_path.with_extension("target.cbor");
    std::fs::rename(&original_evidence_path, &target_path).expect("move evidence target");
    if symlink_file_for_test(&target_path, &original_evidence_path).is_err() {
        return;
    }

    let mut second = build_driver_with_config(
        live_config(),
        ScriptedWalletdTransport::new(),
        not_found_indexer_transport(),
    )
    .with_terminal_index_root_for_test(root);
    let error = second
        .run(OperatorDecision::Approve)
        .expect_err("symlinked bound evidence must fail closed");

    assert_eq!(
        error,
        DriverError::TerminalIndex(TerminalIndexError::EvidenceUnavailable)
    );
    assert_eq!(second.walletd_adapter().transport().create_calls(), 0);
}

#[test]
fn fee_only_receipt_is_non_success() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(fee_only_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(
        driver.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedFeeOnly
    );
    match outcome {
        DriverRunOutcome::FinalizedFeeOnly(evidence) => {
            assert_eq!(evidence.final_status(), "FEE_ONLY_ACCEPTED");
        }
        other => panic!("expected FinalizedFeeOnly, got {other:?}"),
    }
}

#[test]
fn rejected_receipt_is_non_success() {
    // The scripted indexer round-trips a `Finalized(rejected_receipt)` through
    // the Ootle wire `FinalizeOutcome::Commit` (an existing scripted-transport
    // behavior that must not be modified), which would surface as a
    // verification failure rather than a clean reject. The reject scenario is
    // therefore driven through `ScriptedIndexerResponse::Rejected`, which the
    // adapter maps to a finalized rejected receipt via the result-fallback
    // path.
    let _tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = common::rejected_indexer_transport();
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedReject);
    match outcome {
        DriverRunOutcome::FinalizedReject(evidence) => {
            assert_eq!(evidence.final_status(), "REJECTED");
        }
        other => panic!("expected FinalizedReject, got {other:?}"),
    }
}

#[test]
fn verification_failure_missing_anchor_log() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(missing_anchor_log_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert_eq!(
        driver.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );
    match outcome {
        DriverRunOutcome::VerificationFailed(evidence) => {
            assert_eq!(evidence.final_status(), "VERIFICATION_FAILED");
        }
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

#[test]
fn approver_rejection_stops_at_rejected_by_approver() {
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Reject);
    assert_eq!(
        driver.phase(),
        UnifiedAnchorLifecyclePhase::RejectedByApprover
    );
    match outcome {
        DriverRunOutcome::RejectedByApprover(evidence) => {
            assert_eq!(evidence.final_status(), "REJECTED_BY_APPROVER");
        }
        other => panic!("expected RejectedByApprover, got {other:?}"),
    }
}

#[test]
fn no_operator_decision_stops_at_prepared() {
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::NoDecision);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::Prepared);
    match outcome {
        DriverRunOutcome::NotYetFinalized => {}
        other => panic!("expected NotYetFinalized, got {other:?}"),
    }
}

#[test]
fn poll_exhaustion_is_non_success() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let config = exhausted_config();
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("exhausted config must provide runtime facts");
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let mut driver = match AnchorAppDriver::new(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver.with_runtime_archive_for_test(runtime),
        Err(error) => panic!("driver construction failed: {error}"),
    };
    let outcome = match driver.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    match outcome {
        DriverRunOutcome::PollExhaustedUnknown(evidence) => {
            assert_eq!(evidence.final_status(), "POLL_EXHAUSTED_UNKNOWN");
        }
        other => panic!("expected PollExhaustedUnknown, got {other:?}"),
    }
    let _ = tx;
}

fn exhausted_config() -> tari_cc_private_ballot_ootle_anchor_app::AnchorAppConfig {
    use tari_cc_private_ballot_ootle_anchor_network_adapters::NetworkAdapterConfig;
    let adapter = match NetworkAdapterConfig::new(
        canonical_network(),
        walletd_endpoint(),
        indexer_endpoint(),
        fee_component(),
        seal_signer(),
        max_fee(),
        Some(30),
        1,
        None,
    ) {
        Ok(config) => config,
        Err(_) => panic!("adapter must construct"),
    };
    tari_cc_private_ballot_ootle_anchor_app::AnchorAppConfig::new_archive_verified_with_live_approval_facts(
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
        live_approval_facts(),
    )
}

fn restore_from_snapshot(
    snapshot: &tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot,
    indexer: ScriptedIndexerTransport,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let config = live_config();
    let snap_path = config.snapshot_path().to_owned();
    match write_snapshot_atomic(&snap_path, snapshot) {
        Ok(()) => {}
        Err(error) => panic!("snapshot write failed: {error}"),
    }
    let walletd = happy_walletd_transport();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    match AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver.with_runtime_archive_for_test(runtime),
        Err(error) => panic!("restore failed: {error}"),
    }
}

fn restore_from_snapshot_with_terminal_index_root(
    snapshot: &tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot,
    indexer: ScriptedIndexerTransport,
    root: std::path::PathBuf,
) -> AnchorAppDriver<ScriptedWalletdTransport, ScriptedIndexerTransport> {
    let config = live_config();
    let snap_path = config.snapshot_path().to_owned();
    match write_snapshot_atomic(&snap_path, snapshot) {
        Ok(()) => {}
        Err(error) => panic!("snapshot write failed: {error}"),
    }
    let walletd = happy_walletd_transport();
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(indexer);
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    match AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter) {
        Ok(driver) => driver
            .with_runtime_archive_for_test(runtime)
            .with_terminal_index_root_for_test(root),
        Err(error) => panic!("restore failed: {error}"),
    }
}

#[test]
fn restart_after_submission_before_first_poll() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&submitted_snapshot(), indexer);
    let outcome = match restored.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("restored run failed: {error}"),
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => {}
        other => panic!("expected FinalizedAccept after restart, got {other:?}"),
    }
}

#[test]
fn terminal_index_absent_keeps_interrupted_recovery_supported() {
    let tx = canonical_transaction_id();
    let root = terminal_index_root("interrupted");
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored =
        restore_from_snapshot_with_terminal_index_root(&submitted_snapshot(), indexer, root);
    let submits_before = restored.walletd_adapter().transport().submit_calls();
    let outcome = restored
        .run(OperatorDecision::Approve)
        .expect("missing terminal index must allow recovery");
    let submits_after = restored.walletd_adapter().transport().submit_calls();

    assert_eq!(submits_before, submits_after);
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
}

#[test]
fn restart_mid_poll() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&polling_in_progress_snapshot(2), indexer);
    let outcome = match restored.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("restored run failed: {error}"),
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => {}
        other => panic!("expected FinalizedAccept after mid-poll restart, got {other:?}"),
    }
}

#[test]
fn restart_after_finalized_accept_is_idempotent() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&known_answer_snapshot(), indexer);
    let outcome = match restored.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("restored run failed: {error}"),
    };
    assert_eq!(
        restored.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedAccept
    );
    match outcome {
        DriverRunOutcome::FinalizedAccept(_) => {}
        other => panic!("expected FinalizedAccept idempotent, got {other:?}"),
    }
}

#[test]
fn transaction_id_remains_stable_across_restart() {
    let tx = canonical_transaction_id();
    let before = canonical_transaction_id().as_str().to_owned();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let restored = restore_from_snapshot(&submitted_snapshot(), indexer);
    let after = restored.transaction_id().map(|t| t.as_str().to_owned());
    assert_eq!(
        Some(before),
        after,
        "transaction id must remain stable across restart"
    );
}

#[test]
fn fingerprint_remains_stable_across_restart() {
    let tx = canonical_transaction_id();
    let snapshot = submitted_snapshot();
    let fingerprint_before = snapshot
        .walletd_snapshots()
        .first()
        .map(|s| s.binding().fingerprint());
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let restored = restore_from_snapshot(&snapshot, indexer);
    let fingerprint_after = restored
        .snapshot()
        .walletd_snapshots()
        .first()
        .map(|s| s.binding().fingerprint());
    assert_eq!(
        fingerprint_before, fingerprint_after,
        "fingerprint must remain stable"
    );
}

#[test]
fn no_duplicate_transaction_on_restart() {
    let tx = canonical_transaction_id();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut restored = restore_from_snapshot(&submitted_snapshot(), indexer);
    let submits_before = restored.walletd_adapter().transport().submit_calls();
    let _ = restored.run(OperatorDecision::Approve);
    let submits_after = restored.walletd_adapter().transport().submit_calls();
    assert_eq!(
        submits_before, submits_after,
        "restored driver must not resubmit an already-submitted request"
    );
}

#[test]
fn submit_timeout_persists_write_ahead_unknown_and_restart_recovers_first() {
    let config = live_config();
    let snap_path = config.snapshot_path().to_owned();
    let mut walletd = happy_walletd_transport();
    walletd.set_submit_response(ScriptedWalletdResponse::SubmitError(
        TransportError::from_category(TransportErrorCategory::Timeout),
    ));
    let mut driver =
        build_driver_with_config(config.clone(), walletd, not_found_indexer_transport());
    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("submit timeout must surface after write-ahead persistence");

    assert_eq!(error.as_str(), "WALLETD_SUBMIT_TIMEOUT");
    assert_eq!(driver.walletd_adapter().transport().submit_calls(), 1);
    let persisted = read_snapshot(&snap_path).expect("write-ahead snapshot persisted");
    assert_eq!(persisted.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    let walletd_snapshot = persisted
        .walletd_snapshots()
        .first()
        .expect("walletd snapshot persisted");
    assert_eq!(
        walletd_snapshot.submission(),
        WalletdSubmissionStateV1::TimedOutUnknown
    );

    let frozen = driver
        .walletd_adapter()
        .transport()
        .captured_create()
        .expect("prepared frozen transaction captured")
        .transaction
        .clone();
    let mut recovered_walletd = happy_walletd_transport();
    recovered_walletd.set_get_transaction(frozen);
    let walletd_adapter = WalletdAnchorNetworkAdapter::new(recovered_walletd, canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(finalized_indexer_transport(
        accepted_receipt(&canonical_transaction_id()),
    ));
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    let mut restored = AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter)
        .expect("write-ahead snapshot restores")
        .with_runtime_archive_for_test(runtime);
    let outcome = restored
        .run(OperatorDecision::Approve)
        .expect("restart must recover before polling");

    assert_eq!(restored.walletd_adapter().transport().get_calls(), 1);
    assert_eq!(restored.walletd_adapter().transport().submit_calls(), 0);
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
}

#[test]
fn write_ahead_snapshot_persistence_failure_prevents_submit() {
    let config = live_config();
    let snap_path = config.snapshot_path().to_owned();
    write_snapshot_atomic(&snap_path, &approved_snapshot())
        .unwrap_or_else(|error| panic!("approved snapshot write failed: {error}"));

    let walletd_adapter =
        WalletdAnchorNetworkAdapter::new(happy_walletd_transport(), canonical_network());
    let indexer_adapter = IndexerReceiptNetworkAdapter::new(not_found_indexer_transport());
    let runtime = VerifiedRuntimeArchiveFactsV1::matching_config_for_test(&config)
        .expect("live config must provide runtime facts");
    let mut driver = AnchorAppDriver::restore(config, walletd_adapter, indexer_adapter)
        .expect("approved snapshot restores")
        .with_runtime_archive_for_test(runtime);

    std::fs::remove_file(&snap_path)
        .unwrap_or_else(|error| panic!("replace snapshot file failed: {error}"));
    std::fs::create_dir(&snap_path)
        .unwrap_or_else(|error| panic!("snapshot path directory failed: {error}"));

    let error = driver
        .run(OperatorDecision::Approve)
        .expect_err("write-ahead persistence failure must stop before submit");

    assert_eq!(
        error,
        DriverError::Snapshot(SnapshotFileError::AtomicRenameFailure)
    );
    assert_eq!(driver.walletd_adapter().transport().submit_calls(), 0);
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::Approved);
}

#[test]
fn evidence_file_written_on_terminal_accept() {
    let config = live_config();
    let ev_path = config.evidence_path().to_owned();
    let _ = std::fs::remove_file(&ev_path);
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let mut driver = build_driver_with_config(config, walletd, indexer);
    let outcome = match driver.run(OperatorDecision::Approve) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
    assert!(
        ev_path.exists(),
        "evidence file must be written on terminal accept"
    );
    assert_eq!(driver.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

#[test]
fn snapshot_file_written_after_run() {
    let config = live_config();
    let snap_path = config.snapshot_path().to_owned();
    let _ = std::fs::remove_file(&snap_path);
    let walletd = happy_walletd_transport();
    let indexer = not_found_indexer_transport();
    let mut driver = build_driver_with_config(config, walletd, indexer);
    let outcome = match driver.run(OperatorDecision::NoDecision) {
        Ok(outcome) => outcome,
        Err(error) => panic!("driver run failed: {error}"),
    };
    assert!(matches!(outcome, DriverRunOutcome::NotYetFinalized));
    assert!(
        snap_path.exists(),
        "snapshot file must be written after run"
    );
    let _ = driver;
}

#[test]
fn snapshot_round_trip_after_run() {
    let tx = canonical_transaction_id();
    let walletd = happy_walletd_transport();
    let indexer = finalized_indexer_transport(accepted_receipt(&tx));
    let (driver, outcome) = run(walletd, indexer, OperatorDecision::Approve);
    assert!(matches!(outcome, DriverRunOutcome::FinalizedAccept(_)));
    let snapshot = driver.snapshot();
    let snap_path = snapshot_path();
    match write_snapshot_atomic(&snap_path, &snapshot) {
        Ok(()) => {}
        Err(error) => panic!("snapshot write failed: {error}"),
    }
    match tari_cc_private_ballot_ootle_anchor_app::read_snapshot(&snap_path) {
        Ok(decoded) => assert_eq!(decoded, snapshot, "snapshot must round-trip after run"),
        Err(error) => panic!("snapshot read failed: {error}"),
    }
}
