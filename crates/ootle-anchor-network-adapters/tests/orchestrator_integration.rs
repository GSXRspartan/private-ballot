mod common;

use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1;

use na::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerResponse, ScriptedWalletdResponse, TransportError,
    TransportErrorCategory, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters as na;

use common::*;

fn make_walletd() -> WalletdAnchorNetworkAdapter<na::ScriptedWalletdTransport> {
    let mut t = na::ScriptedWalletdTransport::new();
    t.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 100,
        expires_at: 1_900_000_000,
    });
    t.set_approve_response(ScriptedWalletdResponse::Approve {
        request_id: 100,
        status: WalletdEffectiveStatusV1::Approved,
    });
    t.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: transaction_id(0x44),
    });
    t.set_get_response(ScriptedWalletdResponse::Get {
        request_id: 100,
        status: WalletdEffectiveStatusV1::Submitted,
        transaction_id: Some(transaction_id(0x44)),
    });
    WalletdAnchorNetworkAdapter::new(t, network())
}

fn prepare_approve_submit(
    orch: &mut AnchorLifecycleOrchestrator,
    wd: &mut WalletdAnchorNetworkAdapter<na::ScriptedWalletdTransport>,
) {
    let r = orch
        .prepare_fee_bearing(wd, &build_request(), &fee_component(), seal_signer(), None)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::Prepared);
    let r = orch.approve(wd).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::Approved);
    let r = orch.submit(wd).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::Submitted);
}

#[test]
fn scenario_1_not_found_then_acceptance() {
    let mut wd = make_walletd();
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::NotFound);
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    prepare_approve_submit(&mut orch, &mut wd);
    let r = orch
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        !r.phase().is_terminal(),
        "not-found not terminal: {:?}",
        r.phase()
    );
    let tx_id = orch
        .submitted()
        .unwrap_or_else(|| panic!("submitted must exist"))
        .transaction_id()
        .clone();
    ix.transport_mut()
        .set_response(ScriptedIndexerResponse::Finalized(
            receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22)),
        ));
    let r = orch
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

#[test]
fn scenario_2_submit_lost_recover() {
    let mut wd = make_walletd();
    wd.transport_mut()
        .set_submit_response(ScriptedWalletdResponse::SubmitError(
            TransportError::from_category(TransportErrorCategory::Timeout),
        ));
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    orch.prepare_fee_bearing(
        &mut wd,
        &build_request(),
        &fee_component(),
        seal_signer(),
        None,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    orch.approve(&mut wd).unwrap_or_else(|e| panic!("{e:?}"));
    let submit_result = orch.submit(&mut wd);
    assert!(submit_result.is_err());
    assert_eq!(orch.phase(), UnifiedAnchorLifecyclePhase::Unknown);
    wd.transport_mut()
        .set_get_response(ScriptedWalletdResponse::Get {
            request_id: 100,
            status: WalletdEffectiveStatusV1::Submitted,
            transaction_id: Some(transaction_id(0x44)),
        });
    let r = orch.recover(&mut wd).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    let tx_id = orch
        .submitted()
        .unwrap_or_else(|| panic!("submitted"))
        .transaction_id()
        .clone();
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::Finalized(
        receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22)),
    ));
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    let r = orch
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}

#[test]
fn scenario_3_fee_only() {
    let mut wd = make_walletd();
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    prepare_approve_submit(&mut orch, &mut wd);
    let tx_id = orch
        .submitted()
        .unwrap_or_else(|| panic!("submitted must exist"))
        .transaction_id()
        .clone();
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::Finalized(
        receipt_scenarios::fee_only_receipt(&tx_id, &network()),
    ));
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    let r = orch
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::FinalizedFeeOnly);
}

#[test]
fn scenario_4_rejected() {
    let mut wd = make_walletd();
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    prepare_approve_submit(&mut orch, &mut wd);
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::Rejected {
        reason: Some("failure".to_owned()),
    });
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    let r = orch
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::FinalizedReject);
}

#[test]
fn scenario_5_verification_failure() {
    let mut wd = make_walletd();
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    prepare_approve_submit(&mut orch, &mut wd);
    let tx_id = orch
        .submitted()
        .unwrap_or_else(|| panic!("submitted must exist"))
        .transaction_id()
        .clone();
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::Finalized(
        receipt_scenarios::accepted_missing_anchor_log(&tx_id, &network()),
    ));
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    let r = orch
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        r.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
    );
}

#[test]
fn scenario_6_disagreement() {
    let mut wd = make_walletd();
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    prepare_approve_submit(&mut orch, &mut wd);
    let tx_id = orch
        .submitted()
        .unwrap_or_else(|| panic!("submitted must exist"))
        .transaction_id()
        .clone();
    let accepted = receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22));
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::Finalized(accepted.clone()));
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    orch.advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let walletd_obs =
        receipt_scenarios::walletd_accepted_receipt(&tx_id, &network(), &payload(0x99));
    let result = orch.check_agreement(&walletd_obs);
    assert!(result.is_err(), "disagreement should return an error");
    assert_eq!(
        orch.phase(),
        UnifiedAnchorLifecyclePhase::FinalizedDisagreement
    );
}

#[test]
fn scenario_7_malformed_no_panic() {
    let mut wd = make_walletd();
    wd.transport_mut()
        .set_submit_response(ScriptedWalletdResponse::SubmitError(
            TransportError::from_category(TransportErrorCategory::MalformedResponse),
        ));
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    orch.prepare_fee_bearing(
        &mut wd,
        &build_request(),
        &fee_component(),
        seal_signer(),
        None,
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    orch.approve(&mut wd).unwrap_or_else(|e| panic!("{e:?}"));
    let result = orch.submit(&mut wd);
    assert!(result.is_err());
    assert!(!orch.phase().is_terminal_success());
}

#[test]
fn scenario_8_restart_between_submission_and_finalization() {
    let mut wd = make_walletd();
    let mut orch = AnchorLifecycleOrchestrator::new(PollingPolicy::new(10));
    prepare_approve_submit(&mut orch, &mut wd);
    let tx_id = orch
        .submitted()
        .unwrap_or_else(|| panic!("submitted must exist"))
        .transaction_id()
        .clone();
    let snapshot = orch.snapshot();
    let mut it = na::ScriptedIndexerTransport::new();
    it.set_response(ScriptedIndexerResponse::Finalized(
        receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22)),
    ));
    let mut ix = IndexerReceiptNetworkAdapter::new(it);
    let mut restored =
        AnchorLifecycleOrchestrator::from_snapshot(snapshot).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(restored.phase(), UnifiedAnchorLifecyclePhase::Submitted);
    let r = restored
        .advance_one_poll(&mut ix)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(r.phase(), UnifiedAnchorLifecyclePhase::FinalizedAccept);
}
