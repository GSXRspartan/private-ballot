//! Happy-path lifecycle, human-review summary, registry, and restart
//! (Sections C, D, E, F, G).

mod common;

use common::{seal_signer, valid_build_result};
use tari_cc_private_ballot_anchor_transport::AnchorLifecycleState;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, WalletdAnchorCoordinator, WalletdDecisionRequestV1,
    WalletdRequestDecisionV1,
};

#[test]
fn prepare_creates_pending_request_and_registers_it() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let build = valid_build_result();

    let Ok(prepared) = coordinator.prepare(&mut client, &build, seal_signer(), Some(3_600)) else {
        panic!("prepare must succeed");
    };

    assert_eq!(prepared.state(), AnchorLifecycleState::Prepared);
    assert_eq!(prepared.instruction_count(), 1);
    assert_eq!(client.create_calls(), 1);
    assert_eq!(client.captured_creates().len(), 1);

    // The request is registered as Prepared and correlated to the walletd id.
    assert_eq!(
        coordinator
            .registry()
            .decision(prepared.project_request_id()),
        Some(WalletdRequestDecisionV1::Prepared)
    );
    assert!(
        coordinator
            .registry()
            .contains_walletd_request(prepared.walletd_request_id())
    );

    // The captured wire request commits to the same unsigned transaction the
    // build result produced (its fingerprint), and carries no seal secret.
    let Some(captured) = client.last_captured_create() else {
        panic!("a create request must be captured");
    };
    assert_eq!(captured.fingerprint(), build.evidence().fingerprint());
    assert_eq!(captured.binding(), prepared.binding());
}

#[test]
fn prepare_then_approve_yields_approved_without_transaction_id() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();

    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);

    let Ok(approved) = coordinator.approve(&mut client, &decision) else {
        panic!("approve must succeed");
    };

    assert_eq!(approved.state(), AnchorLifecycleState::Approved);
    assert_eq!(approved.project_request_id(), prepared.project_request_id());
    assert_eq!(approved.walletd_request_id(), prepared.walletd_request_id());
    assert_eq!(client.approve_calls(), 1);
    assert_eq!(client.reject_calls(), 0);
    assert_eq!(
        coordinator
            .registry()
            .decision(prepared.project_request_id()),
        Some(WalletdRequestDecisionV1::Approved)
    );
}

#[test]
fn prepare_then_reject_yields_rejected_and_blocks_later_approval() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();

    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);

    let Ok(rejected) = coordinator.reject(&mut client, &decision) else {
        panic!("reject must succeed");
    };
    assert_eq!(rejected.state(), AnchorLifecycleState::RejectedByApprover);

    // A rejected request can never be approved through the adapter.
    assert!(coordinator.approve(&mut client, &decision).is_err());
    assert_eq!(client.approve_calls(), 0);
}

#[test]
fn repeated_rejection_is_deterministic_and_does_not_recall_walletd() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);

    let Ok(first) = coordinator.reject(&mut client, &decision) else {
        panic!("first reject must succeed");
    };
    let Ok(second) = coordinator.reject(&mut client, &decision) else {
        panic!("repeated reject must be deterministic");
    };

    assert_eq!(first, second);
    // The second rejection is served from local state, not a second wire call.
    assert_eq!(client.reject_calls(), 1);
}

#[test]
fn human_review_summary_is_an_exact_stable_vector() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };

    let hex = "22".repeat(32);
    let expected = format!(
        "walletd-anchor-request purpose=NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR \
network=esmeralda fee_account=fee-account max_fee=1000 anchor_digest={hex} \
emit_log_payload=TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1:{hex} instruction_count=1 \
transaction_id=NONE_YET voter_or_ballot_data=NONE"
    );

    let summary = prepared.human_review_summary();
    assert_eq!(summary, expected);
    assert!(summary.contains("transaction_id=NONE_YET"));
    assert!(summary.contains("voter_or_ballot_data=NONE"));
    assert!(!summary.to_ascii_lowercase().contains("ballot_payload"));
}

#[test]
fn registry_snapshot_survives_a_project_restart() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };

    // The project restarts from snapshots; the wallet daemon (fake) keeps state.
    let snapshots = coordinator.registry().snapshots();
    assert_eq!(snapshots.len(), 1);
    let mut restored = WalletdAnchorCoordinator::from_snapshots(snapshots);

    assert_eq!(
        restored.registry().decision(prepared.project_request_id()),
        Some(WalletdRequestDecisionV1::Prepared)
    );

    // Approval works after restart against the same wallet daemon.
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(approved) = restored.approve(&mut client, &decision) else {
        panic!("approve after restart must succeed");
    };
    assert_eq!(approved.state(), AnchorLifecycleState::Approved);
}

#[test]
fn query_status_reports_pending_before_any_decision() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };

    let Ok(status) = coordinator.query_status(&mut client, prepared.project_request_id()) else {
        panic!("status read must succeed");
    };
    assert!(!status.has_transaction_id());
}
