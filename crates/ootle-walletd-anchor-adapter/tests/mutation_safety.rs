//! Binding, state, and client-failure safety (Sections E, F, H, K).
//!
//! Every case drives the coordinator into a rejection and asserts the specific,
//! bounded error. No invalid case may panic, and none registers or advances a
//! request it should not.

mod common;

use common::{account, network, payload, seal_signer, valid_build_result};
use tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorAdapterError, OotleAnchorInspectionFingerprintV1,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, PreparedWalletdAnchorRequestV1, WalletdAnchorAdapterError,
    WalletdAnchorBindingV1, WalletdAnchorCoordinator, WalletdDecisionRequestV1,
    WalletdRequestDecisionV1, WalletdRequestId,
};

/// Prepares one valid request and returns the coordinator, client, and result.
fn prepared() -> (
    WalletdAnchorCoordinator,
    FakeWalletdAnchorClient,
    PreparedWalletdAnchorRequestV1,
) {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &valid_build_result(), seal_signer(), None)
    else {
        panic!("prepare must succeed");
    };
    (coordinator, client, prepared)
}

/// Rebuilds the prepared binding with one field overridden.
fn binding_with(
    prepared: &PreparedWalletdAnchorRequestV1,
    build: impl FnOnce(&WalletdAnchorBindingV1) -> WalletdAnchorBindingV1,
) -> WalletdAnchorBindingV1 {
    build(prepared.binding())
}

#[test]
fn wrong_network_is_rejected_at_approval() {
    let (mut coordinator, mut client, prepared) = prepared();
    let mutated = binding_with(&prepared, |bound| {
        WalletdAnchorBindingV1::new(
            network("igor"),
            bound.account().clone(),
            bound.anchor_digest(),
            *bound.payload(),
            bound.max_fee(),
            bound.fingerprint(),
        )
    });
    let decision = WalletdDecisionRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        mutated,
    );
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::NetworkMismatch)
    );
    assert_eq!(client.approve_calls(), 0);
}

#[test]
fn wrong_account_is_rejected_at_approval() {
    let (mut coordinator, mut client, prepared) = prepared();
    let mutated = binding_with(&prepared, |bound| {
        WalletdAnchorBindingV1::new(
            bound.network().clone(),
            account("other-account"),
            bound.anchor_digest(),
            *bound.payload(),
            bound.max_fee(),
            bound.fingerprint(),
        )
    });
    let decision = WalletdDecisionRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        mutated,
    );
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::AccountMismatch)
    );
}

#[test]
fn wrong_payload_or_digest_is_rejected_at_approval() {
    let (mut coordinator, mut client, prepared) = prepared();
    let mutated = binding_with(&prepared, |bound| {
        WalletdAnchorBindingV1::new(
            bound.network().clone(),
            bound.account().clone(),
            payload(0x33).digest(),
            payload(0x33),
            bound.max_fee(),
            bound.fingerprint(),
        )
    });
    let decision = WalletdDecisionRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        mutated,
    );
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::PayloadMismatch)
    );
}

#[test]
fn wrong_max_fee_is_rejected_at_approval() {
    let (mut coordinator, mut client, prepared) = prepared();
    let mutated = binding_with(&prepared, |bound| {
        WalletdAnchorBindingV1::new(
            bound.network().clone(),
            bound.account().clone(),
            bound.anchor_digest(),
            *bound.payload(),
            AnchorMaxFeeV1::from_units(bound.max_fee().value() + 1),
            bound.fingerprint(),
        )
    });
    let decision = WalletdDecisionRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        mutated,
    );
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::FeeMismatch)
    );
}

#[test]
fn changed_unsigned_fingerprint_is_rejected_at_approval() {
    let (mut coordinator, mut client, prepared) = prepared();
    let mutated = binding_with(&prepared, |bound| {
        WalletdAnchorBindingV1::new(
            bound.network().clone(),
            bound.account().clone(),
            bound.anchor_digest(),
            *bound.payload(),
            bound.max_fee(),
            OotleAnchorInspectionFingerprintV1::new([0x00; 32]),
        )
    });
    let decision = WalletdDecisionRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        mutated,
    );
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::FingerprintMismatch)
    );
}

#[test]
fn mismatched_project_and_walletd_request_ids_are_rejected() {
    let (mut coordinator, mut client, prepared) = prepared();
    let decision = WalletdDecisionRequestV1::new(
        prepared.project_request_id().clone(),
        WalletdRequestId::from_walletd(prepared.walletd_request_id().value().wrapping_add(1)),
        prepared.binding().clone(),
    );
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::RequestIdMismatch)
    );
}

#[test]
fn approving_an_unknown_request_is_rejected() {
    let (mut coordinator, mut client, _prepared) = prepared();
    // A second, never-registered request built from a different build result.
    let mut other_client = FakeWalletdAnchorClient::new();
    let mut other_coordinator = WalletdAnchorCoordinator::new();
    let Ok(other_prepared) = other_coordinator.prepare(
        &mut other_client,
        &common::build_result("esmeralda", "fee-account", 0x44, 1_000, None),
        seal_signer(),
        None,
    ) else {
        panic!("other prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&other_prepared);
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::RequestNotFound)
    );
}

#[test]
fn double_approval_is_rejected() {
    let (mut coordinator, mut client, prepared) = prepared();
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(_first) = coordinator.approve(&mut client, &decision) else {
        panic!("first approval must succeed");
    };
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::RequestAlreadyApproved)
    );
    assert_eq!(client.approve_calls(), 1);
}

#[test]
fn approval_after_rejection_is_rejected() {
    let (mut coordinator, mut client, prepared) = prepared();
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(_rejected) = coordinator.reject(&mut client, &decision) else {
        panic!("reject must succeed");
    };
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::RequestAlreadyRejected)
    );
}

#[test]
fn rejection_after_approval_is_rejected() {
    let (mut coordinator, mut client, prepared) = prepared();
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(_approved) = coordinator.approve(&mut client, &decision) else {
        panic!("approve must succeed");
    };
    assert_eq!(
        coordinator.reject(&mut client, &decision),
        Err(WalletdAnchorAdapterError::RequestAlreadyApproved)
    );
}

#[test]
fn expired_request_is_rejected_and_recorded() {
    let (mut coordinator, mut client, prepared) = prepared();
    // The wallet daemon reports the approval window as expired.
    client.force_status(
        prepared.walletd_request_id(),
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1::Expired,
    );
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::RequestExpired)
    );
    assert_eq!(
        coordinator
            .registry()
            .decision(prepared.project_request_id()),
        Some(WalletdRequestDecisionV1::Expired)
    );
}

#[test]
fn create_rejection_registers_nothing() {
    let mut client = FakeWalletdAnchorClient::new();
    client.inject_create_error(WalletdAnchorAdapterError::RequestCreationRejected);
    let mut coordinator = WalletdAnchorCoordinator::new();
    assert_eq!(
        coordinator
            .prepare(&mut client, &valid_build_result(), seal_signer(), None)
            .err(),
        Some(WalletdAnchorAdapterError::RequestCreationRejected)
    );
    assert!(coordinator.registry().snapshots().is_empty());
}

#[test]
fn walletd_unavailable_on_create_is_mapped() {
    let mut client = FakeWalletdAnchorClient::new();
    client.set_unavailable(true);
    let mut coordinator = WalletdAnchorCoordinator::new();
    assert_eq!(
        coordinator
            .prepare(&mut client, &valid_build_result(), seal_signer(), None)
            .err(),
        Some(WalletdAnchorAdapterError::WalletdUnavailable)
    );
}

#[test]
fn transport_failure_on_approve_leaves_request_prepared() {
    let (mut coordinator, mut client, prepared) = prepared();
    client.inject_approve_error(WalletdAnchorAdapterError::TransportFailure);
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    assert_eq!(
        coordinator.approve(&mut client, &decision),
        Err(WalletdAnchorAdapterError::TransportFailure)
    );
    // A transport failure is not a decision: the request stays approvable.
    assert_eq!(
        coordinator
            .registry()
            .decision(prepared.project_request_id()),
        Some(WalletdRequestDecisionV1::Prepared)
    );
}

#[test]
fn malformed_create_response_is_mapped() {
    let mut client = FakeWalletdAnchorClient::new();
    client.inject_create_error(WalletdAnchorAdapterError::MalformedResponse);
    let mut coordinator = WalletdAnchorCoordinator::new();
    assert_eq!(
        coordinator
            .prepare(&mut client, &valid_build_result(), seal_signer(), None)
            .err(),
        Some(WalletdAnchorAdapterError::MalformedResponse)
    );
}

#[test]
fn unsafe_unsigned_transaction_error_carries_bounded_source() {
    // The convert re-inspection wraps the Slice 4A5 inspector's bounded error.
    let error = WalletdAnchorAdapterError::UnsafeUnsignedTransaction(
        OotleAnchorAdapterError::DuplicateAnchorInstruction,
    );
    assert_eq!(error.as_str(), "WALLETD_UNSAFE_UNSIGNED_TRANSACTION");
    // Display stays bounded and names the wrapped project error, no secret text.
    assert!(format!("{error}").contains("WALLETD_UNSAFE_UNSIGNED_TRANSACTION"));
}
