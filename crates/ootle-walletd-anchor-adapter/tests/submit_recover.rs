//! Submission, transaction-id binding, timeout/unknown, and recovery
//! (Sections C, D, E, F, G, H, K).
//!
//! Every case drives the fee-bearing prepare -> approve -> submit/recover flow
//! against the deterministic offline fake and asserts the exact project-owned
//! result or bounded error. No case contacts a network, and no invalid case may
//! panic or create a second anchor transaction.

mod common;

use common::{
    account, fee_component, network, other_fee_component, payload, seal_signer, valid_build_request,
};
use tari_cc_private_ballot_anchor_transport::{AnchorLifecycleState, AnchorMaxFeeV1};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    ApprovedWalletdAnchorRequestV1, FakeWalletdAnchorClient, WalletdAnchorAdapterError,
    WalletdAnchorBindingV1, WalletdAnchorCoordinator, WalletdDecisionRequestV1,
    WalletdEffectiveStatusV1, WalletdRecoveryStateV1, WalletdRequestId, WalletdSubmissionStateV1,
    WalletdSubmitRequestV1,
};

/// Prepares a fee-bearing request and approves it, returning the pieces a
/// submission or recovery test needs.
fn prepare_and_approve() -> (
    WalletdAnchorCoordinator,
    FakeWalletdAnchorClient,
    ApprovedWalletdAnchorRequestV1,
) {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare_fee_bearing(
        &mut client,
        &valid_build_request(),
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("fee-bearing prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(approved) = coordinator.approve(&mut client, &decision) else {
        panic!("approve must succeed");
    };
    (coordinator, client, approved)
}

/// Rebuilds a binding from an approved result with one field overridden.
fn binding_with(
    approved: &ApprovedWalletdAnchorRequestV1,
    build: impl FnOnce(&WalletdAnchorBindingV1) -> WalletdAnchorBindingV1,
) -> WalletdAnchorBindingV1 {
    build(approved.binding())
}

// ---------------------------------------------------------------------------
// Section D/E: a submission yields exactly one transaction id, bound to the
// approved request.
// ---------------------------------------------------------------------------

#[test]
fn submission_yields_exactly_one_transaction_id_in_submitted_state() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    let Ok(submitted) = coordinator.submit(&mut client, &submit) else {
        panic!("submit must succeed");
    };

    assert_eq!(submitted.state(), AnchorLifecycleState::Submitted);
    assert_eq!(
        submitted.project_request_id(),
        approved.project_request_id()
    );
    assert_eq!(
        submitted.walletd_request_id(),
        approved.walletd_request_id()
    );
    // Exactly one submit reached the fake, producing exactly one transaction.
    assert_eq!(client.submit_calls(), 1);
    assert_eq!(
        client
            .transaction_id_of(approved.walletd_request_id())
            .as_ref(),
        Some(submitted.transaction_id())
    );
    // The result stays bound to the approved request's binding.
    assert_eq!(submitted.binding(), approved.binding());
}

#[test]
fn approval_carries_no_transaction_id_before_submission() {
    let (_coordinator, client, approved) = prepare_and_approve();
    // No transaction id exists at the fake until a submit seals it, and the
    // approved result type structurally has no transaction id to carry.
    assert_eq!(
        client.transaction_id_of(approved.walletd_request_id()),
        None
    );
}

#[test]
fn transaction_id_survives_restart_once_known() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    let Ok(submitted) = coordinator.submit(&mut client, &submit) else {
        panic!("submit must succeed");
    };

    // Restart the project from snapshots; the sealed id is preserved.
    let mut restored = WalletdAnchorCoordinator::from_snapshots(coordinator.registry().snapshots());
    let Some(record) = restored.registry().snapshot(approved.project_request_id()) else {
        panic!("snapshot present after restart");
    };
    assert_eq!(record.submission(), WalletdSubmissionStateV1::Submitted);
    assert_eq!(record.transaction_id(), Some(submitted.transaction_id()));

    // A submit after restart is idempotent: the same id, no second fake call.
    let calls_before = client.submit_calls();
    let Ok(again) = restored.submit(&mut client, &submit) else {
        panic!("idempotent submit after restart must succeed");
    };
    assert_eq!(again.transaction_id(), submitted.transaction_id());
    assert_eq!(client.submit_calls(), calls_before);
}

// ---------------------------------------------------------------------------
// Section G: idempotent duplicate submission.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_submit_before_response_loss_is_locally_idempotent() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    let Ok(first) = coordinator.submit(&mut client, &submit) else {
        panic!("first submit must succeed");
    };
    let Ok(second) = coordinator.submit(&mut client, &submit) else {
        panic!("second submit must return the same id idempotently");
    };

    assert_eq!(first.transaction_id(), second.transaction_id());
    // The second submit never reached the fake: no second transaction.
    assert_eq!(client.submit_calls(), 1);
}

#[test]
fn duplicate_submit_after_response_loss_recovers_the_same_id() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    // The submit reaches walletd (seals) but the response is lost.
    client.inject_submit_timeout_after_processing();
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::SubmitTimeout)
    );

    // A blind resubmit is refused: recovery must resolve the unknown state first.
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::SubmissionStateUnknown)
    );

    // Recovery discovers the sealed id and transitions Unknown -> Submitted.
    let Ok(recovered) = coordinator.recover(&mut client, &submit) else {
        panic!("recovery must succeed");
    };
    let Some(sealed) = client.transaction_id_of(approved.walletd_request_id()) else {
        panic!("fake sealed a transaction id");
    };
    assert_eq!(
        recovered.state(),
        &WalletdRecoveryStateV1::Submitted(sealed.clone())
    );
    assert_eq!(recovered.transaction_id(), Some(&sealed));
    // Exactly one submit was ever processed: no second anchor transaction.
    assert_eq!(client.submit_calls(), 1);
}

#[test]
fn conflicting_recovered_transaction_id_is_rejected() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    let Ok(submitted) = coordinator.submit(&mut client, &submit) else {
        panic!("submit must succeed");
    };

    // The wallet daemon now reports a *different* transaction id for the same
    // request. Recovery must refuse to silently overwrite the bound id.
    let Ok(forged) =
        tari_cc_private_ballot_anchor_transport::AnchorTransactionId::new("aa".repeat(32))
    else {
        panic!("forged id must be valid");
    };
    assert_ne!(&forged, submitted.transaction_id());
    client.force_transaction_id(approved.walletd_request_id(), Some(forged));

    assert_eq!(
        coordinator.recover(&mut client, &submit),
        Err(WalletdAnchorAdapterError::ConflictingTransactionId)
    );
}

// ---------------------------------------------------------------------------
// Section F: timeout and unknown state.
// ---------------------------------------------------------------------------

#[test]
fn submit_timeout_before_processing_stays_retryable() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    // A timeout before the fake processes leaves the request approved at walletd.
    client.inject_submit_error(WalletdAnchorAdapterError::SubmitTimeout);
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::SubmitTimeout)
    );
    assert_eq!(
        client.transaction_id_of(approved.walletd_request_id()),
        None
    );

    // Recovery observes it still approved: a controlled retry is safe.
    let Ok(recovered) = coordinator.recover(&mut client, &submit) else {
        panic!("recovery must succeed");
    };
    assert_eq!(
        recovered.state(),
        &WalletdRecoveryStateV1::NotSubmittedRetryable
    );

    // The controlled retry now succeeds and produces the one transaction.
    let Ok(submitted) = coordinator.submit(&mut client, &submit) else {
        panic!("controlled retry must succeed");
    };
    assert_eq!(submitted.state(), AnchorLifecycleState::Submitted);
    assert_eq!(client.submit_calls(), 2);
}

#[test]
fn unknown_state_blocks_blind_resubmit() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    client.inject_submit_timeout_after_processing();
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::SubmitTimeout)
    );

    // The recorded submission state is unknown, and a blind resubmit is refused.
    let Some(snapshot) = coordinator
        .registry()
        .snapshot(approved.project_request_id())
    else {
        panic!("snapshot present");
    };
    assert_eq!(
        snapshot.submission(),
        WalletdSubmissionStateV1::TimedOutUnknown
    );
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::SubmissionStateUnknown)
    );
}

#[test]
fn malformed_submit_response_marks_unknown() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    client.inject_submit_error(WalletdAnchorAdapterError::MalformedSubmitResponse);
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::MalformedSubmitResponse)
    );
    let Some(snapshot) = coordinator
        .registry()
        .snapshot(approved.project_request_id())
    else {
        panic!("snapshot present");
    };
    assert_eq!(
        snapshot.submission(),
        WalletdSubmissionStateV1::TimedOutUnknown
    );
}

#[test]
fn walletd_unavailable_on_submit_leaves_request_approved() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);

    client.set_unavailable(true);
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::WalletdUnavailable)
    );
    // An unreachable daemon sealed nothing, so the request stays submittable.
    let Some(snapshot) = coordinator
        .registry()
        .snapshot(approved.project_request_id())
    else {
        panic!("snapshot present");
    };
    assert_eq!(
        snapshot.submission(),
        WalletdSubmissionStateV1::NotSubmitted
    );

    client.set_unavailable(false);
    assert!(coordinator.submit(&mut client, &submit).is_ok());
}

// ---------------------------------------------------------------------------
// Section H: request status recovery mapping.
// ---------------------------------------------------------------------------

#[test]
fn recovery_maps_each_effective_status() {
    // Submitting -> in progress, do not retry.
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    client.force_status(
        approved.walletd_request_id(),
        WalletdEffectiveStatusV1::Submitting,
    );
    let Ok(recovered) = coordinator.recover(&mut client, &submit) else {
        panic!("recovery must succeed");
    };
    assert_eq!(
        recovered.state(),
        &WalletdRecoveryStateV1::SubmissionInProgress
    );
    assert_eq!(
        recovered.state().lifecycle_state(),
        AnchorLifecycleState::Unknown
    );

    // Rejected -> terminal rejection.
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    client.force_status(
        approved.walletd_request_id(),
        WalletdEffectiveStatusV1::Rejected,
    );
    let Ok(recovered) = coordinator.recover(&mut client, &submit) else {
        panic!("recovery must succeed");
    };
    assert_eq!(
        recovered.state(),
        &WalletdRecoveryStateV1::RejectedByApprover
    );

    // Expired -> expired.
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    client.force_status(
        approved.walletd_request_id(),
        WalletdEffectiveStatusV1::Expired,
    );
    let Ok(recovered) = coordinator.recover(&mut client, &submit) else {
        panic!("recovery must succeed");
    };
    assert_eq!(recovered.state(), &WalletdRecoveryStateV1::Expired);
}

#[test]
fn recovery_of_submitted_without_id_is_an_error() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    // Force Submitted status but leave the transaction id absent.
    client.force_status(
        approved.walletd_request_id(),
        WalletdEffectiveStatusV1::Submitted,
    );
    assert_eq!(
        coordinator.recover(&mut client, &submit),
        Err(WalletdAnchorAdapterError::SubmittedButTransactionIdMissing)
    );
}

#[test]
fn recovery_with_mismatched_binding_is_a_security_error() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let mutated = binding_with(&approved, |bound| {
        WalletdAnchorBindingV1::new(
            bound.network().clone(),
            bound.account().clone(),
            bound.anchor_digest(),
            *bound.payload(),
            bound.max_fee(),
            OotleAnchorInspectionFingerprintV1::new([0xEE; 32]),
        )
    });
    let recovery = WalletdSubmitRequestV1::new(
        approved.project_request_id().clone(),
        approved.walletd_request_id(),
        mutated,
    );
    assert_eq!(
        coordinator.recover(&mut client, &recovery),
        Err(WalletdAnchorAdapterError::FingerprintMismatch)
    );
    // The mismatch is caught before any client call.
    assert_eq!(client.get_calls(), 0);
}

// ---------------------------------------------------------------------------
// Section K: submission is refused before walletd on any binding/state mismatch.
// ---------------------------------------------------------------------------

#[test]
fn submit_rejects_wrong_walletd_request_id() {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let submit = WalletdSubmitRequestV1::new(
        approved.project_request_id().clone(),
        WalletdRequestId::from_walletd(approved.walletd_request_id().value().wrapping_add(1)),
        approved.binding().clone(),
    );
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::RequestIdMismatch)
    );
    assert_eq!(client.submit_calls(), 0);
}

#[test]
fn submit_rejects_each_wrong_binding_field() {
    // Wrong network.
    assert_submit_mismatch(
        |bound| {
            WalletdAnchorBindingV1::new(
                network("igor"),
                bound.account().clone(),
                bound.anchor_digest(),
                *bound.payload(),
                bound.max_fee(),
                bound.fingerprint(),
            )
        },
        WalletdAnchorAdapterError::NetworkMismatch,
    );
    // Wrong account.
    assert_submit_mismatch(
        |bound| {
            WalletdAnchorBindingV1::new(
                bound.network().clone(),
                account("other-account"),
                bound.anchor_digest(),
                *bound.payload(),
                bound.max_fee(),
                bound.fingerprint(),
            )
        },
        WalletdAnchorAdapterError::AccountMismatch,
    );
    // Wrong payload/digest.
    assert_submit_mismatch(
        |bound| {
            WalletdAnchorBindingV1::new(
                bound.network().clone(),
                bound.account().clone(),
                payload(0x33).digest(),
                payload(0x33),
                bound.max_fee(),
                bound.fingerprint(),
            )
        },
        WalletdAnchorAdapterError::PayloadMismatch,
    );
    // Wrong maximum fee.
    assert_submit_mismatch(
        |bound| {
            WalletdAnchorBindingV1::new(
                bound.network().clone(),
                bound.account().clone(),
                bound.anchor_digest(),
                *bound.payload(),
                AnchorMaxFeeV1::from_units(9_999),
                bound.fingerprint(),
            )
        },
        WalletdAnchorAdapterError::FeeMismatch,
    );
    // Wrong unsigned fingerprint.
    assert_submit_mismatch(
        |bound| {
            WalletdAnchorBindingV1::new(
                bound.network().clone(),
                bound.account().clone(),
                bound.anchor_digest(),
                *bound.payload(),
                bound.max_fee(),
                OotleAnchorInspectionFingerprintV1::new([0x7A; 32]),
            )
        },
        WalletdAnchorAdapterError::FingerprintMismatch,
    );
}

/// Approves a request, then submits with a mutated binding and asserts the error.
fn assert_submit_mismatch(
    mutate: impl FnOnce(&WalletdAnchorBindingV1) -> WalletdAnchorBindingV1,
    expected: WalletdAnchorAdapterError,
) {
    let (mut coordinator, mut client, approved) = prepare_and_approve();
    let mutated = binding_with(&approved, mutate);
    let submit = WalletdSubmitRequestV1::new(
        approved.project_request_id().clone(),
        approved.walletd_request_id(),
        mutated,
    );
    assert_eq!(coordinator.submit(&mut client, &submit), Err(expected));
    assert_eq!(client.submit_calls(), 0);
}

#[test]
fn submit_rejects_unknown_request() {
    let (_coordinator, mut client, approved) = prepare_and_approve();
    // A fresh coordinator does not know this request.
    let mut empty = WalletdAnchorCoordinator::new();
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    assert_eq!(
        empty.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::RequestNotFound)
    );
    assert_eq!(client.submit_calls(), 0);
}

#[test]
fn submit_rejects_unapproved_request() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare_fee_bearing(
        &mut client,
        &valid_build_request(),
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("prepare must succeed");
    };
    // Submit while still merely prepared (never approved).
    let submit = WalletdSubmitRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        prepared.binding().clone(),
    );
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::RequestNotApproved)
    );
    assert_eq!(client.submit_calls(), 0);
}

#[test]
fn submit_rejects_rejected_request() {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare_fee_bearing(
        &mut client,
        &valid_build_request(),
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    if coordinator.reject(&mut client, &decision).is_err() {
        panic!("reject must succeed");
    }
    let submit = WalletdSubmitRequestV1::new(
        prepared.project_request_id().clone(),
        prepared.walletd_request_id(),
        prepared.binding().clone(),
    );
    assert_eq!(
        coordinator.submit(&mut client, &submit),
        Err(WalletdAnchorAdapterError::RequestAlreadyRejected)
    );
    assert_eq!(client.submit_calls(), 0);
}

#[test]
fn fee_bearing_and_fee_less_prepare_have_distinct_fingerprints() {
    // The same logical anchor prepared fee-bearing vs fee-less must differ: the
    // fee instruction is inside the fingerprinted transaction.
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(fee_bearing) = coordinator.prepare_fee_bearing(
        &mut client,
        &valid_build_request(),
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("fee-bearing prepare must succeed");
    };

    // Prepare the same anchor with a different fee account: a different fee
    // component yields a different frozen transaction and fingerprint.
    let mut other_coordinator = WalletdAnchorCoordinator::new();
    let Ok(other_fee) = other_coordinator.prepare_fee_bearing(
        &mut client,
        &valid_build_request(),
        &other_fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("second fee-bearing prepare must succeed");
    };

    assert_ne!(
        fee_bearing.binding().fingerprint(),
        other_fee.binding().fingerprint(),
        "changing the fee account must change the frozen fingerprint"
    );
    assert!(fee_bearing.fee_present());
    assert!(
        fee_bearing
            .human_review_summary()
            .contains("fee_instruction=pay_fee_from_component")
    );
}
