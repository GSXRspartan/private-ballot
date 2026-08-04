//! Section K — restart/recovery via deterministic lifecycle snapshots.

mod common;

use common::{binding, payload, preparation};
use tari_cc_private_ballot_anchor_transport::{
    AnchorLifecycleSnapshotV1, AnchorLifecycleState, AnchorQueryOutcomeV1, AnchorReceiptSource,
    AnchorReceiptSourceKindV1, AnchorRequestId, AnchorSubmissionError, AnchorTransactionApprover,
    AnchorTransactionRequestStore, AnchorTransactionSubmitter, DeterministicAnchorFake,
    FakeFinality, verify_anchor_receipt,
};

/// Restarts a fake by round-tripping through its recovery snapshots.
fn restart(fake: &DeterministicAnchorFake) -> DeterministicAnchorFake {
    DeterministicAnchorFake::from_snapshots(AnchorReceiptSourceKindV1::Walletd, fake.snapshots())
}

/// Prepares a request and returns the fake and the assigned request id.
fn prepared_fake() -> (DeterministicAnchorFake, AnchorRequestId) {
    let mut fake = DeterministicAnchorFake::new();
    let Ok(prepared) = fake.create_request(&preparation(binding("esmeralda", "fee-account", 0x22)))
    else {
        panic!("preparation should succeed");
    };
    let request_id = prepared.request_id().clone();
    (fake, request_id)
}

fn only_snapshot(
    fake: &DeterministicAnchorFake,
    request_id: &AnchorRequestId,
) -> AnchorLifecycleSnapshotV1 {
    match fake.get_request(request_id) {
        Ok(snapshot) => snapshot,
        Err(_) => panic!("snapshot should exist"),
    }
}

#[test]
fn restart_after_prepare_can_still_approve() {
    let (fake, request_id) = prepared_fake();

    let mut restored = restart(&fake);
    assert_eq!(
        only_snapshot(&restored, &request_id).lifecycle_state(),
        AnchorLifecycleState::Prepared
    );

    assert!(
        restored
            .approve(&request_id, &binding("esmeralda", "fee-account", 0x22))
            .is_ok()
    );
}

#[test]
fn restart_after_approval_can_still_submit() {
    let (mut fake, request_id) = prepared_fake();
    if fake
        .approve(&request_id, &binding("esmeralda", "fee-account", 0x22))
        .is_err()
    {
        panic!("approval should succeed");
    }

    let mut restored = restart(&fake);
    assert_eq!(
        only_snapshot(&restored, &request_id).lifecycle_state(),
        AnchorLifecycleState::Approved
    );

    assert!(
        restored
            .submit(
                &request_id,
                &binding("esmeralda", "fee-account", 0x22),
                &payload(0x22).digest()
            )
            .is_ok()
    );
}

#[test]
fn restart_after_submit_timeout_recovers_unknown_then_finalizes() {
    let (mut fake, request_id) = prepared_fake();
    let bound = binding("esmeralda", "fee-account", 0x22);
    if fake.approve(&request_id, &bound).is_err() {
        panic!("approval should succeed");
    }
    fake.arm_submit_timeout();
    assert_eq!(
        fake.submit(&request_id, &bound, &payload(0x22).digest()),
        Err(AnchorSubmissionError::Timeout)
    );

    let mut restored = restart(&fake);
    let snapshot = only_snapshot(&restored, &request_id);
    assert_eq!(snapshot.lifecycle_state(), AnchorLifecycleState::Unknown);
    let Some(recovered_transaction) = snapshot.transaction_id().cloned() else {
        panic!("a transaction id must survive the restart");
    };

    let Ok(unknown) = restored.query_receipt(&recovered_transaction, bound.network()) else {
        panic!("query should succeed");
    };
    assert_eq!(unknown, AnchorQueryOutcomeV1::Unknown);

    restored.set_finality(&request_id, FakeFinality::Accepted);
    let Ok(finalized) = restored.query_receipt(&recovered_transaction, bound.network()) else {
        panic!("query should succeed");
    };
    assert!(matches!(finalized, AnchorQueryOutcomeV1::Finalized(_)));
}

#[test]
fn restart_after_transaction_known_then_eventual_finalized_receipt() {
    let (mut fake, request_id) = prepared_fake();
    let bound = binding("esmeralda", "fee-account", 0x22);
    if fake.approve(&request_id, &bound).is_err() {
        panic!("approval should succeed");
    }
    let Ok(submitted) = fake.submit(&request_id, &bound, &payload(0x22).digest()) else {
        panic!("submission should succeed");
    };
    let transaction_id = submitted.transaction_id().clone();

    let mut restored = restart(&fake);
    assert_eq!(
        only_snapshot(&restored, &request_id).lifecycle_state(),
        AnchorLifecycleState::Submitted
    );

    // Not finalized yet after restart.
    let Ok(pending) = restored.query_receipt(&transaction_id, bound.network()) else {
        panic!("query should succeed");
    };
    assert_eq!(pending, AnchorQueryOutcomeV1::NotFinalized);

    // Finality is eventually observed and verifies against the expected anchor.
    restored.set_finality(&request_id, FakeFinality::Accepted);
    let Ok(AnchorQueryOutcomeV1::Finalized(receipt)) =
        restored.query_receipt(&transaction_id, bound.network())
    else {
        panic!("a finalized receipt should be retrievable");
    };

    let Ok(evidence) =
        verify_anchor_receipt(&transaction_id, bound.network(), &payload(0x22), &receipt)
    else {
        panic!("finalized receipt should verify");
    };
    assert_eq!(evidence.anchor_digest(), payload(0x22).digest());
}

#[test]
fn rejection_survives_restart_and_blocks_submission() {
    let (mut fake, request_id) = prepared_fake();
    if fake.reject(&request_id).is_err() {
        panic!("rejection should succeed");
    }

    let mut restored = restart(&fake);
    assert_eq!(
        only_snapshot(&restored, &request_id).lifecycle_state(),
        AnchorLifecycleState::RejectedByApprover
    );

    assert_eq!(
        restored.submit(
            &request_id,
            &binding("esmeralda", "fee-account", 0x22),
            &payload(0x22).digest()
        ),
        Err(AnchorSubmissionError::Rejected)
    );
}

#[test]
fn duplicate_submit_after_restart_returns_same_transaction_id() {
    let (mut fake, request_id) = prepared_fake();
    let bound = binding("esmeralda", "fee-account", 0x22);
    if fake.approve(&request_id, &bound).is_err() {
        panic!("approval should succeed");
    }
    let Ok(before) = fake.submit(&request_id, &bound, &payload(0x22).digest()) else {
        panic!("submission should succeed");
    };
    let transaction_before = before.transaction_id().clone();

    let mut restored = restart(&fake);
    let Ok(after) = restored.submit(&request_id, &bound, &payload(0x22).digest()) else {
        panic!("resubmission should succeed");
    };

    assert_eq!(after.transaction_id(), &transaction_before);
}
