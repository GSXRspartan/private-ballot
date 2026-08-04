//! Sections C, D, E — preparation, approval, and submission over the
//! deterministic fake.

mod common;

use common::{binding, payload, preparation, preparation_with_reference};
use tari_cc_private_ballot_anchor_transport::{
    AnchorApprovalError, AnchorLifecycleState, AnchorPreparationError, AnchorQueryOutcomeV1,
    AnchorReceiptSource, AnchorSubmissionError, AnchorTransactionApprover,
    AnchorTransactionRequestStore, AnchorTransactionSubmitter, DeterministicAnchorFake,
    FakeFinality,
};

#[test]
fn preparation_binds_digest_payload_and_summary() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));

    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };

    assert_eq!(prepared.state(), AnchorLifecycleState::Prepared);
    assert_eq!(prepared.anchor_digest(), payload(0x22).digest());
    assert_eq!(prepared.payload(), &payload(0x22));

    let summary = prepared.human_review_summary();
    assert!(summary.contains("esmeralda"));
    assert!(summary.contains("fee-account"));
    assert!(summary.contains(&payload(0x22).to_encoded_string()));
    assert!(summary.contains("NON_BINDING_APPROVAL_PILOT_ARCHIVE_ANCHOR"));
    // The summary must never leak anything secret; it is built only from the
    // network, account, digest, purpose, and fee.
    assert!(!summary.contains("secret"));
    assert!(!summary.contains("mnemonic"));
}

#[test]
fn field_substitution_changes_request_identity() {
    let mut fake = DeterministicAnchorFake::new();

    let Ok(base) = fake.create_request(&preparation(binding("esmeralda", "fee-account", 0x22)))
    else {
        panic!("base preparation should succeed");
    };
    let Ok(other_network) = fake.create_request(&preparation(binding("igor", "fee-account", 0x22)))
    else {
        panic!("network-substituted preparation should succeed");
    };
    let Ok(other_account) =
        fake.create_request(&preparation(binding("esmeralda", "other-account", 0x22)))
    else {
        panic!("account-substituted preparation should succeed");
    };
    let Ok(other_digest) =
        fake.create_request(&preparation(binding("esmeralda", "fee-account", 0x33)))
    else {
        panic!("digest-substituted preparation should succeed");
    };

    assert_ne!(base.request_id(), other_network.request_id());
    assert_ne!(base.request_id(), other_account.request_id());
    assert_ne!(base.request_id(), other_digest.request_id());
}

#[test]
fn client_reference_makes_preparation_idempotent() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation_with_reference(binding("esmeralda", "fee-account", 0x22), "anchor-1");

    let Ok(first) = fake.create_request(&request) else {
        panic!("first preparation should succeed");
    };
    let Ok(second) = fake.create_request(&request) else {
        panic!("idempotent preparation should succeed");
    };

    assert_eq!(first.request_id(), second.request_id());
}

#[test]
fn client_reference_conflict_is_rejected() {
    let mut fake = DeterministicAnchorFake::new();

    let first = preparation_with_reference(binding("esmeralda", "fee-account", 0x22), "anchor-1");
    let conflicting =
        preparation_with_reference(binding("esmeralda", "fee-account", 0x33), "anchor-1");

    if fake.create_request(&first).is_err() {
        panic!("first preparation should succeed");
    }

    assert_eq!(
        fake.create_request(&conflicting),
        Err(AnchorPreparationError::ClientReferenceConflict)
    );
}

#[test]
fn injected_preparation_failure_is_reported() {
    let mut fake = DeterministicAnchorFake::new();
    fake.inject_create_failure(AnchorPreparationError::InjectedFailure);

    assert_eq!(
        fake.create_request(&preparation(binding("esmeralda", "fee-account", 0x22))),
        Err(AnchorPreparationError::InjectedFailure)
    );
}

#[test]
fn approval_happy_path_then_double_approval_is_rejected() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();

    let Ok(approved) = fake.approve(prepared.request_id(), &binding) else {
        panic!("approval should succeed");
    };
    assert_eq!(approved.state(), AnchorLifecycleState::Approved);
    assert_eq!(approved.request_id(), prepared.request_id());

    assert_eq!(
        fake.approve(prepared.request_id(), &binding),
        Err(AnchorApprovalError::AlreadyApproved)
    );
}

#[test]
fn approval_requires_matching_binding() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };

    assert_eq!(
        fake.approve(prepared.request_id(), &binding("igor", "fee-account", 0x22)),
        Err(AnchorApprovalError::NetworkMismatch)
    );
    assert_eq!(
        fake.approve(prepared.request_id(), &binding("esmeralda", "other", 0x22)),
        Err(AnchorApprovalError::AccountMismatch)
    );
    assert_eq!(
        fake.approve(
            prepared.request_id(),
            &binding("esmeralda", "fee-account", 0x33)
        ),
        Err(AnchorApprovalError::PayloadMismatch)
    );
}

#[test]
fn rejection_is_distinct_from_approval_and_blocks_it() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();

    if fake.reject(prepared.request_id()).is_err() {
        panic!("rejection should succeed");
    }

    assert_eq!(
        fake.approve(prepared.request_id(), &binding),
        Err(AnchorApprovalError::AlreadyRejected)
    );

    let Ok(snapshot) = fake.get_request(prepared.request_id()) else {
        panic!("snapshot should exist");
    };
    assert_eq!(
        snapshot.lifecycle_state(),
        AnchorLifecycleState::RejectedByApprover
    );
}

#[test]
fn expired_request_cannot_be_approved() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };

    fake.inject_expire(prepared.request_id());

    assert_eq!(
        fake.approve(prepared.request_id(), request.binding()),
        Err(AnchorApprovalError::Expired)
    );
}

#[test]
fn approving_unknown_request_is_rejected() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let orphan_binding = binding("esmeralda", "fee-account", 0x44);
    let mut orphan_fake = DeterministicAnchorFake::new();
    let Ok(orphan) = orphan_fake.create_request(&preparation(orphan_binding)) else {
        panic!("orphan preparation should succeed");
    };

    // A request id from a different fake is not present in this store.
    assert_eq!(
        fake.approve(orphan.request_id(), request.binding()),
        Err(AnchorApprovalError::RequestNotFound)
    );
    assert_ne!(orphan.request_id(), prepared.request_id());
}

#[test]
fn submission_happy_path_returns_transaction_without_finality() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();

    if fake.approve(prepared.request_id(), &binding).is_err() {
        panic!("approval should succeed");
    }

    let Ok(submitted) = fake.submit(prepared.request_id(), &binding, &payload(0x22).digest())
    else {
        panic!("submission should succeed");
    };

    assert_eq!(submitted.state(), AnchorLifecycleState::Submitted);
    assert_eq!(submitted.anchor_digest(), payload(0x22).digest());

    // No finality is claimed: the receipt is not yet finalized.
    let Ok(outcome) = fake.query_receipt(submitted.transaction_id(), binding.network()) else {
        panic!("query should succeed");
    };
    assert_eq!(outcome, AnchorQueryOutcomeV1::NotFinalized);
}

#[test]
fn duplicate_submission_returns_same_transaction_id() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();
    if fake.approve(prepared.request_id(), &binding).is_err() {
        panic!("approval should succeed");
    }

    let Ok(first) = fake.submit(prepared.request_id(), &binding, &payload(0x22).digest()) else {
        panic!("first submission should succeed");
    };
    let Ok(second) = fake.submit(prepared.request_id(), &binding, &payload(0x22).digest()) else {
        panic!("duplicate submission should succeed");
    };

    assert_eq!(first.transaction_id(), second.transaction_id());
}

#[test]
fn approval_for_one_anchor_cannot_submit_another() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let bound = request.binding().clone();
    if fake.approve(prepared.request_id(), &bound).is_err() {
        panic!("approval should succeed");
    }

    // A different expected digest must not be submittable against this request.
    assert_eq!(
        fake.submit(prepared.request_id(), &bound, &payload(0x33).digest()),
        Err(AnchorSubmissionError::PayloadMismatch)
    );
    // A different network binding is likewise refused.
    assert_eq!(
        fake.submit(
            prepared.request_id(),
            &binding("igor", "fee-account", 0x22),
            &payload(0x22).digest()
        ),
        Err(AnchorSubmissionError::NetworkMismatch)
    );
    assert_eq!(
        fake.submit(
            prepared.request_id(),
            &binding("esmeralda", "other", 0x22),
            &payload(0x22).digest()
        ),
        Err(AnchorSubmissionError::AccountMismatch)
    );
}

#[test]
fn unapproved_and_rejected_requests_cannot_submit() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();

    assert_eq!(
        fake.submit(prepared.request_id(), &binding, &payload(0x22).digest()),
        Err(AnchorSubmissionError::NotApproved)
    );

    if fake.reject(prepared.request_id()).is_err() {
        panic!("rejection should succeed");
    }
    assert_eq!(
        fake.submit(prepared.request_id(), &binding, &payload(0x22).digest()),
        Err(AnchorSubmissionError::Rejected)
    );
}

#[test]
fn submit_timeout_leaves_recoverable_unknown_and_retry_discovers_transaction() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();
    if fake.approve(prepared.request_id(), &binding).is_err() {
        panic!("approval should succeed");
    }

    fake.arm_submit_timeout();
    assert_eq!(
        fake.submit(prepared.request_id(), &binding, &payload(0x22).digest()),
        Err(AnchorSubmissionError::Timeout)
    );

    // The sealed transaction id is recoverable from the snapshot even though the
    // submit response was lost.
    let Ok(snapshot) = fake.get_request(prepared.request_id()) else {
        panic!("snapshot should exist");
    };
    assert_eq!(snapshot.lifecycle_state(), AnchorLifecycleState::Unknown);
    let Some(recovered_transaction) = snapshot.transaction_id() else {
        panic!("a sealed transaction id must be recoverable after timeout");
    };

    let Ok(unknown_outcome) = fake.query_receipt(recovered_transaction, binding.network()) else {
        panic!("query should succeed");
    };
    assert_eq!(unknown_outcome, AnchorQueryOutcomeV1::Unknown);

    // Retrying submission after the timeout discovers the same transaction id.
    let Ok(retried) = fake.submit(prepared.request_id(), &binding, &payload(0x22).digest()) else {
        panic!("retry submission should succeed");
    };
    assert_eq!(retried.transaction_id(), recovered_transaction);

    // Once finality is observed, the same transaction resolves cleanly.
    fake.set_finality(prepared.request_id(), FakeFinality::Accepted);
    let Ok(final_outcome) = fake.query_receipt(recovered_transaction, binding.network()) else {
        panic!("query should succeed");
    };
    assert!(matches!(final_outcome, AnchorQueryOutcomeV1::Finalized(_)));
}

#[test]
fn querying_unavailable_source_is_reported() {
    let mut fake = DeterministicAnchorFake::new();
    let request = preparation(binding("esmeralda", "fee-account", 0x22));
    let Ok(prepared) = fake.create_request(&request) else {
        panic!("preparation should succeed");
    };
    let binding = request.binding().clone();
    if fake.approve(prepared.request_id(), &binding).is_err() {
        panic!("approval should succeed");
    }
    let Ok(submitted) = fake.submit(prepared.request_id(), &binding, &payload(0x22).digest())
    else {
        panic!("submission should succeed");
    };

    fake.set_query_unavailable(true);
    assert!(
        fake.query_receipt(submitted.transaction_id(), binding.network())
            .is_err()
    );
}
