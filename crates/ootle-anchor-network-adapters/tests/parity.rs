mod common;

use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    FakeIndexerReceiptClient, FakeReceiptStep, IndexerAnchorReceiptClient,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, WalletdAnchorClient, WalletdDecisionCommandV1, WalletdRequestId,
    WalletdSubmitCommandV1,
};

use na::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerResponse, ScriptedWalletdResponse,
    WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters as na;

use common::*;

#[test]
fn create_outcome_agrees() {
    let command = walletd_create_request();
    let mut fake = FakeWalletdAnchorClient::new();
    let fake_outcome = fake
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: fake_outcome.walletd_request_id().value(),
        expires_at: fake_outcome.expires_at(),
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, network());
    let real_outcome = real
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        fake_outcome.walletd_request_id(),
        real_outcome.walletd_request_id()
    );
    assert_eq!(fake_outcome.expires_at(), real_outcome.expires_at());
}

#[test]
fn fingerprint_cache_provides_observed_fingerprint() {
    let command = walletd_create_request();
    let fingerprint = command.fingerprint();
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 42,
        expires_at: 0,
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, network());
    real.create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    real.transport_mut()
        .set_get_response(ScriptedWalletdResponse::Get {
        request_id: 42,
        status:
            tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1::Approved,
        transaction_id: None,
    });
    let status = real
        .get_transaction_request(WalletdRequestId::from_walletd(42))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(status.observed_fingerprint(), Some(fingerprint));
}

#[test]
fn approve_outcome_agrees() {
    let mut fake = FakeWalletdAnchorClient::new();
    let command = walletd_create_request();
    let created = fake
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let rid = created.walletd_request_id();
    let fake_outcome = fake
        .approve_transaction_request(&WalletdDecisionCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_approve_response(ScriptedWalletdResponse::Approve {
        request_id: rid.value(),
        status: fake_outcome.status(),
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, network());
    let real_outcome = real
        .approve_transaction_request(&WalletdDecisionCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_outcome.status(), real_outcome.status());
}

#[test]
fn reject_outcome_agrees() {
    let mut fake = FakeWalletdAnchorClient::new();
    let command = walletd_create_request();
    let created = fake
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let rid = created.walletd_request_id();
    let fake_outcome = fake
        .reject_transaction_request(&WalletdDecisionCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_reject_response(ScriptedWalletdResponse::Reject {
        request_id: rid.value(),
        status: fake_outcome.status(),
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, network());
    let real_outcome = real
        .reject_transaction_request(&WalletdDecisionCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_outcome.status(), real_outcome.status());
}

#[test]
fn submit_outcome_agrees() {
    let mut fake = FakeWalletdAnchorClient::new();
    let command = walletd_create_request();
    let created = fake
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let rid = created.walletd_request_id();
    fake.approve_transaction_request(&WalletdDecisionCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let fake_outcome = fake
        .submit_transaction_request(&WalletdSubmitCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: fake_outcome.transaction_id().clone(),
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, network());
    let real_outcome = real
        .submit_transaction_request(&WalletdSubmitCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_outcome.transaction_id(), real_outcome.transaction_id());
}

#[test]
fn get_outcome_agrees() {
    let mut fake = FakeWalletdAnchorClient::new();
    let command = walletd_create_request();
    let created = fake
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let rid = created.walletd_request_id();
    fake.approve_transaction_request(&WalletdDecisionCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    fake.submit_transaction_request(&WalletdSubmitCommandV1::new(rid))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let fake_status = fake
        .get_transaction_request(rid)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: rid.value(),
        expires_at: created.expires_at(),
    });
    transport.set_get_response(ScriptedWalletdResponse::Get {
        request_id: rid.value(),
        status: fake_status.status(),
        transaction_id: fake_status.transaction_id().cloned(),
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, network());
    real.create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let real_status = real
        .get_transaction_request(rid)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_status.status(), real_status.status());
    assert_eq!(fake_status.transaction_id(), real_status.transaction_id());
}

#[test]
fn indexer_full_acceptance_agrees() {
    let query = receipt_query();
    let tx_id = query.transaction_id().clone();
    let receipt = receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22));
    let mut fake = FakeIndexerReceiptClient::new();
    fake.script(&tx_id, FakeReceiptStep::finalized(receipt.clone()));
    let fake_result = fake
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Finalized(receipt));
    let mut real = IndexerReceiptNetworkAdapter::new(transport);
    let real_result = real
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_result, real_result);
}

#[test]
fn indexer_pending_agrees() {
    let query = receipt_query();
    let tx_id = query.transaction_id().clone();
    let mut fake = FakeIndexerReceiptClient::new();
    fake.script(&tx_id, FakeReceiptStep::pending());
    let fake_result = fake
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Pending);
    let mut real = IndexerReceiptNetworkAdapter::new(transport);
    let real_result = real
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_result, real_result);
}

#[test]
fn indexer_not_found_agrees() {
    let query = receipt_query();
    let tx_id = query.transaction_id().clone();
    let mut fake = FakeIndexerReceiptClient::new();
    fake.script(&tx_id, FakeReceiptStep::not_found());
    let fake_result = fake
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::NotFound);
    let mut real = IndexerReceiptNetworkAdapter::new(transport);
    let real_result = real
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(fake_result, real_result);
}

#[test]
fn network_mismatch_rejected() {
    let wrong = tari_cc_private_ballot_anchor::OotleNetworkIdV1::new("localnet".to_owned())
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 1,
        expires_at: 0,
    });
    let mut real = WalletdAnchorNetworkAdapter::new(transport, wrong);
    let result = real.create_transaction_request(&walletd_create_request());
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "WALLETD_NETWORK_MISMATCH"
    );
}
