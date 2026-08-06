mod common;

use tari_cc_private_ballot_anchor_transport::AnchorFinalStatusV1;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    IndexerAnchorReceiptClient, IndexerReceiptFetchV1,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdAnchorClient, WalletdDecisionCommandV1, WalletdEffectiveStatusV1, WalletdRequestId,
    WalletdSubmitCommandV1,
};
use tari_ootle_walletd_client::types::TransactionRequestCreateRequest;

use na::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerResponse, ScriptedWalletdResponse,
    TransportErrorCategory, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters as na;

use common::*;

#[test]
fn walletd_create_captures_correct_wire_request() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 42,
        expires_at: 1_900_000_000,
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());

    let command = walletd_create_request();
    let outcome = adapter
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("create must succeed: {e:?}"));

    assert_eq!(
        outcome.walletd_request_id(),
        WalletdRequestId::from_walletd(42)
    );
    assert_eq!(outcome.expires_at(), 1_900_000_000);

    let captured = adapter
        .transport()
        .captured_create()
        .unwrap_or_else(|| panic!("create request must be captured"));
    assert_eq!(captured.seal_signer, command.wire_request().seal_signer);
    assert_eq!(captured.other_signers, command.wire_request().other_signers);
    assert_eq!(captured.signatures, command.wire_request().signatures);
    assert_eq!(captured.lock_ids, command.wire_request().lock_ids);
    assert_eq!(captured.ttl_secs, command.wire_request().ttl_secs);
}

#[test]
fn walletd_create_request_serializes_to_expected_json() {
    let command = walletd_create_request();
    let wire: &TransactionRequestCreateRequest = command.wire_request();
    let json =
        serde_json::to_value(wire).unwrap_or_else(|e| panic!("wire request must serialize: {e:?}"));
    assert!(
        json.get("transaction").is_some(),
        "transaction field present"
    );
    assert!(
        json.get("seal_signer").is_some(),
        "seal_signer field present"
    );
    assert!(
        json.get("other_signers").is_some(),
        "other_signers field present"
    );
}

#[test]
fn walletd_approve_captures_correct_request_id() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_approve_response(ScriptedWalletdResponse::Approve {
        request_id: 42,
        status: WalletdEffectiveStatusV1::Approved,
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());

    let cmd = WalletdDecisionCommandV1::new(WalletdRequestId::from_walletd(42));
    let outcome = adapter
        .approve_transaction_request(&cmd)
        .unwrap_or_else(|e| panic!("approve must succeed: {e:?}"));

    assert_eq!(outcome.status(), WalletdEffectiveStatusV1::Approved);
    assert_eq!(
        adapter
            .transport()
            .captured_approve()
            .unwrap_or_else(|| panic!("captured approve must exist"))
            .request_id,
        42
    );
}

#[test]
fn walletd_reject_captures_correct_request_id() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_reject_response(ScriptedWalletdResponse::Reject {
        request_id: 42,
        status: WalletdEffectiveStatusV1::Rejected,
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());

    let cmd = WalletdDecisionCommandV1::new(WalletdRequestId::from_walletd(42));
    let outcome = adapter
        .reject_transaction_request(&cmd)
        .unwrap_or_else(|e| panic!("reject must succeed: {e:?}"));

    assert_eq!(outcome.status(), WalletdEffectiveStatusV1::Rejected);
}

#[test]
fn walletd_get_captures_correct_request_id() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_get_response(ScriptedWalletdResponse::Get {
        request_id: 42,
        status: WalletdEffectiveStatusV1::Submitted,
        transaction_id: Some(transaction_id(0x33)),
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());

    let status = adapter
        .get_transaction_request(WalletdRequestId::from_walletd(42))
        .unwrap_or_else(|e| panic!("get must succeed: {e:?}"));

    assert_eq!(status.status(), WalletdEffectiveStatusV1::Submitted);
    assert!(status.has_transaction_id());
}

#[test]
fn walletd_submit_captures_correct_request_id() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: transaction_id(0x33),
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());

    let cmd = WalletdSubmitCommandV1::new(WalletdRequestId::from_walletd(42));
    let outcome = adapter
        .submit_transaction_request(&cmd)
        .unwrap_or_else(|e| panic!("submit must succeed: {e:?}"));

    assert_eq!(outcome.transaction_id(), &transaction_id(0x33));
}

#[test]
fn indexer_receipt_lookup_uses_correct_derived_address() {
    let query = receipt_query();
    let tx_id = query.transaction_id().clone();

    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Finalized(
        receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22)),
    ));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);

    let result = adapter
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("fetch must succeed: {e:?}"));
    assert!(matches!(result, IndexerReceiptFetchV1::Finalized(_)));

    let captured = adapter
        .transport()
        .captured_receipt_address()
        .unwrap_or_else(|| panic!("receipt address must be captured"));
    let expected =
        tari_cc_private_ballot_ootle_receipt_anchor_adapter::derive_receipt_address_evidence(
            &tx_id,
            &network(),
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        captured.as_object_key().to_string(),
        expected.receipt_object_key_hex()
    );
}

#[test]
fn indexer_not_found_maps_correctly() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::NotFound);
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(result, IndexerReceiptFetchV1::NotFound));
}

#[test]
fn indexer_pending_maps_correctly() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Pending);
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(result, IndexerReceiptFetchV1::Pending));
}

#[test]
fn indexer_full_acceptance_maps_correctly() {
    let query = receipt_query();
    let tx_id = query.transaction_id().clone();
    let receipt = receipt_scenarios::accepted_receipt(&tx_id, &network(), &payload(0x22));
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Finalized(receipt));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    match result {
        IndexerReceiptFetchV1::Finalized(r) => {
            assert_eq!(r.final_status(), AnchorFinalStatusV1::Accepted)
        }
        _ => panic!("expected Finalized"),
    }
}

#[test]
fn indexer_fee_only_maps_correctly() {
    let query = receipt_query();
    let tx_id = query.transaction_id().clone();
    let receipt = receipt_scenarios::fee_only_receipt(&tx_id, &network());
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Finalized(receipt));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    match result {
        IndexerReceiptFetchV1::Finalized(r) => {
            assert_eq!(r.final_status(), AnchorFinalStatusV1::FeeOnlyAccepted)
        }
        _ => panic!("expected Finalized"),
    }
}

#[test]
fn indexer_rejected_maps_correctly() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Rejected {
        reason: Some("execution failure".to_owned()),
    });
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter
        .fetch_anchor_receipt(&query)
        .unwrap_or_else(|e| panic!("{e:?}"));
    match result {
        IndexerReceiptFetchV1::Finalized(r) => {
            assert_eq!(r.final_status(), AnchorFinalStatusV1::Rejected)
        }
        _ => panic!("expected Finalized"),
    }
}

#[test]
fn indexer_timeout_maps_to_timeout_error() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Error(
        na::TransportError::from_category(TransportErrorCategory::Timeout),
    ));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter.fetch_anchor_receipt(&query);
    assert!(result.is_err());
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "INDEXER_RECEIPT_TIMEOUT"
    );
}

#[test]
fn walletd_connection_refused_maps_to_unavailable() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::CreateError(
        na::TransportError::from_category(TransportErrorCategory::ConnectionRefused),
    ));
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());
    let result = adapter.create_transaction_request(&walletd_create_request());
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "WALLETD_UNAVAILABLE"
    );
}

#[test]
fn walletd_submit_timeout_maps_to_submit_timeout() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_submit_response(ScriptedWalletdResponse::SubmitError(
        na::TransportError::from_category(TransportErrorCategory::Timeout),
    ));
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());
    let cmd = WalletdSubmitCommandV1::new(WalletdRequestId::from_walletd(42));
    let result = adapter.submit_transaction_request(&cmd);
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "WALLETD_SUBMIT_TIMEOUT"
    );
}
