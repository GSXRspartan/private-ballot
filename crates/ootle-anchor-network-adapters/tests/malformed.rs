mod common;

use tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerAnchorReceiptClient;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdAnchorClient, WalletdDecisionCommandV1, WalletdRequestId, WalletdSubmitCommandV1,
};

use na::{
    IndexerEndpoint, IndexerReceiptNetworkAdapter, ScriptedIndexerResponse,
    ScriptedWalletdResponse, TransportError, TransportErrorCategory, WalletdAnchorNetworkAdapter,
    WalletdEndpoint, WalletdEndpointError,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters as na;

use common::*;

#[test]
fn wrong_network_rejected_before_transport() {
    let wrong = tari_cc_private_ballot_anchor::OotleNetworkIdV1::new("localnet".to_owned())
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 1,
        expires_at: 0,
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, wrong);
    let result = adapter.create_transaction_request(&walletd_create_request());
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "WALLETD_NETWORK_MISMATCH"
    );
    assert_eq!(adapter.transport().create_calls(), 0);
}

#[test]
fn walletd_not_found_maps_to_request_not_found() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_approve_response(ScriptedWalletdResponse::ApproveError(
        TransportError::from_category(TransportErrorCategory::NotFound),
    ));
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());
    let result = adapter.approve_transaction_request(&WalletdDecisionCommandV1::new(
        WalletdRequestId::from_walletd(999),
    ));
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "WALLETD_REQUEST_NOT_FOUND"
    );
}

#[test]
fn walletd_service_unavailable_maps_to_unavailable() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_create_response(ScriptedWalletdResponse::CreateError(
        TransportError::from_category(TransportErrorCategory::ServiceUnavailable),
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
fn walletd_submit_malformed_maps_to_malformed() {
    let mut transport = na::ScriptedWalletdTransport::new();
    transport.set_submit_response(ScriptedWalletdResponse::SubmitError(
        TransportError::from_category(TransportErrorCategory::MalformedResponse),
    ));
    let mut adapter = WalletdAnchorNetworkAdapter::new(transport, network());
    let result = adapter.submit_transaction_request(&WalletdSubmitCommandV1::new(
        WalletdRequestId::from_walletd(42),
    ));
    assert!(result.is_err());
}

#[test]
fn indexer_malformed_maps_to_malformed() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Error(
        TransportError::from_category(TransportErrorCategory::MalformedResponse),
    ));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter.fetch_anchor_receipt(&query);
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "INDEXER_RECEIPT_MALFORMED_RESPONSE"
    );
}

#[test]
fn indexer_unavailable_maps_to_unavailable() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Error(
        TransportError::from_category(TransportErrorCategory::ConnectionRefused),
    ));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter.fetch_anchor_receipt(&query);
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "INDEXER_RECEIPT_UNAVAILABLE"
    );
}

#[test]
fn indexer_timeout_maps_to_timeout() {
    let query = receipt_query();
    let mut transport = na::ScriptedIndexerTransport::new();
    transport.set_response(ScriptedIndexerResponse::Error(
        TransportError::from_category(TransportErrorCategory::Timeout),
    ));
    let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
    let result = adapter.fetch_anchor_receipt(&query);
    assert_eq!(
        result
            .err()
            .unwrap_or_else(|| panic!("expected error"))
            .as_str(),
        "INDEXER_RECEIPT_TIMEOUT"
    );
}

#[test]
fn endpoint_embedded_credentials_rejected() {
    assert_eq!(
        WalletdEndpoint::parse("http://user:pass@127.0.0.1:12009")
            .err()
            .unwrap_or_else(|| panic!("expected error")),
        WalletdEndpointError::EmbeddedCredentials
    );
    assert_eq!(
        IndexerEndpoint::parse("http://user@127.0.0.1:12500")
            .err()
            .unwrap_or_else(|| panic!("expected error")),
        WalletdEndpointError::EmbeddedCredentials
    );
}

#[test]
fn endpoint_query_rejected() {
    assert_eq!(
        WalletdEndpoint::parse("http://127.0.0.1:12009?foo=bar")
            .err()
            .unwrap_or_else(|| panic!("expected error")),
        WalletdEndpointError::QueryPresent
    );
}

#[test]
fn endpoint_fragment_rejected() {
    assert_eq!(
        IndexerEndpoint::parse("http://127.0.0.1:12500#section")
            .err()
            .unwrap_or_else(|| panic!("expected error")),
        WalletdEndpointError::FragmentPresent
    );
}

#[test]
fn no_panic_on_all_error_categories() {
    let query = receipt_query();
    for category in [
        TransportErrorCategory::ConnectionRefused,
        TransportErrorCategory::Timeout,
        TransportErrorCategory::TlsFailure,
        TransportErrorCategory::AuthenticationFailure,
        TransportErrorCategory::HttpStatusError,
        TransportErrorCategory::MalformedResponse,
        TransportErrorCategory::UnsupportedApi,
        TransportErrorCategory::ServiceUnavailable,
        TransportErrorCategory::Unknown,
        TransportErrorCategory::ExecutorUnavailable,
    ] {
        let mut transport = na::ScriptedIndexerTransport::new();
        transport.set_response(ScriptedIndexerResponse::Error(
            TransportError::from_category(category),
        ));
        let mut adapter = IndexerReceiptNetworkAdapter::new(transport);
        let _ = adapter.fetch_anchor_receipt(&query);
    }
}

#[test]
fn transport_error_does_not_leak_third_party_text() {
    let error = TransportError::with_status(TransportErrorCategory::HttpStatusError, 500);
    let display = format!("{error}");
    assert!(display.contains("TRANSPORT_HTTP_STATUS_ERROR"));
    assert!(display.contains("500"));
    assert!(!display.contains("reqwest"));
    assert!(!display.contains("internal server error"));
}
