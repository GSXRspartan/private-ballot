mod common;

use tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerAnchorReceiptClient;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdAnchorClient, WalletdRequestId, WalletdSubmitCommandV1,
};

use na::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerResponse, ScriptedWalletdResponse, TransportError,
    TransportErrorCategory, WalletdAnchorNetworkAdapter,
};
use tari_cc_private_ballot_ootle_anchor_network_adapters as na;

use common::*;

#[test]
fn artifacts_unchanged_across_outcomes() {
    let command = walletd_create_request();
    let anchor_digest = command.binding().anchor_digest();
    let fingerprint = command.fingerprint();
    let net = command.binding().network().clone();

    let mut t = na::ScriptedWalletdTransport::new();
    t.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 42,
        expires_at: 1_900_000_000,
    });
    t.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: transaction_id(0x44),
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(t, net.clone());

    let outcome = adapter
        .create_transaction_request(&command)
        .unwrap_or_else(|e| panic!("{e:?}"));
    let submit_outcome = adapter
        .submit_transaction_request(&WalletdSubmitCommandV1::new(outcome.walletd_request_id()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let tx_id = submit_outcome.transaction_id().clone();

    for response in [
        ScriptedIndexerResponse::NotFound,
        ScriptedIndexerResponse::Pending,
        ScriptedIndexerResponse::Error(TransportError::from_category(
            TransportErrorCategory::Timeout,
        )),
        ScriptedIndexerResponse::Error(TransportError::from_category(
            TransportErrorCategory::MalformedResponse,
        )),
        ScriptedIndexerResponse::Error(TransportError::from_category(
            TransportErrorCategory::ConnectionRefused,
        )),
    ] {
        let query = receipt_query_for_tx(&tx_id);
        let mut it = na::ScriptedIndexerTransport::new();
        it.set_response(response);
        let mut ix = IndexerReceiptNetworkAdapter::new(it);
        let _ = ix.fetch_anchor_receipt(&query);
    }

    assert_eq!(
        command.binding().anchor_digest(),
        anchor_digest,
        "digest unchanged"
    );
    assert_eq!(command.fingerprint(), fingerprint, "fingerprint unchanged");
    assert_eq!(command.binding().network(), &net, "network unchanged");
    assert_eq!(submit_outcome.transaction_id(), &tx_id, "tx ID unchanged");
}

#[test]
fn fingerprint_unchanged_after_walletd_failure() {
    let command = walletd_create_request();
    let fingerprint = command.fingerprint();
    let mut t = na::ScriptedWalletdTransport::new();
    t.set_create_response(ScriptedWalletdResponse::CreateError(
        TransportError::from_category(TransportErrorCategory::ConnectionRefused),
    ));
    let mut adapter = WalletdAnchorNetworkAdapter::new(t, network());
    let _ = adapter.create_transaction_request(&command);
    assert_eq!(command.fingerprint(), fingerprint);
}

#[test]
fn transaction_id_stable_across_recovery() {
    let mut t = na::ScriptedWalletdTransport::new();
    t.set_create_response(ScriptedWalletdResponse::Create {
        request_id: 42,
        expires_at: 0,
    });
    t.set_submit_response(ScriptedWalletdResponse::Submit {
        transaction_id: transaction_id(0x44),
    });
    t.set_get_response(ScriptedWalletdResponse::Get {
        request_id: 42,
        status: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdEffectiveStatusV1::Submitted,
        transaction_id: Some(transaction_id(0x44)),
    });
    let mut adapter = WalletdAnchorNetworkAdapter::new(t, network());

    let outcome = adapter
        .create_transaction_request(&walletd_create_request())
        .unwrap_or_else(|e| panic!("{e:?}"));
    let submit = adapter
        .submit_transaction_request(&WalletdSubmitCommandV1::new(outcome.walletd_request_id()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    let status = adapter
        .get_transaction_request(WalletdRequestId::from_walletd(42))
        .unwrap_or_else(|e| panic!("{e:?}"));

    assert_eq!(status.transaction_id(), Some(&transaction_id(0x44)));
    assert_eq!(submit.transaction_id(), &transaction_id(0x44));
    assert_eq!(
        status
            .transaction_id()
            .unwrap_or_else(|| panic!("transaction id must be present")),
        submit.transaction_id()
    );
}
