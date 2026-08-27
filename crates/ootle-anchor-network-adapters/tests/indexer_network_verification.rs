//! The configured indexer's network is verified before its epoch is trusted.
//!
//! Phase 3 fail-closed: a v0.39.2 transaction's bounded expiry is derived from
//! the epoch the *configured* indexer reports, but only after that indexer
//! proves it is actually serving the operator-selected network. A mismatch is
//! refused before any epoch (or later receipt) is trusted, so pointing the app
//! at the wrong network's indexer can never silently anchor on that network.

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    IndexerReceiptNetworkAdapter, ScriptedIndexerTransport,
};
use tari_ootle_transaction::Network;

fn net(value: &str) -> OotleNetworkIdV1 {
    OotleNetworkIdV1::new(value.to_owned()).unwrap_or_else(|error| panic!("{error:?}"))
}

#[test]
fn matching_network_yields_the_observed_epoch() {
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_network_info(Network::Esmeralda, 4_242);
    let mut indexer = IndexerReceiptNetworkAdapter::new(transport);
    let epoch = indexer
        .observed_network_epoch(&net("esmeralda"))
        .unwrap_or_else(|error| panic!("matching network must yield an epoch: {error:?}"));
    assert_eq!(epoch, 4_242);
}

#[test]
fn igor_configuration_is_accepted_against_an_igor_indexer() {
    // The network is runtime data: selecting igor and pointing at an igor
    // indexer verifies exactly as esmeralda does — nothing is hard-coded.
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_network_info(Network::Igor, 77);
    let mut indexer = IndexerReceiptNetworkAdapter::new(transport);
    assert_eq!(
        indexer
            .observed_network_epoch(&net("igor"))
            .unwrap_or_else(|error| panic!("igor must verify against an igor indexer: {error:?}")),
        77
    );
}

#[test]
fn indexer_on_a_different_network_is_refused() {
    // The operator selected esmeralda but the indexer reports igor: fail closed
    // before the epoch is trusted.
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_network_info(Network::Igor, 9);
    let mut indexer = IndexerReceiptNetworkAdapter::new(transport);
    assert!(indexer.observed_network_epoch(&net("esmeralda")).is_err());
}

#[test]
fn unsupported_configured_network_is_refused() {
    // A network with no supported deployment (mainnet) cannot even be resolved,
    // so no epoch is trusted regardless of what the indexer claims.
    let mut transport = ScriptedIndexerTransport::new();
    transport.set_network_info(Network::Esmeralda, 1);
    let mut indexer = IndexerReceiptNetworkAdapter::new(transport);
    assert!(indexer.observed_network_epoch(&net("mainnet")).is_err());
}
