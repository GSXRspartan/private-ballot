//! Network-agnostic V4 config round-trip and durable V3<->V4 compatibility.
//!
//! The selected Ootle network is runtime data carried through the config, never
//! a compile-time constant: esmeralda, igor, and localnet each configure and
//! round-trip identically, the per-network template deployment binding travels
//! with the config, and a network with no configured trusted deployment
//! (mainnet and the pre-production networks) fails closed. Adding a future
//! network is therefore a configuration/provisioning change, not a source
//! change.

mod common;

use common::*;
use tari_cc_private_ballot_ootle_anchor_app::{AnchorAppConfig, AnchorConfigInputProvenanceV1};
use tari_cc_private_ballot_ootle_anchor_network_adapters::{
    NetworkAdapterConfig, NetworkAdapterConfigError,
};

fn network_adapter_for(net: &str) -> NetworkAdapterConfig {
    match NetworkAdapterConfig::new(
        network(net),
        walletd_endpoint(),
        indexer_endpoint(),
        fee_component(),
        seal_signer(),
        max_fee(),
        Some(30),
        8,
        None,
    ) {
        Ok(config) => config,
        Err(error) => panic!("adapter config for {net} must construct: {error}"),
    }
}

fn v4_config_for(net: &str) -> AnchorAppConfig {
    let config = AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter_for(net),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        network(net),
        snapshot_path(),
        evidence_path(),
        1,
        1,
        None,
        live_approval_facts(),
    );
    match config.with_event_template_binding(template_binding(), SCENARIO_MAX_EPOCH_DELTA) {
        Ok(config) => config,
        Err(error) => panic!("v4 event template must attach for {net}: {error}"),
    }
}

#[test]
fn every_supported_network_v4_config_round_trips() {
    for net in ["esmeralda", "igor", "localnet"] {
        let config = v4_config_for(net);
        let bytes = config
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("encode {net}: {error}"));
        let decoded = AnchorAppConfig::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("decode {net}: {error}"));
        // The network is runtime data that survives the round trip on both the
        // adapter locator and the anchor-record binding.
        assert_eq!(decoded.network_adapter().network().as_str(), net);
        assert_eq!(decoded.anchor_record_network().as_str(), net);
        // The per-network deployment binding and bounded epoch policy survive.
        assert_eq!(decoded.event_template(), Some(&template_binding()));
        assert_eq!(decoded.max_epoch_delta(), Some(SCENARIO_MAX_EPOCH_DELTA));
        assert_eq!(
            decoded.input_provenance(),
            AnchorConfigInputProvenanceV1::ArchiveVerified
        );
    }
}

#[test]
fn v3_config_without_event_template_still_round_trips() {
    // A pre-v0.39.2 (V3) live config remains byte-decodable and reports no event
    // template: the dual reader keeps historical configs usable.
    let config = AnchorAppConfig::new_archive_verified_with_live_approval_facts(
        network_adapter_for("esmeralda"),
        canonical_account(),
        canonical_manifest_hash(),
        canonical_archive_hash(),
        network("esmeralda"),
        snapshot_path(),
        evidence_path(),
        1,
        1,
        None,
        live_approval_facts(),
    );
    let bytes = config
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode: {error}"));
    let decoded = AnchorAppConfig::from_canonical_bytes(&bytes)
        .unwrap_or_else(|error| panic!("decode: {error}"));
    assert_eq!(decoded.event_template(), None);
    assert_eq!(decoded.max_epoch_delta(), None);
    assert_eq!(decoded.network_adapter().network().as_str(), "esmeralda");
}

#[test]
fn a_network_without_a_trusted_deployment_fails_closed() {
    // mainnet (and the pre-production networks) have no configured trusted
    // template deployment, so the network adapter refuses them rather than
    // silently falling back to another network's deployment.
    for net in ["mainnet", "stagenet", "nextnet"] {
        let result = NetworkAdapterConfig::new(
            network(net),
            walletd_endpoint(),
            indexer_endpoint(),
            fee_component(),
            seal_signer(),
            max_fee(),
            Some(30),
            8,
            None,
        );
        assert_eq!(
            result.err(),
            Some(NetworkAdapterConfigError::UnsupportedNetwork),
            "{net} must fail closed"
        );
    }
}
