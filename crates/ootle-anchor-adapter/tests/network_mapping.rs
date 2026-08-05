//! Section B / Section M(2,3) — explicit network mapping.

mod common;

use common::network;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorAdapterError, map_ootle_network, supported_testnet_network_ids,
};
use tari_ootle_transaction::Network;

#[test]
fn every_supported_identifier_maps_to_its_ootle_network() {
    let expected = [
        ("esmeralda", Network::Esmeralda),
        ("igor", Network::Igor),
        ("localnet", Network::LocalNet),
    ];

    // The supported set is exactly these three identifiers.
    let supported: Vec<&str> = supported_testnet_network_ids().collect();
    assert_eq!(supported, vec!["esmeralda", "igor", "localnet"]);

    for (identifier, ootle_network) in expected {
        match map_ootle_network(&network(identifier)) {
            Ok(mapped) => assert_eq!(mapped, ootle_network),
            Err(_) => panic!("supported identifier {identifier} must map"),
        }
    }
}

#[test]
fn unsupported_identifier_is_rejected() {
    match map_ootle_network(&network("teronet")) {
        Err(OotleAnchorAdapterError::UnsupportedNetwork { requested }) => {
            assert_eq!(requested, "teronet");
        }
        other => panic!("unsupported identifier must be rejected, got {other:?}"),
    }
}

#[test]
fn mainnet_and_preproduction_networks_are_rejected() {
    for identifier in ["mainnet", "stagenet", "nextnet"] {
        assert!(
            matches!(
                map_ootle_network(&network(identifier)),
                Err(OotleAnchorAdapterError::UnsupportedNetwork { .. })
            ),
            "{identifier} must be rejected as out of scope"
        );
    }
}

#[test]
fn casing_changes_are_rejected() {
    for identifier in ["Esmeralda", "ESMERALDA", "Igor", "LocalNet"] {
        assert!(
            matches!(
                map_ootle_network(&network(identifier)),
                Err(OotleAnchorAdapterError::UnsupportedNetwork { .. })
            ),
            "non-canonical casing {identifier} must be rejected"
        );
    }
}

#[test]
fn aliases_and_similar_names_are_rejected() {
    // `esme` is a valid Ootle FromStr alias for Esmeralda, but the adapter's
    // explicit table only accepts the exact canonical identifier, so the alias
    // and any similarly-named network are rejected rather than coerced.
    for identifier in [
        "esme",
        "esmerald",
        "esmeraldas",
        "igor1",
        "local",
        "localnet-2",
    ] {
        assert!(
            matches!(
                map_ootle_network(&network(identifier)),
                Err(OotleAnchorAdapterError::UnsupportedNetwork { .. })
            ),
            "alias or near-name {identifier} must be rejected"
        );
    }
}

#[test]
fn embedded_separators_are_rejected() {
    // The network identifier type already forbids whitespace and control
    // characters, so the strongest legal near-miss uses the allowed `-`/`_`
    // separators; these are still not in the supported table.
    for identifier in ["esmeralda-1", "esmeralda_", "-esmeralda", "es-meralda"] {
        assert!(
            matches!(
                map_ootle_network(&network(identifier)),
                Err(OotleAnchorAdapterError::UnsupportedNetwork { .. })
            ),
            "separated near-name {identifier} must be rejected"
        );
    }
}
