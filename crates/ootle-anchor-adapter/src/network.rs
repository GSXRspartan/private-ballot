//! Explicit project-network to Ootle-network mapping (Section B).
//!
//! The mapping is a small, exhaustive, exact-match table. It never falls back to
//! a default, never reads an environment variable, never infers a network from a
//! wallet address, and never passes the project identifier string through into
//! the Ootle transaction. Only exact lowercase canonical testnet identifiers are
//! accepted, so casing changes (`Esmeralda`), aliases (`esme`), production
//! networks (`mainnet`, `stagenet`, `nextnet`), and any similar-but-different
//! name are rejected rather than silently coerced.
//!
//! The confirmed candidate networks for a non-binding testnet pilot are the two
//! named public Ootle testnets, `esmeralda` and `igor`, plus `localnet` for
//! offline and local development. Final target selection is left to a later
//! configuration slice; this table only fixes which identifiers are mappable at
//! all. `mainnet` (and the pre-production `stagenet`/`nextnet`) are deliberately
//! out of scope and always rejected.

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_ootle_transaction::Network;

use crate::errors::OotleAnchorAdapterError;

/// Exhaustive supported mapping from an exact lowercase canonical project
/// network identifier to the pinned Ootle [`Network`].
const SUPPORTED_TESTNET_MAPPINGS: &[(&str, Network)] = &[
    ("esmeralda", Network::Esmeralda),
    ("igor", Network::Igor),
    ("localnet", Network::LocalNet),
];

/// Maps a validated project network identifier to the pinned Ootle network.
///
/// # Errors
///
/// Returns [`OotleAnchorAdapterError::UnsupportedNetwork`] for any identifier not
/// present verbatim in the supported table.
pub fn map_ootle_network(
    network_id: &OotleNetworkIdV1,
) -> Result<Network, OotleAnchorAdapterError> {
    let requested = network_id.as_str();

    for (name, network) in SUPPORTED_TESTNET_MAPPINGS {
        if requested == *name {
            return Ok(*network);
        }
    }

    Err(OotleAnchorAdapterError::UnsupportedNetwork {
        requested: requested.to_owned(),
    })
}

/// Returns the exact set of supported project network identifiers.
///
/// This is the single source of truth for the supported mapping, exposed so
/// tests and diagnostics enumerate the same identifiers the mapper accepts.
pub fn supported_testnet_network_ids() -> impl Iterator<Item = &'static str> {
    SUPPORTED_TESTNET_MAPPINGS.iter().map(|(name, _)| *name)
}
