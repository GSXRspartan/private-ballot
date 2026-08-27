#![forbid(unsafe_code)]

//! Pinned Tari Ootle transaction-construction adapter (offline).
//!
//! This leaf crate translates the project-owned offline anchor-transport
//! preparation DTOs into an **unsigned** Tari Ootle transaction that carries
//! exactly one transaction-level `CallFunction` instruction invoking the pinned
//! stateless event-only anchor template with the canonical anchor digest. It
//! depends on an exact pinned Tari Ootle revision (`tari-ootle` git rev
//! `dd1d731`, v0.39.2 workspace) and does nothing beyond construction and
//! inspection. The network is never hard-coded: it is carried as runtime data
//! through [`map_ootle_network`] and the per-network template deployment
//! binding travels with each build request.
//!
//! It deliberately never:
//!
//! * accesses a private key, mnemonic, or signer secret;
//! * signs, seals, submits, or polls a transaction;
//! * contacts walletd, an indexer, or any network;
//! * reconstructs or rehashes an election artifact;
//! * parses ballots, proofs, nullifiers, registries, or tallies.
//!
//! Fees are handled by walletd during a later preparation slice (see
//! [`build`]); this adapter constructs only the normal instruction list and an
//! offline walletd preparation DTO. Constructing a transaction is a pure
//! transformation of already-frozen commitments, so a failure at any step leaves
//! every offline election artifact unchanged.
//!
//! The pinned Ootle [`UnsignedTransaction`] is reachable only through this crate,
//! inside [`build::OotleAnchorBuildResultV1`]; the anchor and anchor-transport
//! crates never depend on this crate and never see an Ootle type.
//!
//! [`UnsignedTransaction`]: tari_ootle_transaction::UnsignedTransaction

mod build;
mod constructor;
mod errors;
mod evidence;
mod inspect;
mod event_instruction;
mod network;
mod request;

pub use build::{
    OotleAnchorBuildResultV1, OotleWalletdAnchorPreparationV1,
    build_fee_bearing_anchor_transaction, build_unsigned_anchor_transaction,
};
pub use constructor::{AnchorTransactionConstructor, PinnedOotleAnchorTransactionConstructor};
pub use errors::OotleAnchorAdapterError;
pub use evidence::{OotleAnchorInspectionFingerprintV1, OotleUnsignedAnchorTransactionEvidenceV1};
pub use inspect::{
    AnchorInspectionExpectationV1, fingerprint_unsigned_anchor_transaction,
    inspect_detected_fee_bearing_anchor_transaction, inspect_fee_bearing_anchor_transaction,
    inspect_unsigned_anchor_transaction,
};
pub use event_instruction::build_anchor_call_function;
pub use network::{map_ootle_network, supported_testnet_network_ids};
pub use request::OotleAnchorTransactionBuildRequestV1;
