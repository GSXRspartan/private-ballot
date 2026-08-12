#![forbid(unsafe_code)]

//! Pinned Tari Ootle transaction-construction adapter (offline, Slice 4A5).
//!
//! This leaf crate translates the project-owned offline anchor-transport
//! preparation DTOs into an **unsigned**, fee-less Tari Ootle transaction that
//! carries exactly one transaction-level `EmitLog` instruction with the canonical
//! anchor payload. It depends on an exact pinned Tari Ootle revision
//! (`tari-ootle` git rev `92023e0`, v0.37.0 workspace) and does nothing beyond
//! construction and inspection.
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
mod log_instruction;
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
    inspect_fee_bearing_anchor_transaction, inspect_unsigned_anchor_transaction,
};
pub use log_instruction::{ANCHOR_EMIT_LOG_LEVEL, build_anchor_emit_log};
pub use network::{map_ootle_network, supported_testnet_network_ids};
pub use request::OotleAnchorTransactionBuildRequestV1;
