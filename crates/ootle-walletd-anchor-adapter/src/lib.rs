#![forbid(unsafe_code)]

//! Pinned Tari Ootle walletd prepare/approve adapter (offline, Slice 4A6A).
//!
//! This leaf crate takes a completed Slice 4A5
//! [`OotleAnchorBuildResultV1`] — a fee-less, single-`EmitLog` unsigned Ootle
//! transaction plus its project-owned inspection evidence — and drives the
//! confirmed walletd approval-gate lifecycle up to, but not including,
//! submission:
//!
//! 1. [`WalletdAnchorCoordinator::prepare`] re-inspects the unsigned transaction,
//!    converts it into the exact confirmed
//!    [`TransactionRequestCreateRequest`], and creates a frozen walletd request
//!    that walletd stores verbatim;
//! 2. [`WalletdAnchorCoordinator::approve`] / [`WalletdAnchorCoordinator::reject`]
//!    make an explicit, fully-bound approval-gate decision.
//!
//! It depends on the exact pinned Tari Ootle revision (`tari-ootle` git rev
//! `92023e0`, v0.37.0 workspace) for the walletd wire types, and on the wallet
//! SDK only to name those types' public fields ([`KeyId`], `EffectiveStatus`).
//!
//! It deliberately never:
//!
//! * accepts or exposes a private key, mnemonic, or signer secret (the seal
//!   signer is only a wallet key handle, and no wallet-SDK type appears in the
//!   public API);
//! * signs, seals, submits, or produces a transaction identifier;
//! * contacts walletd, an indexer, or any network (all tests use the offline
//!   [`FakeWalletdAnchorClient`]);
//! * owns an async runtime or starts a background task;
//! * reconstructs, rehashes, or mutates an election artifact, anchor record, or
//!   `ArchiveHashV1`.
//!
//! Preparing, approving, or rejecting an anchor is a pure transformation of
//! already-frozen commitments, so a failure at any step — including any walletd
//! error — leaves every offline election artifact unchanged.
//!
//! # Fee representation caveat
//!
//! The confirmed `transaction_requests.create` request stores a complete unsigned
//! transaction verbatim and has no separate `fee_account`/`max_fee` fields; those
//! belong to the immediate `transactions.submit_instruction` path, which does not
//! create an approvable frozen request. The Slice 4A5 transaction is deliberately
//! fee-less, so the fee account and maximum fee are preserved here as project-owned
//! binding metadata for human review. How the fee is actually paid at submit is a
//! Slice 4A6B concern and is not invented in this slice; see the evidence report.
//!
//! [`OotleAnchorBuildResultV1`]: tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorBuildResultV1
//! [`TransactionRequestCreateRequest`]: tari_ootle_walletd_client::types::TransactionRequestCreateRequest
//! [`KeyId`]: tari_ootle_wallet_sdk::models::KeyId

mod binding;
mod client;
mod convert;
mod coordinator;
mod errors;
mod fake;
mod identifiers;
mod registry;
mod results;
mod status;

pub use binding::WalletdAnchorBindingV1;
pub use client::{
    WalletdAnchorClient, WalletdCreateOutcomeV1, WalletdDecisionCommandV1,
    WalletdDecisionOutcomeV1, WalletdRequestStatusV1,
};
pub use convert::{WalletdCreateAnchorRequestV1, build_walletd_create_request};
pub use coordinator::{WalletdAnchorCoordinator, WalletdDecisionRequestV1};
pub use errors::WalletdAnchorAdapterError;
pub use fake::FakeWalletdAnchorClient;
pub use identifiers::{WalletdRequestId, WalletdSealSignerRef};
pub use registry::{LocalWalletdAnchorRegistry, WalletdAnchorSnapshotV1, WalletdRequestDecisionV1};
pub use results::{
    ApprovedWalletdAnchorRequestV1, PreparedWalletdAnchorRequestV1, RejectedWalletdAnchorRequestV1,
};
pub use status::WalletdEffectiveStatusV1;
