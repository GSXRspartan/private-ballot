#![forbid(unsafe_code)]

//! Pinned Tari Ootle walletd prepare/approve/submit adapter (offline, Slices
//! 4A6A + 4A6B).
//!
//! This leaf crate takes a completed Slice 4A5
//! [`OotleAnchorBuildResultV1`] — a single-`EmitLog` unsigned Ootle transaction
//! plus its project-owned inspection evidence — and drives the confirmed walletd
//! lifecycle from creation through submission and transaction-id recovery:
//!
//! 1. [`WalletdAnchorCoordinator::prepare_fee_bearing`] resolves the fee account
//!    component, builds a **fee-bearing** transaction (one anchor `EmitLog` plus
//!    one `pay_fee_from_component`), re-inspects it, and creates a frozen walletd
//!    request that walletd stores verbatim. (The legacy fee-less
//!    [`WalletdAnchorCoordinator::prepare`] is retained for the approval-gate
//!    reference path but is not submittable.)
//! 2. [`WalletdAnchorCoordinator::approve`] / [`WalletdAnchorCoordinator::reject`]
//!    make an explicit, fully-bound approval-gate decision;
//! 3. [`WalletdAnchorCoordinator::submit`] seals and submits an approved,
//!    fully-rebound request, mapping the sealed transaction id into a
//!    project-owned result — the first result that carries a transaction id;
//! 4. [`WalletdAnchorCoordinator::recover`] resolves a lost submit result through
//!    the confirmed status API, discovering the transaction id where walletd
//!    already sealed one and otherwise classifying the request safely.
//!
//! # Fee strategy (Slice 4A6B, confirmed from local source)
//!
//! The confirmed `transaction_requests.submit` path seals the frozen transaction
//! **verbatim** (`detect_inputs = false`) and injects no fee; only the immediate
//! `transactions.submit_instruction` / `submit_manifest` paths inject a
//! `pay_fee`. A fee-of-zero transaction is never valid. So a submittable anchor
//! transaction must embed its fee **before** creation (Strategy 2): exactly one
//! `pay_fee_from_component` naming the resolved fee account and locking the
//! maximum fee. The opaque project account cannot be resolved offline, so the
//! caller supplies the exact Ootle component address, parsed only at this leaf
//! ([`WalletdFeeComponentRef`]); the inspection fingerprint over the whole
//! transaction transitively binds the fee account and amount.
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
//! * signs or seals a transaction itself (sealing happens inside walletd at
//!   submit; this crate only maps the resulting transaction id) and never
//!   fabricates a transaction id from unsigned bytes;
//! * contacts walletd, an indexer, or any network (all tests use the offline
//!   [`FakeWalletdAnchorClient`]);
//! * owns an async runtime or starts a background task;
//! * claims acceptance, finalization, receipt retrieval, or any finality — submit
//!   yields only a `Submitted` state with an opaque transaction id;
//! * reconstructs, rehashes, or mutates an election artifact, anchor record, or
//!   `ArchiveHashV1`.
//!
//! Preparing, approving, rejecting, submitting, or recovering an anchor is a pure
//! transformation of already-frozen commitments, so a failure at any step —
//! including any walletd error, timeout, or lost response — leaves every offline
//! election artifact unchanged.
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
    WalletdDecisionOutcomeV1, WalletdRequestStatusV1, WalletdSubmitCommandV1,
    WalletdSubmitOutcomeV1,
};
pub use convert::{
    WalletdCreateAnchorRequestV1, build_fee_bearing_walletd_create_request,
    build_walletd_create_request,
};
pub use coordinator::{WalletdAnchorCoordinator, WalletdDecisionRequestV1, WalletdSubmitRequestV1};
pub use errors::WalletdAnchorAdapterError;
pub use fake::FakeWalletdAnchorClient;
pub use identifiers::{
    WalletdFeeComponentRef, WalletdRequestId, WalletdSealSignerRef, canonicalize_transaction_id,
};
pub use registry::{
    LocalWalletdAnchorRegistry, WalletdAnchorSnapshotV1, WalletdRequestDecisionV1,
    WalletdSubmissionStateV1,
};
pub use results::{
    ApprovedWalletdAnchorRequestV1, PreparedWalletdAnchorRequestV1,
    RecoveredWalletdAnchorRequestV1, RejectedWalletdAnchorRequestV1,
    SubmittedWalletdAnchorRequestV1, WalletdRecoveryStateV1,
};
pub use status::WalletdEffectiveStatusV1;
/// Re-exported so downstream crates that depend only on this adapter can name
/// the build-request type that `prepare_fee_bearing` takes as a parameter. This
/// is a narrow interface fix: the type is already part of this crate's public
/// API surface (a parameter to a public method) but was not previously
/// re-exported. No semantics are changed.
pub use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;
