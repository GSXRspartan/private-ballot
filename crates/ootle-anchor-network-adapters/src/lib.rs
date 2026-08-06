#![forbid(unsafe_code)]

//! Real walletd and indexer client adapters for the pinned Tari Ootle anchor
//! lifecycle (Slice 4A9).
//!
//! This leaf crate implements real, pinned client adapters that satisfy the
//! narrow project-owned client traits already used by the 4A6–4A8 coordinators:
//!
//! * [`WalletdAnchorNetworkAdapter`] implements
//!   [`WalletdAnchorClient`](tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient)
//!   by forwarding project-owned commands to the confirmed
//!   [`WalletDaemonClient`](tari_ootle_walletd_client::WalletDaemonClient) through
//!   an injectable [`WalletdWireTransport`] seam.
//! * [`IndexerReceiptNetworkAdapter`] implements
//!   [`IndexerAnchorReceiptClient`](tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerAnchorReceiptClient)
//!   by forwarding project-owned receipt queries to the confirmed
//!   [`IndexerRestApiClient`](tari_indexer_client::rest_api_client::IndexerRestApiClient)
//!   through an injectable [`IndexerReceiptWireTransport`] seam.
//!
//! # Runtime ownership
//!
//! This crate owns no async runtime and starts no background task. The confirmed
//! walletd and indexer client methods are `async` and reqwest-backed; the real
//! transports bridge async-to-sync through a caller-provided
//! [`BlockingExecutor`]. A future application command supplies a tokio-based
//! executor; the offline test suites use scripted transports that require no
//! executor and open no socket.
//!
//! # What this crate never does
//!
//! It never contacts walletd, an indexer, or any network during tests; never
//! opens a socket; never submits a transaction; never signs or seals; never
//! accepts or exposes a private key, mnemonic, or signer secret; never creates a
//! process-global runtime; never adds lifecycle or verification state; and never
//! mutates an election artifact, anchor record, or archive hash. Transport and
//! conversion failures are pure transforms of already-frozen commitments, so any
//! failure leaves every offline artifact unchanged.
//!
//! # Dependency direction
//!
//! This crate is a leaf at the application layer. It depends on the 4A5–4A8
//! crates and the pinned Tari Ootle client crates. No lower-level project crate
//! depends on it.

mod auth;
mod config;
mod endpoint;
mod error;
mod executor;
mod indexer;
mod walletd;

pub use auth::{WalletdAuthSecret, WalletdAuthSecretError};
pub use config::{NetworkAdapterConfig, NetworkAdapterConfigError};
pub use endpoint::{
    IndexerEndpoint, IndexerEndpointError, MAX_ENDPOINT_BASE_PATH_BYTES, WalletdEndpoint,
    WalletdEndpointError,
};
pub use error::{TransportError, TransportErrorCategory};
pub use executor::{BlockingExecutor, BlockingExecutorError, SimpleBlockingExecutor};
pub use indexer::{
    IndexerReceiptNetworkAdapter, IndexerReceiptWireTransport, RealIndexerTransport,
    ScriptedIndexerResponse, ScriptedIndexerTransport,
};
pub use walletd::{
    RealWalletdTransport, ScriptedWalletdResponse, ScriptedWalletdTransport,
    WalletdAnchorNetworkAdapter, WalletdWireTransport,
};
