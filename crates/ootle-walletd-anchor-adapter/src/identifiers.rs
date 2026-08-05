//! Project-owned, bounded references at the walletd boundary (Sections A, C).
//!
//! [`WalletdRequestId`] wraps the opaque walletd request handle. [`WalletdSealSignerRef`]
//! is a project-owned reference to the wallet key walletd seals with at submit;
//! it converts to the confirmed [`KeyId`] but is itself only an index into
//! walletd's keystore and can never carry a private key or mnemonic. No
//! wallet-SDK type appears in this module's public surface.

use core::fmt;

use tari_ootle_wallet_sdk::models::{KeyBranch, KeyId};

/// Opaque walletd transaction-request identifier.
///
/// Slice 4A3 confirmed walletd exposes only an opaque request handle here
/// (`TransactionRequestId`, an `i32`). It is treated as opaque and bounded: the
/// project never interprets its value beyond equality and correlation. Its
/// `Debug` is redacted so it cannot leak into logs; human review reads it
/// explicitly through [`Self::value`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletdRequestId(i32);

impl WalletdRequestId {
    /// Wraps an opaque walletd request identifier value.
    #[must_use]
    pub const fn from_walletd(value: i32) -> Self {
        Self(value)
    }

    /// Returns the opaque identifier value for explicit human review.
    #[must_use]
    pub const fn value(self) -> i32 {
        self.0
    }
}

impl fmt::Debug for WalletdRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletdRequestId(<redacted>)")
    }
}

/// Project-owned reference to the wallet key that seals the request at submit.
///
/// The confirmed `transaction_requests.create` API requires a `seal_signer`
/// naming which wallet key pays and seals last. That key stays in walletd's
/// custody: this reference is only a branch-and-index (or imported-key index)
/// handle, never key material. Modelling it explicitly keeps the wallet-SDK
/// [`KeyId`] type out of this crate's public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WalletdSealSignerRef {
    /// The account key branch at the given derivation index (pays and seals).
    AccountKey {
        /// Derivation index within the account branch.
        index: u64,
    },
    /// The transaction key branch at the given derivation index.
    TransactionKey {
        /// Derivation index within the transaction branch.
        index: u64,
    },
    /// A previously imported wallet key, by its local key identifier.
    ImportedKey {
        /// Local imported-key identifier held by walletd.
        local_key_id: u64,
    },
}

impl WalletdSealSignerRef {
    /// Converts the project reference into the confirmed walletd [`KeyId`].
    ///
    /// This produces only a key handle; it derives no key and holds no secret.
    #[must_use]
    pub(crate) fn to_key_id(self) -> KeyId {
        match self {
            Self::AccountKey { index } => KeyId::derived(KeyBranch::Account, index),
            Self::TransactionKey { index } => KeyId::derived(KeyBranch::Transaction, index),
            Self::ImportedKey { local_key_id } => KeyId::imported(local_key_id),
        }
    }
}
