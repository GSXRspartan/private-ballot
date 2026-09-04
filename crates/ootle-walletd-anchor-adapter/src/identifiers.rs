//! Project-owned, bounded references at the walletd boundary (Sections A, C).
//!
//! [`WalletdRequestId`] wraps the opaque walletd request handle. [`WalletdSealSignerRef`]
//! is a project-owned reference to the wallet key walletd seals with at submit;
//! it converts to the confirmed [`KeyId`] but is itself only an index into
//! walletd's keystore and can never carry a private key or mnemonic. No
//! wallet-SDK type appears in this module's public surface.

use core::fmt;
use core::str::FromStr;

use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;
use tari_ootle_transaction::TransactionId;
use tari_ootle_wallet_sdk::models::{KeyBranch, KeyId};
use tari_template_lib_types::ComponentAddress;

use crate::errors::WalletdAnchorAdapterError;

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
    pub fn to_key_id(self) -> KeyId {
        match self {
            Self::AccountKey { index } => KeyId::derived(KeyBranch::Account, index),
            Self::TransactionKey { index } => KeyId::derived(KeyBranch::Transaction, index),
            Self::ImportedKey { local_key_id } => KeyId::imported(local_key_id),
        }
    }
}

/// Project-owned, resolved reference to the fee account's Ootle component address.
///
/// The opaque project [`AnchorAccountReference`] cannot be resolved offline, so a
/// human operator supplies the exact Ootle component address of the fee account
/// (as printed by walletd, `component_<hex>` or bare hex). This is the single
/// place the project turns that string into a pinned Ootle [`ComponentAddress`]
/// for the `pay_fee_from_component` instruction — address resolution never leaks
/// past this leaf. A component address is public ledger data but still identifies
/// an account, so its `Debug` is redacted to keep it out of logs.
///
/// [`AnchorAccountReference`]: tari_cc_private_ballot_anchor_transport::AnchorAccountReference
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletdFeeComponentRef {
    component: ComponentAddress,
}

impl WalletdFeeComponentRef {
    /// Parses and freezes a resolved fee account component address.
    ///
    /// # Errors
    ///
    /// Returns [`WalletdAnchorAdapterError::FeeComponentInvalid`] if `value` is not
    /// a valid Ootle component address.
    pub fn parse(value: &str) -> Result<Self, WalletdAnchorAdapterError> {
        let component = ComponentAddress::from_str(value)
            .map_err(|_error| WalletdAnchorAdapterError::FeeComponentInvalid)?;
        Ok(Self { component })
    }

    /// Returns the resolved pinned Ootle component address (leaf-internal).
    #[must_use]
    /// Returns the already-validated pinned component address for the narrow
    /// pre-CREATE input-detection/reinspection path. It never parses caller
    /// input and exposes no wallet secret.
    pub const fn component_address(&self) -> ComponentAddress {
        self.component
    }

    /// Returns the canonical `component_<hex>` display string for human review.
    #[must_use]
    pub fn display_string(&self) -> String {
        self.component.to_string()
    }
}

impl fmt::Debug for WalletdFeeComponentRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletdFeeComponentRef(<redacted>)")
    }
}

/// Canonicalizes a sealed Ootle [`TransactionId`] into a project transaction id.
///
/// The pinned `TransactionId` is a fixed 32-byte value whose `Display` is exactly
/// 64 lowercase hexadecimal characters — always a valid bounded
/// [`AnchorTransactionId`]. This is the single, safe canonicalization a real
/// walletd client uses at this leaf to turn the submit response's opaque id into a
/// project-owned identifier; it derives nothing and cannot fail. It is the one
/// deliberate seam that names the pinned Ootle `TransactionId`, mirroring how the
/// construction adapter names the pinned `UnsignedTransaction`.
#[must_use]
pub fn canonicalize_transaction_id(id: &TransactionId) -> AnchorTransactionId {
    let mut encoded = String::with_capacity(64);
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in id.as_bytes() {
        encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    match AnchorTransactionId::new(encoded) {
        Ok(transaction_id) => transaction_id,
        Err(_error) => {
            unreachable!("64 lowercase hex characters are always a valid transaction identifier")
        }
    }
}
