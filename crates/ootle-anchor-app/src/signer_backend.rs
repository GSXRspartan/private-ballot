//! Anchor signer backend selection.
//!
//! This module is intentionally small: it names the architecture seam without
//! changing the existing external-walletd protocol path or pretending that an
//! embedded managed signer is already safe to publish with.

/// Future internal target once the managed wallet path is implemented.
pub const MANAGED_ANCHOR_WALLET_BACKEND_V1: &str = "ManagedAnchorWallet";

/// The current operational path backed by a user-managed local walletd.
pub const EXTERNAL_WALLETD_BACKEND_V1: &str = "ExternalWalletd";

/// This build has not enabled the managed wallet publisher.
///
/// The pinned v0.39.2 Ootle tree contains local signing, wallet SDK, SQLite
/// wallet storage, indexer submission, and OS-keyring password support. What is
/// not yet wired here is the full supported application flow that would make it
/// safe to replace walletd: install the native keyring store in this app,
/// initialize/load the wallet seed without override passwords, create or
/// recover the anchor-only account, fund it, report a trustworthy balance, sign
/// and submit the exact inspected anchor transaction, and persist recoverable
/// finality state. Until that complete flow exists, managed mode fails closed.
pub const MANAGED_ANCHOR_WALLET_ENABLED_V1: bool = false;

/// Stable operator-facing blocker for disabled managed-wallet publishing.
pub const MANAGED_ANCHOR_WALLET_BLOCKER_V1: &str =
    "ManagedAnchorWallet is not enabled in this build; use Advanced ExternalWalletd";

/// Public signer backend choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorSignerBackendV1 {
    /// Future app-owned anchor-only wallet, protected by the OS credential
    /// store. This build keeps the seam but does not enable it.
    ManagedAnchorWallet,
    /// The current operational path: a loopback walletd signs and submits.
    ExternalWalletd,
}

impl AnchorSignerBackendV1 {
    /// Returns the stable display name for this backend.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManagedAnchorWallet => MANAGED_ANCHOR_WALLET_BACKEND_V1,
            Self::ExternalWalletd => EXTERNAL_WALLETD_BACKEND_V1,
        }
    }

    /// Returns whether this backend is enabled in the current build.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        match self {
            Self::ManagedAnchorWallet => MANAGED_ANCHOR_WALLET_ENABLED_V1,
            Self::ExternalWalletd => true,
        }
    }

    /// Returns the stable blocker text when the backend is disabled.
    #[must_use]
    pub const fn disabled_blocker(self) -> Option<&'static str> {
        match self {
            Self::ManagedAnchorWallet if !MANAGED_ANCHOR_WALLET_ENABLED_V1 => {
                Some(MANAGED_ANCHOR_WALLET_BLOCKER_V1)
            }
            _ => None,
        }
    }
}

impl Default for AnchorSignerBackendV1 {
    fn default() -> Self {
        Self::ExternalWalletd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_walletd_is_the_operational_default() {
        let backend = AnchorSignerBackendV1::default();
        assert_eq!(backend, AnchorSignerBackendV1::ExternalWalletd);
        assert_eq!(backend.as_str(), EXTERNAL_WALLETD_BACKEND_V1);
        assert!(backend.is_enabled());
        assert_eq!(backend.disabled_blocker(), None);
    }

    #[test]
    fn managed_anchor_wallet_remains_unavailable_future_seam() {
        let backend = AnchorSignerBackendV1::ManagedAnchorWallet;
        assert_eq!(backend.as_str(), MANAGED_ANCHOR_WALLET_BACKEND_V1);
        assert!(!backend.is_enabled());
        assert_eq!(
            backend.disabled_blocker(),
            Some(MANAGED_ANCHOR_WALLET_BLOCKER_V1)
        );
    }
}
