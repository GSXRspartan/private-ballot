//! Documented application configuration (Section P).
//!
//! [`NetworkAdapterConfig`] is the minimum project-owned configuration a
//! future CLI/GUI supplies to drive the anchor lifecycle through the real
//! network adapters. It carries only public locator data and bounded policy
//! values; no secret is persisted in `Debug` output, and the optional auth
//! reference redacts its `Debug`.

use core::fmt;

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1;
use tari_cc_private_ballot_ootle_anchor_adapter::map_ootle_network;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdFeeComponentRef, WalletdSealSignerRef,
};

use crate::auth::WalletdAuthSecret;
use crate::endpoint::{IndexerEndpoint, WalletdEndpoint};

/// Hard policy ceiling for the anchor transaction's maximum fee, in the
/// ledger's smallest unit.
///
/// The anchor transaction is minimal: exactly one `pay_fee_from_component` plus
/// one `CallFunction` to the stateless event template. Its real fee is on the
/// order of the operator default of
/// 1,000 units (see the GUI default). This ceiling is ~10,000× that default —
/// generous headroom for any fee-market fluctuation while making it impossible
/// for a mis-entered or a maliciously modified frontend to authorize a
/// wallet-draining budget (e.g. `u64::MAX`). The ceiling bounds only the
/// operator-authorized spend limit; it is not a protocol constant and never
/// enters the anchor-record digest (which commits to network + manifest hash +
/// archive hash only).
pub const OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1: u64 = 10_000_000;

/// Minimum accepted request timeout, in seconds. Zero is rejected so a
/// misconfigured "0s" can never make every request time out instantly.
pub const OOTLE_ANCHOR_REQUEST_TIMEOUT_MIN_SECS_V1: u64 = 1;

/// Maximum accepted request timeout, in seconds (ten minutes). Bounds an
/// over-large value so a single request can never park a worker indefinitely.
pub const OOTLE_ANCHOR_REQUEST_TIMEOUT_MAX_SECS_V1: u64 = 600;

/// Rejection categories for application configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAdapterConfigError {
    /// The network is not a supported testnet.
    UnsupportedNetwork,
    /// The maximum fee was zero.
    InvalidMaxFee,
    /// The maximum fee exceeded [`OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1`].
    MaxFeeAboveCeiling,
    /// The receipt-query attempt count was zero.
    InvalidReceiptQueryAttempts,
    /// The optional request timeout was present but outside the sane bounds
    /// [`OOTLE_ANCHOR_REQUEST_TIMEOUT_MIN_SECS_V1`]..=[`OOTLE_ANCHOR_REQUEST_TIMEOUT_MAX_SECS_V1`].
    InvalidRequestTimeout,
}

impl NetworkAdapterConfigError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedNetwork => "CONFIG_UNSUPPORTED_NETWORK",
            Self::InvalidMaxFee => "CONFIG_INVALID_MAX_FEE",
            Self::MaxFeeAboveCeiling => "CONFIG_MAX_FEE_ABOVE_CEILING",
            Self::InvalidReceiptQueryAttempts => "CONFIG_INVALID_RECEIPT_QUERY_ATTEMPTS",
            Self::InvalidRequestTimeout => "CONFIG_INVALID_REQUEST_TIMEOUT",
        }
    }
}

impl fmt::Display for NetworkAdapterConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for NetworkAdapterConfigError {}

/// Minimum project-owned configuration for a future CLI/GUI.
///
/// No secret is persisted in `Debug` output: the optional
/// [`WalletdAuthSecret`] redacts its `Debug`, and no endpoint carries
/// credentials (the endpoint validation rejects embedded credentials).
#[derive(Debug, Clone)]
pub struct NetworkAdapterConfig {
    network: OotleNetworkIdV1,
    walletd_endpoint: WalletdEndpoint,
    indexer_endpoint: IndexerEndpoint,
    fee_component: WalletdFeeComponentRef,
    seal_signer: WalletdSealSignerRef,
    max_fee: AnchorMaxFeeV1,
    request_timeout_secs: Option<u64>,
    receipt_query_max_attempts: u32,
    auth: Option<WalletdAuthSecret>,
}

impl NetworkAdapterConfig {
    /// Creates a new application configuration from already-validated parts.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkAdapterConfigError::UnsupportedNetwork`] if the
    /// network is not a supported testnet, [`NetworkAdapterConfigError::InvalidMaxFee`]
    /// if the maximum fee is zero, or
    /// [`NetworkAdapterConfigError::InvalidReceiptQueryAttempts`] if the
    /// receipt-query attempt count is zero.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: OotleNetworkIdV1,
        walletd_endpoint: WalletdEndpoint,
        indexer_endpoint: IndexerEndpoint,
        fee_component: WalletdFeeComponentRef,
        seal_signer: WalletdSealSignerRef,
        max_fee: AnchorMaxFeeV1,
        request_timeout_secs: Option<u64>,
        receipt_query_max_attempts: u32,
        auth: Option<WalletdAuthSecret>,
    ) -> Result<Self, NetworkAdapterConfigError> {
        map_ootle_network(&network).map_err(|_| NetworkAdapterConfigError::UnsupportedNetwork)?;
        if max_fee.value() == 0 {
            return Err(NetworkAdapterConfigError::InvalidMaxFee);
        }
        if max_fee.value() > OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1 {
            return Err(NetworkAdapterConfigError::MaxFeeAboveCeiling);
        }
        if receipt_query_max_attempts == 0 {
            return Err(NetworkAdapterConfigError::InvalidReceiptQueryAttempts);
        }
        if let Some(secs) = request_timeout_secs {
            if !(OOTLE_ANCHOR_REQUEST_TIMEOUT_MIN_SECS_V1
                ..=OOTLE_ANCHOR_REQUEST_TIMEOUT_MAX_SECS_V1)
                .contains(&secs)
            {
                return Err(NetworkAdapterConfigError::InvalidRequestTimeout);
            }
        }
        Ok(Self {
            network,
            walletd_endpoint,
            indexer_endpoint,
            fee_component,
            seal_signer,
            max_fee,
            request_timeout_secs,
            receipt_query_max_attempts,
            auth,
        })
    }

    /// Returns the selected Ootle network.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the walletd endpoint.
    #[must_use]
    pub fn walletd_endpoint(&self) -> &WalletdEndpoint {
        &self.walletd_endpoint
    }

    /// Returns the indexer endpoint.
    #[must_use]
    pub fn indexer_endpoint(&self) -> &IndexerEndpoint {
        &self.indexer_endpoint
    }

    /// Returns the resolved fee account component address.
    #[must_use]
    pub fn fee_component(&self) -> &WalletdFeeComponentRef {
        &self.fee_component
    }

    /// Returns the seal-signer key handle.
    #[must_use]
    pub const fn seal_signer(&self) -> WalletdSealSignerRef {
        self.seal_signer
    }

    /// Returns the maximum fee.
    #[must_use]
    pub const fn max_fee(&self) -> AnchorMaxFeeV1 {
        self.max_fee
    }

    /// Returns the optional request timeout, in seconds.
    #[must_use]
    pub const fn request_timeout_secs(&self) -> Option<u64> {
        self.request_timeout_secs
    }

    /// Returns the receipt-query maximum attempt count.
    #[must_use]
    pub const fn receipt_query_max_attempts(&self) -> u32 {
        self.receipt_query_max_attempts
    }

    /// Returns the optional walletd auth secret.
    #[must_use]
    pub fn auth(&self) -> Option<&WalletdAuthSecret> {
        self.auth.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_network() -> OotleNetworkIdV1 {
        OotleNetworkIdV1::new("esmeralda".to_owned())
            .unwrap_or_else(|e| panic!("test network must be valid: {e:?}"))
    }

    fn valid_endpoint() -> WalletdEndpoint {
        WalletdEndpoint::parse("http://127.0.0.1:12009")
            .unwrap_or_else(|e| panic!("test endpoint must be valid: {e:?}"))
    }

    fn valid_indexer_endpoint() -> IndexerEndpoint {
        IndexerEndpoint::parse("http://127.0.0.1:12500")
            .unwrap_or_else(|e| panic!("test indexer endpoint must be valid: {e:?}"))
    }

    fn valid_fee_component() -> WalletdFeeComponentRef {
        WalletdFeeComponentRef::parse(
            "component_1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap_or_else(|e| panic!("test fee component must be valid: {e:?}"))
    }

    #[test]
    fn valid_config_is_accepted() {
        let config = NetworkAdapterConfig::new(
            valid_network(),
            valid_endpoint(),
            valid_indexer_endpoint(),
            valid_fee_component(),
            WalletdSealSignerRef::AccountKey { index: 0 },
            AnchorMaxFeeV1::from_units(1000),
            Some(30),
            8,
            None,
        )
        .unwrap_or_else(|e| panic!("valid config must be accepted: {e:?}"));
        assert_eq!(config.network().as_str(), "esmeralda");
        assert_eq!(config.max_fee().value(), 1000);
        assert_eq!(config.receipt_query_max_attempts(), 8);
    }

    #[test]
    fn unsupported_network_is_rejected() {
        let bad_network =
            OotleNetworkIdV1::new("mainnet".to_owned()).unwrap_or_else(|e| panic!("{e:?}"));
        let result = NetworkAdapterConfig::new(
            bad_network,
            valid_endpoint(),
            valid_indexer_endpoint(),
            valid_fee_component(),
            WalletdSealSignerRef::AccountKey { index: 0 },
            AnchorMaxFeeV1::from_units(1000),
            None,
            8,
            None,
        );
        assert_eq!(
            result.err().unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::UnsupportedNetwork
        );
    }

    #[test]
    fn zero_max_fee_is_rejected() {
        let result = NetworkAdapterConfig::new(
            valid_network(),
            valid_endpoint(),
            valid_indexer_endpoint(),
            valid_fee_component(),
            WalletdSealSignerRef::AccountKey { index: 0 },
            AnchorMaxFeeV1::from_units(0),
            None,
            8,
            None,
        );
        assert_eq!(
            result.err().unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::InvalidMaxFee
        );
    }

    #[test]
    fn zero_receipt_attempts_is_rejected() {
        let result = NetworkAdapterConfig::new(
            valid_network(),
            valid_endpoint(),
            valid_indexer_endpoint(),
            valid_fee_component(),
            WalletdSealSignerRef::AccountKey { index: 0 },
            AnchorMaxFeeV1::from_units(1000),
            None,
            0,
            None,
        );
        assert_eq!(
            result.err().unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::InvalidReceiptQueryAttempts
        );
    }

    fn config_with_fee_and_timeout(
        fee: u64,
        timeout: Option<u64>,
    ) -> Result<NetworkAdapterConfig, NetworkAdapterConfigError> {
        NetworkAdapterConfig::new(
            valid_network(),
            valid_endpoint(),
            valid_indexer_endpoint(),
            valid_fee_component(),
            WalletdSealSignerRef::AccountKey { index: 0 },
            AnchorMaxFeeV1::from_units(fee),
            timeout,
            8,
            None,
        )
    }

    #[test]
    fn max_fee_at_policy_ceiling_is_accepted() {
        let config = config_with_fee_and_timeout(OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1, Some(30))
            .unwrap_or_else(|e| panic!("ceiling fee must be accepted: {e:?}"));
        assert_eq!(
            config.max_fee().value(),
            OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1
        );
    }

    #[test]
    fn max_fee_above_policy_ceiling_is_rejected() {
        assert_eq!(
            config_with_fee_and_timeout(OOTLE_ANCHOR_MAX_FEE_CEILING_UNITS_V1 + 1, Some(30))
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::MaxFeeAboveCeiling
        );
        assert_eq!(
            config_with_fee_and_timeout(u64::MAX, Some(30))
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::MaxFeeAboveCeiling
        );
    }

    #[test]
    fn request_timeout_bounds_are_enforced() {
        // In-range values (including the exact bounds) are accepted.
        assert!(config_with_fee_and_timeout(1000, None).is_ok());
        assert!(
            config_with_fee_and_timeout(1000, Some(OOTLE_ANCHOR_REQUEST_TIMEOUT_MIN_SECS_V1))
                .is_ok()
        );
        assert!(
            config_with_fee_and_timeout(1000, Some(OOTLE_ANCHOR_REQUEST_TIMEOUT_MAX_SECS_V1))
                .is_ok()
        );
        // Zero and over-max are rejected.
        assert_eq!(
            config_with_fee_and_timeout(1000, Some(0))
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::InvalidRequestTimeout
        );
        assert_eq!(
            config_with_fee_and_timeout(1000, Some(OOTLE_ANCHOR_REQUEST_TIMEOUT_MAX_SECS_V1 + 1))
                .err()
                .unwrap_or_else(|| panic!("expected error")),
            NetworkAdapterConfigError::InvalidRequestTimeout
        );
    }
}
