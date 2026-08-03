//! Production proof-suite allowlist for application verification boundaries.

use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// Default production proof-suite policy for version-one ballot ingestion.
///
/// Test-only suites remain available only behind their explicit crypto feature,
/// but are rejected here even when that feature is enabled for tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProductionProofSuitePolicyV1;

impl ProductionProofSuitePolicyV1 {
    /// Creates the fixed version-one production policy.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Rejects proof suites that are not approved for production ingestion.
    pub fn validate(&self, proof_suite_id: &str) -> Result<(), ProtocolError> {
        if proof_suite_id != TARI_TRIPTYCH_PROOF_SUITE_ID_V1 {
            return Err(ProtocolError::new(
                ValidationCode::UnsupportedProofSuite,
                "proof suite is not permitted by the production verification policy",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ProductionProofSuitePolicyV1;
    use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
    use tari_cc_private_ballot_protocol::{TEST_ONLY_SUITE_ID, ValidationCode};

    #[test]
    fn production_policy_accepts_the_real_triptych_suite() {
        let policy = ProductionProofSuitePolicyV1::new();

        assert!(policy.validate(TARI_TRIPTYCH_PROOF_SUITE_ID_V1).is_ok());
    }

    #[test]
    fn production_policy_rejects_the_test_only_suite() {
        let policy = ProductionProofSuitePolicyV1::new();

        assert!(matches!(
            policy.validate(TEST_ONLY_SUITE_ID),
            Err(error) if error.code() == ValidationCode::UnsupportedProofSuite
        ));
    }
}
