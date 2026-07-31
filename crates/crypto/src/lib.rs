#![forbid(unsafe_code)]

//! Cryptography-agnostic anonymous-membership boundary.

use tari_cc_private_ballot_protocol::ProtocolError;

/// Borrowed inputs required to verify one membership proof.
#[derive(Debug)]
pub struct ProofVerificationRequest<'a> {
    pub election_scope: &'a [u8],
    pub registry_commitment: &'a [u8],
    pub ballot_commitment: &'a [u8],
    pub proof: &'a [u8],
    pub claimed_nullifier: &'a [u8],
}

/// Verified membership output used for duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMembership {
    election_scoped_nullifier: Vec<u8>,
}

impl VerifiedMembership {
    /// Creates verified output.
    #[must_use]
    pub fn new(election_scoped_nullifier: Vec<u8>) -> Self {
        Self {
            election_scoped_nullifier,
        }
    }

    /// Returns the election-scoped nullifier.
    #[must_use]
    pub fn election_scoped_nullifier(&self) -> &[u8] {
        &self.election_scoped_nullifier
    }
}

/// Suite-independent anonymous-membership verification interface.
pub trait AnonymousMembershipVerifier {
    /// Returns the exact versioned suite identifier.
    fn suite_id(&self) -> &'static str;

    /// Verifies one proof.
    fn verify(
        &self,
        request: &ProofVerificationRequest<'_>,
    ) -> Result<VerifiedMembership, ProtocolError>;
}

/// Debug and test-only protocol plumbing.
#[cfg(any(test, debug_assertions))]
pub mod test_only {
    use super::{AnonymousMembershipVerifier, ProofVerificationRequest, VerifiedMembership};
    use tari_cc_private_ballot_protocol::{ProtocolError, TEST_ONLY_SUITE_ID, ValidationCode};

    /// Marker bytes accepted only by the test-only provider.
    pub const TEST_ONLY_PROOF_BYTES: &[u8] = b"TEST_ONLY_PROOF";

    /// Explicitly non-anonymous test provider.
    #[derive(Debug, Clone, Copy)]
    pub struct TestOnlyProofVerifier;

    impl AnonymousMembershipVerifier for TestOnlyProofVerifier {
        fn suite_id(&self) -> &'static str {
            TEST_ONLY_SUITE_ID
        }

        fn verify(
            &self,
            request: &ProofVerificationRequest<'_>,
        ) -> Result<VerifiedMembership, ProtocolError> {
            if request.election_scope.is_empty()
                || request.registry_commitment.is_empty()
                || request.ballot_commitment.is_empty()
                || request.claimed_nullifier.is_empty()
            {
                return Err(ProtocolError::new(
                    ValidationCode::InvalidData,
                    "test-only verification inputs must not be empty",
                ));
            }

            if request.proof != TEST_ONLY_PROOF_BYTES {
                return Err(ProtocolError::new(
                    ValidationCode::MalformedProof,
                    "invalid test-only proof marker",
                ));
            }

            Ok(VerifiedMembership::new(request.claimed_nullifier.to_vec()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            AnonymousMembershipVerifier, ProofVerificationRequest, TEST_ONLY_PROOF_BYTES,
            TestOnlyProofVerifier,
        };

        #[test]
        fn accepts_the_explicit_test_marker() {
            let verifier = TestOnlyProofVerifier;
            let request = ProofVerificationRequest {
                election_scope: b"pilot-election",
                registry_commitment: b"registry",
                ballot_commitment: b"ballot",
                proof: TEST_ONLY_PROOF_BYTES,
                claimed_nullifier: b"nullifier",
            };

            assert!(verifier.verify(&request).is_ok());
        }
    }
}

pub mod test_only_verifier;
mod verification;
pub use verification::{ProofVerifierV1, VerifiedNullifier, VerifiedProofV1};
