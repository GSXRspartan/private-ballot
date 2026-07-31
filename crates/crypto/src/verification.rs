//! Proof-verification authority and authenticated nullifier types.

use tari_cc_private_ballot_protocol::{
    MAX_NULLIFIER_BYTES, ProofStatementV1, ProtocolError, ValidationCode,
};

mod private {
    pub trait Sealed {}
}

pub(crate) use private::Sealed;

/// A proof-suite implementation authorized by the crypto crate.
///
/// The private sealing trait prevents external crates from implementing
/// counterfeit verifiers that manufacture successful verification results.
pub trait ProofVerifierV1: Sealed {
    /// Returns the stable proof-suite identifier implemented by this verifier.
    fn proof_suite_id(&self) -> &'static str;

    /// Verifies proof bytes against the complete reconstructed statement.
    fn verify(
        &self,
        statement: &ProofStatementV1,
        proof_bytes: &[u8],
    ) -> Result<VerifiedProofV1, ProtocolError>;
}

/// Nullifier or key image authenticated by successful proof verification.
///
/// This type has no public constructor. Ballot packages and callers cannot
/// promote arbitrary bytes into verified duplicate-detection material.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifiedNullifier(Vec<u8>);

impl VerifiedNullifier {
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyNullifier,
                "verified nullifier must not be empty",
            ));
        }

        if bytes.len() > MAX_NULLIFIER_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "verified nullifier exceeds the protocol size limit",
            ));
        }

        Ok(Self(bytes))
    }

    /// Returns the authenticated nullifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Successful proof-verification output.
///
/// The result preserves both the exact verified statement and the
/// proof-authenticated nullifier returned by the proof suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProofV1 {
    statement: ProofStatementV1,
    nullifier: VerifiedNullifier,
}

impl VerifiedProofV1 {
    pub(crate) fn new(statement: ProofStatementV1, nullifier: VerifiedNullifier) -> Self {
        Self {
            statement,
            nullifier,
        }
    }

    /// Returns the exact statement authenticated by the proof.
    #[must_use]
    pub const fn statement(&self) -> &ProofStatementV1 {
        &self.statement
    }

    /// Returns the proof-authenticated nullifier.
    #[must_use]
    pub const fn nullifier(&self) -> &VerifiedNullifier {
        &self.nullifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        BallotPayloadHash, ElectionScope, ManifestHash, PROTOCOL_VERSION_V1, ProofStatementV1Input,
        RegistryCommitment,
    };

    fn statement() -> ProofStatementV1 {
        let Ok(statement) = ProofStatementV1::new(ProofStatementV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            proof_suite_id: "test-suite".to_owned(),
            manifest_hash: ManifestHash::new([1_u8; 32]),
            election_scope: ElectionScope::new([2_u8; 32]),
            registry_commitment: RegistryCommitment::new([3_u8; 32]),
            ballot_payload_hash: BallotPayloadHash::new([4_u8; 32]),
            ballot_kind_id: "TEST_KIND".to_owned(),
            ballot_confidentiality_id: "PUBLIC".to_owned(),
        }) else {
            panic!("test proof statement must be valid");
        };

        statement
    }

    #[test]
    fn verified_nullifier_rejects_empty_and_oversized_values() {
        assert!(matches!(
            VerifiedNullifier::new(Vec::new()),
            Err(error) if error.code() == ValidationCode::EmptyNullifier
        ));

        assert!(matches!(
            VerifiedNullifier::new(vec![0_u8; MAX_NULLIFIER_BYTES + 1]),
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn verified_result_preserves_statement_and_nullifier() {
        let statement = statement();

        let Ok(nullifier) = VerifiedNullifier::new(b"verified-nf".to_vec()) else {
            panic!("test nullifier must be valid");
        };

        let result = VerifiedProofV1::new(statement.clone(), nullifier);

        assert_eq!(result.statement(), &statement);
        assert_eq!(result.nullifier().as_bytes(), b"verified-nf");
    }
}
