//! Project-owned Tari Triptych prototype proof construction.
//!
//! This module deliberately exposes no third-party cryptographic types. It
//! accepts only the complete project proof statement, a previously configured
//! registry-bound verifier, and one canonical zeroizing secret-scalar wrapper.
//!
//! The implementation is experimental prototype cryptography. It does not
//! provide key generation, persistence, import UX, hardware-backed storage, or
//! authorization for binding elections.

use core::fmt;

use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand_core::OsRng;
use tari_cc_private_ballot_protocol::{ProofStatementV1, ProtocolError, ValidationCode};
use triptych::{TriptychProof, TriptychWitness};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    RISTRETTO_COMPRESSED_POINT_BYTES, RistrettoPublicKeyV1, TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
    TariTriptychProofEnvelopeV1, TariTriptychPrototypeVerifierV1,
    triptych_prototype::build_triptych_statement_v1, triptych_verifier::triptych_transcript_v1,
};

/// Canonical nonzero Triptych signing scalar for prototype proof construction.
///
/// The canonical 32-byte representation is zeroized when this value is
/// dropped. The type intentionally implements neither `Copy` nor `Clone`, and
/// its `Debug` representation never includes secret bytes.
pub struct TariTriptychSecretKeyV1 {
    bytes: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
}

impl TariTriptychSecretKeyV1 {
    /// Generates one nonzero Triptych signing scalar with operating-system
    /// randomness.
    ///
    /// This is credential/key generation only. It does not construct a proof,
    /// linking tag, nullifier, or ballot package.
    pub fn generate_os_rng() -> Result<Self, ProtocolError> {
        loop {
            let scalar = Zeroizing::new(Scalar::random(&mut OsRng));
            if *scalar == Scalar::ZERO {
                continue;
            }
            let mut bytes = scalar.to_bytes();
            let secret = Self::from_canonical_bytes(bytes);
            bytes.zeroize();
            return secret;
        }
    }

    /// Parses one canonical, nonzero scalar encoding.
    pub fn from_canonical_bytes(
        bytes: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    ) -> Result<Self, ProtocolError> {
        let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)) else {
            return Err(invalid_secret(
                "Triptych secret key is not a canonical scalar encoding",
            ));
        };

        if scalar == Scalar::ZERO {
            return Err(invalid_secret("Triptych secret key must be nonzero"));
        }

        Ok(Self { bytes })
    }

    /// Derives the canonical governance public key corresponding to this
    /// secret scalar.
    pub fn governance_public_key(&self) -> Result<RistrettoPublicKeyV1, ProtocolError> {
        let scalar = self.scalar()?;
        let encoded = (RISTRETTO_BASEPOINT_POINT * *scalar).compress().to_bytes();
        RistrettoPublicKeyV1::from_bytes(&encoded)
    }

    fn scalar(&self) -> Result<Zeroizing<Scalar>, ProtocolError> {
        let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(self.bytes)) else {
            return Err(invalid_secret(
                "stored Triptych secret key is not canonical",
            ));
        };

        if scalar == Scalar::ZERO {
            return Err(invalid_secret("stored Triptych secret key must be nonzero"));
        }

        Ok(Zeroizing::new(scalar))
    }
}

impl fmt::Debug for TariTriptychSecretKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TariTriptychSecretKeyV1([REDACTED])")
    }
}

impl Drop for TariTriptychSecretKeyV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Constructs one Tari Triptych prototype proof envelope.
///
/// The verifier supplies the frozen canonical registry key list and expected
/// registry commitment. The signer key is derived from `secret_key`, located in
/// that canonical registry, and bound to the complete `statement`.
///
/// Fresh operating-system randomness is requested internally for every proof.
/// This function is not a production signing API and must not be used for a
/// binding election without independent cryptographic and side-channel review.
pub fn prove_tari_triptych_prototype_v1(
    statement: &ProofStatementV1,
    verifier: &TariTriptychPrototypeVerifierV1,
    secret_key: &TariTriptychSecretKeyV1,
) -> Result<Vec<u8>, ProtocolError> {
    if statement.proof_suite_id() != TARI_TRIPTYCH_PROOF_SUITE_ID_V1 {
        return Err(invalid_data(
            "Triptych prototype prover received a different proof suite",
        ));
    }

    if statement.registry_commitment() != verifier.registry_commitment() {
        return Err(invalid_data(
            "Triptych prover registry commitment does not match the proof statement",
        ));
    }

    let registry_keys = verifier.registry_keys();
    let placeholder_linking_tag = *registry_keys
        .first()
        .ok_or_else(|| invalid_data("Triptych prover registry configuration is empty"))?;
    let election_scope = statement.election_scope();

    let seed_statement = build_triptych_statement_v1(
        statement.protocol_version(),
        statement.proof_suite_id(),
        election_scope.as_bytes(),
        registry_keys,
        placeholder_linking_tag,
    )?;
    let secret_scalar = secret_key.scalar()?;
    let seed_witness = TriptychWitness::new(seed_statement.get_params(), 0, &secret_scalar)
        .map_err(|_| invalid_secret("Triptych secret key cannot construct a witness"))?;
    let signer_key = seed_witness
        .compute_verification_key()
        .compress()
        .to_bytes();
    let linking_tag = seed_witness.compute_linking_tag().compress().to_bytes();

    let signer_index = registry_keys.binary_search(&signer_key).map_err(|_| {
        invalid_secret("Triptych secret key does not match any frozen registry member")
    })?;
    let signer_index = u32::try_from(signer_index)
        .map_err(|_| invalid_data("Triptych signer index exceeds the supported range"))?;

    let triptych_statement = build_triptych_statement_v1(
        statement.protocol_version(),
        statement.proof_suite_id(),
        election_scope.as_bytes(),
        registry_keys,
        linking_tag,
    )?;
    let witness = TriptychWitness::new(
        triptych_statement.get_params(),
        signer_index,
        &secret_scalar,
    )
    .map_err(|_| invalid_secret("Triptych witness construction failed"))?;
    let mut transcript = triptych_transcript_v1(statement)?;
    let proof =
        TriptychProof::prove_with_rng(&witness, &triptych_statement, &mut OsRng, &mut transcript)
            .map_err(|_| malformed_proof("Triptych proof construction failed"))?;
    let envelope = TariTriptychProofEnvelopeV1::new(linking_tag, proof.to_bytes())?;

    Ok(envelope.to_bytes())
}

fn invalid_secret(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidData, message)
}

fn invalid_data(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidData, message)
}

fn malformed_proof(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::MalformedProof, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use tari_cc_private_ballot_protocol::{
        BallotPayloadHash, ElectionScope, ManifestHash, PROTOCOL_VERSION_V1, ProofStatementV1Input,
        RegistryCommitment,
    };

    use crate::ProofVerifierV1;

    const SECRET_SCALAR: u64 = 7;

    #[test]
    fn valid_prototype_proof_verifies_and_authenticates_linking_tag() {
        let fixture = fixture();
        let Ok(proof_bytes) = prove_tari_triptych_prototype_v1(
            &fixture.statement,
            &fixture.verifier,
            &fixture.secret_key,
        ) else {
            panic!("registered prototype secret must construct a proof");
        };

        let Ok(verified) = fixture.verifier.verify(&fixture.statement, &proof_bytes) else {
            panic!("constructed Triptych proof must verify");
        };
        let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(&proof_bytes) else {
            panic!("constructed proof envelope must parse");
        };

        assert_eq!(
            verified.nullifier().as_bytes(),
            envelope.linking_tag_bytes(),
        );
    }

    #[test]
    fn proof_is_bound_to_the_complete_statement() {
        let fixture = fixture();
        let Ok(proof_bytes) = prove_tari_triptych_prototype_v1(
            &fixture.statement,
            &fixture.verifier,
            &fixture.secret_key,
        ) else {
            panic!("registered prototype secret must construct a proof");
        };
        let changed_statement = proof_statement(
            fixture.statement.registry_commitment(),
            9,
            TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        );

        assert!(
            fixture
                .verifier
                .verify(&changed_statement, &proof_bytes)
                .is_err()
        );
    }

    #[test]
    fn unregistered_secret_is_rejected() {
        let fixture = fixture();
        let Ok(other_secret) =
            TariTriptychSecretKeyV1::from_canonical_bytes(Scalar::from(99_u64).to_bytes())
        else {
            panic!("test scalar must be canonical");
        };

        assert!(matches!(
            prove_tari_triptych_prototype_v1(
                &fixture.statement,
                &fixture.verifier,
                &other_secret,
            ),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn mismatched_registry_commitment_is_rejected_before_proving() {
        let fixture = fixture();
        let changed_statement = proof_statement(
            RegistryCommitment::new([0xaa_u8; 32]),
            4,
            TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        );

        assert!(matches!(
            prove_tari_triptych_prototype_v1(
                &changed_statement,
                &fixture.verifier,
                &fixture.secret_key,
            ),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn noncanonical_and_zero_secret_scalars_are_rejected() {
        assert!(matches!(
            TariTriptychSecretKeyV1::from_canonical_bytes([0xff_u8; 32]),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
        assert!(matches!(
            TariTriptychSecretKeyV1::from_canonical_bytes([0_u8; 32]),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn generation_produces_valid_distinct_public_keys() {
        let Ok(first) = TariTriptychSecretKeyV1::generate_os_rng() else {
            panic!("OS RNG generation must succeed");
        };
        let Ok(second) = TariTriptychSecretKeyV1::generate_os_rng() else {
            panic!("OS RNG generation must succeed");
        };
        let Ok(first_public) = first.governance_public_key() else {
            panic!("generated secret must derive a public key");
        };
        let Ok(second_public) = second.governance_public_key() else {
            panic!("generated secret must derive a public key");
        };

        assert_ne!(first_public, second_public);
    }

    #[test]
    fn public_key_derivation_matches_triptych_verification_key() {
        let secret_key = secret_key();
        let Ok(public_key) = secret_key.governance_public_key() else {
            panic!("secret must derive public key");
        };
        let expected = (RISTRETTO_BASEPOINT_POINT * Scalar::from(SECRET_SCALAR))
            .compress()
            .to_bytes();

        assert_eq!(public_key.as_bytes(), &expected);
    }

    #[test]
    fn secret_key_debug_output_is_redacted_and_drop_is_required() {
        let secret = secret_key();

        assert_eq!(format!("{secret:?}"), "TariTriptychSecretKeyV1([REDACTED])",);
        assert!(core::mem::needs_drop::<TariTriptychSecretKeyV1>());
        assert_eq!(
            core::mem::size_of::<TariTriptychSecretKeyV1>(),
            RISTRETTO_COMPRESSED_POINT_BYTES,
        );
    }

    struct Fixture {
        statement: ProofStatementV1,
        verifier: TariTriptychPrototypeVerifierV1,
        secret_key: TariTriptychSecretKeyV1,
    }

    fn fixture() -> Fixture {
        let secret_key = secret_key();
        let signer_key = (RISTRETTO_BASEPOINT_POINT * Scalar::from(SECRET_SCALAR))
            .compress()
            .to_bytes();
        let mut registry_keys = vec![point_bytes(1), point_bytes(2), point_bytes(3), signer_key];
        registry_keys.sort_unstable();
        let registry_commitment = RegistryCommitment::new([3_u8; 32]);
        let Ok(verifier) = TariTriptychPrototypeVerifierV1::new(registry_commitment, registry_keys)
        else {
            panic!("test verifier configuration must be valid");
        };
        let statement = proof_statement(registry_commitment, 4, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);

        Fixture {
            statement,
            verifier,
            secret_key,
        }
    }

    fn secret_key() -> TariTriptychSecretKeyV1 {
        let Ok(secret) =
            TariTriptychSecretKeyV1::from_canonical_bytes(Scalar::from(SECRET_SCALAR).to_bytes())
        else {
            panic!("test secret scalar must be canonical and nonzero");
        };

        secret
    }

    fn proof_statement(
        registry_commitment: RegistryCommitment,
        payload_byte: u8,
        proof_suite_id: &str,
    ) -> ProofStatementV1 {
        let Ok(statement) = ProofStatementV1::new(ProofStatementV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            proof_suite_id: proof_suite_id.to_owned(),
            manifest_hash: ManifestHash::new([1_u8; 32]),
            election_scope: ElectionScope::new([2_u8; 32]),
            registry_commitment,
            ballot_payload_hash: BallotPayloadHash::new([payload_byte; 32]),
            ballot_kind_id: "TEST_KIND".to_owned(),
            ballot_confidentiality_id: "PUBLIC".to_owned(),
        }) else {
            panic!("test proof statement must be valid");
        };

        statement
    }

    fn point_bytes(multiplier: u64) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
        (RISTRETTO_BASEPOINT_POINT * Scalar::from(multiplier))
            .compress()
            .to_bytes()
    }
}
