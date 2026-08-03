//! Tari Triptych prototype proof verification.
//!
//! This module keeps all third-party cryptographic types private. Public callers
//! provide only the frozen registry commitment and canonically encoded,
//! strictly sorted registry keys.
//!
//! This remains prototype cryptography. The constructor does not recompute a
//! registry commitment from the key list; callers must derive both values from
//! the same validated frozen registry snapshot.

use merlin::Transcript;
use tari_cc_private_ballot_protocol::{
    ProofStatementV1, ProtocolError, RegistryCommitment, ValidationCode,
};

use crate::{
    ProofVerifierV1, RISTRETTO_COMPRESSED_POINT_BYTES, TariTriptychProofEnvelopeV1,
    VerifiedNullifier, VerifiedProofV1,
    triptych_prototype::{
        build_triptych_statement_v1, parse_canonical_triptych_proof_v1,
        validate_triptych_registry_keys_v1,
    },
    verification::Sealed,
};

/// Stable identifier for the Tari Triptych prototype proof suite.
pub const TARI_TRIPTYCH_PROOF_SUITE_ID_V1: &str = "TARI_TRIPTYCH_PROTOTYPE_V1";

const TARI_TRIPTYCH_TRANSCRIPT_LABEL_V1: &[u8] = b"tari-cc-private-ballot-triptych-v1";
const PROOF_STATEMENT_TRANSCRIPT_LABEL_V1: &[u8] = b"proof_statement_v1";

/// Sealed Tari Triptych prototype verifier for one frozen registry.
///
/// The verifier binds proof verification to both the reconstructed
/// [`ProofStatementV1`] and the registry commitment supplied at construction.
/// The key list must be canonical, strictly sorted, unique, and derived from
/// the same frozen registry snapshot as `registry_commitment`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TariTriptychPrototypeVerifierV1 {
    registry_commitment: RegistryCommitment,
    registry_keys: Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>,
}

impl TariTriptychPrototypeVerifierV1 {
    /// Validates and freezes one verifier configuration.
    ///
    /// This crypto crate deliberately does not depend on the registry crate, so
    /// it cannot recompute `registry_commitment`. The caller must pass the
    /// commitment and keys from one already validated frozen registry snapshot.
    pub fn new(
        registry_commitment: RegistryCommitment,
        registry_keys: Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>,
    ) -> Result<Self, ProtocolError> {
        validate_triptych_registry_keys_v1(&registry_keys)?;

        Ok(Self {
            registry_commitment,
            registry_keys,
        })
    }

    /// Returns the frozen registry commitment required by this verifier.
    #[must_use]
    pub const fn registry_commitment(&self) -> RegistryCommitment {
        self.registry_commitment
    }

    /// Returns the canonical registry keys used to reconstruct Triptych statements.
    #[must_use]
    pub fn registry_keys(&self) -> &[[u8; RISTRETTO_COMPRESSED_POINT_BYTES]] {
        &self.registry_keys
    }
}

impl Sealed for TariTriptychPrototypeVerifierV1 {}

impl ProofVerifierV1 for TariTriptychPrototypeVerifierV1 {
    fn proof_suite_id(&self) -> &'static str {
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1
    }

    fn verify(
        &self,
        statement: &ProofStatementV1,
        proof_bytes: &[u8],
    ) -> Result<VerifiedProofV1, ProtocolError> {
        if statement.proof_suite_id() != TARI_TRIPTYCH_PROOF_SUITE_ID_V1 {
            return Err(invalid_data(
                "Triptych prototype verifier received a different proof suite",
            ));
        }

        if statement.registry_commitment() != self.registry_commitment {
            return Err(invalid_data(
                "Triptych verifier registry commitment does not match the proof statement",
            ));
        }

        let envelope = TariTriptychProofEnvelopeV1::from_bytes(proof_bytes)?;
        let election_scope = statement.election_scope();

        let triptych_statement = build_triptych_statement_v1(
            statement.protocol_version(),
            statement.proof_suite_id(),
            election_scope.as_bytes(),
            &self.registry_keys,
            *envelope.linking_tag_bytes(),
        )?;

        let proof = parse_canonical_triptych_proof_v1(envelope.triptych_proof_bytes())?;
        let mut transcript = triptych_transcript_v1(statement)?;

        proof
            .verify(&triptych_statement, &mut transcript)
            .map_err(|_| malformed_proof("Triptych proof verification failed"))?;

        let nullifier = VerifiedNullifier::new(envelope.linking_tag_bytes().to_vec())?;

        Ok(VerifiedProofV1::new(statement.clone(), nullifier))
    }
}

pub(crate) fn triptych_transcript_v1(
    statement: &ProofStatementV1,
) -> Result<Transcript, ProtocolError> {
    let mut transcript = Transcript::new(TARI_TRIPTYCH_TRANSCRIPT_LABEL_V1);
    let statement_bytes = statement.transcript_bytes()?;

    transcript.append_message(PROOF_STATEMENT_TRANSCRIPT_LABEL_V1, &statement_bytes);

    Ok(transcript)
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
    use crate::TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES;
    use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use tari_cc_private_ballot_protocol::{
        BallotPayloadHash, ElectionScope, ManifestHash, PROTOCOL_VERSION_V1, ProofStatementV1Input,
    };
    use triptych::{TriptychProof, TriptychWitness};

    struct ValidFixture {
        statement: ProofStatementV1,
        verifier: TariTriptychPrototypeVerifierV1,
        envelope: Vec<u8>,
        linking_tag: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    }

    fn proof_statement(
        payload_byte: u8,
        registry_byte: u8,
        proof_suite_id: &str,
    ) -> ProofStatementV1 {
        let Ok(statement) = ProofStatementV1::new(ProofStatementV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            proof_suite_id: proof_suite_id.to_owned(),
            manifest_hash: ManifestHash::new([1_u8; 32]),
            election_scope: ElectionScope::new([2_u8; 32]),
            registry_commitment: RegistryCommitment::new([registry_byte; 32]),
            ballot_payload_hash: BallotPayloadHash::new([payload_byte; 32]),
            ballot_kind_id: "TEST_KIND".to_owned(),
            ballot_confidentiality_id: "PUBLIC".to_owned(),
        }) else {
            panic!("test proof statement must be valid");
        };

        statement
    }

    fn valid_fixture(payload_byte: u8) -> ValidFixture {
        let statement = proof_statement(payload_byte, 3, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);

        let seed_registry = registry_keys(&[1, 2, 3, 4]);
        let Ok(seed_statement) = build_triptych_statement_v1(
            statement.protocol_version(),
            statement.proof_suite_id(),
            statement.election_scope().as_bytes(),
            &seed_registry,
            point_bytes(9),
        ) else {
            panic!("seed Triptych statement must be valid");
        };

        let secret = Scalar::from(7_u64);
        let Ok(seed_witness) = TriptychWitness::new(seed_statement.get_params(), 0, &secret) else {
            panic!("seed Triptych witness must be valid");
        };

        let signer_key = seed_witness
            .compute_verification_key()
            .compress()
            .to_bytes();
        let linking_tag = seed_witness.compute_linking_tag().compress().to_bytes();

        let mut registry_keys = registry_keys(&[1, 2, 3]);
        registry_keys.push(signer_key);
        registry_keys.sort_unstable();

        let Some(signer_index) = registry_keys.iter().position(|key| key == &signer_key) else {
            panic!("signer key must be present in the canonical registry");
        };
        let Ok(signer_index) = u32::try_from(signer_index) else {
            panic!("test signer index must fit in u32");
        };

        let Ok(triptych_statement) = build_triptych_statement_v1(
            statement.protocol_version(),
            statement.proof_suite_id(),
            statement.election_scope().as_bytes(),
            &registry_keys,
            linking_tag,
        ) else {
            panic!("Triptych statement must be valid");
        };

        let Ok(witness) =
            TriptychWitness::new(triptych_statement.get_params(), signer_index, &secret)
        else {
            panic!("Triptych witness must be valid");
        };

        assert_eq!(
            witness.compute_verification_key().compress().to_bytes(),
            signer_key,
        );
        assert_eq!(
            witness.compute_linking_tag().compress().to_bytes(),
            linking_tag,
        );

        let Ok(mut transcript) = triptych_transcript_v1(&statement) else {
            panic!("Triptych transcript must be constructible");
        };
        let Ok(proof) = TriptychProof::prove(&witness, &triptych_statement, &mut transcript) else {
            panic!("Triptych proof generation must succeed in tests");
        };

        let Ok(envelope) = TariTriptychProofEnvelopeV1::new(linking_tag, proof.to_bytes()) else {
            panic!("Triptych proof envelope must be valid");
        };

        let registry_commitment = statement.registry_commitment();
        let Ok(verifier) = TariTriptychPrototypeVerifierV1::new(registry_commitment, registry_keys)
        else {
            panic!("Triptych verifier configuration must be valid");
        };

        ValidFixture {
            statement,
            verifier,
            envelope: envelope.to_bytes(),
            linking_tag,
        }
    }

    #[test]
    fn valid_proof_authenticates_statement_and_promotes_linking_tag() {
        let fixture = valid_fixture(4);

        let Ok(verified) = fixture
            .verifier
            .verify(&fixture.statement, &fixture.envelope)
        else {
            panic!("valid Triptych proof must verify");
        };

        assert_eq!(verified.statement(), &fixture.statement);
        assert_eq!(
            verified.nullifier().as_bytes(),
            fixture.linking_tag.as_slice(),
        );
    }

    #[test]
    fn canonical_triptych_proof_and_envelope_reject_appended_bytes() {
        let fixture = valid_fixture(4);
        let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(&fixture.envelope) else {
            panic!("valid Triptych proof envelope must decode");
        };
        let canonical_proof = envelope.triptych_proof_bytes().to_vec();

        assert!(parse_canonical_triptych_proof_v1(&canonical_proof).is_ok());
        assert!(
            fixture
                .verifier
                .verify(&fixture.statement, &fixture.envelope)
                .is_ok()
        );

        let other_fixture = valid_fixture(5);
        let Ok(other_envelope) = TariTriptychProofEnvelopeV1::from_bytes(&other_fixture.envelope)
        else {
            panic!("second valid Triptych proof envelope must decode");
        };
        let Some(serialized_a) = other_envelope.triptych_proof_bytes().get(8..40) else {
            panic!("Triptych proof must contain its first serialized point");
        };
        let other_envelope_bytes = other_envelope.to_bytes();
        let Some(version_and_linking_tag) =
            other_envelope_bytes.get(..TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES)
        else {
            panic!("Triptych proof envelope must contain its fixed header");
        };

        let suffixes = [
            ("one zero byte", vec![0_u8]),
            ("one nonzero byte", vec![0xa5_u8]),
            (
                "eight arbitrary bytes",
                vec![0x10_u8, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87],
            ),
            ("thirty-two arbitrary bytes", vec![0x5a_u8; 32]),
            (
                "a serialized point copied from another valid proof",
                serialized_a.to_vec(),
            ),
            (
                "another envelope version and linking-tag header",
                version_and_linking_tag.to_vec(),
            ),
            ("another complete valid envelope", other_envelope_bytes),
        ];

        for (label, suffix) in suffixes {
            let mut mutated_proof = canonical_proof.clone();
            mutated_proof.extend_from_slice(&suffix);

            assert_ne!(
                mutated_proof, canonical_proof,
                "{label} must alter the canonical Triptych proof bytes"
            );

            let Ok(mutated_envelope) = TariTriptychProofEnvelopeV1::new(
                *envelope.linking_tag_bytes(),
                mutated_proof.clone(),
            ) else {
                panic!("appended proof bytes must remain structurally encodable");
            };
            let mutated_envelope_bytes = mutated_envelope.to_bytes();

            let Ok(decoded_mutated_envelope) =
                TariTriptychProofEnvelopeV1::from_bytes(&mutated_envelope_bytes)
            else {
                panic!("envelope transport decoding must retain all supplied proof bytes");
            };
            assert_eq!(decoded_mutated_envelope.to_bytes(), mutated_envelope_bytes);
            assert_eq!(
                decoded_mutated_envelope.triptych_proof_bytes(),
                mutated_proof.as_slice(),
            );

            for repetition in 0..3 {
                assert!(
                    matches!(
                        parse_canonical_triptych_proof_v1(&mutated_proof),
                        Err(error) if error.code() == ValidationCode::MalformedProof
                    ),
                    "{label} was not rejected by canonical Triptych parsing on repetition {repetition}"
                );

                assert!(
                    matches!(
                        fixture
                            .verifier
                            .verify(&fixture.statement, &mutated_envelope_bytes),
                        Err(error) if error.code() == ValidationCode::MalformedProof
                    ),
                    "{label} was not rejected by Triptych verification on repetition {repetition}"
                );
            }
        }
    }

    #[test]
    fn proof_for_one_statement_is_rejected_for_another() {
        let fixture = valid_fixture(4);
        let changed = proof_statement(5, 3, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);

        assert!(
            fixture
                .verifier
                .verify(&changed, &fixture.envelope)
                .is_err()
        );
    }

    #[test]
    fn wrong_proof_suite_is_rejected_before_envelope_parsing() {
        let registry_keys = registry_keys(&[1, 2, 3, 4]);
        let Ok(verifier) = TariTriptychPrototypeVerifierV1::new(
            RegistryCommitment::new([3_u8; 32]),
            registry_keys,
        ) else {
            panic!("test verifier configuration must be valid");
        };
        let statement = proof_statement(4, 3, "OTHER_SUITE");

        assert!(matches!(
            verifier.verify(&statement, &[]),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn registry_commitment_mismatch_is_rejected_before_envelope_parsing() {
        let registry_keys = registry_keys(&[1, 2, 3, 4]);
        let Ok(verifier) = TariTriptychPrototypeVerifierV1::new(
            RegistryCommitment::new([3_u8; 32]),
            registry_keys,
        ) else {
            panic!("test verifier configuration must be valid");
        };
        let statement = proof_statement(4, 9, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);

        assert!(matches!(
            verifier.verify(&statement, &[]),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn proof_is_rejected_by_a_different_registry_key_set() {
        let fixture = valid_fixture(4);
        let alternate_keys = registry_keys(&[1, 2, 3, 8]);
        let Ok(alternate_verifier) = TariTriptychPrototypeVerifierV1::new(
            fixture.statement.registry_commitment(),
            alternate_keys,
        ) else {
            panic!("alternate verifier configuration must be valid");
        };

        assert!(
            alternate_verifier
                .verify(&fixture.statement, &fixture.envelope)
                .is_err()
        );
    }

    #[test]
    fn malformed_envelope_is_rejected() {
        let registry_keys = registry_keys(&[1, 2, 3, 4]);
        let Ok(verifier) = TariTriptychPrototypeVerifierV1::new(
            RegistryCommitment::new([3_u8; 32]),
            registry_keys,
        ) else {
            panic!("test verifier configuration must be valid");
        };
        let statement = proof_statement(4, 3, TARI_TRIPTYCH_PROOF_SUITE_ID_V1);

        assert!(matches!(
            verifier.verify(&statement, &[0_u8; 8]),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn duplicate_registry_keys_are_rejected_at_construction() {
        let duplicate = point_bytes(2);
        let registry_keys = vec![duplicate, duplicate];

        assert!(matches!(
            TariTriptychPrototypeVerifierV1::new(
                RegistryCommitment::new([3_u8; 32]),
                registry_keys,
            ),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn verifier_reports_the_frozen_proof_suite_identifier() {
        let registry_keys = registry_keys(&[1, 2, 3, 4]);
        let Ok(verifier) = TariTriptychPrototypeVerifierV1::new(
            RegistryCommitment::new([3_u8; 32]),
            registry_keys,
        ) else {
            panic!("test verifier configuration must be valid");
        };

        assert_eq!(verifier.proof_suite_id(), TARI_TRIPTYCH_PROOF_SUITE_ID_V1,);
    }

    fn registry_keys(multipliers: &[u64]) -> Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]> {
        let mut keys = multipliers
            .iter()
            .copied()
            .map(point_bytes)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys
    }

    fn point_bytes(multiplier: u64) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
        (RISTRETTO_BASEPOINT_POINT * Scalar::from(multiplier))
            .compress()
            .to_bytes()
    }
}
