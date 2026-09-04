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
use triptych::{TriptychProof, TriptychStatement, proof::ProofError};

use crate::{
    ProofBatchInputV1, ProofVerifierV1, RISTRETTO_COMPRESSED_POINT_BYTES,
    TariTriptychProofEnvelopeV1, VerifiedNullifier, VerifiedProofV1,
    triptych_prototype::{
        TriptychElectionContextV1, build_triptych_election_context_v1, build_triptych_statement_v1,
        finish_triptych_statement_v1, parse_canonical_triptych_proof_v1,
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
        // Observational only: count adapter invocations so a test can prove a
        // path performs zero verification. Records no proof/ring/nullifier data.
        crate::instrumentation::record_verify_invocation();
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

    /// Verifies a homogeneous election batch, reusing one immutable election
    /// context and amortizing the ring multiscalar multiplication across proofs.
    ///
    /// # Security-critical equivalence
    ///
    /// The result for each input is guaranteed identical to calling
    /// [`verify`](Self::verify) on that input alone:
    ///
    /// * Every per-input structural check ([`proof_suite_id`], registry
    ///   commitment, envelope/proof canonical parsing, statement/transcript
    ///   construction) runs per input, exactly as in `verify`, and a failure
    ///   marks only that input — it never enters the shared batch.
    /// * The successfully-prepared inputs are verified by the vendored
    ///   `TriptychProof::verify_batch`, whose accept condition is identical to
    ///   individual verification (single `verify` is itself a batch of one). On
    ///   batch failure, `verify_batch_with_full_blame` re-runs individual
    ///   verification per proof and returns the exact set of invalid indexes, so
    ///   one invalid proof can never suppress an unrelated valid ballot.
    ///
    /// Cryptographic validity is order-independent; nullifier/ledger/tally
    /// semantics are applied by the caller separately and in canonical order.
    fn verify_batch_v1(
        &self,
        inputs: &[ProofBatchInputV1<'_>],
    ) -> Vec<Result<VerifiedProofV1, ProtocolError>> {
        let mut results: Vec<Option<Result<VerifiedProofV1, ProtocolError>>> =
            (0..inputs.len()).map(|_| None).collect();
        let mut prepared: Vec<PreparedBatchItem> = Vec::new();

        // The immutable election context is built once for the first input and
        // reused for every subsequent input whose election identity matches.
        let mut context: Option<(ElectionContextKey, TriptychElectionContextV1)> = None;

        for (index, input) in inputs.iter().enumerate() {
            crate::instrumentation::record_verify_invocation();

            match self.prepare_batch_item(input.statement, input.proof_bytes, &mut context) {
                Ok(item) => prepared.push(PreparedBatchItem {
                    input_index: index,
                    proof_statement: input.statement.clone(),
                    ..item
                }),
                Err(error) => results[index] = Some(Err(error)),
            }
        }

        self.run_prepared_batch(prepared, &mut results);

        results
            .into_iter()
            .map(|result| result.unwrap_or_else(|| Err(internal_batch_error())))
            .collect()
    }
}

/// Election identity that selects whether a prebuilt context can be reused. All
/// ballots in one frozen election share these values, so the context is built
/// at most once per election batch.
#[derive(PartialEq, Eq)]
struct ElectionContextKey {
    protocol_version: u16,
    proof_suite_id: String,
    election_scope: Vec<u8>,
}

/// One batch input that passed every per-ballot structural check and is ready
/// for the shared multiscalar verification.
struct PreparedBatchItem {
    input_index: usize,
    proof_statement: ProofStatementV1,
    triptych_statement: TriptychStatement,
    proof: TriptychProof,
    transcript: Transcript,
    linking_tag: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
}

impl TariTriptychPrototypeVerifierV1 {
    /// Runs every per-ballot structural check from [`verify`](Self::verify)
    /// except the final multiscalar multiplication, reusing (or building) the
    /// shared election context. A returned `Err` is exactly the error `verify`
    /// would return at the same stage.
    fn prepare_batch_item(
        &self,
        statement: &ProofStatementV1,
        proof_bytes: &[u8],
        context: &mut Option<(ElectionContextKey, TriptychElectionContextV1)>,
    ) -> Result<PreparedBatchItem, ProtocolError> {
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

        let key = ElectionContextKey {
            protocol_version: statement.protocol_version(),
            proof_suite_id: statement.proof_suite_id().to_owned(),
            election_scope: election_scope.as_bytes().to_vec(),
        };
        let needs_build = !matches!(context, Some((existing, _)) if *existing == key);
        if needs_build {
            let built = build_triptych_election_context_v1(
                statement.protocol_version(),
                statement.proof_suite_id(),
                election_scope.as_bytes(),
                &self.registry_keys,
            )?;
            crate::instrumentation::record_verifier_context_build();
            *context = Some((key, built));
        } else {
            crate::instrumentation::record_verifier_context_reuse();
        }
        let Some((_, election_context)) = context.as_ref() else {
            // Unreachable: the branch above either reused an existing context or
            // built and stored one (returning early on build failure). Fail
            // closed rather than assume.
            return Err(malformed_proof(
                "Triptych election context was not constructed for the batch",
            ));
        };

        let triptych_statement =
            finish_triptych_statement_v1(election_context, *envelope.linking_tag_bytes())?;
        let proof = parse_canonical_triptych_proof_v1(envelope.triptych_proof_bytes())?;
        let transcript = triptych_transcript_v1(statement)?;

        Ok(PreparedBatchItem {
            input_index: 0,
            proof_statement: statement.clone(),
            triptych_statement,
            proof,
            transcript,
            linking_tag: *envelope.linking_tag_bytes(),
        })
    }

    /// Verifies the prepared items as one shared batch and writes each result
    /// back into `results` at its original input index.
    fn run_prepared_batch(
        &self,
        prepared: Vec<PreparedBatchItem>,
        results: &mut [Option<Result<VerifiedProofV1, ProtocolError>>],
    ) {
        if prepared.is_empty() {
            return;
        }

        crate::instrumentation::record_historical_crypto_batch();
        crate::instrumentation::add_historical_crypto_proofs(prepared.len() as u64);

        let statements: Vec<TriptychStatement> = prepared
            .iter()
            .map(|item| item.triptych_statement.clone())
            .collect();
        let proofs: Vec<TriptychProof> = prepared.iter().map(|item| item.proof.clone()).collect();
        let mut transcripts: Vec<Transcript> = prepared
            .iter()
            .map(|item| item.transcript.clone())
            .collect();

        let batch_start = std::time::Instant::now();
        let valid_flags = match TriptychProof::verify_batch(&statements, &proofs, &mut transcripts)
        {
            Ok(()) => vec![true; prepared.len()],
            Err(_) => self.blame_prepared_batch(&statements, &proofs, &prepared),
        };
        crate::instrumentation::add_batch_verify_micros(
            u64::try_from(batch_start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );

        for (item, valid) in prepared.into_iter().zip(valid_flags) {
            let result = if valid {
                match VerifiedNullifier::new(item.linking_tag.to_vec()) {
                    Ok(nullifier) => Ok(VerifiedProofV1::new(item.proof_statement, nullifier)),
                    Err(error) => Err(error),
                }
            } else {
                Err(malformed_proof("Triptych proof verification failed"))
            };
            if let Some(slot) = results.get_mut(item.input_index) {
                *slot = Some(result);
            }
        }
    }

    /// On batch failure, re-derives exact per-proof validity with the vendored
    /// full-blame path so a single invalid proof rejects only itself.
    fn blame_prepared_batch(
        &self,
        statements: &[TriptychStatement],
        proofs: &[TriptychProof],
        prepared: &[PreparedBatchItem],
    ) -> Vec<bool> {
        crate::instrumentation::record_historical_crypto_batch_fallback();
        crate::instrumentation::add_historical_crypto_individual_fallback_verifies(
            prepared.len() as u64
        );

        let mut blame_transcripts: Vec<Transcript> = prepared
            .iter()
            .map(|item| item.transcript.clone())
            .collect();

        match TriptychProof::verify_batch_with_full_blame(
            statements,
            proofs,
            &mut blame_transcripts,
        ) {
            // The full batch actually verified on the blame retry: every proof
            // is valid. (Deterministic weights make this agree with the first
            // attempt; treating it as all-valid is the correct direction.)
            Ok(()) => vec![true; prepared.len()],
            Err(ProofError::FailedBatchVerificationWithFullBlame { indexes }) => {
                let mut flags = vec![true; prepared.len()];
                for index in indexes {
                    if let Some(flag) = flags.get_mut(index) {
                        *flag = false;
                    }
                }
                flags
            }
            // Any other error (e.g. a parameter mismatch that cannot occur for a
            // context-shared batch) fails closed: reject every member rather
            // than accept an unverified proof.
            Err(_) => vec![false; prepared.len()],
        }
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

fn internal_batch_error() -> ProtocolError {
    // Unreachable: every batch input is assigned a result before this fallback
    // is consulted. Fail closed if that invariant is ever broken.
    ProtocolError::new(
        ValidationCode::InvalidData,
        "Triptych batch verification did not produce a result for an input",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES;
    use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use tari_cc_private_ballot_protocol::{
        BallotPayloadHash, ElectionScope, ManifestHash, PROTOCOL_VERSION_V1, ProofStatementV1Input,
    };
    use triptych::{TriptychProof, TriptychStatement, TriptychWitness, proof::ProofError};

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

    #[test]
    fn vendor_batch_verification_matches_individual_verification_for_project_statements() {
        let valid = batch_components(&[4, 5, 6, 7]);
        assert_batch_matches_individual(&valid, "all valid proofs");

        let empty_statements: Vec<TriptychStatement> = Vec::new();
        let empty_proofs: Vec<TriptychProof> = Vec::new();
        let mut empty_transcripts: Vec<Transcript> = Vec::new();
        assert!(
            TriptychProof::verify_batch(&empty_statements, &empty_proofs, &mut empty_transcripts,)
                .is_ok(),
            "the vendored API defines an empty homogeneous batch as valid",
        );

        let single = batch_components(&[4]);
        assert_batch_matches_individual(&single, "single proof");

        let duplicate_source = batch_components(&[4]);
        let duplicate = BatchComponents {
            statements: vec![
                duplicate_source.statements[0].clone(),
                duplicate_source.statements[0].clone(),
            ],
            proofs: vec![
                duplicate_source.proofs[0].clone(),
                duplicate_source.proofs[0].clone(),
            ],
            transcripts: vec![
                duplicate_source.transcripts[0].clone(),
                duplicate_source.transcripts[0].clone(),
            ],
        };
        assert_batch_matches_individual(&duplicate, "duplicate cryptographically valid proof");

        let wrong = batch_components(&[99]);
        for (index, label) in [(0_usize, "first"), (2, "middle"), (3, "last")] {
            let mut invalid = batch_components(&[4, 5, 6, 7]);
            invalid.proofs[index] = wrong.proofs[0].clone();

            assert_batch_matches_individual(&invalid, label);
            assert_full_batch_blame_indexes(&invalid, &[index]);
        }

        let mut multiple_invalid = batch_components(&[4, 5, 6, 7]);
        multiple_invalid.proofs[1] = wrong.proofs[0].clone();
        multiple_invalid.proofs[3] = wrong.proofs[0].clone();
        assert_batch_matches_individual(&multiple_invalid, "multiple invalid proofs");
        assert_full_batch_blame_indexes(&multiple_invalid, &[1, 3]);

        let fixture = valid_fixture(4);
        let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(&fixture.envelope) else {
            panic!("valid project proof envelope must decode for the batch API inventory");
        };
        let alternate_registry = registry_keys(&[1, 2, 3, 8]);
        let Ok(alternate_statement) = build_triptych_statement_v1(
            fixture.statement.protocol_version(),
            fixture.statement.proof_suite_id(),
            fixture.statement.election_scope().as_bytes(),
            &alternate_registry,
            *envelope.linking_tag_bytes(),
        ) else {
            panic!("alternate registry statement must remain structurally valid");
        };
        let homogeneous = batch_components(&[4]);
        let mut cross_registry_transcripts = vec![
            homogeneous.transcripts[0].clone(),
            homogeneous.transcripts[0].clone(),
        ];
        let cross_registry_result = TriptychProof::verify_batch(
            &[homogeneous.statements[0].clone(), alternate_statement],
            &[homogeneous.proofs[0].clone(), homogeneous.proofs[0].clone()],
            &mut cross_registry_transcripts,
        );
        assert!(matches!(
            cross_registry_result,
            Err(ProofError::InvalidParameter { .. })
        ));
    }

    /// Serializes the three `verify_batch_v1` tests so the process-global batch
    /// counters read by the reuse test are never perturbed by a sibling batch
    /// call running in parallel.
    static BATCH_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn verify_batch_v1_matches_individual_verify_for_every_input() {
        let _guard = BATCH_COUNTER_LOCK.lock().expect("batch counter lock");
        let fixtures = [
            valid_fixture(4),
            valid_fixture(5),
            valid_fixture(6),
            valid_fixture(7),
        ];
        // All fixtures share one registry, so they use one common verifier.
        let verifier = &fixtures[0].verifier;

        // A corrupted proof (appended byte) fails canonical parsing per input.
        let mut corrupted = fixtures[2].envelope.clone();
        corrupted.push(0xAB);
        // A structurally valid proof paired with the WRONG statement fails the
        // multiscalar check, not parsing — this is the "invalid inside a batch"
        // case that must not suppress the valid neighbours.
        let cross = fixtures[3].envelope.clone();

        let inputs = vec![
            ProofBatchInputV1 {
                statement: &fixtures[0].statement,
                proof_bytes: &fixtures[0].envelope,
            },
            ProofBatchInputV1 {
                statement: &fixtures[1].statement,
                proof_bytes: &corrupted,
            },
            ProofBatchInputV1 {
                statement: &fixtures[2].statement,
                proof_bytes: &fixtures[2].envelope,
            },
            ProofBatchInputV1 {
                // fixtures[3]'s proof against fixtures[0]'s statement: parses,
                // but is cryptographically invalid for this statement.
                statement: &fixtures[0].statement,
                proof_bytes: &cross,
            },
        ];

        let batch = verifier.verify_batch_v1(&inputs);
        assert_eq!(batch.len(), inputs.len());

        for (index, input) in inputs.iter().enumerate() {
            let individual = verifier.verify(input.statement, input.proof_bytes);
            match (&batch[index], &individual) {
                (Ok(batched), Ok(single)) => assert_eq!(
                    batched, single,
                    "batched result must equal individual verify for input {index}",
                ),
                (Err(batched), Err(single)) => assert_eq!(
                    batched.code(),
                    single.code(),
                    "batched rejection code must equal individual verify for input {index}",
                ),
                _ => panic!(
                    "batch and individual verification disagreed on acceptance for input {index}",
                ),
            }
        }

        // The first and third inputs are valid; a bad neighbour did not suppress
        // them.
        assert!(batch[0].is_ok());
        assert!(batch[2].is_ok());
        assert!(batch[1].is_err());
        assert!(batch[3].is_err());
    }

    #[test]
    fn verify_batch_v1_builds_one_election_context_and_reuses_it() {
        let _guard = BATCH_COUNTER_LOCK.lock().expect("batch counter lock");
        let fixtures = [valid_fixture(4), valid_fixture(5), valid_fixture(6)];
        let verifier = &fixtures[0].verifier;
        let inputs: Vec<ProofBatchInputV1<'_>> = fixtures
            .iter()
            .map(|fixture| ProofBatchInputV1 {
                statement: &fixture.statement,
                proof_bytes: &fixture.envelope,
            })
            .collect();

        crate::reset_verify_invocation_count();
        let batch = verifier.verify_batch_v1(&inputs);
        let counters = crate::batch_verification_snapshot();

        assert!(batch.iter().all(std::result::Result::is_ok));
        assert_eq!(
            counters.verifier_context_build_count, 1,
            "one immutable election context is built for a same-election batch",
        );
        assert_eq!(
            counters.verifier_context_reuse_count, 2,
            "the remaining inputs reuse the prebuilt context",
        );
        assert_eq!(counters.historical_crypto_batches, 1);
        assert_eq!(counters.historical_crypto_proofs, 3);
        assert_eq!(
            counters.historical_crypto_batch_fallbacks, 0,
            "an all-valid batch never falls back to per-proof blame",
        );
    }

    #[test]
    fn verify_batch_v1_of_an_empty_slice_is_empty() {
        let _guard = BATCH_COUNTER_LOCK.lock().expect("batch counter lock");
        let fixture = valid_fixture(4);
        let results = fixture.verifier.verify_batch_v1(&[]);
        assert!(results.is_empty());
    }

    struct BatchComponents {
        statements: Vec<TriptychStatement>,
        proofs: Vec<TriptychProof>,
        transcripts: Vec<Transcript>,
    }

    fn batch_components(payload_bytes: &[u8]) -> BatchComponents {
        let mut statements = Vec::with_capacity(payload_bytes.len());
        let mut proofs = Vec::with_capacity(payload_bytes.len());
        let mut transcripts = Vec::with_capacity(payload_bytes.len());

        for payload_byte in payload_bytes {
            let fixture = valid_fixture(*payload_byte);
            let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(&fixture.envelope) else {
                panic!("valid project proof envelope must decode for a batch component");
            };
            let Ok(statement) = build_triptych_statement_v1(
                fixture.statement.protocol_version(),
                fixture.statement.proof_suite_id(),
                fixture.statement.election_scope().as_bytes(),
                fixture.verifier.registry_keys(),
                *envelope.linking_tag_bytes(),
            ) else {
                panic!("valid project proof statement must reconstruct for a batch component");
            };
            let Ok(proof) = parse_canonical_triptych_proof_v1(envelope.triptych_proof_bytes())
            else {
                panic!("valid project inner proof must parse for a batch component");
            };
            let Ok(transcript) = triptych_transcript_v1(&fixture.statement) else {
                panic!("valid project proof transcript must reconstruct for a batch component");
            };

            statements.push(statement);
            proofs.push(proof);
            transcripts.push(transcript);
        }

        BatchComponents {
            statements,
            proofs,
            transcripts,
        }
    }

    fn assert_batch_matches_individual(components: &BatchComponents, label: &str) {
        let individual = components
            .statements
            .iter()
            .zip(&components.proofs)
            .zip(&components.transcripts)
            .map(|((statement, proof), transcript)| {
                let mut transcript = transcript.clone();

                proof.verify(statement, &mut transcript).is_ok()
            })
            .collect::<Vec<_>>();
        let every_individual_proof_verified = individual.iter().all(|result| *result);
        let mut batch_transcripts = components.transcripts.clone();
        let batch_verified = TriptychProof::verify_batch(
            &components.statements,
            &components.proofs,
            &mut batch_transcripts,
        )
        .is_ok();

        assert_eq!(
            batch_verified, every_individual_proof_verified,
            "vendor batch verification must match individual project-proof verification for {label}",
        );
    }

    fn assert_full_batch_blame_indexes(components: &BatchComponents, expected: &[usize]) {
        let mut transcripts = components.transcripts.clone();
        let result = TriptychProof::verify_batch_with_full_blame(
            &components.statements,
            &components.proofs,
            &mut transcripts,
        );

        match result {
            Err(ProofError::FailedBatchVerificationWithFullBlame { indexes }) => {
                assert_eq!(indexes, expected);
            }
            other => panic!("batch full-blame result must report exact invalid indexes: {other:?}"),
        }
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
