//! Private Tari Triptych prototype construction primitives.
//!
//! This module is deliberately crate-private. It bridges project-owned
//! canonical bytes into the audited Triptych dependency without exposing
//! Triptych or curve25519-dalek v4 types through the public API.
//!
//! It does not implement `ProofVerifierV1`, authenticate a nullifier, provide
//! signing, or authorize production use.

#![cfg_attr(not(test), allow(dead_code))]

use core::mem::size_of;

use blake3::Hasher;
use curve25519_dalek_v4::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    traits::IsIdentity,
};
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};
use triptych::{TriptychInputSet, TriptychParameters, TriptychProof, TriptychStatement};

const SCOPE_GENERATOR_DOMAIN_V1: &str = "tari-cc-private-ballot-triptych-scope-generator-v1";
const TRIPTYCH_RING_BASE_V1: u32 = 2;
const TRIPTYCH_MINIMUM_EXPONENT_V1: u32 = 2;
const UNIFORM_RISTRETTO_BYTES: usize = 64;
const COMPRESSED_RISTRETTO_BYTES: usize = 32;

pub(crate) fn build_triptych_statement_v1(
    protocol_version: u16,
    proof_suite_id: &str,
    election_scope: &[u8],
    registry_keys: &[[u8; COMPRESSED_RISTRETTO_BYTES]],
    linking_tag: [u8; COMPRESSED_RISTRETTO_BYTES],
) -> Result<TriptychStatement, ProtocolError> {
    let exponent = ring_exponent_v1(registry_keys.len())?;
    let scope_generator =
        derive_scope_generator_v1(protocol_version, proof_suite_id, election_scope)?;

    let parameters = TriptychParameters::new_with_generators(
        TRIPTYCH_RING_BASE_V1,
        exponent,
        &RISTRETTO_BASEPOINT_POINT,
        &scope_generator,
    )
    .map_err(|_| {
        malformed_proof("Triptych parameters rejected the prototype ring configuration")
    })?;

    let verification_keys = parse_sorted_registry_keys_v1(registry_keys)?;
    let input_set = TriptychInputSet::new_with_padding(&verification_keys, &parameters)
        .map_err(|_| malformed_proof("Triptych rejected the prototype registry input set"))?;
    let linking_tag = decode_non_identity_v4(
        linking_tag,
        "Triptych linking tag is not a canonical non-identity Ristretto point",
    )?;

    TriptychStatement::new(&parameters, &input_set, &linking_tag)
        .map_err(|_| malformed_proof("Triptych rejected the prototype proof statement"))
}

pub(crate) fn validate_triptych_registry_keys_v1(
    registry_keys: &[[u8; COMPRESSED_RISTRETTO_BYTES]],
) -> Result<(), ProtocolError> {
    ring_exponent_v1(registry_keys.len())?;
    parse_sorted_registry_keys_v1(registry_keys)?;

    Ok(())
}

pub(crate) fn parse_canonical_triptych_proof_v1(
    proof_bytes: &[u8],
) -> Result<TriptychProof, ProtocolError> {
    let proof = TriptychProof::from_bytes(proof_bytes)
        .map_err(|_| malformed_proof("Triptych proof bytes are malformed or non-canonical"))?;

    if proof.to_bytes() != proof_bytes {
        return Err(malformed_proof(
            "Triptych proof bytes do not round-trip canonically",
        ));
    }

    Ok(proof)
}

fn derive_scope_generator_v1(
    protocol_version: u16,
    proof_suite_id: &str,
    election_scope: &[u8],
) -> Result<RistrettoPoint, ProtocolError> {
    let preimage = scope_generator_preimage_v1(protocol_version, proof_suite_id, election_scope)?;

    let mut hasher = Hasher::new();
    hasher.update(&preimage);

    let mut uniform = [0_u8; UNIFORM_RISTRETTO_BYTES];
    hasher.finalize_xof().fill(&mut uniform);

    let generator = RistrettoPoint::from_uniform_bytes(&uniform);

    if generator.is_identity() || generator == RISTRETTO_BASEPOINT_POINT {
        return Err(malformed_proof(
            "election-scoped Triptych generator is invalid",
        ));
    }

    Ok(generator)
}

fn scope_generator_preimage_v1(
    protocol_version: u16,
    proof_suite_id: &str,
    election_scope: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let suite_bytes = proof_suite_id.as_bytes();
    let suite_len = u32::try_from(suite_bytes.len())
        .map_err(|_| protocol_limit("Triptych proof-suite identifier exceeds the framing limit"))?;
    let scope_len = u32::try_from(election_scope.len())
        .map_err(|_| protocol_limit("election scope exceeds the Triptych framing limit"))?;

    let mut preimage = Vec::with_capacity(
        SCOPE_GENERATOR_DOMAIN_V1.len()
            + size_of::<u64>()
            + size_of::<u32>()
            + suite_bytes.len()
            + size_of::<u32>()
            + election_scope.len(),
    );

    preimage.extend_from_slice(SCOPE_GENERATOR_DOMAIN_V1.as_bytes());
    preimage.extend_from_slice(&u64::from(protocol_version).to_le_bytes());
    preimage.extend_from_slice(&suite_len.to_le_bytes());
    preimage.extend_from_slice(suite_bytes);
    preimage.extend_from_slice(&scope_len.to_le_bytes());
    preimage.extend_from_slice(election_scope);

    Ok(preimage)
}

fn ring_exponent_v1(registry_size: usize) -> Result<u32, ProtocolError> {
    if registry_size == 0 {
        return Err(malformed_proof(
            "Triptych registry must contain at least one verification key",
        ));
    }

    let registry_size = u32::try_from(registry_size)
        .map_err(|_| protocol_limit("Triptych registry exceeds the supported ring size"))?;
    let mut exponent = TRIPTYCH_MINIMUM_EXPONENT_V1;
    let mut capacity = TRIPTYCH_RING_BASE_V1
        .checked_pow(exponent)
        .ok_or_else(|| protocol_limit("Triptych ring capacity overflowed"))?;

    while capacity < registry_size {
        exponent = exponent
            .checked_add(1)
            .ok_or_else(|| protocol_limit("Triptych ring exponent overflowed"))?;
        capacity = TRIPTYCH_RING_BASE_V1
            .checked_pow(exponent)
            .ok_or_else(|| protocol_limit("Triptych ring capacity overflowed"))?;
    }

    Ok(exponent)
}

fn parse_sorted_registry_keys_v1(
    registry_keys: &[[u8; COMPRESSED_RISTRETTO_BYTES]],
) -> Result<Vec<RistrettoPoint>, ProtocolError> {
    if registry_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(malformed_proof(
            "Triptych registry keys must be strictly sorted and unique",
        ));
    }

    registry_keys
        .iter()
        .copied()
        .map(|encoded| {
            decode_non_identity_v4(
                encoded,
                "Triptych registry key is not a canonical non-identity Ristretto point",
            )
        })
        .collect()
}

fn decode_non_identity_v4(
    encoded: [u8; COMPRESSED_RISTRETTO_BYTES],
    message: &'static str,
) -> Result<RistrettoPoint, ProtocolError> {
    let point = CompressedRistretto(encoded)
        .decompress()
        .ok_or_else(|| malformed_proof(message))?;

    if point.is_identity() || point.compress().to_bytes() != encoded {
        return Err(malformed_proof(message));
    }

    Ok(point)
}

fn malformed_proof(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::MalformedProof, message)
}

fn protocol_limit(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::ProtocolLimitExceeded, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v4::scalar::Scalar;

    const TEST_SUITE: &str = "TARI_TRIPTYCH_PROTOTYPE_V1";

    #[test]
    fn scope_generator_preimage_uses_the_frozen_framing() {
        let scope = [0xA5_u8; 32];

        let Ok(actual) = scope_generator_preimage_v1(1, TEST_SUITE, &scope) else {
            panic!("scope-generator preimage should be constructible");
        };

        let mut expected = Vec::new();
        expected.extend_from_slice(SCOPE_GENERATOR_DOMAIN_V1.as_bytes());
        expected.extend_from_slice(&1_u64.to_le_bytes());
        let Ok(suite_len) = u32::try_from(TEST_SUITE.len()) else {
            panic!("test suite length must fit in u32");
        };
        let Ok(scope_len) = u32::try_from(scope.len()) else {
            panic!("test scope length must fit in u32");
        };

        expected.extend_from_slice(&suite_len.to_le_bytes());
        expected.extend_from_slice(TEST_SUITE.as_bytes());
        expected.extend_from_slice(&scope_len.to_le_bytes());
        expected.extend_from_slice(&scope);

        assert_eq!(actual, expected);
    }

    #[test]
    fn scope_generator_is_deterministic_and_scope_bound() {
        let first_scope = [0x11_u8; 32];
        let second_scope = [0x22_u8; 32];

        let Ok(first) = derive_scope_generator_v1(1, TEST_SUITE, &first_scope) else {
            panic!("first scope generator should be valid");
        };
        let Ok(repeated) = derive_scope_generator_v1(1, TEST_SUITE, &first_scope) else {
            panic!("repeated scope generator should be valid");
        };
        let Ok(second) = derive_scope_generator_v1(1, TEST_SUITE, &second_scope) else {
            panic!("second scope generator should be valid");
        };

        assert_eq!(first, repeated);
        assert_ne!(first, second);
        assert!(!first.is_identity());
        assert_ne!(first, RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn six_member_registry_uses_eight_member_ring_capacity() {
        let Ok(exponent) = ring_exponent_v1(6) else {
            panic!("six members should fit a Triptych ring");
        };

        assert_eq!(exponent, 3);
        assert_eq!(TRIPTYCH_RING_BASE_V1.pow(exponent), 8);
    }

    #[test]
    fn statement_construction_accepts_sorted_canonical_registry_keys() {
        let mut registry_keys = (1_u64..=6).map(point_bytes).collect::<Vec<_>>();
        registry_keys.sort_unstable();

        let result = build_triptych_statement_v1(
            1,
            TEST_SUITE,
            &[0x33_u8; 32],
            &registry_keys,
            point_bytes(11),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn statement_construction_rejects_duplicate_registry_keys() {
        let duplicate = point_bytes(2);
        let mut registry_keys = vec![point_bytes(1), duplicate, duplicate, point_bytes(3)];
        registry_keys.sort_unstable();

        let result = build_triptych_statement_v1(
            1,
            TEST_SUITE,
            &[0x44_u8; 32],
            &registry_keys,
            point_bytes(12),
        );

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn malformed_triptych_proof_bytes_are_rejected() {
        let result = parse_canonical_triptych_proof_v1(&[0_u8; 64]);

        assert!(matches!(
            result,
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    fn point_bytes(multiplier: u64) -> [u8; COMPRESSED_RISTRETTO_BYTES] {
        (RISTRETTO_BASEPOINT_POINT * Scalar::from(multiplier))
            .compress()
            .to_bytes()
    }
}
