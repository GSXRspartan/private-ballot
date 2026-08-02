//! Registry-bound Tari Triptych verifier construction.
//!
//! This module is the project-owned bridge between a validated frozen
//! [`RegistrySnapshot`] and the sealed crypto verifier. It derives the registry
//! commitment and exact key bytes from the same snapshot so normal callers
//! cannot accidentally pair a commitment from one registry with keys from
//! another.

use tari_cc_private_ballot_crypto::{
    RISTRETTO_COMPRESSED_POINT_BYTES, TariTriptychPrototypeVerifierV1,
};
use tari_cc_private_ballot_protocol::{HashProvider, ProtocolError, ValidationCode};
use tari_cc_private_ballot_registry::RegistrySnapshot;

/// Constructs the Tari Triptych prototype verifier from one frozen registry.
///
/// The canonical commitment and every Triptych verification key are derived
/// from `registry`. Governance keys must be exactly one compressed Ristretto
/// point each; the crypto crate performs canonical point, identity, ordering,
/// uniqueness, and ring-capacity validation.
pub fn build_tari_triptych_verifier_from_registry_v1<H: HashProvider>(
    registry: &RegistrySnapshot,
    hash_provider: &H,
) -> Result<TariTriptychPrototypeVerifierV1, ProtocolError> {
    let registry_commitment = registry.canonical_commitment(hash_provider)?;
    let registry_keys = registry
        .entries()
        .iter()
        .map(|entry| {
            entry.governance_key().as_bytes().try_into().map_err(|_| {
                ProtocolError::new(
                    ValidationCode::InvalidData,
                    "Triptych governance public key must be exactly 32 bytes",
                )
            })
        })
        .collect::<Result<Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>, ProtocolError>>()?;

    TariTriptychPrototypeVerifierV1::new(registry_commitment, registry_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        CanonicalCborWriter, RegistryCommitment, test_only::TestOnlyDeterministicHasher,
    };

    const RISTRETTO_BASEPOINT_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ];

    #[test]
    fn factory_derives_commitment_and_keys_from_the_same_snapshot() {
        let registry = single_key_registry(&RISTRETTO_BASEPOINT_BYTES);
        let provider = TestOnlyDeterministicHasher;

        let Ok(expected_commitment) = registry.canonical_commitment(&provider) else {
            panic!("test registry commitment must be derivable");
        };
        let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider)
        else {
            panic!("valid frozen registry must construct a Triptych verifier");
        };

        assert_eq!(verifier.registry_commitment(), expected_commitment);
        assert_eq!(verifier.registry_keys(), &[RISTRETTO_BASEPOINT_BYTES],);
    }

    #[test]
    fn non_ristretto_length_governance_key_is_rejected() {
        let registry = single_key_registry(b"not-a-ristretto-point");
        let provider = TestOnlyDeterministicHasher;

        assert!(matches!(
            build_tari_triptych_verifier_from_registry_v1(&registry, &provider),
            Err(error) if error.code() == ValidationCode::InvalidData
        ));
    }

    #[test]
    fn identity_governance_key_is_rejected_by_crypto_validation() {
        let registry = single_key_registry(&[0_u8; RISTRETTO_COMPRESSED_POINT_BYTES]);
        let provider = TestOnlyDeterministicHasher;

        assert!(matches!(
            build_tari_triptych_verifier_from_registry_v1(&registry, &provider),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ));
    }

    #[test]
    fn factory_commitment_is_not_caller_supplied() {
        let registry = single_key_registry(&RISTRETTO_BASEPOINT_BYTES);
        let provider = TestOnlyDeterministicHasher;

        let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider)
        else {
            panic!("valid frozen registry must construct a Triptych verifier");
        };

        assert_ne!(
            verifier.registry_commitment(),
            RegistryCommitment::new([0xff_u8; 32]),
        );
    }

    fn single_key_registry(key: &[u8]) -> RegistrySnapshot {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(1).is_ok());
        assert!(writer.write_byte_string(key).is_ok());

        let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
            panic!("single-key registry fixture must be valid");
        };

        registry
    }
}
