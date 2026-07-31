//! Canonical registry serialization and commitment derivation.

use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, HashDomain, HashProvider, MAX_CANONICAL_OBJECT_BYTES,
    MAX_REGISTRY_MEMBERS, ProtocolError, RegistryCommitment, ValidationCode, hash_domain_separated,
};

use crate::{GovernancePublicKey, RegistryEntry, RegistrySnapshot};

impl RegistrySnapshot {
    /// Encodes the frozen registry as a canonical CBOR array of key bytes.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(self.entries().len())?;

        for entry in self.entries() {
            writer.write_byte_string(entry.governance_key().as_bytes())?;
        }

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical registry exceeds the protocol object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes one canonically ordered frozen registry.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded registry exceeds the protocol object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);
        let member_count = reader.read_array_len()?;

        if member_count == 0 {
            return Err(ProtocolError::new(
                ValidationCode::EmptyRegistry,
                "registry must contain at least one governance key",
            ));
        }

        if member_count > MAX_REGISTRY_MEMBERS {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "registry member count exceeds the protocol limit",
            ));
        }

        let mut keys = Vec::with_capacity(member_count);

        for _ in 0..member_count {
            let bytes = reader.read_byte_string()?;
            keys.push(GovernancePublicKey::new(bytes.to_vec())?);
        }

        reader.finish()?;

        for pair in keys.windows(2) {
            if pair[0] == pair[1] {
                return Err(ProtocolError::new(
                    ValidationCode::DuplicateGovernanceKey,
                    "registry contains a duplicate governance key",
                ));
            }

            if pair[0] > pair[1] {
                return Err(ProtocolError::new(
                    ValidationCode::NonCanonicalCbor,
                    "registry keys are not in canonical order",
                ));
            }
        }

        let entries = keys.into_iter().map(RegistryEntry::new).collect();

        Self::new(entries)
    }

    /// Derives the registry commitment from canonical CBOR bytes.
    pub fn canonical_commitment<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<RegistryCommitment, ProtocolError> {
        let encoded = self.to_canonical_cbor()?;
        let digest = hash_domain_separated(provider, HashDomain::RegistrySnapshotV1, &encoded);

        Ok(RegistryCommitment::new(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES, MAX_REGISTRY_MEMBERS, ValidationCode,
        test_only::TestOnlyDeterministicHasher,
    };

    fn entry(bytes: &[u8]) -> RegistryEntry {
        let Ok(key) = GovernancePublicKey::new(bytes.to_vec()) else {
            panic!("test governance key must be valid");
        };

        RegistryEntry::new(key)
    }

    fn registry(entries: Vec<RegistryEntry>) -> RegistrySnapshot {
        let Ok(snapshot) = RegistrySnapshot::new(entries) else {
            panic!("test registry must be valid");
        };

        snapshot
    }

    #[test]
    fn registry_cbor_vector_is_exact() {
        let snapshot = registry(vec![entry(b"bb"), entry(b"a")]);

        let Ok(encoded) = snapshot.to_canonical_cbor() else {
            panic!("registry encoding should succeed");
        };

        assert_eq!(encoded, vec![0x82, 0x41, b'a', 0x42, b'b', b'b']);
    }

    #[test]
    fn registry_round_trip_preserves_exact_bytes() {
        let snapshot = registry(vec![entry(b"key-c"), entry(b"key-a"), entry(b"key-b")]);

        let Ok(encoded) = snapshot.to_canonical_cbor() else {
            panic!("registry encoding should succeed");
        };

        let Ok(decoded) = RegistrySnapshot::from_canonical_cbor(&encoded) else {
            panic!("registry decoding should succeed");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("registry re-encoding should succeed");
        };

        assert_eq!(decoded, snapshot);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn input_order_does_not_change_bytes_or_commitment() {
        let first = registry(vec![entry(b"key-a"), entry(b"key-b"), entry(b"key-c")]);

        let second = registry(vec![entry(b"key-c"), entry(b"key-a"), entry(b"key-b")]);

        let Ok(first_bytes) = first.to_canonical_cbor() else {
            panic!("first registry encoding should succeed");
        };

        let Ok(second_bytes) = second.to_canonical_cbor() else {
            panic!("second registry encoding should succeed");
        };

        let provider = TestOnlyDeterministicHasher;

        let Ok(first_commitment) = first.canonical_commitment(&provider) else {
            panic!("first registry commitment should succeed");
        };

        let Ok(second_commitment) = second.canonical_commitment(&provider) else {
            panic!("second registry commitment should succeed");
        };

        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first_commitment, second_commitment);
    }

    #[test]
    fn membership_changes_produce_different_commitments() {
        let base = registry(vec![entry(b"key-a"), entry(b"key-b")]);
        let added = registry(vec![entry(b"key-a"), entry(b"key-b"), entry(b"key-c")]);
        let removed = registry(vec![entry(b"key-a")]);
        let replaced = registry(vec![entry(b"key-a"), entry(b"key-z")]);

        let provider = TestOnlyDeterministicHasher;

        let Ok(base_commitment) = base.canonical_commitment(&provider) else {
            panic!("base commitment should succeed");
        };

        let Ok(added_commitment) = added.canonical_commitment(&provider) else {
            panic!("added commitment should succeed");
        };

        let Ok(removed_commitment) = removed.canonical_commitment(&provider) else {
            panic!("removed commitment should succeed");
        };

        let Ok(replaced_commitment) = replaced.canonical_commitment(&provider) else {
            panic!("replaced commitment should succeed");
        };

        assert_ne!(base_commitment, added_commitment);
        assert_ne!(base_commitment, removed_commitment);
        assert_ne!(base_commitment, replaced_commitment);
    }

    #[test]
    fn unsorted_encoded_registry_is_rejected() {
        let encoded = vec![0x82, 0x41, b'b', 0x41, b'a'];

        let result = RegistrySnapshot::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn duplicate_encoded_registry_key_is_rejected() {
        let encoded = vec![0x82, 0x41, b'a', 0x41, b'a'];

        let result = RegistrySnapshot::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::DuplicateGovernanceKey
        ));
    }

    #[test]
    fn encoded_registry_member_limit_is_enforced_before_allocation() {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(MAX_REGISTRY_MEMBERS + 1).is_ok());

        let result = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes());

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_encoded_registry_is_rejected() {
        let encoded = vec![0_u8; MAX_CANONICAL_OBJECT_BYTES + 1];
        let result = RegistrySnapshot::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
