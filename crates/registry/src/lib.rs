#![forbid(unsafe_code)]

//! Frozen electorate registry models.

use tari_cc_private_ballot_protocol::{
    MAX_GOVERNANCE_KEY_BYTES, MAX_REGISTRY_MEMBERS, ProtocolError, ValidationCode,
};

mod canonical;
mod key_policy;

pub use key_policy::{
    GOVERNANCE_KEY_WARNING, VoterGovernanceKeyRegistrationV1, VoterKeyProvisioningV1,
};

/// Canonical encoding of one dedicated governance public key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GovernancePublicKey(Vec<u8>);

impl GovernancePublicKey {
    /// Creates a governance public key from a bounded non-empty encoding.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyGovernanceKey,
                "governance public key must not be empty",
            ));
        }

        if bytes.len() > MAX_GOVERNANCE_KEY_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "governance public key exceeds the protocol size limit",
            ));
        }

        Ok(Self(bytes))
    }

    /// Returns the canonical public-key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One member of a frozen election registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistryEntry {
    governance_key: GovernancePublicKey,
}

impl RegistryEntry {
    /// Creates a registry entry from an explicit voter-controlled registration.
    #[must_use]
    pub fn from_voter_registration(registration: VoterGovernanceKeyRegistrationV1) -> Self {
        Self {
            governance_key: registration.into_public_key(),
        }
    }

    /// Reconstructs a public entry while decoding an already frozen snapshot.
    ///
    /// Snapshot decoding does not repeat or replace the original enrollment
    /// authorization process.
    pub(crate) const fn from_snapshot_public_key(governance_key: GovernancePublicKey) -> Self {
        Self { governance_key }
    }

    /// Returns the dedicated governance key.
    #[must_use]
    pub const fn governance_key(&self) -> &GovernancePublicKey {
        &self.governance_key
    }
}

/// Canonically ordered frozen electorate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySnapshot {
    entries: Vec<RegistryEntry>,
}

impl RegistrySnapshot {
    /// Sorts entries and rejects empty, oversized, or duplicate registries.
    pub fn new(mut entries: Vec<RegistryEntry>) -> Result<Self, ProtocolError> {
        if entries.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyRegistry,
                "registry must contain at least one governance key",
            ));
        }

        if entries.len() > MAX_REGISTRY_MEMBERS {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "registry member count exceeds the protocol limit",
            ));
        }

        entries.sort();

        if entries.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProtocolError::new(
                ValidationCode::DuplicateGovernanceKey,
                "registry contains a duplicate governance key",
            ));
        }

        Ok(Self { entries })
    }

    /// Returns entries in canonical governance-key order.
    #[must_use]
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// Returns the number of registry members.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GovernancePublicKey, RegistryEntry, RegistrySnapshot, VoterGovernanceKeyRegistrationV1,
        VoterKeyProvisioningV1,
    };
    use tari_cc_private_ballot_protocol::{
        MAX_GOVERNANCE_KEY_BYTES, MAX_REGISTRY_MEMBERS, ValidationCode,
    };

    fn entry(bytes: &[u8]) -> RegistryEntry {
        let Ok(key) = GovernancePublicKey::new(bytes.to_vec()) else {
            panic!("test governance key must be valid");
        };

        let registration =
            VoterGovernanceKeyRegistrationV1::new(key, VoterKeyProvisioningV1::GeneratedByVoter);

        RegistryEntry::from_voter_registration(registration)
    }

    #[test]
    fn registry_entry_is_created_from_voter_registration() {
        let Ok(key) = GovernancePublicKey::new(b"voter-public-key".to_vec()) else {
            panic!("test governance key must be valid");
        };

        let registration = VoterGovernanceKeyRegistrationV1::new(
            key.clone(),
            VoterKeyProvisioningV1::ImportedByVoter,
        );

        let entry = RegistryEntry::from_voter_registration(registration);

        assert_eq!(entry.governance_key(), &key);
    }

    #[test]
    fn registry_is_sorted_canonically() {
        let Ok(snapshot) =
            RegistrySnapshot::new(vec![entry(b"key-c"), entry(b"key-a"), entry(b"key-b")])
        else {
            panic!("registry should be valid");
        };

        let keys: Vec<&[u8]> = snapshot
            .entries()
            .iter()
            .map(|entry| entry.governance_key().as_bytes())
            .collect();

        assert_eq!(keys, vec![b"key-a", b"key-b", b"key-c"]);
    }

    #[test]
    fn duplicate_governance_key_is_rejected() {
        let error = RegistrySnapshot::new(vec![entry(b"key-a"), entry(b"key-a")]);

        assert!(matches!(
            error,
            Err(error)
                if error.code() == ValidationCode::DuplicateGovernanceKey
        ));
    }

    #[test]
    fn empty_registry_is_rejected() {
        let error = RegistrySnapshot::new(Vec::new());

        assert!(matches!(
            error,
            Err(error) if error.code() == ValidationCode::EmptyRegistry
        ));
    }

    #[test]
    fn empty_governance_key_is_rejected() {
        let error = GovernancePublicKey::new(Vec::new());

        assert!(matches!(
            error,
            Err(error)
                if error.code() == ValidationCode::EmptyGovernanceKey
        ));
    }

    #[test]
    fn oversized_governance_key_is_rejected() {
        let error = GovernancePublicKey::new(vec![7_u8; MAX_GOVERNANCE_KEY_BYTES + 1]);

        assert!(matches!(
            error,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_registry_is_rejected() {
        let mut entries = Vec::with_capacity(MAX_REGISTRY_MEMBERS + 1);

        for index in 0..=MAX_REGISTRY_MEMBERS {
            let Ok(value) = u32::try_from(index) else {
                panic!("test registry index must fit in u32");
            };

            entries.push(entry(&value.to_be_bytes()));
        }

        let error = RegistrySnapshot::new(entries);

        assert!(matches!(
            error,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }
}
