#![forbid(unsafe_code)]

//! Frozen electorate registry models.

use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// Canonical encoding of one dedicated governance public key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GovernancePublicKey(Vec<u8>);

impl GovernancePublicKey {
    /// Creates a governance public key from a non-empty canonical encoding.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyGovernanceKey,
                "governance public key must not be empty",
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
    /// Creates one registry entry.
    #[must_use]
    pub const fn new(governance_key: GovernancePublicKey) -> Self {
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
    /// Sorts entries and rejects an empty registry or duplicate keys.
    pub fn new(mut entries: Vec<RegistryEntry>) -> Result<Self, ProtocolError> {
        if entries.is_empty() {
            return Err(ProtocolError::new(
                ValidationCode::EmptyRegistry,
                "registry must contain at least one governance key",
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
    use super::{GovernancePublicKey, RegistryEntry, RegistrySnapshot};
    use tari_cc_private_ballot_protocol::ValidationCode;

    fn entry(bytes: &[u8]) -> RegistryEntry {
        let Ok(key) = GovernancePublicKey::new(bytes.to_vec()) else {
            panic!("test governance key must be valid");
        };

        RegistryEntry::new(key)
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
}
