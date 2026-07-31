//! Election-specific scope derivation.

use crate::{ElectionScope, HashDomain, HashProvider, ManifestHash, hash_domain_separated};

/// Derives an election-specific scope from a canonical manifest hash.
///
/// Anonymous duplicate-detection identifiers must bind to this scope
/// rather than a human-readable election identifier.
#[must_use]
pub fn derive_election_scope<H: HashProvider>(
    provider: &H,
    manifest_hash: &ManifestHash,
) -> ElectionScope {
    ElectionScope::new(hash_domain_separated(
        provider,
        HashDomain::ElectionScopeV1,
        manifest_hash.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::derive_election_scope;
    use crate::{
        HashDomain, ManifestHash, hash_domain_separated, test_only::TestOnlyDeterministicHasher,
    };

    #[test]
    fn identical_manifest_hashes_produce_identical_scopes() {
        let provider = TestOnlyDeterministicHasher;
        let manifest_hash = ManifestHash::new([7_u8; 32]);

        let first = derive_election_scope(&provider, &manifest_hash);
        let second = derive_election_scope(&provider, &manifest_hash);

        assert_eq!(first, second);
    }

    #[test]
    fn different_manifest_hashes_produce_different_scopes() {
        let provider = TestOnlyDeterministicHasher;

        let first = derive_election_scope(&provider, &ManifestHash::new([1_u8; 32]));

        let second = derive_election_scope(&provider, &ManifestHash::new([2_u8; 32]));

        assert_ne!(first, second);
    }

    #[test]
    fn scope_domain_is_distinct_from_manifest_domain() {
        let provider = TestOnlyDeterministicHasher;
        let manifest_hash = ManifestHash::new([9_u8; 32]);

        let scope = derive_election_scope(&provider, &manifest_hash);

        let manifest_domain_digest = hash_domain_separated(
            &provider,
            HashDomain::ElectionManifestV1,
            manifest_hash.as_bytes(),
        );

        assert_ne!(scope.into_bytes(), manifest_domain_digest);
    }
}
