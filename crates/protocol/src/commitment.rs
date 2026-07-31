//! Fixed-size protocol commitment types.

macro_rules! fixed_commitment_type {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates a commitment from exactly 32 bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the fixed-size commitment bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Consumes the wrapper and returns its bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

fixed_commitment_type!(
    ManifestHash,
    "Fixed-size hash binding a ballot to one election manifest."
);

fixed_commitment_type!(
    RegistryCommitment,
    "Fixed-size commitment to one frozen electorate registry."
);

fixed_commitment_type!(
    CandidateSetCommitment,
    "Fixed-size commitment to one canonical candidate set."
);

#[cfg(test)]
mod tests {
    use super::{CandidateSetCommitment, ManifestHash, RegistryCommitment};

    #[test]
    fn commitment_bytes_round_trip() {
        let hash = ManifestHash::new([7_u8; 32]);

        assert_eq!(hash.as_bytes(), &[7_u8; 32]);
        assert_eq!(hash.into_bytes(), [7_u8; 32]);
    }

    #[test]
    fn commitment_wrappers_preserve_exact_bytes() {
        let registry = RegistryCommitment::new([3_u8; 32]);
        let candidates = CandidateSetCommitment::new([9_u8; 32]);

        assert_eq!(registry.into_bytes(), [3_u8; 32]);
        assert_eq!(candidates.into_bytes(), [9_u8; 32]);
    }
}
