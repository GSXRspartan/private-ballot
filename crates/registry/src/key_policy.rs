//! Voter-owned dedicated governance-key registration policy.

use crate::GovernancePublicKey;

/// Warning that must be shown before governance-key provisioning.
pub const GOVERNANCE_KEY_WARNING: &str =
    "This is a governance key. Do not import a Tari wallet seed, account key, or spending key.";

/// Supported voter-controlled provisioning paths.
///
/// There is deliberately no election-authority-generated variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoterKeyProvisioningV1 {
    /// The voter generated a new dedicated governance keypair.
    GeneratedByVoter,
    /// The voter imported a previously created dedicated governance keypair.
    ImportedByVoter,
}

impl VoterKeyProvisioningV1 {
    /// Returns the stable machine-readable provisioning identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeneratedByVoter => "VOTER_GENERATED",
            Self::ImportedByVoter => "VOTER_IMPORTED",
        }
    }
}

/// Voter-side registration of one dedicated governance public key.
///
/// This structure contains only public material. It never accepts or stores
/// a governance private key, wallet seed, account key, or spending key.
///
/// The registration is an explicit local provisioning attestation. It is
/// not enrollment authorization evidence and does not prove political
/// eligibility. It also does not define rotation, replacement, revocation,
/// suspension, lost-key, or compromised-key procedures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoterGovernanceKeyRegistrationV1 {
    public_key: GovernancePublicKey,
    provisioning: VoterKeyProvisioningV1,
}

impl VoterGovernanceKeyRegistrationV1 {
    /// Records a voter-controlled dedicated governance public key.
    #[must_use]
    pub const fn new(
        public_key: GovernancePublicKey,
        provisioning: VoterKeyProvisioningV1,
    ) -> Self {
        Self {
            public_key,
            provisioning,
        }
    }

    /// Returns the public key supplied by the voter.
    #[must_use]
    pub const fn public_key(&self) -> &GovernancePublicKey {
        &self.public_key
    }

    /// Returns how the voter provisioned the dedicated key.
    #[must_use]
    pub const fn provisioning(&self) -> VoterKeyProvisioningV1 {
        self.provisioning
    }

    pub(crate) fn into_public_key(self) -> GovernancePublicKey {
        self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(bytes: &[u8]) -> GovernancePublicKey {
        let Ok(key) = GovernancePublicKey::new(bytes.to_vec()) else {
            panic!("test governance key must be valid");
        };

        key
    }

    #[test]
    fn governance_key_warning_is_exact() {
        assert_eq!(
            GOVERNANCE_KEY_WARNING,
            "This is a governance key. Do not import a Tari wallet seed, account key, or spending key."
        );
    }

    #[test]
    fn provisioning_identifiers_are_stable() {
        assert_eq!(
            VoterKeyProvisioningV1::GeneratedByVoter.as_str(),
            "VOTER_GENERATED"
        );
        assert_eq!(
            VoterKeyProvisioningV1::ImportedByVoter.as_str(),
            "VOTER_IMPORTED"
        );
    }

    #[test]
    fn generated_registration_preserves_only_public_policy_data() {
        let public_key = key(b"generated-public-key");
        let registration = VoterGovernanceKeyRegistrationV1::new(
            public_key.clone(),
            VoterKeyProvisioningV1::GeneratedByVoter,
        );

        assert_eq!(registration.public_key(), &public_key);
        assert_eq!(
            registration.provisioning(),
            VoterKeyProvisioningV1::GeneratedByVoter
        );
    }

    #[test]
    fn imported_registration_preserves_only_public_policy_data() {
        let public_key = key(b"imported-public-key");
        let registration = VoterGovernanceKeyRegistrationV1::new(
            public_key.clone(),
            VoterKeyProvisioningV1::ImportedByVoter,
        );

        assert_eq!(registration.public_key(), &public_key);
        assert_eq!(
            registration.provisioning(),
            VoterKeyProvisioningV1::ImportedByVoter
        );
    }
}
