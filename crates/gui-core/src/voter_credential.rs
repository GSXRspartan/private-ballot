//! Session-only voter governance credential boundary.
//!
//! This module is the first gui-core facade that deliberately owns voter
//! secret material. The secret is held only in this Rust process, is never
//! serialized into a DTO, and is replaced/dropped explicitly when the voter
//! credential session is reset or an election session changes.

use core::fmt;

use serde::Serialize;
use tari_cc_private_ballot_crypto::{RISTRETTO_COMPRESSED_POINT_BYTES, TariTriptychSecretKeyV1};
use tari_cc_private_ballot_registry::{GOVERNANCE_KEY_WARNING, RegistrySnapshot};

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::GuiCoreError;
use crate::hex::{abbreviate_hex, to_lower_hex};

/// Public notice attached to every voter credential status.
pub const GOVERNANCE_CREDENTIAL_SESSION_NOTICE: &str = "Governance credentials are session-only in this build and are lost on restart or election reset.";

/// Public notice explaining why generation after freeze usually is not eligible.
pub const GOVERNANCE_CREDENTIAL_ENROLLMENT_NOTICE: &str = "A newly generated public governance key is eligible only if it was already enrolled in the frozen voter registry.";

/// Stable origin code for the active Rust-side credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GuiVoterCredentialOriginV1 {
    /// Generated inside Rust with operating-system randomness.
    Generated,
}

impl GuiVoterCredentialOriginV1 {
    /// Returns the stable machine-readable origin code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "Generated",
        }
    }
}

/// Stable eligibility status for the current loaded election.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum GuiVoterEligibilityV1 {
    /// No credential is currently loaded.
    NotChecked,
    /// The derived public key exists in the current frozen registry.
    Eligible,
    /// The derived public key does not exist in the current frozen registry.
    NotEligible,
}

impl GuiVoterEligibilityV1 {
    /// Returns a concise display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotChecked => "No credential loaded",
            Self::Eligible => "Eligible",
            Self::NotEligible => "Not eligible for this election",
        }
    }

    /// Returns whether the status unlocks the next voter stage.
    #[must_use]
    pub const fn permits_next_stage(self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// Safe public status returned over the Tauri boundary.
///
/// This DTO contains only public metadata: a derived governance public key,
/// abbreviated display text, eligibility status, and fixed notices. It never
/// contains a scalar, seed, mnemonic, credential bytes, wallet key, registry
/// index, proof, nullifier, or ballot package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuiVoterCredentialStatusV1 {
    /// Whether Rust currently owns a voter credential secret.
    pub credential_loaded: bool,
    /// How the current credential was provisioned. `None` when unloaded.
    pub credential_origin: Option<GuiVoterCredentialOriginV1>,
    /// Full derived public governance key, lowercase hex.
    pub public_governance_key_hex: Option<String>,
    /// Abbreviated public governance key for display.
    pub public_governance_key_abbrev: Option<String>,
    /// Eligibility against the current frozen registry.
    pub eligibility: GuiVoterEligibilityV1,
    /// Human-readable eligibility label.
    pub eligibility_label: &'static str,
    /// Whether the voter may proceed to the next stage.
    pub can_continue: bool,
    /// True because this slice implements no secure persistence.
    pub session_only: bool,
    /// Fixed session-only notice.
    pub session_notice: &'static str,
    /// Fixed wallet-seed separation warning.
    pub wallet_key_warning: &'static str,
    /// Fixed enrollment notice for generated credentials.
    pub enrollment_notice: &'static str,
}

impl GuiVoterCredentialStatusV1 {
    /// Returns an explicit unloaded status.
    #[must_use]
    pub const fn unloaded() -> Self {
        Self {
            credential_loaded: false,
            credential_origin: None,
            public_governance_key_hex: None,
            public_governance_key_abbrev: None,
            eligibility: GuiVoterEligibilityV1::NotChecked,
            eligibility_label: GuiVoterEligibilityV1::NotChecked.label(),
            can_continue: false,
            session_only: true,
            session_notice: GOVERNANCE_CREDENTIAL_SESSION_NOTICE,
            wallet_key_warning: GOVERNANCE_KEY_WARNING,
            enrollment_notice: GOVERNANCE_CREDENTIAL_ENROLLMENT_NOTICE,
        }
    }
}

/// Rust-owned voter governance credential.
///
/// This wrapper intentionally implements neither `Serialize`, `Clone`, `Copy`,
/// nor `Display`. Its `Debug` output is redacted. Dropping it drops the
/// underlying `TariTriptychSecretKeyV1`, which zeroizes its canonical scalar
/// bytes.
pub struct VoterGovernanceCredentialV1 {
    secret_key: TariTriptychSecretKeyV1,
}

impl VoterGovernanceCredentialV1 {
    /// Generates one session-only governance credential in Rust.
    pub fn generate() -> Result<Self, GuiCoreError> {
        let secret_key = TariTriptychSecretKeyV1::generate_os_rng()
            .map_err(|error| GuiCoreError::from_protocol(&error, "voter-credential"))?;
        Ok(Self { secret_key })
    }

    /// Parses an existing canonical scalar for tests and controlled internal
    /// fixtures. This is not exposed as a Tauri import API because the project
    /// has no reviewed private credential file format.
    #[cfg(test)]
    pub(crate) fn from_test_canonical_scalar(
        bytes: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    ) -> Result<Self, GuiCoreError> {
        let secret_key = TariTriptychSecretKeyV1::from_canonical_bytes(bytes)
            .map_err(|error| GuiCoreError::from_protocol(&error, "voter-credential"))?;
        Ok(Self { secret_key })
    }

    /// Returns the derived canonical public governance key bytes.
    pub fn public_key_bytes(&self) -> Result<[u8; RISTRETTO_COMPRESSED_POINT_BYTES], GuiCoreError> {
        let public_key = self
            .secret_key
            .governance_public_key()
            .map_err(|error| GuiCoreError::from_protocol(&error, "voter-credential"))?;
        Ok(public_key.into_bytes())
    }
}

impl fmt::Debug for VoterGovernanceCredentialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VoterGovernanceCredentialV1([REDACTED])")
    }
}

/// One active voter credential bound to the current loaded election session.
pub struct GuiVoterCredentialSessionV1 {
    credential: VoterGovernanceCredentialV1,
    origin: GuiVoterCredentialOriginV1,
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    eligibility: GuiVoterEligibilityV1,
}

impl GuiVoterCredentialSessionV1 {
    /// Generates and evaluates a fresh session credential.
    pub fn generate_for(artifacts: &GuiElectionArtifactsV1) -> Result<Self, GuiCoreError> {
        let credential = VoterGovernanceCredentialV1::generate()?;
        Self::from_credential(
            credential,
            GuiVoterCredentialOriginV1::Generated,
            artifacts.registry(),
        )
    }

    /// Creates a session from a controlled fixture credential.
    pub fn from_credential(
        credential: VoterGovernanceCredentialV1,
        origin: GuiVoterCredentialOriginV1,
        registry: &RegistrySnapshot,
    ) -> Result<Self, GuiCoreError> {
        let public_key = credential.public_key_bytes()?;
        let eligibility = eligibility_for_public_key(registry, &public_key);
        Ok(Self {
            credential,
            origin,
            public_key,
            eligibility,
        })
    }

    /// Recomputes eligibility for another loaded election without revealing or
    /// cloning the secret.
    pub fn recompute_for(&mut self, registry: &RegistrySnapshot) {
        self.eligibility = eligibility_for_public_key(registry, &self.public_key);
    }

    /// Returns public status only.
    #[must_use]
    pub fn status(&self) -> GuiVoterCredentialStatusV1 {
        let public_hex = to_lower_hex(&self.public_key);
        GuiVoterCredentialStatusV1 {
            credential_loaded: true,
            credential_origin: Some(self.origin),
            public_governance_key_hex: Some(public_hex.clone()),
            public_governance_key_abbrev: Some(abbreviate_hex(&public_hex, 8, 6)),
            eligibility: self.eligibility,
            eligibility_label: self.eligibility.label(),
            can_continue: self.eligibility.permits_next_stage(),
            session_only: true,
            session_notice: GOVERNANCE_CREDENTIAL_SESSION_NOTICE,
            wallet_key_warning: GOVERNANCE_KEY_WARNING,
            enrollment_notice: GOVERNANCE_CREDENTIAL_ENROLLMENT_NOTICE,
        }
    }
}

impl fmt::Debug for GuiVoterCredentialSessionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuiVoterCredentialSessionV1")
            .field("credential", &self.credential)
            .field("origin", &self.origin)
            .field("public_key", &"[PUBLIC]")
            .field("eligibility", &self.eligibility)
            .finish()
    }
}

fn eligibility_for_public_key(
    registry: &RegistrySnapshot,
    public_key: &[u8; RISTRETTO_COMPRESSED_POINT_BYTES],
) -> GuiVoterEligibilityV1 {
    if registry
        .entries()
        .iter()
        .any(|entry| entry.governance_key().as_bytes() == public_key)
    {
        GuiVoterEligibilityV1::Eligible
    } else {
        GuiVoterEligibilityV1::NotEligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek_v4::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
    use serde_json::Value;
    use tari_cc_private_ballot_protocol::CanonicalCborWriter;
    use tari_cc_private_ballot_registry::RegistrySnapshot;

    #[test]
    fn generated_credentials_are_valid_and_distinct() {
        let first = ok(
            VoterGovernanceCredentialV1::generate(),
            "first generated credential",
        );
        let second = ok(
            VoterGovernanceCredentialV1::generate(),
            "second generated credential",
        );

        assert_ne!(
            ok(first.public_key_bytes(), "first public key"),
            ok(second.public_key_bytes(), "second public key"),
        );
    }

    #[test]
    fn derived_public_key_matches_existing_triptych_primitive() {
        let scalar = Scalar::from(7_u64);
        let credential = ok(
            VoterGovernanceCredentialV1::from_test_canonical_scalar(scalar.to_bytes()),
            "fixture credential",
        );
        let expected = (RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes();

        assert_eq!(ok(credential.public_key_bytes(), "public key"), expected);
    }

    #[test]
    fn zero_and_noncanonical_scalars_are_rejected() {
        assert!(VoterGovernanceCredentialV1::from_test_canonical_scalar([0_u8; 32]).is_err());
        assert!(VoterGovernanceCredentialV1::from_test_canonical_scalar([0xff_u8; 32]).is_err());
    }

    #[test]
    fn eligible_credential_matches_registry_without_returning_index() {
        let fixture = voter(7);
        let credential = ok(
            VoterGovernanceCredentialV1::from_test_canonical_scalar(fixture.secret_bytes),
            "fixture credential",
        );
        let session = ok(
            GuiVoterCredentialSessionV1::from_credential(
                credential,
                GuiVoterCredentialOriginV1::Generated,
                &registry_from_keys(&[fixture.public_bytes]),
            ),
            "credential session",
        );
        let status = session.status();
        let json = ok(serde_json::to_value(&status), "status serializes");

        assert_eq!(status.eligibility, GuiVoterEligibilityV1::Eligible);
        assert!(status.can_continue);
        assert!(json.get("registry_index").is_none());
    }

    #[test]
    fn generated_public_key_can_be_enrolled_and_later_match() {
        let credential = ok(
            VoterGovernanceCredentialV1::generate(),
            "generated credential",
        );
        let public_key = ok(credential.public_key_bytes(), "public key");
        let registry = registry_from_keys(&[public_key]);
        let session = ok(
            GuiVoterCredentialSessionV1::from_credential(
                credential,
                GuiVoterCredentialOriginV1::Generated,
                &registry,
            ),
            "credential session",
        );

        assert_eq!(
            session.status().eligibility,
            GuiVoterEligibilityV1::Eligible
        );
    }

    #[test]
    fn unrelated_generated_credential_is_not_eligible_for_fixture_registry() {
        let credential = ok(
            VoterGovernanceCredentialV1::generate(),
            "generated credential",
        );
        let registry = registry_from_scalars(&[7, 11, 13]);
        let session = ok(
            GuiVoterCredentialSessionV1::from_credential(
                credential,
                GuiVoterCredentialOriginV1::Generated,
                &registry,
            ),
            "credential session",
        );

        assert_eq!(
            session.status().eligibility,
            GuiVoterEligibilityV1::NotEligible
        );
        assert!(!session.status().can_continue);
    }

    #[test]
    fn eligibility_recomputes_after_registry_change() {
        let fixture = voter(7);
        let credential = ok(
            VoterGovernanceCredentialV1::from_test_canonical_scalar(fixture.secret_bytes),
            "fixture credential",
        );
        let mut session = ok(
            GuiVoterCredentialSessionV1::from_credential(
                credential,
                GuiVoterCredentialOriginV1::Generated,
                &registry_from_keys(&[fixture.public_bytes]),
            ),
            "credential session",
        );
        let other = registry_from_scalars(&[17]);

        session.recompute_for(&other);

        assert_eq!(
            session.status().eligibility,
            GuiVoterEligibilityV1::NotEligible
        );
    }

    #[test]
    fn public_status_serialization_contains_no_secret_fields_or_bytes() {
        let fixture = voter(7);
        let credential = ok(
            VoterGovernanceCredentialV1::from_test_canonical_scalar(fixture.secret_bytes),
            "fixture credential",
        );
        let session = ok(
            GuiVoterCredentialSessionV1::from_credential(
                credential,
                GuiVoterCredentialOriginV1::Generated,
                &registry_from_keys(&[fixture.public_bytes]),
            ),
            "credential session",
        );
        let value = ok(serde_json::to_value(session.status()), "status serializes");
        let json = value.to_string();
        let secret_hex = to_lower_hex(&fixture.secret_bytes);

        assert!(!json.to_lowercase().contains(&secret_hex));
        let object = some(value.as_object(), "status is object");
        for field in object.keys() {
            for forbidden in [
                "secret",
                "scalar",
                "seed",
                "mnemonic",
                "private",
                "credential_bytes",
                "registry_index",
                "nullifier",
                "proof",
            ] {
                assert!(
                    !field.to_lowercase().contains(forbidden),
                    "status field leaked forbidden marker: {field}"
                );
            }
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let fixture = voter(7);
        let credential = ok(
            VoterGovernanceCredentialV1::from_test_canonical_scalar(fixture.secret_bytes),
            "fixture credential",
        );
        let rendered = format!("{credential:?}");

        assert_eq!(rendered, "VoterGovernanceCredentialV1([REDACTED])");
        assert!(!rendered.contains(&to_lower_hex(&fixture.secret_bytes)));
    }

    #[test]
    fn unloaded_status_has_no_public_key_or_origin() {
        let status = GuiVoterCredentialStatusV1::unloaded();
        let json: Value = ok(serde_json::to_value(&status), "status serializes");

        assert!(!status.credential_loaded);
        assert!(status.public_governance_key_hex.is_none());
        assert!(status.credential_origin.is_none());
        assert_eq!(json.get("public_governance_key_hex"), Some(&Value::Null));
    }

    #[test]
    fn secret_types_are_not_copy_or_clone_and_need_drop() {
        assert!(core::mem::needs_drop::<VoterGovernanceCredentialV1>());
        assert!(core::mem::needs_drop::<GuiVoterCredentialSessionV1>());
    }

    struct Voter {
        secret_bytes: [u8; 32],
        public_bytes: [u8; 32],
    }

    fn voter(scalar: u64) -> Voter {
        let scalar_value = Scalar::from(scalar);
        let public_bytes = (RISTRETTO_BASEPOINT_POINT * scalar_value)
            .compress()
            .to_bytes();
        Voter {
            secret_bytes: scalar_value.to_bytes(),
            public_bytes,
        }
    }

    fn registry_from_scalars(scalars: &[u64]) -> RegistrySnapshot {
        let mut keys = Vec::with_capacity(scalars.len());
        for scalar in scalars {
            keys.push(voter(*scalar).public_bytes);
        }
        registry_from_keys(&keys)
    }

    fn registry_from_keys(keys: &[[u8; 32]]) -> RegistrySnapshot {
        let mut sorted = keys.to_vec();
        sorted.sort_unstable();
        let mut writer = CanonicalCborWriter::new();
        assert!(writer.write_array_len(sorted.len()).is_ok());
        for key in sorted {
            assert!(writer.write_byte_string(&key).is_ok());
        }
        ok(
            RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()),
            "fixture registry",
        )
    }

    fn ok<T, E>(result: Result<T, E>, label: &'static str) -> T {
        match result {
            Ok(value) => value,
            Err(_) => panic!("{label}"),
        }
    }

    fn some<T>(value: Option<T>, label: &'static str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{label}"),
        }
    }
}
