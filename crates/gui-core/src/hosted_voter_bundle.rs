//! Production V2 voter-public bundle for Hosted elections.
//!
//! This is the PRODUCTION format for the voter-side bundle — not the test-only
//! [`TARI_CC_PRIVATE_BALLOT_TEST_VOTER_PUBLIC_BUNDLE_V1`] from the
//! transport-gateway provisioning module. It is served by the Hosted authority
//! over the public API and imported by the Desktop voter. No organizer secret
//! or private transport key is ever included.
//!
//! Bundle layout (10-element canonical CBOR array):
//!   [0] version    u64 = 1
//!   [1] type_id    text = HOSTED_VOTER_BUNDLE_V2_TYPE_ID
//!   [2] authority_key_id  text
//!   [3] authority_public_key  bytes (32 — Ed25519 public key)
//!   [4] election_id  bytes
//!   [5] manifest_hash  bytes (32)
//!   [6] manifest_cbor  bytes
//!   [7] registry_cbor  bytes
//!   [8] candidate_cbor bytes
//!   [9] descriptor_cbor bytes  (the authority-signed TransportDescriptorV1)

use tari_cc_private_ballot_protocol::{CanonicalCborReader, CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES};

use crate::{
    DescriptorConsistencyStoreV1, GuiCoreError, GuiElectionArtifactsV1,
    TransportAuthorityRootSetV1, TransportAuthorityRootV1, TransportDescriptorV1,
};

pub const HOSTED_VOTER_BUNDLE_V2_VERSION: u64 = 1;
pub const HOSTED_VOTER_BUNDLE_V2_TYPE_ID: &str =
    "TARI_CC_PRIVATE_BALLOT_HOSTED_VOTER_PUBLIC_BUNDLE_V2";

/// Maximum size guard: 3 × MAX_CANONICAL_OBJECT_BYTES for the three election
/// artifacts, plus generous headroom for the descriptor and envelope.
fn max_bundle_bytes() -> usize {
    MAX_CANONICAL_OBJECT_BYTES
        .saturating_mul(3)
        .saturating_add(32_768)
}

/// A production Hosted voter-public bundle: everything the voter needs to
/// verify the election and configure private-ballot transport. Contains only
/// public material — no organizer or authority private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedVoterPublicBundleV2 {
    authority_key_id: String,
    authority_public_key: [u8; 32],
    election_id: Vec<u8>,
    manifest_hash: [u8; 32],
    manifest_cbor: Vec<u8>,
    registry_cbor: Vec<u8>,
    candidate_cbor: Vec<u8>,
    descriptor_cbor: Vec<u8>,
}

/// The verified output of [`HostedVoterPublicBundleV2::verify`]. All fields
/// have been cross-validated and are safe to use for transport configuration.
#[derive(Debug, Clone)]
pub struct VerifiedHostedVoterBundleV2 {
    /// Cross-validated election artifacts (manifest, registry, candidates).
    pub artifacts: GuiElectionArtifactsV1,
    /// Authority-signed transport descriptor.
    pub descriptor: TransportDescriptorV1,
    /// The authority root used to verify the descriptor.
    pub root: TransportAuthorityRootV1,
}

impl HostedVoterPublicBundleV2 {
    /// Constructs a bundle from pre-validated components. All callers are
    /// trusted (the Hosted server or a test fixture); runtime validation is
    /// done in `verify()` and `from_canonical_cbor()`.
    pub fn new(
        authority_key_id: String,
        authority_public_key: [u8; 32],
        election_id: Vec<u8>,
        manifest_hash: [u8; 32],
        manifest_cbor: Vec<u8>,
        registry_cbor: Vec<u8>,
        candidate_cbor: Vec<u8>,
        descriptor_cbor: Vec<u8>,
    ) -> Result<Self, GuiCoreError> {
        if authority_key_id.is_empty() || election_id.is_empty() || manifest_hash == [0u8; 32] {
            return Err(bundle_error());
        }
        Ok(Self {
            authority_key_id,
            authority_public_key,
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        })
    }

    #[must_use]
    pub fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    #[must_use]
    pub fn authority_public_key(&self) -> [u8; 32] {
        self.authority_public_key
    }

    #[must_use]
    pub fn election_id(&self) -> &[u8] {
        &self.election_id
    }

    #[must_use]
    pub fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, GuiCoreError> {
        let mut w = CanonicalCborWriter::new();
        w.write_array_len(10).map_err(|_| bundle_error())?;
        w.write_unsigned(HOSTED_VOTER_BUNDLE_V2_VERSION);
        w.write_text_string(HOSTED_VOTER_BUNDLE_V2_TYPE_ID)
            .map_err(|_| bundle_error())?;
        w.write_text_string(&self.authority_key_id)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.authority_public_key)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.election_id)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.manifest_hash)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.manifest_cbor)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.registry_cbor)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.candidate_cbor)
            .map_err(|_| bundle_error())?;
        w.write_byte_string(&self.descriptor_cbor)
            .map_err(|_| bundle_error())?;
        Ok(w.into_bytes())
    }

    /// Strictly decodes one canonical bundle. The re-encoding equality check
    /// rejects alternate CBOR encodings and trailing input before verification.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, GuiCoreError> {
        if bytes.len() > max_bundle_bytes() {
            return Err(bundle_error());
        }
        let mut r = CanonicalCborReader::new(bytes);
        if r.read_array_len().map_err(|_| bundle_error())? != 10
            || r.read_unsigned().map_err(|_| bundle_error())? != HOSTED_VOTER_BUNDLE_V2_VERSION
            || r.read_text_string().map_err(|_| bundle_error())?
                != HOSTED_VOTER_BUNDLE_V2_TYPE_ID
        {
            return Err(bundle_error());
        }
        let authority_key_id = r
            .read_text_string()
            .map_err(|_| bundle_error())?
            .to_owned();
        let authority_public_key = read_fixed_32(&mut r)?;
        let election_id = r
            .read_byte_string()
            .map_err(|_| bundle_error())?
            .to_vec();
        let manifest_hash = read_fixed_32(&mut r)?;
        let manifest_cbor = r.read_byte_string().map_err(|_| bundle_error())?.to_vec();
        let registry_cbor = r.read_byte_string().map_err(|_| bundle_error())?.to_vec();
        let candidate_cbor = r.read_byte_string().map_err(|_| bundle_error())?.to_vec();
        let descriptor_cbor = r.read_byte_string().map_err(|_| bundle_error())?.to_vec();
        r.finish().map_err(|_| bundle_error())?;

        if authority_key_id.is_empty() || election_id.is_empty() {
            return Err(bundle_error());
        }
        let output = Self {
            authority_key_id,
            authority_public_key,
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        };
        // Re-encoding equality — rejects alternate CBOR forms.
        if output.to_canonical_cbor()? != bytes {
            return Err(bundle_error());
        }
        Ok(output)
    }

    /// Full 10-step verification. Returns the cross-validated artifacts,
    /// descriptor, and authority root on success.
    ///
    /// Steps:
    ///  1. authority_key_id is non-empty (checked in from_canonical_cbor)
    ///  2. election artifacts decode and cross-validate
    ///  3. election is a V2 election (proposal_question is Some)
    ///  4. manifest.election_id matches bundle.election_id
    ///  5. computed manifest_hash matches bundle.manifest_hash
    ///  6. descriptor decodes as TransportDescriptorV1
    ///  7. descriptor is NOT an unsigned authority draft
    ///  8. descriptor verifies under the bundle's authority root
    ///  9. descriptor.election_id matches bundle.election_id
    /// 10. descriptor.manifest_hash matches bundle.manifest_hash
    pub fn verify(&self) -> Result<VerifiedHostedVoterBundleV2, GuiCoreError> {
        // 2. Election artifacts decode and cross-validate.
        let artifacts = GuiElectionArtifactsV1::from_bytes(
            &self.manifest_cbor,
            &self.registry_cbor,
            &self.candidate_cbor,
        )?;

        // 3. V2 election required.
        if artifacts.manifest().proposal_question().is_none() {
            return Err(bundle_error());
        }

        // 4. Manifest election_id matches.
        if artifacts.manifest().election_id().as_bytes() != self.election_id.as_slice() {
            return Err(bundle_error());
        }

        // 5. Manifest hash matches.
        if artifacts.manifest_hash().as_bytes() != &self.manifest_hash {
            return Err(bundle_error());
        }

        // 6. Descriptor decodes.
        let descriptor = TransportDescriptorV1::from_canonical_cbor(&self.descriptor_cbor)
            .map_err(|_| bundle_error())?;

        // 7. Descriptor is NOT an unsigned draft.
        if descriptor.is_unsigned_authority_draft() {
            return Err(bundle_error());
        }

        // 8. Descriptor verifies under the bundle's authority root.
        let root = TransportAuthorityRootV1::Pinned {
            key_id: self.authority_key_id.clone(),
            public_key: self.authority_public_key,
        };
        let roots = TransportAuthorityRootSetV1::new(root.clone());
        let mut consistency = DescriptorConsistencyStoreV1::default();
        roots
            .verify_and_accept_descriptor(
                &descriptor,
                artifacts.manifest_hash(),
                &mut consistency,
            )
            .map_err(|_| bundle_error())?;

        // 9. Descriptor election_id matches.
        if descriptor.election_id() != self.election_id.as_slice() {
            return Err(bundle_error());
        }

        // 10. Descriptor manifest_hash matches.
        if descriptor.manifest_hash() != artifacts.manifest_hash() {
            return Err(bundle_error());
        }

        Ok(VerifiedHostedVoterBundleV2 {
            artifacts,
            descriptor,
            root,
        })
    }
}

fn read_fixed_32(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], GuiCoreError> {
    reader
        .read_byte_string()
        .map_err(|_| bundle_error())?
        .try_into()
        .map_err(|_| bundle_error())
}

const fn bundle_error() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_HOSTED_VOTER_BUNDLE_INVALID",
        crate::GuiErrorCategory::InvalidInput,
        Some("hosted-voter-bundle-v2"),
        "the hosted voter public bundle is invalid or not trusted",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{
        BatchPolicyV1, PaddingPolicyV1, TransportDescriptorV1, TransportRoutePolicyV1,
    };
    use tari_cc_private_ballot_protocol::ManifestHash;

    fn make_authority() -> (SigningKey, TransportAuthorityRootV1) {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let root = TransportAuthorityRootV1::Pinned {
            key_id: "test-authority".to_owned(),
            public_key: key.verifying_key().to_bytes(),
        };
        (key, root)
    }

    fn make_signed_descriptor(authority: &SigningKey, election_id: &[u8], manifest_hash: [u8; 32]) -> TransportDescriptorV1 {
        let gateway_key = SigningKey::from_bytes(&[0x11; 32]);
        let receipt_key = SigningKey::from_bytes(&[0x22; 32]);
        let draft = TransportDescriptorV1::unsigned_for_authority(
            election_id.to_vec(),
            ManifestHash::new(manifest_hash),
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion".to_owned()],
            Vec::new(),
            gateway_key.verifying_key().to_bytes(),
            "test-gateway".to_owned(),
            vec![receipt_key.verifying_key().to_bytes()],
            PaddingPolicyV1 { id: "p".to_owned(), padded_bytes: 2048 },
            BatchPolicyV1 { id: "b".to_owned(), accepted_unique_floor: 1 },
            None,
            "test-authority".to_owned(),
        )
        .expect("draft");
        let payload = draft.authority_signing_payload().expect("payload");
        use ed25519_dalek::Signer;
        let sig = authority.sign(&payload).to_bytes();
        draft.with_authority_signature(sig).expect("signed")
    }

    fn make_v2_artifacts() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]) {
        // A minimal V2 artifact triple using the existing test helpers from artifacts.rs.
        // We use the fact that GuiElectionArtifactsV1::from_bytes re-validates internally.
        // Build minimal valid V2 election artifacts from the test fixtures approach.
        // For this test we rely on the protocol test helpers.
        use tari_cc_private_ballot_ballot::{
            ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition,
            CandidateId, CandidateSet, ElectionId, ElectionManifest, ElectionManifestV2,
            ElectionManifestV2Input,
        };
        use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
        use tari_cc_private_ballot_registry::{
            GovernancePublicKey, RegistryEntry, RegistrySnapshot,
            VoterGovernanceKeyRegistrationV1, VoterKeyProvisioningV1,
        };
        let p = Blake3HashProviderV1;
        let election_id = ElectionId::new(vec![0xAB; 32]).expect("eid");
        let cand_id = CandidateId::new(b"cand-a".to_vec()).expect("cand id");
        let cand_def = CandidateDefinition::new(cand_id, "Candidate A".to_owned()).expect("cand def");
        let cands = CandidateSet::new(vec![cand_def]).expect("cands");
        let candidate_cbor = cands.to_canonical_cbor().expect("cands cbor");
        let candidate_commitment = cands.canonical_commitment(&p).expect("cc");
        let gov_key = GovernancePublicKey::new(vec![0x01; 32]).expect("gov key");
        let reg_entry = RegistryEntry::from_voter_registration(
            VoterGovernanceKeyRegistrationV1::new(gov_key, VoterKeyProvisioningV1::GeneratedByVoter),
        );
        let registry = RegistrySnapshot::new(vec![reg_entry]).expect("registry");
        let registry_cbor = registry.to_canonical_cbor().expect("reg cbor");
        let registry_commitment = registry.canonical_commitment(&p).expect("rc");
        let approval_limits = ApprovalLimits::new(1, 1, false).expect("al");
        let manifest = ElectionManifest::V2(
            ElectionManifestV2::new(ElectionManifestV2Input {
                protocol_version: 1,
                election_id: election_id.clone(),
                ballot_kind: BallotKindV1::NonBindingApprovalPilot,
                ballot_confidentiality: BallotConfidentialityV1::Public,
                registry_commitment,
                candidate_set_commitment: candidate_commitment,
                proof_suite_id: tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
                approval_limits,
                governance_source_revision: "rev".to_owned(),
                proposal_question: "Test question?".to_owned(),
            })
            .expect("manifest"),
        );
        let manifest_cbor = manifest.to_canonical_cbor().expect("manifest cbor");
        let manifest_hash = manifest.canonical_hash(&p).expect("hash");
        let manifest_hash_bytes: [u8; 32] = (*manifest_hash.as_bytes()).try_into().expect("32");
        let election_id_bytes = election_id.as_bytes().to_vec();
        (election_id_bytes, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash_bytes)
    }

    #[test]
    fn bundle_round_trips_through_cbor() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id.clone(),
            manifest_hash,
            manifest_cbor.clone(),
            registry_cbor.clone(),
            candidate_cbor.clone(),
            descriptor_cbor.clone(),
        )
        .expect("bundle");
        let cbor = bundle.to_canonical_cbor().expect("cbor");
        let decoded = HostedVoterPublicBundleV2::from_canonical_cbor(&cbor).expect("decoded");
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn bundle_verify_accepts_valid_bundle() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id.clone(),
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle");
        let verified = bundle.verify().expect("verify");
        assert_eq!(
            verified.descriptor.election_id(),
            election_id.as_slice()
        );
        assert_eq!(
            verified.descriptor.manifest_hash().as_bytes(),
            &manifest_hash
        );
    }

    #[test]
    fn bundle_verify_rejects_wrong_authority_key() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        // Use a DIFFERENT public key than the one that signed the descriptor.
        let wrong_key = SigningKey::from_bytes(&[0xFF; 32]);
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            wrong_key.verifying_key().to_bytes(),
            election_id.clone(),
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle");
        assert!(bundle.verify().is_err(), "wrong authority key must fail");
    }

    #[test]
    fn bundle_verify_rejects_unsigned_draft_descriptor() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let gateway_key = SigningKey::from_bytes(&[0x11; 32]);
        let receipt_key = SigningKey::from_bytes(&[0x22; 32]);
        let draft = TransportDescriptorV1::unsigned_for_authority(
            election_id.clone(),
            ManifestHash::new(manifest_hash),
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion".to_owned()],
            Vec::new(),
            gateway_key.verifying_key().to_bytes(),
            "test-gateway".to_owned(),
            vec![receipt_key.verifying_key().to_bytes()],
            PaddingPolicyV1 { id: "p".to_owned(), padded_bytes: 2048 },
            BatchPolicyV1 { id: "b".to_owned(), accepted_unique_floor: 1 },
            None,
            "test-authority".to_owned(),
        )
        .expect("draft");
        let draft_cbor = draft.to_canonical_cbor().expect("draft cbor");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            draft_cbor,
        )
        .expect("bundle");
        assert!(bundle.verify().is_err(), "unsigned draft must fail verification");
    }

    #[test]
    fn bundle_verify_rejects_v1_election() {
        // A V1 election has proposal_question = None; the bundle must reject it.
        // We cannot easily construct a valid V1 manifest here without duplicating
        // the V1 build path, so we only verify the check is in place via the
        // `GuiElectionArtifactsV1::from_bytes` path returning an artifact with
        // proposal_question = None.
        //
        // Build a V1 manifest and verify the bundle rejects it.
        use tari_cc_private_ballot_ballot::{
            ApprovalLimits, BallotConfidentialityV1, BallotKindV1, CandidateDefinition,
            CandidateId, CandidateSet, ElectionId, ElectionManifest, ElectionManifestV1,
            ElectionManifestV1Input,
        };
        use tari_cc_private_ballot_protocol::Blake3HashProviderV1;
        use tari_cc_private_ballot_registry::{
            GovernancePublicKey, RegistryEntry, RegistrySnapshot,
            VoterGovernanceKeyRegistrationV1, VoterKeyProvisioningV1,
        };
        let p = Blake3HashProviderV1;
        let election_id = ElectionId::new(vec![0xAB; 32]).expect("eid");
        let cand_id = CandidateId::new(b"cand-a".to_vec()).expect("cand id");
        let cand_def = CandidateDefinition::new(cand_id, "Candidate A".to_owned()).expect("cand def");
        let cands = CandidateSet::new(vec![cand_def]).expect("cands");
        let candidate_cbor = cands.to_canonical_cbor().expect("cands cbor");
        let candidate_commitment = cands.canonical_commitment(&p).expect("cc");
        let gov_key = GovernancePublicKey::new(vec![0x01; 32]).expect("gov key");
        let reg_entry = RegistryEntry::from_voter_registration(
            VoterGovernanceKeyRegistrationV1::new(gov_key, VoterKeyProvisioningV1::GeneratedByVoter),
        );
        let registry = RegistrySnapshot::new(vec![reg_entry]).expect("registry");
        let registry_cbor = registry.to_canonical_cbor().expect("reg cbor");
        let registry_commitment = registry.canonical_commitment(&p).expect("rc");
        let approval_limits = ApprovalLimits::new(1, 1, false).expect("al");
        let manifest_v1 = ElectionManifest::V1(
            ElectionManifestV1::new(ElectionManifestV1Input {
                protocol_version: 1,
                election_id: election_id.clone(),
                ballot_kind: BallotKindV1::NonBindingApprovalPilot,
                ballot_confidentiality: BallotConfidentialityV1::Public,
                registry_commitment,
                candidate_set_commitment: candidate_commitment,
                proof_suite_id: tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
                approval_limits,
                governance_source_revision: "rev".to_owned(),
            })
            .expect("manifest"),
        );
        let manifest_cbor = manifest_v1.to_canonical_cbor().expect("manifest cbor");
        let manifest_hash = manifest_v1.canonical_hash(&p).expect("hash");
        let manifest_hash_bytes: [u8; 32] = (*manifest_hash.as_bytes()).try_into().expect("32");
        let election_id_bytes = election_id.as_bytes().to_vec();
        let (authority_key, _) = make_authority();
        let descriptor = make_signed_descriptor(&authority_key, &election_id_bytes, manifest_hash_bytes);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("desc");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id_bytes,
            manifest_hash_bytes,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle constructed");
        assert!(
            bundle.verify().is_err(),
            "a V1 election (no proposal_question) must be rejected"
        );
    }

    #[test]
    fn from_canonical_cbor_rejects_tampered_bytes() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle");
        let mut cbor = bundle.to_canonical_cbor().expect("cbor");
        // Flip a byte in the descriptor cbor area (last 64 bytes = signature area).
        // A byte flip within a CBOR byte string field may pass structural decode
        // (the tampered content round-trips unchanged through re-encoding), but
        // verify() must reject the bundle because the authority signature over
        // the tampered descriptor bytes is invalid.
        let len = cbor.len();
        cbor[len - 10] ^= 0xFF;
        match HostedVoterPublicBundleV2::from_canonical_cbor(&cbor) {
            Err(_) => { /* structural rejection is also valid */ }
            Ok(tampered) => {
                assert!(
                    tampered.verify().is_err(),
                    "tampered bytes that pass CBOR decode must fail verify()"
                );
            }
        }
    }

    #[test]
    fn from_canonical_cbor_rejects_wrong_type_id() {
        // Build a valid bundle, then mutate the CBOR to have the wrong type_id.
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle");
        let cbor = bundle.to_canonical_cbor().expect("cbor");
        // Corrupt the type_id string byte to produce a different type marker.
        let mut bad = cbor.clone();
        // The type_id text starts after: array header (1) + version (2) + text header (varies).
        // Simply find the type_id bytes and flip one character.
        let type_id = HOSTED_VOTER_BUNDLE_V2_TYPE_ID.as_bytes();
        if let Some(pos) = bad.windows(type_id.len()).position(|w| w == type_id) {
            bad[pos] ^= 0x01;
        }
        assert!(
            HostedVoterPublicBundleV2::from_canonical_cbor(&bad).is_err(),
            "wrong type_id must be rejected"
        );
    }

    #[test]
    fn bundle_verify_rejects_election_id_mismatch_in_descriptor() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        // Sign a descriptor for a DIFFERENT election_id.
        let wrong_election_id = vec![0xCC; 32];
        let descriptor = make_signed_descriptor(&authority_key, &wrong_election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle");
        assert!(
            bundle.verify().is_err(),
            "descriptor election_id mismatch must fail"
        );
    }

    #[test]
    fn from_canonical_cbor_rejects_empty_authority_key_id() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("descriptor cbor");
        // We cannot construct a bundle with empty authority_key_id via `new` —
        // it's rejected there. Build the CBOR directly with an empty key_id.
        let mut w = CanonicalCborWriter::new();
        w.write_array_len(10).unwrap();
        w.write_unsigned(HOSTED_VOTER_BUNDLE_V2_VERSION);
        w.write_text_string(HOSTED_VOTER_BUNDLE_V2_TYPE_ID).unwrap();
        w.write_text_string("").unwrap(); // empty authority_key_id
        w.write_byte_string(&authority_key.verifying_key().to_bytes()).unwrap();
        w.write_byte_string(&election_id).unwrap();
        w.write_byte_string(&manifest_hash).unwrap();
        w.write_byte_string(&manifest_cbor).unwrap();
        w.write_byte_string(&registry_cbor).unwrap();
        w.write_byte_string(&candidate_cbor).unwrap();
        w.write_byte_string(&descriptor_cbor).unwrap();
        let cbor = w.into_bytes();
        assert!(
            HostedVoterPublicBundleV2::from_canonical_cbor(&cbor).is_err(),
            "empty authority_key_id must be rejected"
        );
    }

    // --- Negative security matrix: remaining rejection cases ---

    #[test]
    fn bundle_verify_rejects_manifest_hash_mismatch() {
        // Bundle fields say manifest_hash = X, but the manifest actually hashes to Y.
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        // Provide a wrong manifest_hash that doesn't match manifest_cbor.
        let mut wrong_hash = manifest_hash;
        wrong_hash[0] ^= 0xFF;
        let descriptor = make_signed_descriptor(&authority_key, &election_id, wrong_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("desc");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            wrong_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle constructed");
        assert!(
            bundle.verify().is_err(),
            "manifest_hash mismatch must be rejected"
        );
    }

    #[test]
    fn from_canonical_cbor_rejects_truncated_cbor() {
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("desc");
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle");
        let cbor = bundle.to_canonical_cbor().expect("cbor");
        // Truncate the last third of the bundle.
        let truncated = &cbor[..cbor.len() / 3 * 2];
        assert!(
            HostedVoterPublicBundleV2::from_canonical_cbor(truncated).is_err(),
            "truncated CBOR must be rejected"
        );
        // Also reject empty input.
        assert!(
            HostedVoterPublicBundleV2::from_canonical_cbor(&[]).is_err(),
            "empty input must be rejected"
        );
    }

    #[test]
    fn bundle_verify_rejects_tampered_authority_public_key() {
        // Signed with key A; bundle claims public key B → signature fails.
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        let descriptor = make_signed_descriptor(&authority_key, &election_id, manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("desc");
        // Tamper: use a different public key (all 0xAA) to claim authority.
        let tampered_pub = [0xAA_u8; 32];
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            tampered_pub,
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle constructed");
        assert!(
            bundle.verify().is_err(),
            "tampered authority_public_key must fail verification"
        );
    }

    #[test]
    fn bundle_verify_rejects_descriptor_for_wrong_manifest_hash() {
        // Descriptor is signed for manifest_hash B but the bundle's manifest hashes to A.
        let (authority_key, _root) = make_authority();
        let (election_id, manifest_cbor, registry_cbor, candidate_cbor, manifest_hash) =
            make_v2_artifacts();
        // Sign the descriptor for a DIFFERENT manifest_hash.
        let different_manifest_hash = [0xBB_u8; 32];
        let descriptor =
            make_signed_descriptor(&authority_key, &election_id, different_manifest_hash);
        let descriptor_cbor = descriptor.to_canonical_cbor().expect("desc");
        // Bundle advertises the correct hash but contains the wrong descriptor.
        let bundle = HostedVoterPublicBundleV2::new(
            "test-authority".to_owned(),
            authority_key.verifying_key().to_bytes(),
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            descriptor_cbor,
        )
        .expect("bundle constructed");
        assert!(
            bundle.verify().is_err(),
            "descriptor for wrong manifest hash must be rejected"
        );
    }
}
