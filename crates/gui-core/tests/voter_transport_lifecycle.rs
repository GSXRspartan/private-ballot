//! Ballot-office connection ("voter transport bundle") × distributed
//! lifecycle tests.
//!
//! Behavioral counterpart of the frontend repair that separated BALLOT-OFFICE
//! CONNECTION / LIFECYCLE CONFIGURATION from BALLOT SUBMISSION. The physical
//! two-computer test exposed a dead end where a FROZEN voter could not reach
//! the transport-bundle configuration that both lifecycle-update routes
//! (private status check and signed status import) authenticate against.
//!
//! These tests model the repaired flow entirely in gui-core, with no Tor and
//! no shell state:
//!
//! 1. "Configuring the bundle" = building a pinned root set from the bundle's
//!    office key and accepting its signed descriptor for THIS election
//!    (`verify_and_accept_descriptor` — the exact primitive the shell's
//!    `configure_managed_tor` uses).
//! 2. Configuration must NOT advance lifecycle knowledge or session state,
//!    must reject a bundle bound to another election/manifest, must reject a
//!    competing signer reusing the pinned key id, and must detect
//!    same-generation descriptor conflicts.
//! 3. A signed OPEN status must be REFUSED while no trusted office authority
//!    is pinned (the gui-core half of GUI_ELECTION_STATUS_NO_TRUSTED_AUTHORITY),
//!    then APPLY once the bundle authority is pinned — advancing FROZEN →
//!    OPEN monotonically, with rollback still refused afterwards.
//! 4. Selection/preparation remain backend-refused while FROZEN even after a
//!    connection is configured; configuring grants no workflow ability.

mod common;

use ed25519_dalek::SigningKey;
use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    AppliedElectionStatusV1, AuthenticatedElectionStatusStatementV1, BatchPolicyV1,
    DescriptorConsistencyStoreV1, ElectionStatusErrorV1, ElectionStatusKnowledgeV1,
    GuiElectionArtifactsV1, GuiElectionSessionV1, GuiVoterSessionV1, PaddingPolicyV1,
    TransportAuthorityRootSetV1, TransportAuthorityRootV1, TransportDescriptorV1, TransportError,
    TransportRoutePolicyV1, verify_and_apply_election_status_statement_v1,
    voter_selectable_options,
};
use tari_cc_private_ballot_protocol::ManifestHash;

use common::{approval_limits, artifacts, candidate_bytes, manifest_with, registry_bytes};

const ROOT_KEY_ID: &str = "ballot-office-root-1";
const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
const GATEWAY_KEY_ID: &str = "intake-gateway-2026";

/// The ballot office's transport signing identity (what the exported voter
/// bundle pins): one Ed25519 root key plus opaque gateway/receipt key bytes.
struct OfficeFixture {
    signing_key: SigningKey,
}

impl OfficeFixture {
    fn new(byte: u8) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[byte; 32]),
        }
    }

    fn roots(&self) -> TransportAuthorityRootSetV1 {
        TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
            key_id: ROOT_KEY_ID.to_owned(),
            public_key: self.signing_key.verifying_key().to_bytes(),
        })
    }

    /// Signs a descriptor exactly as organizer provisioning does.
    fn descriptor_for(
        &self,
        election_id: &[u8],
        manifest_hash: ManifestHash,
        gateway_public_key: [u8; 32],
    ) -> TransportDescriptorV1 {
        TransportDescriptorV1::sign_for_test_or_ceremony(
            election_id.to_vec(),
            manifest_hash,
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec![TEST_ONION.to_owned()],
            Vec::new(),
            gateway_public_key,
            GATEWAY_KEY_ID.to_owned(),
            vec![[0x88; 32]],
            PaddingPolicyV1 {
                id: "fixed-connection".to_owned(),
                padded_bytes: 64 * 1024,
            },
            BatchPolicyV1 {
                id: "accepted-1".to_owned(),
                accepted_unique_floor: 1,
            },
            None,
            ROOT_KEY_ID.to_owned(),
            &self.signing_key,
        )
        .expect("fixture descriptor must sign")
    }

    /// Signs an election-status statement as the organizer export command does.
    fn signed_status(
        &self,
        election_artifacts: &GuiElectionArtifactsV1,
        state: ElectionLifecycleStateV1,
        generation: u64,
    ) -> Vec<u8> {
        AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
            election_artifacts
                .manifest()
                .election_id()
                .as_bytes()
                .to_vec(),
            election_artifacts.manifest_hash(),
            election_artifacts.registry_commitment(),
            state,
            generation,
            ROOT_KEY_ID.to_owned(),
            &self.signing_key,
        )
        .expect("fixture statement must sign")
        .to_canonical_cbor()
        .expect("fixture statement must encode")
    }
}

fn other_election_artifacts() -> GuiElectionArtifactsV1 {
    let manifest = manifest_with(
        b"a-completely-different-election",
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        approval_limits(),
    );
    let bytes = manifest.to_canonical_cbor().expect("encode");
    GuiElectionArtifactsV1::from_bytes(&bytes, &registry_bytes(), &candidate_bytes())
        .expect("other election artifacts")
}

fn apply(
    voter_session: &mut GuiElectionSessionV1,
    knowledge: &mut ElectionStatusKnowledgeV1,
    roots: &TransportAuthorityRootSetV1,
    bytes: &[u8],
) -> Result<AppliedElectionStatusV1, ElectionStatusErrorV1> {
    verify_and_apply_election_status_statement_v1(bytes, roots, knowledge, voter_session)
}

#[test]
fn configuring_the_bundle_authority_does_not_advance_a_frozen_election() {
    let office = OfficeFixture::new(0x42);
    let voter_session = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let knowledge = ElectionStatusKnowledgeV1::new();
    let mut consistency = DescriptorConsistencyStoreV1::default();
    let identity = artifacts();

    // "Configure the ballot-office connection": pin the bundle root and accept
    // its descriptor against THIS frozen election.
    let roots = office.roots();
    let fingerprint = roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect("correct-election bundle must configure");

    // Configuration is lifecycle-inert: nothing advanced, nothing recorded.
    assert_eq!(
        voter_session.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen
    );
    assert_eq!(knowledge.accepted_generation(), None);

    // Re-configuring with the identical bundle is idempotent.
    let again = roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect("identical reconfigure is idempotent");
    assert_eq!(fingerprint, again);
    assert_eq!(
        voter_session.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen,
        "configuration must never open voting"
    );
}

#[test]
fn wrong_election_and_competing_root_bundles_are_refused() {
    let office = OfficeFixture::new(0x42);
    let identity = artifacts();
    let roots = office.roots();
    let mut consistency = DescriptorConsistencyStoreV1::default();

    // 1. A bundle bound to ANOTHER election can never configure this one
    //    (hostile/wrong-election bundle).
    let other = other_election_artifacts();
    assert_ne!(other.manifest_hash(), identity.manifest_hash());
    let error = roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                other.manifest().election_id().as_bytes(),
                other.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect_err("wrong-election bundle must be refused");
    assert!(matches!(error, TransportError::WrongElection));

    // 2. A COMPETING signer reusing the pinned key id is refused: descriptors
    //    select an already-pinned root, never install or replace one.
    let impostor = OfficeFixture::new(0x43);
    let error = roots
        .verify_and_accept_descriptor(
            &impostor.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect_err("competing-root bundle must fail closed");
    assert!(matches!(
        error,
        TransportError::UntrustedRoot | TransportError::CryptoFailure
    ));

    // The legitimate bundle still configures after those refusals.
    roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect("legitimate bundle still configures after refusals");
}

#[test]
fn same_generation_descriptor_conflict_is_refused() {
    let office = OfficeFixture::new(0x42);
    let identity = artifacts();
    let roots = office.roots();
    let mut consistency = DescriptorConsistencyStoreV1::default();
    roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect("first acceptance");

    // Same election + same generation but different content (different gateway
    // key and endpoint) must conflict instead of silently replacing the route.
    let conflicting = office.descriptor_for(
        identity.manifest().election_id().as_bytes(),
        identity.manifest_hash(),
        [0x99; 32],
    );
    let error = roots
        .verify_and_accept_descriptor(&conflicting, identity.manifest_hash(), &mut consistency)
        .expect_err("same-generation conflicting descriptor must be refused");
    assert!(matches!(error, TransportError::DescriptorConflict));
}

#[test]
fn open_status_requires_the_pinned_office_then_applies_monotonically() {
    let office = OfficeFixture::new(0x42);
    let identity = artifacts();
    let mut voter_session = GuiElectionSessionV1::new(identity.clone()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();
    let mut consistency = DescriptorConsistencyStoreV1::default();

    // BEFORE configuration: no trusted authority exists for this office on
    // this computer. A correctly signed OPEN under the REAL office key is
    // still refused because nothing is pinned (gui-core half of
    // GUI_ELECTION_STATUS_NO_TRUSTED_AUTHORITY): some unrelated root set must
    // never authenticate this office's statements.
    let open_bytes = office.signed_status(&identity, ElectionLifecycleStateV1::Open, 2);
    let unrelated_roots = OfficeFixture::new(0x7B).roots();
    let error = apply(
        &mut voter_session,
        &mut knowledge,
        &unrelated_roots,
        &open_bytes,
    )
    .expect_err("status without the pinned office authority must be refused");
    assert!(matches!(
        error,
        ElectionStatusErrorV1::InvalidSignature | ElectionStatusErrorV1::UntrustedRoot
    ));
    assert_eq!(
        voter_session.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen
    );
    assert_eq!(knowledge.accepted_generation(), None);

    // Configure the ballot-office connection (pin + accept descriptor).
    let roots = office.roots();
    roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect("bundle configures while FROZEN");
    assert_eq!(
        voter_session.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen,
        "configuring must not open the election"
    );

    // NOW the same signed OPEN authenticates and advances FROZEN -> OPEN.
    let applied = apply(&mut voter_session, &mut knowledge, &roots, &open_bytes)
        .expect("authenticated OPEN applies once the office is pinned");
    assert!(applied.advanced);
    assert_eq!(
        voter_session.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Open
    );

    // Rollback protection is unchanged by the connection: CLOSED applies
    // forward, then an OLD OPEN is rejected regardless of its generation.
    let closed_bytes = office.signed_status(&identity, ElectionLifecycleStateV1::Closed, 3);
    apply(&mut voter_session, &mut knowledge, &roots, &closed_bytes)
        .expect("CLOSED applies forward");
    let stale_open = office.signed_status(&identity, ElectionLifecycleStateV1::Open, 4);
    let error = apply(&mut voter_session, &mut knowledge, &roots, &stale_open)
        .expect_err("OPEN after CLOSED must stay refused");
    assert_eq!(error, ElectionStatusErrorV1::LifecycleRollbackRejected);
}

#[test]
fn frozen_selection_and_preparation_stay_refused_after_connection_setup() {
    let office = OfficeFixture::new(0x42);
    let identity = artifacts();
    let mut voter = GuiVoterSessionV1::new(&identity);
    let mut consistency = DescriptorConsistencyStoreV1::default();
    let roots = office.roots();

    // Configure the connection FIRST (the repaired flow allows this while
    // FROZEN), then prove it granted no workflow ability.
    roots
        .verify_and_accept_descriptor(
            &office.descriptor_for(
                identity.manifest().election_id().as_bytes(),
                identity.manifest_hash(),
                [0x77; 32],
            ),
            identity.manifest_hash(),
            &mut consistency,
        )
        .expect("bundle configures on a frozen imported election");

    let selection_hex: Vec<String> = voter_selectable_options(&identity)
        .into_iter()
        .take(1)
        .map(|option| option.machine_id_hex)
        .collect();

    // Response selection stays backend-refused while FROZEN.
    let error = voter
        .set_selection(
            &identity,
            ElectionLifecycleStateV1::Frozen,
            selection_hex.clone(),
            false,
        )
        .expect_err("FROZEN selection must be refused");
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");

    // Ballot preparation stays backend-refused while FROZEN.
    let error = voter
        .begin_preparation_operation(ElectionLifecycleStateV1::Frozen)
        .expect_err("FROZEN preparation must be refused");
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");

    // And clearing selection is equally refused while FROZEN.
    let error = voter
        .clear_selection(&identity, ElectionLifecycleStateV1::Frozen)
        .expect_err("FROZEN clear-selection must be refused");
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");
}
