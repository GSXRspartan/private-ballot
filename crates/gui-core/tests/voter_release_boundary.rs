#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Shared irreversible release-boundary tests for private online transport.
//!
//! These prove that a private-transport (managed-Tor) release crosses the SAME
//! durable, irreversible cast boundary as offline export, using instrumented
//! fake carriers (no real Tor, no network, no Ootle):
//!
//!   A. the durable PENDING release record exists at the instant the carrier is
//!      first invoked (before any ballot bytes can leave the process);
//!   B. a pre-PENDING failure (untrusted / wrong-election descriptor) never
//!      invokes the carrier, writes no PENDING record, and leaves the voter free;
//!   C. a network failure AFTER PENDING keeps the voter CAST_PENDING with the
//!      exact staged envelope retained and no choice change;
//!   D. a retry retransmits the EXACT staged envelope bytes and, on an
//!      authenticated receipt, transitions to CAST;
//!   E. restart reconstructs a locked session and retries the same envelope;
//!   F. a persisted authenticated receipt recovers to CAST after a crash before
//!      promotion;
//!   G. a missing/corrupt staged envelope fails closed (stays CAST_PENDING).
//!
//! The organizer's election-scoped nullifier remains the sole cryptographic
//! one-vote rule; this boundary is local honest-UX defense-in-depth only.

mod common;

use ed25519_dalek::SigningKey;
use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
use tari_cc_private_ballot_ballot::{
    BallotConfidentialityV1, BallotKindV1, ElectionId, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    AuthenticatedTransportReceiptV1, BatchPolicyV1, DescriptorConsistencyStoreV1,
    ElectionLifecycleStateV1, GuiCoreError, GuiElectionArtifactsV1, GuiVoterCastLockStateV1,
    GuiVoterElectionBindingV1, GuiVoterSessionV1, PaddingPolicyV1, PrivateReleaseCarrierV1,
    RetryStatusV1, TransportAuthorityRootSetV1, TransportAuthorityRootV1, TransportDescriptorV1,
    TransportRoutePolicyV1, VoterCredentialContainerV1, VoterGovernanceCredentialV1,
    VoterReceiptStateV1, VoterTransportReceiptV1, cast_record_exists_v1,
    load_pending_release_retry_handle_v1, persist_release_receipt_evidence_v1,
    public_credential_fingerprint_hex_v1, release_receipt_evidence_path_v1,
    resolve_and_recover_cast_lock_state_v1,
    resolve_and_recover_private_transport_cast_lock_state_v1, stage_release_envelope_v1,
    staged_release_envelope_digest_hex_v1, staged_release_envelope_path_v1,
    write_cast_record_pending_private_transport_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;

type Kem = X25519HkdfSha256;

// A valid-shape Tor v3 onion hostname; the descriptor does not validate its
// format (that is the carrier's job), but it must be non-empty.
const TEST_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

// -------------------------------------------------------------------------
// A. PENDING before the carrier is invoked.
// -------------------------------------------------------------------------

#[test]
fn durable_pending_release_record_exists_before_carrier_is_invoked() {
    let env = ReleaseEnv::new("release-pending-before-carrier");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // The carrier asserts, at the instant of send, that a durable PENDING
    // online release record already exists for this pair.
    let mut carrier = RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest))
        .assert_pending_before_send(
            env.cast_dir.clone(),
            fixture.manifest_hex.clone(),
            fixture.fingerprint.clone(),
        );

    let result = ok(fixture.release(&env, &descriptor, &mut carrier));
    assert!(result.released, "an authenticated receipt promotes to CAST");
    assert_eq!(result.cast_lock_state, "CAST");
    assert_eq!(result.receipt_state, "ACCEPTED");
    assert_eq!(
        result.diagnostic_stage, None,
        "a successful CAST reports no failure diagnostic stage",
    );
    assert_eq!(carrier.envelopes.len(), 1, "carrier invoked exactly once");
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::Cast
    );
}

// -------------------------------------------------------------------------
// B. Pre-PENDING failure: carrier never invoked, no PENDING, still free.
// -------------------------------------------------------------------------

#[test]
fn untrusted_descriptor_fails_before_pending_and_leaves_voter_free() {
    let env = ReleaseEnv::new("release-untrusted-descriptor");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    // A descriptor whose signature does not match the pinned root.
    let untrusted = env.descriptor_signed_by(&fixture, &SigningKey::from_bytes(&[0x5b; 32]));

    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.release(&env, &untrusted, &mut carrier));
    // A descriptor-authenticity failure is now a distinct, HONEST terminal error
    // in the descriptor-auth phase — never the transient "transport unavailable"
    // (retry-later) code, which is reserved for post-staging delivery outages.
    assert_eq!(error.code(), "GUI_RELEASE_DESCRIPTOR_UNTRUSTED");
    assert_eq!(error.context(), Some("release-descriptor-auth"));
    assert_ne!(
        error.code(),
        "GUI_PRIVATE_TRANSPORT_UNAVAILABLE",
        "a pre-staging auth failure must not masquerade as a transient transport outage",
    );
    assert!(
        carrier.envelopes.is_empty(),
        "carrier must never be invoked"
    );
    assert!(
        !ok(cast_record_exists_v1(
            &env.cast_dir,
            &fixture.manifest_hex,
            &fixture.fingerprint
        )),
        "no PENDING record may be written on a pre-PENDING failure",
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::NotCast,
    );
    // The voter may still change choice and prepare a new ballot.
    let digest_b = fixture.reprepare(&env, b"candidate-b");
    assert!(
        !digest_b.is_empty(),
        "voter can still prepare after failure"
    );
}

#[test]
fn wrong_election_descriptor_fails_before_pending() {
    let env = ReleaseEnv::new("release-wrong-election");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    // A descriptor validly signed by the pinned root but for a DIFFERENT
    // election manifest.
    let other = env.other_election_descriptor(&fixture);

    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.release(&env, &other, &mut carrier));
    // A wrong-election descriptor fails in the descriptor-auth phase (via the
    // signed manifest binding) or the explicit election-id guard; either way it
    // is a distinct terminal binding error, never the transient transport code.
    assert!(
        error.code() == "GUI_RELEASE_DESCRIPTOR_WRONG_ELECTION"
            || error.code() == "GUI_RELEASE_WRONG_ELECTION",
        "unexpected code: {}",
        error.code()
    );
    assert_ne!(error.code(), "GUI_PRIVATE_TRANSPORT_UNAVAILABLE");
    assert!(carrier.envelopes.is_empty());
    assert!(!ok(cast_record_exists_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint
    )));
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::NotCast
    );
}

// -------------------------------------------------------------------------
// C. Network failure AFTER PENDING keeps the voter locked, envelope retained.
// -------------------------------------------------------------------------

#[test]
fn network_failure_after_pending_stays_locked_and_retains_envelope() {
    let env = ReleaseEnv::new("release-network-failure");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let mut carrier = RecordingCarrier::failing();
    let result = ok(fixture.release(&env, &descriptor, &mut carrier));
    assert!(
        !result.released,
        "an uncertain send must not report released"
    );
    assert_eq!(result.cast_lock_state, "CAST_PENDING");
    assert_eq!(result.receipt_state, "PENDING");
    assert_eq!(
        result.diagnostic_stage,
        Some("PRIVATE_TRANSPORT_UNAVAILABLE"),
        "a carrier failure records the safe transport-unavailable stage",
    );
    assert_eq!(carrier.envelopes.len(), 1, "the carrier was invoked once");
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
    );

    // The exact staged envelope is retained on disk.
    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    assert!(staged.exists(), "the staged envelope must be retained");

    // No choice change, no re-preparation, no discard after PENDING.
    assert_code(
        fixture.session.set_selection(
            &env.artifacts,
            ElectionLifecycleStateV1::Open,
            vec![lower_hex(common::candidate_id(b"candidate-b").as_bytes())],
            false,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        fixture
            .session
            .prepare_ballot(&env.artifacts, ElectionLifecycleStateV1::Open),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        fixture
            .session
            .discard_prepared_ballot(&env.artifacts, ElectionLifecycleStateV1::Open),
        "GUI_BALLOT_ALREADY_CAST",
    );
}

// -------------------------------------------------------------------------
// C2. Release-phase taxonomy (Failure 7 instrumentation): a PRE-staging
// descriptor-authenticity failure and a POST-staging delivery outage are
// DISTINGUISHABLE — different phase label, different durable state, different
// recoverability — so a runtime failure is attributable to a phase instead of
// being masked as one ambiguous "transport unavailable". This is the exact
// distinction the real Crash-Test-3/4 evidence required: only a durable
// CAST_PENDING is a recoverable retryable state; a pre-staging local failure
// fails closed as NOT_CAST and is terminal.
// -------------------------------------------------------------------------

#[test]
fn pre_staging_auth_failure_and_delivery_outage_are_distinguishable() {
    // (1) PRE-staging: an unverifiable descriptor fails closed in the
    //     descriptor-auth phase — terminal, NOT_CAST, nothing staged, and NOT
    //     the transient transport-unavailable code (so it is never auto-retried
    //     as if it were a temporary ballot-office outage).
    let env = ReleaseEnv::new("release-phase-taxonomy-auth");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let untrusted = env.descriptor_signed_by(&fixture, &SigningKey::from_bytes(&[0x71; 32]));
    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.release(&env, &untrusted, &mut carrier));
    assert_eq!(error.context(), Some("release-descriptor-auth"));
    assert!(error.code().starts_with("GUI_RELEASE_DESCRIPTOR_"));
    assert_ne!(error.code(), "GUI_PRIVATE_TRANSPORT_UNAVAILABLE");
    assert!(
        carrier.envelopes.is_empty(),
        "no bytes may leave pre-staging"
    );
    assert!(!ok(cast_record_exists_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint
    )));
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::NotCast
    );

    // (2) POST-staging: a valid, authenticated descriptor with a dead carrier
    //     (the ballot office is unreachable) stages the exact envelope, persists
    //     CAST_PENDING, and RETURNS a recoverable pending result — never a thrown
    //     terminal error. This is the state Crash Test 4 must reach.
    let env2 = ReleaseEnv::new("release-phase-taxonomy-delivery");
    let mut fixture2 = env2.prepared_fixture(b"candidate-a");
    let descriptor = env2.descriptor(&fixture2);
    let mut dead = RecordingCarrier::failing();
    let result = ok(fixture2.release(&env2, &descriptor, &mut dead));
    assert_eq!(result.cast_lock_state, "CAST_PENDING");
    assert_eq!(
        result.diagnostic_stage,
        Some("PRIVATE_TRANSPORT_UNAVAILABLE")
    );
    assert_eq!(
        dead.envelopes.len(),
        1,
        "the carrier was invoked (post-staging)"
    );
    assert!(ok(cast_record_exists_v1(
        &env2.cast_dir,
        &fixture2.manifest_hex,
        &fixture2.fingerprint
    )));
    assert!(
        staged_release_envelope_path_v1(
            &env2.staging_dir,
            &fixture2.manifest_hex,
            &fixture2.fingerprint
        )
        .exists(),
        "the exact envelope is durably staged before delivery is attempted",
    );
    assert_eq!(
        fixture2.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending
    );
}

// -------------------------------------------------------------------------
// D. Same-envelope retry transitions to CAST on an authenticated receipt.
// -------------------------------------------------------------------------

#[test]
fn retry_retransmits_exact_envelope_and_casts_on_authenticated_receipt() {
    let env = ReleaseEnv::new("release-retry-same-envelope");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // First attempt fails after PENDING; capture the exact bytes sent.
    let mut failing = RecordingCarrier::failing();
    ok(fixture.release(&env, &descriptor, &mut failing));
    let first_envelope = failing.envelopes[0].clone();

    // Retry with an accepting carrier that returns an authenticated receipt.
    let mut accepting =
        RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let result = ok(fixture.retry(&env, &descriptor, &mut accepting));
    assert!(result.released);
    assert_eq!(result.cast_lock_state, "CAST");
    assert_eq!(
        accepting.envelopes[0], first_envelope,
        "retry must retransmit the EXACT staged envelope bytes",
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::Cast
    );
}

// D2. The idempotent-retry receipt the organizer now returns for a delivery it
// already accepted (state Accepted, retry status PreviousDeliveryAccepted) must
// promote the voter to CAST — closing the loop with the transport-gateway
// idempotency fix so a receipt lost to a delayed/reset Tor close is recoverable.
#[test]
fn retry_with_previous_delivery_accepted_receipt_promotes_to_cast() {
    let env = ReleaseEnv::new("release-retry-previous-accepted");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // First attempt fails after PENDING (e.g. the receipt was lost on the wire).
    let mut failing = RecordingCarrier::failing();
    ok(fixture.release(&env, &descriptor, &mut failing));
    let first_envelope = failing.envelopes[0].clone();
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
    );

    // The organizer had actually accepted the first delivery; the exact retry now
    // returns an authenticated PreviousDeliveryAccepted receipt.
    let mut accepting = RecordingCarrier::accepting(
        env.previous_delivery_accepted_receipt_bytes(&descriptor, digest),
    );
    let result = ok(fixture.retry(&env, &descriptor, &mut accepting));
    assert!(
        result.released,
        "a previously-accepted delivery promotes to CAST"
    );
    assert_eq!(result.cast_lock_state, "CAST");
    assert_eq!(
        accepting.envelopes[0], first_envelope,
        "retry retransmits the EXACT staged envelope bytes",
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::Cast,
    );
}

// -------------------------------------------------------------------------
// E. Restart reconstructs a locked session, then retries the same envelope.
// -------------------------------------------------------------------------

#[test]
fn restart_stays_locked_then_retries_same_envelope_to_cast() {
    let env = ReleaseEnv::new("release-restart-retry");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    let mut failing = RecordingCarrier::failing();
    ok(fixture.release(&env, &descriptor, &mut failing));
    let sent_envelope = failing.envelopes[0].clone();

    // "Restart": a brand-new session with the same credential re-unlocked.
    let mut restarted = env.eligible_session();
    let recovered = ok(resolve_and_recover_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &env.artifacts,
    ));
    assert_eq!(
        recovered,
        GuiVoterCastLockStateV1::CastPending,
        "an online PENDING release stays locked across restart",
    );
    restarted.apply_cast_lock_state(recovered);

    let mut consistency = DescriptorConsistencyStoreV1::default();
    let mut accepting =
        RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let result = ok(restarted.retry_pending_private_transport_release(
        &env.artifacts,
        &descriptor,
        &env.roots,
        &mut consistency,
        &env.cast_dir,
        &mut accepting,
    ));
    assert!(result.released);
    assert_eq!(
        accepting.envelopes[0], sent_envelope,
        "the restarted retry retransmits the same staged envelope",
    );
    assert_eq!(restarted.cast_lock_state(), GuiVoterCastLockStateV1::Cast);
}

// -------------------------------------------------------------------------
// F. A persisted authenticated receipt recovers to CAST after a crash.
// -------------------------------------------------------------------------

#[test]
fn persisted_authenticated_receipt_recovers_to_cast() {
    let env = ReleaseEnv::new("release-receipt-crash-recovery");
    let fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // Simulate the state just before promotion: staged envelope + PENDING record
    // + a durably persisted authenticated receipt, then "crash".
    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let receipt_path = release_receipt_evidence_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    ok(stage_release_envelope_v1(&staged, b"opaque-envelope-bytes"));
    ok(write_cast_record_pending_private_transport_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &fixture.package_digest_hex,
        &staged,
        &staged_release_envelope_digest_hex_v1(b"opaque-envelope-bytes"),
        &env.descriptor_fingerprint_hex(&descriptor),
        &receipt_path,
    ));
    ok(persist_release_receipt_evidence_v1(
        &receipt_path,
        &env.accepted_receipt_bytes(&descriptor, digest),
    ));

    // The descriptor-authenticated resolver promotes to CAST on restart.
    let recovered = ok(resolve_and_recover_private_transport_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &descriptor,
    ));
    assert_eq!(recovered, GuiVoterCastLockStateV1::Cast);

    // A generic resolver (no descriptor) still keeps it locked, never unlocks —
    // and after promotion the terminal CAST state is durable either way.
    let generic = ok(resolve_and_recover_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &env.artifacts,
    ));
    assert_eq!(generic, GuiVoterCastLockStateV1::Cast);
}

#[test]
fn tampered_receipt_never_recovers_to_cast() {
    let env = ReleaseEnv::new("release-tampered-receipt");
    let fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let receipt_path = release_receipt_evidence_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    ok(stage_release_envelope_v1(&staged, b"opaque-envelope-bytes"));
    ok(write_cast_record_pending_private_transport_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &fixture.package_digest_hex,
        &staged,
        &staged_release_envelope_digest_hex_v1(b"opaque-envelope-bytes"),
        &env.descriptor_fingerprint_hex(&descriptor),
        &receipt_path,
    ));
    // A receipt bound to the correct descriptor + package but signed by a key
    // NOT authorized by the descriptor.
    let forged = AuthenticatedTransportReceiptV1::sign_for_test_or_ceremony(
        VoterTransportReceiptV1 {
            state: VoterReceiptStateV1::Accepted,
            retry_status: RetryStatusV1::NewDelivery,
        },
        ok_t(descriptor.fingerprint()),
        hex32(&fixture.package_digest_hex),
        None,
        "forged".to_owned(),
        &SigningKey::from_bytes(&[0x99; 32]),
    );
    ok(persist_release_receipt_evidence_v1(
        &receipt_path,
        &ok_t(forged.to_canonical_cbor()),
    ));

    let recovered = ok(resolve_and_recover_private_transport_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &descriptor,
    ));
    assert_eq!(
        recovered,
        GuiVoterCastLockStateV1::CastPending,
        "an unauthenticated receipt must never promote to CAST",
    );
}

// -------------------------------------------------------------------------
// G. Missing staged envelope fails closed on retry (stays locked).
// -------------------------------------------------------------------------

#[test]
fn missing_staged_envelope_fails_closed_on_retry() {
    let env = ReleaseEnv::new("release-missing-staged");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    // Write a PENDING record whose staged envelope does not exist.
    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let receipt_path = release_receipt_evidence_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    ok(write_cast_record_pending_private_transport_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &fixture.package_digest_hex,
        &staged,
        &staged_release_envelope_digest_hex_v1(b"never-staged"),
        &env.descriptor_fingerprint_hex(&descriptor),
        &receipt_path,
    ));
    fixture
        .session
        .apply_cast_lock_state(GuiVoterCastLockStateV1::CastPending);

    let mut consistency = DescriptorConsistencyStoreV1::default();
    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.session.retry_pending_private_transport_release(
        &env.artifacts,
        &descriptor,
        &env.roots,
        &mut consistency,
        &env.cast_dir,
        &mut carrier,
    ));
    assert_eq!(error.code(), "GUI_RELEASE_ENVELOPE_UNAVAILABLE");
    assert!(
        carrier.envelopes.is_empty(),
        "no send without a staged envelope"
    );
    // Still locked; the record remains a non-terminal PENDING online release.
    assert!(
        load_pending_release_retry_handle_v1(
            &env.cast_dir,
            &fixture.manifest_hex,
            &fixture.fingerprint
        )
        .is_some(),
        "the pending release record must remain (fail closed)",
    );
}

// -------------------------------------------------------------------------
// Receipt-binding matrix (Blocker A).
// -------------------------------------------------------------------------

// A receipt validly minted for Descriptor A — under a receipt key that is ALSO
// authorized by Descriptor B, and for the SAME package digest B's pending
// release expects — must NOT promote B. This is the exact reviewer scenario.
#[test]
fn reused_receipt_key_wrong_descriptor_does_not_promote() {
    let env = ReleaseEnv::new("release-reused-key-wrong-descriptor");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor_b = env.descriptor(&fixture);
    let descriptor_a = env.second_descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // Sanity: the two descriptors genuinely differ, yet share the receipt key.
    assert_ne!(
        ok_t(descriptor_a.fingerprint()),
        ok_t(descriptor_b.fingerprint()),
        "descriptors A and B must have distinct fingerprints",
    );

    // A receipt bound to A, signed by the shared receipt key, for B's package.
    let receipt_for_a =
        env.signed_receipt_bytes(ok_t(descriptor_a.fingerprint()), digest, &env.receipt_key);
    // It genuinely verifies for A — proving the rejection below is the
    // descriptor-fingerprint binding doing real work, not a broken signature.
    assert!(
        ok_t(AuthenticatedTransportReceiptV1::from_canonical_cbor(
            &receipt_for_a
        ))
        .verify_for_descriptor(&descriptor_a)
        .is_ok(),
        "the receipt must be genuinely valid for descriptor A",
    );

    // Release through descriptor B; the collector returns the A-bound receipt.
    let mut carrier = RecordingCarrier::accepting(receipt_for_a);
    let result = ok(fixture.release(&env, &descriptor_b, &mut carrier));
    assert!(!result.released, "an A-bound receipt must not promote B");
    assert_eq!(result.cast_lock_state, "CAST_PENDING");
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
    );
}

// A retry whose supplied descriptor differs from the one the pending release was
// bound to is rejected BEFORE the carrier is ever invoked — zero network
// activity, still locked. This is the route-binding defense at the boundary: the
// carrier can never be handed a descriptor that disagrees with the pending one.
#[test]
fn retry_with_wrong_descriptor_never_reaches_the_carrier() {
    let env = ReleaseEnv::new("release-retry-wrong-descriptor");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor_a = env.descriptor(&fixture);

    // Fail after PENDING so a staged envelope + pending record (bound to A) exist.
    let mut failing = RecordingCarrier::failing();
    ok(fixture.release(&env, &descriptor_a, &mut failing));

    // A genuinely different descriptor B for the same election.
    let descriptor_b = env.second_descriptor(&fixture);
    assert_ne!(
        ok_t(descriptor_a.fingerprint()),
        ok_t(descriptor_b.fingerprint()),
        "descriptors A and B must differ",
    );

    // Retry with B: rejected before any carrier send.
    let mut carrier = RecordingCarrier::accepting(
        env.accepted_receipt_bytes(&descriptor_b, hex32(&fixture.package_digest_hex)),
    );
    let error = err(fixture.retry(&env, &descriptor_b, &mut carrier));
    assert_eq!(error.code(), "GUI_RELEASE_DESCRIPTOR_CHANGED");
    assert!(
        carrier.envelopes.is_empty(),
        "a changed descriptor must never reach the carrier (zero network)",
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
    );
}

// A receipt bound to the correct descriptor but acknowledging a DIFFERENT
// package digest must not promote.
#[test]
fn wrong_package_receipt_does_not_promote() {
    let env = ReleaseEnv::new("release-wrong-package-receipt");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let wrong_package =
        env.signed_receipt_bytes(ok_t(descriptor.fingerprint()), [0xAB; 32], &env.receipt_key);
    let mut carrier = RecordingCarrier::accepting(wrong_package);
    let result = ok(fixture.release(&env, &descriptor, &mut carrier));
    assert!(!result.released, "a wrong-package receipt must not promote");
    assert_eq!(result.cast_lock_state, "CAST_PENDING");
    assert_eq!(
        result.diagnostic_stage,
        Some("RECEIPT_PACKAGE_MISMATCH"),
        "a receipt acknowledging a different package records the package-mismatch stage",
    );
}

// A receipt bound to the correct descriptor + package but signed by a key the
// descriptor does not authorize must not promote.
#[test]
fn wrong_key_receipt_does_not_promote() {
    let env = ReleaseEnv::new("release-wrong-key-receipt");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    let wrong_key = env.signed_receipt_bytes(
        ok_t(descriptor.fingerprint()),
        digest,
        &SigningKey::from_bytes(&[0x77; 32]),
    );
    let mut carrier = RecordingCarrier::accepting(wrong_key);
    let result = ok(fixture.release(&env, &descriptor, &mut carrier));
    assert!(!result.released, "a wrong-key receipt must not promote");
    assert_eq!(result.cast_lock_state, "CAST_PENDING");
    assert_eq!(
        result.diagnostic_stage,
        Some("RECEIPT_SIGNATURE_INVALID"),
        "a receipt signed by an unauthorized key records the signature-invalid stage",
    );
}

// -------------------------------------------------------------------------
// Staged-envelope integrity on retry (Blocker B).
// -------------------------------------------------------------------------

#[test]
fn tampered_staged_envelope_is_never_transmitted_on_retry() {
    let env = ReleaseEnv::new("release-staged-tamper");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // Fail after PENDING so a staged envelope exists.
    let mut failing = RecordingCarrier::failing();
    ok(fixture.release(&env, &descriptor, &mut failing));
    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let original = ok(std::fs::read(&staged));

    // Tamper one byte, preserving the file size.
    let mut tampered = original.clone();
    tampered[0] ^= 0x01;
    ok(std::fs::write(&staged, &tampered));

    // Retry must detect the digest mismatch BEFORE any carrier invocation.
    let mut carrier = RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let error = err(fixture.retry(&env, &descriptor, &mut carrier));
    assert_eq!(error.code(), "GUI_RELEASE_ENVELOPE_TAMPERED");
    assert!(
        carrier.envelopes.is_empty(),
        "altered bytes must never reach the carrier",
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
    );
    // No choice change or re-preparation after PENDING.
    assert_code(
        fixture.session.set_selection(
            &env.artifacts,
            ElectionLifecycleStateV1::Open,
            vec![lower_hex(common::candidate_id(b"candidate-b").as_bytes())],
            false,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );

    // Restore the exact original staged bytes; retry now succeeds byte-for-byte.
    ok(std::fs::write(&staged, &original));
    let mut good = RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let result = ok(fixture.retry(&env, &descriptor, &mut good));
    assert!(result.released);
    assert_eq!(good.envelopes[0], original, "exact original bytes are sent");
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::Cast
    );
}

// The digest matches but the staged bytes are not a canonical envelope: the
// strict parse/binding check rejects them before the carrier, independent of the
// byte digest. Uses only the production PENDING-writer (no digest-update hook).
#[test]
fn non_canonical_staged_envelope_rejected_before_carrier() {
    let env = ReleaseEnv::new("release-staged-noncanonical");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let receipt_path = release_receipt_evidence_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let malformed = b"this is not a canonical PrivateBallotEnvelopeV1".to_vec();
    ok(stage_release_envelope_v1(&staged, &malformed));
    // The recorded digest MATCHES the malformed staged bytes (hash check passes).
    ok(write_cast_record_pending_private_transport_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &fixture.package_digest_hex,
        &staged,
        &staged_release_envelope_digest_hex_v1(&malformed),
        &env.descriptor_fingerprint_hex(&descriptor),
        &receipt_path,
    ));
    fixture
        .session
        .apply_cast_lock_state(GuiVoterCastLockStateV1::CastPending);

    let mut consistency = DescriptorConsistencyStoreV1::default();
    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.session.retry_pending_private_transport_release(
        &env.artifacts,
        &descriptor,
        &env.roots,
        &mut consistency,
        &env.cast_dir,
        &mut carrier,
    ));
    assert_eq!(error.code(), "GUI_RELEASE_ENVELOPE_TAMPERED");
    assert!(
        carrier.envelopes.is_empty(),
        "a malformed envelope is never sent"
    );
}

// -------------------------------------------------------------------------
// Cross-mechanism shared-boundary tests (§16).
// -------------------------------------------------------------------------

#[test]
fn online_pending_blocks_offline_export() {
    let env = ReleaseEnv::new("cross-online-pending-blocks-offline");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let mut failing = RecordingCarrier::failing();
    ok(fixture.release(&env, &descriptor, &mut failing));
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
    );

    let final_path = env._dir.join("offline-after-online-pending.cbor");
    assert_code(
        fixture.session.export_and_cast_prepared_ballot(
            &env.artifacts,
            ElectionLifecycleStateV1::Open,
            &final_path,
            &env.cast_dir,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert!(!final_path.exists(), "no offline final may be created");
}

#[test]
fn online_cast_blocks_offline_export() {
    let env = ReleaseEnv::new("cross-online-cast-blocks-offline");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    let mut carrier = RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let result = ok(fixture.release(&env, &descriptor, &mut carrier));
    assert!(result.released);

    let final_path = env._dir.join("offline-after-online-cast.cbor");
    assert_code(
        fixture.session.export_and_cast_prepared_ballot(
            &env.artifacts,
            ElectionLifecycleStateV1::Open,
            &final_path,
            &env.cast_dir,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert!(!final_path.exists());
}

#[test]
fn offline_cast_blocks_online_release() {
    let env = ReleaseEnv::new("cross-offline-cast-blocks-online");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let final_path = env._dir.join("offline-first.cbor");
    ok(fixture.session.export_and_cast_prepared_ballot(
        &env.artifacts,
        ElectionLifecycleStateV1::Open,
        &final_path,
        &env.cast_dir,
    ));
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::Cast
    );

    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.release(&env, &descriptor, &mut carrier));
    assert_eq!(error.code(), "GUI_BALLOT_ALREADY_CAST");
    assert!(
        carrier.envelopes.is_empty(),
        "online release must be refused before the carrier",
    );
}

#[test]
fn offline_pending_blocks_online_release() {
    use tari_cc_private_ballot_gui_core::write_cast_record_pending_v1;
    let env = ReleaseEnv::new("cross-offline-pending-blocks-online");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    // Durable OFFLINE pending record whose final/temp files do not exist, so
    // recovery keeps it locked.
    ok(write_cast_record_pending_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &fixture.package_digest_hex,
        &env._dir.join("offline-final.cbor"),
        &env._dir.join("offline-temp.cbor"),
    ));
    let resolved = ok(resolve_and_recover_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &env.artifacts,
    ));
    assert_eq!(resolved, GuiVoterCastLockStateV1::CastPending);
    fixture.session.apply_cast_lock_state(resolved);

    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    let error = err(fixture.release(&env, &descriptor, &mut carrier));
    assert_eq!(error.code(), "GUI_BALLOT_ALREADY_CAST");
    assert!(carrier.envelopes.is_empty());
}

// -------------------------------------------------------------------------
// Malformed online record fails closed (§17).
// -------------------------------------------------------------------------

#[test]
fn malformed_online_record_recovers_cast_pending_never_notcast() {
    let env = ReleaseEnv::new("release-malformed-online-record");
    let fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    let receipt_path = release_receipt_evidence_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    ok(stage_release_envelope_v1(&staged, b"opaque-envelope-bytes"));
    ok(write_cast_record_pending_private_transport_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &fixture.package_digest_hex,
        &staged,
        &staged_release_envelope_digest_hex_v1(b"opaque-envelope-bytes"),
        &env.descriptor_fingerprint_hex(&descriptor),
        &receipt_path,
    ));

    // Corrupt the on-disk record by truncation.
    let record_file = env.cast_dir.join(format!(
        "{}-{}.castlock",
        fixture.fingerprint, fixture.manifest_hex
    ));
    let bytes = ok(std::fs::read(&record_file));
    ok(std::fs::write(&record_file, &bytes[..bytes.len() / 2]));

    // Both resolvers fail closed to CAST_PENDING, never NOT_CAST.
    let generic = ok(resolve_and_recover_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &env.artifacts,
    ));
    assert_eq!(generic, GuiVoterCastLockStateV1::CastPending);
    let bound = ok(resolve_and_recover_private_transport_cast_lock_state_v1(
        &env.cast_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
        &descriptor,
    ));
    assert_eq!(bound, GuiVoterCastLockStateV1::CastPending);
}

// -------------------------------------------------------------------------
// Stale-Tor pre-PENDING guard (BLOCKER 2 regression).
//
// The Tauri managed-Tor submit path runs a FRESH readiness preflight BEFORE
// the shared release boundary. These tests model that ordering — a preflight
// Result gates entry to the release/retry boundary — and prove:
//   * a failed preflight never enters the boundary (no PENDING, no carrier,
//     NotCast, choice changeable);
//   * a failed retry preflight keeps CastPending with the exact staged
//     envelope untouched, then a successful retry retransmits it.
// The actual preflight (controller child-liveness + fresh SOCKS probe) is
// proven in the transport-network crate tests; here we prove the boundary
// ordering invariant the Tauri shell relies on.
// -------------------------------------------------------------------------

/// Models the Tauri submit ordering: preflight THEN shared release boundary.
fn submit_with_preflight(
    preflight: Result<(), GuiCoreError>,
    fixture: &mut ReleaseFixture,
    env: &ReleaseEnv,
    descriptor: &TransportDescriptorV1,
    carrier: &mut RecordingCarrier,
) -> Result<tari_cc_private_ballot_gui_core::GuiPrivateReleaseResultV1, GuiCoreError> {
    preflight?;
    fixture.release(env, descriptor, carrier)
}

/// Models the Tauri retry ordering: preflight THEN shared retry boundary.
fn retry_with_preflight(
    preflight: Result<(), GuiCoreError>,
    fixture: &mut ReleaseFixture,
    env: &ReleaseEnv,
    descriptor: &TransportDescriptorV1,
    carrier: &mut RecordingCarrier,
) -> Result<tari_cc_private_ballot_gui_core::GuiPrivateReleaseResultV1, GuiCoreError> {
    preflight?;
    fixture.retry(env, descriptor, carrier)
}

fn stale_tor_preflight_error() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_TOR_NOT_READY",
        tari_cc_private_ballot_gui_core::GuiErrorCategory::Unavailable,
        Some("private-release"),
        "the managed Tor SOCKS listener is not currently ready",
    )
}

#[test]
fn stale_tor_preflight_failure_prevents_pending_release() {
    let env = ReleaseEnv::new("release-stale-tor-preflight");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);

    let mut carrier = RecordingCarrier::accepting(vec![0xAA; 8]);
    // Tor died after initial startup; the controller object still exists but
    // the fresh readiness preflight fails. The release boundary must NEVER be
    // entered.
    let error = err(submit_with_preflight(
        Err(stale_tor_preflight_error()),
        &mut fixture,
        &env,
        &descriptor,
        &mut carrier,
    ));
    assert_eq!(error.code(), "GUI_TOR_NOT_READY");
    assert!(
        carrier.envelopes.is_empty(),
        "carrier must never be invoked on a failed preflight"
    );
    assert!(
        !ok(cast_record_exists_v1(
            &env.cast_dir,
            &fixture.manifest_hex,
            &fixture.fingerprint
        )),
        "no PENDING record may be written on a failed preflight"
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::NotCast,
        "voter remains NotCast when the preflight fails before the boundary"
    );
    // The choice is still changeable: re-prepare a different selection.
    let digest_b = fixture.reprepare(&env, b"candidate-b");
    assert!(!digest_b.is_empty(), "voter can still change choice");
}

#[test]
fn stale_tor_retry_preflight_failure_keeps_pending_then_succeeds() {
    let env = ReleaseEnv::new("release-stale-tor-retry");
    let mut fixture = env.prepared_fixture(b"candidate-a");
    let descriptor = env.descriptor(&fixture);
    let digest = hex32(&fixture.package_digest_hex);

    // First attempt: preflight succeeds but the carrier fails AFTER PENDING.
    let mut failing = RecordingCarrier::failing();
    ok(submit_with_preflight(
        Ok(()),
        &mut fixture,
        &env,
        &descriptor,
        &mut failing,
    ));
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending
    );
    let staged = staged_release_envelope_path_v1(
        &env.staging_dir,
        &fixture.manifest_hex,
        &fixture.fingerprint,
    );
    assert!(staged.exists(), "the staged envelope is retained");
    let original_staged = ok(std::fs::read(&staged));

    // Retry with a STALE Tor preflight: must remain CastPending, exact staged
    // envelope untouched, carrier never invoked, no resealing/rollback.
    let mut accepting =
        RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let error = err(retry_with_preflight(
        Err(stale_tor_preflight_error()),
        &mut fixture,
        &env,
        &descriptor,
        &mut accepting,
    ));
    assert_eq!(error.code(), "GUI_TOR_NOT_READY");
    assert!(
        accepting.envelopes.is_empty(),
        "carrier must not be invoked on a failed retry preflight"
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::CastPending,
        "failed retry preflight must keep CastPending, never rollback to NotCast"
    );
    let still_staged = ok(std::fs::read(&staged));
    assert_eq!(
        still_staged, original_staged,
        "the exact staged envelope must remain untouched"
    );

    // Now simulate readiness success and retry: the same staged envelope is
    // retransmitted and the authenticated receipt promotes to CAST.
    let mut accepting2 =
        RecordingCarrier::accepting(env.accepted_receipt_bytes(&descriptor, digest));
    let result = ok(retry_with_preflight(
        Ok(()),
        &mut fixture,
        &env,
        &descriptor,
        &mut accepting2,
    ));
    assert!(
        result.released,
        "successful retry after readiness promotes to CAST"
    );
    assert_eq!(
        accepting2.envelopes[0], original_staged,
        "retry retransmits the EXACT staged envelope"
    );
    assert_eq!(
        fixture.session.cast_lock_state(),
        GuiVoterCastLockStateV1::Cast
    );
}

// =========================================================================
// Instrumented fake carrier.
// =========================================================================

struct RecordingCarrier {
    behavior: Behavior,
    envelopes: Vec<Vec<u8>>,
    assert_pending: Option<(std::path::PathBuf, String, String)>,
}

enum Behavior {
    Accept(Vec<u8>),
    Fail,
}

impl RecordingCarrier {
    fn accepting(receipt_bytes: Vec<u8>) -> Self {
        Self {
            behavior: Behavior::Accept(receipt_bytes),
            envelopes: Vec::new(),
            assert_pending: None,
        }
    }
    fn failing() -> Self {
        Self {
            behavior: Behavior::Fail,
            envelopes: Vec::new(),
            assert_pending: None,
        }
    }
    fn assert_pending_before_send(
        mut self,
        cast_dir: std::path::PathBuf,
        manifest_hex: String,
        fingerprint: String,
    ) -> Self {
        self.assert_pending = Some((cast_dir, manifest_hex, fingerprint));
        self
    }
}

impl PrivateReleaseCarrierV1 for RecordingCarrier {
    fn deliver_opaque_envelope(
        &mut self,
        _descriptor: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<Vec<u8>, GuiCoreError> {
        if let Some((cast_dir, manifest_hex, fingerprint)) = &self.assert_pending {
            assert!(
                cast_record_exists_v1(cast_dir, manifest_hex, fingerprint).unwrap_or(false),
                "a durable cast record must exist before the carrier is invoked",
            );
            assert!(
                load_pending_release_retry_handle_v1(cast_dir, manifest_hex, fingerprint).is_some(),
                "the durable record must be a PENDING online release before send",
            );
        }
        self.envelopes.push(envelope.to_vec());
        match &self.behavior {
            Behavior::Accept(bytes) => Ok(bytes.clone()),
            Behavior::Fail => Err(GuiCoreError::new(
                "TEST_CARRIER_FAILURE",
                tari_cc_private_ballot_gui_core::GuiErrorCategory::Unavailable,
                Some("test-carrier"),
                "the fake carrier simulated a delivery failure",
            )),
        }
    }
}

// =========================================================================
// Fixtures.
// =========================================================================

struct ReleaseEnv {
    _dir: common::TestDir,
    artifacts: GuiElectionArtifactsV1,
    cast_dir: std::path::PathBuf,
    staging_dir: std::path::PathBuf,
    roots: TransportAuthorityRootSetV1,
    authority: SigningKey,
    receipt_key: SigningKey,
    gateway_public: [u8; 32],
    credential_public: [u8; 32],
    credential_container: VoterCredentialContainerV1,
    election_id: Vec<u8>,
}

struct ReleaseFixture {
    session: GuiVoterSessionV1,
    manifest_hex: String,
    fingerprint: String,
    package_digest_hex: String,
}

const ROOT_KEY_ID: &str = "release-test-root-2026";

impl ReleaseEnv {
    fn new(label: &str) -> Self {
        let dir = common::TestDir::new(label);
        let cast_dir = dir.join("voter-cast-locks");
        ok(tari_cc_private_ballot_gui_core::ensure_voter_cast_locks_directory_v1(&cast_dir));
        let staging_dir = dir.join("voter-release-staging");
        ok(std::fs::create_dir_all(&staging_dir));

        let credential = ok(VoterGovernanceCredentialV1::generate());
        let credential_public = ok(credential.public_key_bytes());
        let credential_container = ok(
            tari_cc_private_ballot_gui_core::export_voter_credential_container_v1(
                &credential,
                PASSPHRASE,
            ),
        );

        let election_id = b"release-boundary-election".to_vec();
        let artifacts = artifacts_for_public_key(credential_public, &election_id);

        let authority = SigningKey::from_bytes(&[0x11; 32]);
        let receipt_key = SigningKey::from_bytes(&[0x22; 32]);
        let roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
            key_id: ROOT_KEY_ID.to_owned(),
            public_key: authority.verifying_key().to_bytes(),
        });
        let (_gateway_secret, gateway_public_key) = Kem::gen_keypair();
        let mut gateway_public = [0; 32];
        gateway_public.copy_from_slice(gateway_public_key.to_bytes().as_slice());

        Self {
            _dir: dir,
            artifacts,
            cast_dir,
            staging_dir,
            roots,
            authority,
            receipt_key,
            gateway_public,
            credential_public,
            credential_container,
            election_id,
        }
    }

    fn eligible_session(&self) -> GuiVoterSessionV1 {
        let credential = ok(
            tari_cc_private_ballot_gui_core::import_voter_credential_container_v1(
                &self.credential_container,
                PASSPHRASE,
            ),
        );
        let mut session = GuiVoterSessionV1::new(&self.artifacts);
        let status = ok(session.install_credential(credential, &self.artifacts));
        assert!(status.can_continue, "credential must be eligible");
        session
    }

    fn prepared_fixture(&self, selection: &[u8]) -> ReleaseFixture {
        let mut session = self.eligible_session();
        let package_digest_hex = prepare_digest(&mut session, &self.artifacts, selection);
        ReleaseFixture {
            session,
            manifest_hex: manifest_hash_hex_of(&self.artifacts),
            fingerprint: fingerprint_for(self.credential_public),
            package_digest_hex,
        }
    }

    fn padded_bytes_for(&self, fixture: &ReleaseFixture) -> usize {
        // Size the fixed padding profile to comfortably hold the real prepared
        // package plus its 4-byte length prefix.
        let len = ok(fixture
            .session
            .prepared_canonical_ballot_bytes(&self.artifacts, ElectionLifecycleStateV1::Open))
        .len();
        len + 4 + 1024
    }

    fn descriptor(&self, fixture: &ReleaseFixture) -> TransportDescriptorV1 {
        self.descriptor_signed_by(fixture, &self.authority)
    }

    fn descriptor_signed_by(
        &self,
        fixture: &ReleaseFixture,
        signing_key: &SigningKey,
    ) -> TransportDescriptorV1 {
        ok_t(TransportDescriptorV1::sign_for_test_or_ceremony(
            self.election_id.clone(),
            self.artifacts.manifest_hash(),
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec![TEST_ONION.to_owned()],
            Vec::new(),
            self.gateway_public,
            "release-gateway-2026".to_owned(),
            vec![self.receipt_key.verifying_key().to_bytes()],
            PaddingPolicyV1 {
                id: "fixed-release".to_owned(),
                padded_bytes: self.padded_bytes_for(fixture),
            },
            BatchPolicyV1 {
                id: "accepted-1".to_owned(),
                accepted_unique_floor: 1,
            },
            None,
            ROOT_KEY_ID.to_owned(),
            signing_key,
        ))
    }

    fn other_election_descriptor(&self, fixture: &ReleaseFixture) -> TransportDescriptorV1 {
        let other = artifacts_for_public_key(self.credential_public, b"a-different-election");
        ok_t(TransportDescriptorV1::sign_for_test_or_ceremony(
            b"a-different-election".to_vec(),
            other.manifest_hash(),
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec![TEST_ONION.to_owned()],
            Vec::new(),
            self.gateway_public,
            "release-gateway-2026".to_owned(),
            vec![self.receipt_key.verifying_key().to_bytes()],
            PaddingPolicyV1 {
                id: "fixed-release".to_owned(),
                padded_bytes: self.padded_bytes_for(fixture),
            },
            BatchPolicyV1 {
                id: "accepted-1".to_owned(),
                accepted_unique_floor: 1,
            },
            None,
            ROOT_KEY_ID.to_owned(),
            &self.authority,
        ))
    }

    /// A second descriptor for the SAME election that shares the SAME receipt
    /// verification key but differs in gateway/receiver identity (and thus has a
    /// different canonical fingerprint). Used to prove receipt-key reuse cannot
    /// promote the wrong descriptor.
    fn second_descriptor(&self, fixture: &ReleaseFixture) -> TransportDescriptorV1 {
        let (_secret, other_gateway_public) = Kem::gen_keypair();
        let mut gateway = [0; 32];
        gateway.copy_from_slice(other_gateway_public.to_bytes().as_slice());
        ok_t(TransportDescriptorV1::sign_for_test_or_ceremony(
            self.election_id.clone(),
            self.artifacts.manifest_hash(),
            2,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec![TEST_ONION.to_owned()],
            Vec::new(),
            gateway,
            "release-gateway-2026-alt".to_owned(),
            vec![self.receipt_key.verifying_key().to_bytes()],
            PaddingPolicyV1 {
                id: "fixed-release".to_owned(),
                padded_bytes: self.padded_bytes_for(fixture),
            },
            BatchPolicyV1 {
                id: "accepted-1".to_owned(),
                accepted_unique_floor: 1,
            },
            None,
            ROOT_KEY_ID.to_owned(),
            &self.authority,
        ))
    }

    fn descriptor_fingerprint_hex(&self, descriptor: &TransportDescriptorV1) -> String {
        lower_hex(&ok_t(descriptor.fingerprint()))
    }

    /// A correct, descriptor-bound accepted receipt signed by the descriptor's
    /// authorized receipt key.
    fn accepted_receipt_bytes(
        &self,
        descriptor: &TransportDescriptorV1,
        digest: [u8; 32],
    ) -> Vec<u8> {
        self.signed_receipt_bytes(ok_t(descriptor.fingerprint()), digest, &self.receipt_key)
    }

    /// The receipt the organizer returns for an idempotent EXACT retry of a
    /// delivery it already accepted: state `Accepted`, retry status
    /// `PreviousDeliveryAccepted`. It must promote the voter to CAST exactly like
    /// a fresh acceptance.
    fn previous_delivery_accepted_receipt_bytes(
        &self,
        descriptor: &TransportDescriptorV1,
        digest: [u8; 32],
    ) -> Vec<u8> {
        let receipt = AuthenticatedTransportReceiptV1::sign_for_test_or_ceremony(
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Accepted,
                retry_status: RetryStatusV1::PreviousDeliveryAccepted,
            },
            ok_t(descriptor.fingerprint()),
            digest,
            None,
            "release-receipt-key-1".to_owned(),
            &self.receipt_key,
        );
        ok_t(receipt.to_canonical_cbor())
    }

    /// A receipt with caller-chosen descriptor fingerprint, package digest, and
    /// signing key — for the adversarial matrix.
    fn signed_receipt_bytes(
        &self,
        descriptor_fingerprint: [u8; 32],
        digest: [u8; 32],
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let receipt = AuthenticatedTransportReceiptV1::sign_for_test_or_ceremony(
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Accepted,
                retry_status: RetryStatusV1::NewDelivery,
            },
            descriptor_fingerprint,
            digest,
            None,
            "release-receipt-key-1".to_owned(),
            signing_key,
        );
        ok_t(receipt.to_canonical_cbor())
    }
}

impl ReleaseFixture {
    fn release(
        &mut self,
        env: &ReleaseEnv,
        descriptor: &TransportDescriptorV1,
        carrier: &mut RecordingCarrier,
    ) -> Result<tari_cc_private_ballot_gui_core::GuiPrivateReleaseResultV1, GuiCoreError> {
        let mut consistency = DescriptorConsistencyStoreV1::default();
        self.session.release_prepared_ballot_via_private_transport(
            &env.artifacts,
            ElectionLifecycleStateV1::Open,
            descriptor,
            &env.roots,
            &mut consistency,
            &env.cast_dir,
            &env.staging_dir,
            carrier,
        )
    }

    fn retry(
        &mut self,
        env: &ReleaseEnv,
        descriptor: &TransportDescriptorV1,
        carrier: &mut RecordingCarrier,
    ) -> Result<tari_cc_private_ballot_gui_core::GuiPrivateReleaseResultV1, GuiCoreError> {
        let mut consistency = DescriptorConsistencyStoreV1::default();
        self.session.retry_pending_private_transport_release(
            &env.artifacts,
            descriptor,
            &env.roots,
            &mut consistency,
            &env.cast_dir,
            carrier,
        )
    }

    fn reprepare(&mut self, env: &ReleaseEnv, selection: &[u8]) -> String {
        prepare_digest(&mut self.session, &env.artifacts, selection)
    }
}

// =========================================================================
// Shared helpers (mirrors of the cast-lock test harness).
// =========================================================================

const PASSPHRASE: &str = "release-boundary test passphrase";

fn prepare_digest(
    session: &mut GuiVoterSessionV1,
    artifacts: &GuiElectionArtifactsV1,
    selection: &[u8],
) -> String {
    ok(session.set_selection(
        artifacts,
        ElectionLifecycleStateV1::Open,
        vec![lower_hex(common::candidate_id(selection).as_bytes())],
        false,
    ));
    let status = ok(session.prepare_ballot(artifacts, ElectionLifecycleStateV1::Open));
    assert!(status.ready_to_export);
    status
        .summary
        .expect("prepared summary present")
        .package_digest_hex
}

fn fingerprint_for(public_key: [u8; 32]) -> String {
    public_credential_fingerprint_hex_v1(&lower_hex(&public_key)).expect("fingerprint")
}

fn manifest_hash_hex_of(artifacts: &GuiElectionArtifactsV1) -> String {
    GuiVoterElectionBindingV1::from_artifacts(artifacts).manifest_hash_hex
}

fn artifacts_for_public_key(public_key: [u8; 32], election_id: &[u8]) -> GuiElectionArtifactsV1 {
    let provider = Blake3HashProviderV1;
    let registry = registry_from_key(public_key);
    let candidates = common::candidate_set();
    let manifest = ok_t(ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: ok_t(ElectionId::new(election_id.to_vec())),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: ok_t(registry.canonical_commitment(&provider)),
        candidate_set_commitment: ok_t(candidates.canonical_commitment(&provider)),
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: common::approval_limits(),
        governance_source_revision: "release-boundary-test".to_owned(),
    }));
    let manifest_bytes = ok_t(manifest.to_canonical_cbor());
    let candidate_bytes = ok_t(candidates.to_canonical_cbor());
    ok_t(GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes,
        &registry_bytes_from_key(public_key),
        &candidate_bytes,
    ))
}

fn registry_from_key(public_key: [u8; 32]) -> RegistrySnapshot {
    ok_t(RegistrySnapshot::from_canonical_cbor(
        &registry_bytes_from_key(public_key),
    ))
}

fn registry_bytes_from_key(public_key: [u8; 32]) -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(1).is_ok());
    assert!(writer.write_byte_string(&public_key).is_ok());
    writer.into_bytes()
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "expected a 32-byte hex digest");
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = from_hex_digit(chunk[0]);
        let lo = from_hex_digit(chunk[1]);
        out[index] = (hi << 4) | lo;
    }
    out
}

fn from_hex_digit(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

fn assert_code<T>(result: Result<T, GuiCoreError>, expected: &str) {
    match result {
        Ok(_) => panic!("expected error {expected}, got Ok"),
        Err(error) => assert_eq!(error.code(), expected),
    }
}

fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn ok_t<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    ok(result)
}

fn err<T: core::fmt::Debug>(result: Result<T, GuiCoreError>) -> GuiCoreError {
    match result {
        Ok(value) => panic!("expected error, got Ok: {value:?}"),
        Err(error) => error,
    }
}
