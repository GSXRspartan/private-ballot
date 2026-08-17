//! Pre-cast reconsideration + durable local cast-lock tests.
//!
//! These prove the defense-in-depth voter cast lock: free reconsideration
//! before export, an irrevocable local cast on export, durability across a
//! reconstructed session and credential re-unlock, election specificity,
//! crash-recovery of a pending cast, and — crucially — that the organizer's
//! election-scoped nullifier remains the authoritative one-vote rule regardless
//! of the local lock.

mod common;

use tari_cc_private_ballot_ballot::{
    BallotConfidentialityV1, BallotKindV1, BallotPackageV1, ElectionId, ElectionLifecycleV1,
    ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    ElectionLifecycleStateV1, GuiElectionArtifactsV1, GuiVoterCastLockStateV1,
    GuiVoterElectionBindingV1, GuiVoterSessionV1, VoterGovernanceCredentialV1,
    cast_record_exists_v1, classify_cast_destination_probe_failure_v1,
    classify_cast_destination_probe_phase_a_v1, classify_cast_destination_probe_phase_b_v1,
    export_voter_credential_container_v1, finalize_verified_cast_temp_without_overwrite,
    import_voter_credential_container_v1, probe_cast_export_destination_supports_no_overwrite_v1,
    probe_phase_a_create_link_v1, public_credential_fingerprint_hex_v1,
    resolve_and_recover_cast_lock_state_v1, write_cast_record_pending_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1, ProtocolError, ValidationCode,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, VerifiedApprovalBallotV1,
    build_tari_triptych_verifier_from_registry_v1, verify_approval_proof,
};

const PASSPHRASE: &str = "cast-lock test passphrase";

// -------------------------------------------------------------------------
// A. Reconsider before export.
// -------------------------------------------------------------------------

#[test]
fn reconsider_before_export_discards_old_and_prepares_new_package() {
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let artifacts = artifacts_for_public_key(public_key, b"cast-reconsider");
    let mut session = eligible_session(&artifacts, credential);

    let digest_a = prepare_digest(&mut session, &artifacts, b"candidate-a");
    // Change my choice: authoritatively discard the prepared package/proof.
    let discarded = ok(session.discard_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open));
    assert_ne!(discarded.state, "Ready");
    assert_eq!(session.cast_lock_state(), GuiVoterCastLockStateV1::NotCast);

    let digest_b = prepare_digest(&mut session, &artifacts, b"candidate-b");
    // The active prepared ballot is a brand-new package for B, never the old A.
    assert_ne!(digest_a, digest_b, "a new selection yields a new package");
}

// -------------------------------------------------------------------------
// B. Export locks (irreversible cast boundary).
// -------------------------------------------------------------------------

#[test]
fn export_and_cast_locks_change_and_reprepare() {
    let dir = common::TestDir::new("cast-export-locks");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let artifacts = artifacts_for_public_key(public_key, b"cast-export-lock");
    let mut session = eligible_session(&artifacts, credential);
    prepare_digest(&mut session, &artifacts, b"candidate-a");

    let final_path = dir.join("ballot.cbor");
    ok(session.export_and_cast_prepared_ballot(
        &artifacts,
        ElectionLifecycleStateV1::Open,
        &final_path,
        &cast_dir,
    ));
    assert_eq!(session.cast_lock_state(), GuiVoterCastLockStateV1::Cast);
    assert!(final_path.exists(), "the exported ballot file must exist");

    // No change, no re-preparation, no re-export, no discard after cast.
    assert_code(
        session.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![lower_hex(common::candidate_id(b"candidate-b").as_bytes())],
            false,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        session.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        session.discard_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        session.export_and_cast_prepared_ballot(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &dir.join("second.cbor"),
            &cast_dir,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );
}

// -------------------------------------------------------------------------
// C. Restart durability + D. credential clear/unlock stays cast.
// -------------------------------------------------------------------------

#[test]
fn cast_survives_restart_and_credential_reunlock() {
    let dir = common::TestDir::new("cast-restart");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let artifacts = artifacts_for_public_key(public_key, b"cast-restart-a");
    let manifest_hex = manifest_hash_hex_of(&artifacts);

    // A durable copy of the same credential to re-unlock after "restart".
    let container = ok(export_voter_credential_container_v1(
        &credential,
        PASSPHRASE,
    ));

    let mut session = eligible_session(&artifacts, credential);
    prepare_digest(&mut session, &artifacts, b"candidate-a");
    ok(session.export_and_cast_prepared_ballot(
        &artifacts,
        ElectionLifecycleStateV1::Open,
        &dir.join("ballot.cbor"),
        &cast_dir,
    ));

    // Restart: a brand-new session over the same election with the same
    // credential re-unlocked from the durable store.
    let reunlocked = ok(import_voter_credential_container_v1(&container, PASSPHRASE));
    let mut restarted = eligible_session(&artifacts, reunlocked);
    let state = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(state, GuiVoterCastLockStateV1::Cast);
    restarted.apply_cast_lock_state(state);
    assert_code(
        restarted.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![lower_hex(common::candidate_id(b"candidate-a").as_bytes())],
            false,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );

    // Clearing the credential from memory must not clear the durable cast.
    let _ = restarted.reset_credential();
    let still_cast = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(still_cast, GuiVoterCastLockStateV1::Cast);
}

// -------------------------------------------------------------------------
// E. Election specificity.
// -------------------------------------------------------------------------

#[test]
fn cast_lock_is_election_specific() {
    let dir = common::TestDir::new("cast-election-specific");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let container = ok(export_voter_credential_container_v1(
        &credential,
        PASSPHRASE,
    ));

    let artifacts_a = artifacts_for_public_key(public_key, b"cast-specific-a");
    let mut session_a = eligible_session(&artifacts_a, credential);
    prepare_digest(&mut session_a, &artifacts_a, b"candidate-a");
    ok(session_a.export_and_cast_prepared_ballot(
        &artifacts_a,
        ElectionLifecycleStateV1::Open,
        &dir.join("ballot-a.cbor"),
        &cast_dir,
    ));

    // The SAME credential in a DIFFERENT election is not locally cast.
    let artifacts_b = artifacts_for_public_key(public_key, b"cast-specific-b");
    let manifest_b_hex = manifest_hash_hex_of(&artifacts_b);
    let state_b = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_b_hex,
        &fingerprint,
        &artifacts_b,
    ));
    assert_eq!(state_b, GuiVoterCastLockStateV1::NotCast);

    let reunlocked = ok(import_voter_credential_container_v1(&container, PASSPHRASE));
    let mut session_b = eligible_session(&artifacts_b, reunlocked);
    session_b.apply_cast_lock_state(state_b);
    // Normal preparation is allowed in election B.
    let digest_b = prepare_digest(&mut session_b, &artifacts_b, b"candidate-a");
    assert!(!digest_b.is_empty());
}

// -------------------------------------------------------------------------
// F. Organizer nullifier authority is unchanged (item 15).
// -------------------------------------------------------------------------

#[test]
fn changed_ballot_shares_nullifier_and_cannot_be_accepted_twice() {
    let dir = common::TestDir::new("cast-nullifier");
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let artifacts = artifacts_for_public_key(public_key, b"cast-nullifier");
    let mut session = eligible_session(&artifacts, credential);

    // Prepare + export package A, then "change my choice" and prepare + export a
    // DIFFERENT package B — both from the same credential + election. (Pure
    // export here; the local cast lock is a separate concern.)
    prepare_digest(&mut session, &artifacts, b"candidate-a");
    let path_a = dir.join("old.cbor");
    ok(session.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &path_a));
    ok(session.discard_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open));
    prepare_digest(&mut session, &artifacts, b"candidate-b");
    let path_b = dir.join("new.cbor");
    ok(session.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &path_b));

    let bytes_a = ok(std::fs::read(&path_a));
    let bytes_b = ok(std::fs::read(&path_b));
    assert_ne!(
        bytes_a, bytes_b,
        "different choices produce different packages"
    );

    let verified_a = ok(verify_package(&artifacts, &bytes_a));
    let verified_b = ok(verify_package(&artifacts, &bytes_b));
    // Same election-scoped nullifier: the protocol one-vote rule is unchanged.
    assert_eq!(
        verified_a.nullifier().as_bytes(),
        verified_b.nullifier().as_bytes()
    );

    // The organizer accepts the first and rejects the later package as a
    // duplicate; the accepted count stays exactly one.
    let lifecycle = open_lifecycle(&artifacts);
    let mut ledger = BallotAcceptanceLedger::new();
    ok(ledger.accept_verified(&lifecycle, verified_a));
    let duplicate = ledger.accept_verified(&lifecycle, verified_b);
    assert!(matches!(
        duplicate,
        Err(error) if error.code() == ValidationCode::DuplicateNullifier
    ));
    assert_eq!(ledger.len(), 1);
}

// -------------------------------------------------------------------------
// G. Crash-journal recovery states.
// -------------------------------------------------------------------------

#[test]
fn pending_cast_recovers_when_final_file_is_present() {
    let dir = common::TestDir::new("cast-recover-final");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let artifacts = artifacts_for_public_key(public_key, b"cast-recover-final");
    let manifest_hex = manifest_hash_hex_of(&artifacts);
    let mut session = eligible_session(&artifacts, credential);
    let digest = prepare_digest(&mut session, &artifacts, b"candidate-a");

    // Simulate a crash after PENDING was written but before promotion: the final
    // file exists (pure export) and a pending record points at it.
    let final_path = dir.join("ballot.cbor");
    ok(session.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &final_path));
    ok(write_cast_record_pending_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &digest,
        &final_path,
        &dir.join("ballot.cbor.castpart"),
    ));

    let state = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(state, GuiVoterCastLockStateV1::Cast);
}

#[test]
fn pending_cast_recovers_by_linking_temp_when_final_is_absent() {
    let dir = common::TestDir::new("cast-recover-temp");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let artifacts = artifacts_for_public_key(public_key, b"cast-recover-temp");
    let manifest_hex = manifest_hash_hex_of(&artifacts);
    let mut session = eligible_session(&artifacts, credential);
    let digest = prepare_digest(&mut session, &artifacts, b"candidate-a");

    // The verified bytes exist only at the temp path; final is absent.
    let temp_path = dir.join("ballot.cbor.castpart");
    let final_path = dir.join("ballot.cbor");
    ok(session.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &temp_path));
    ok(write_cast_record_pending_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &digest,
        &final_path,
        &temp_path,
    ));

    let state = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(state, GuiVoterCastLockStateV1::Cast);
    assert!(
        final_path.exists(),
        "recovery exposes the temp file as final (no-overwrite link)"
    );
    assert_eq!(
        package_digest_hex_of_path(&final_path, &artifacts),
        Some(digest),
        "the finalized ballot is exactly the recorded one",
    );
}

#[test]
fn pending_cast_without_recoverable_file_stays_locked() {
    let dir = common::TestDir::new("cast-recover-neither");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let artifacts = artifacts_for_public_key(public_key, b"cast-recover-neither");
    let manifest_hex = manifest_hash_hex_of(&artifacts);

    // A pending record whose ballot files are both missing must FAIL CLOSED.
    ok(write_cast_record_pending_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &"00".repeat(32),
        &dir.join("missing-final.cbor"),
        &dir.join("missing-temp.cbor.castpart"),
    ));
    let state = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(state, GuiVoterCastLockStateV1::CastPending);
}

#[test]
fn malformed_cast_record_fails_closed_and_unrelated_is_not_locked() {
    let dir = common::TestDir::new("cast-malformed");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let artifacts = artifacts_for_public_key(public_key, b"cast-malformed");
    let manifest_hex = manifest_hash_hex_of(&artifacts);

    // A present-but-garbage record file must never unlock the voter.
    let record_path = cast_dir.join(format!("{fingerprint}-{manifest_hex}.castlock"));
    ok(std::fs::write(&record_path, b"not a valid cast record"));
    let malformed = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(malformed, GuiVoterCastLockStateV1::CastPending);

    // An unrelated credential/election is not falsely locked.
    let other = ok(VoterGovernanceCredentialV1::generate());
    let other_key = ok(other.public_key_bytes());
    let other_fingerprint = fingerprint_for(other_key);
    let other_artifacts = artifacts_for_public_key(other_key, b"cast-unrelated");
    let other_manifest_hex = manifest_hash_hex_of(&other_artifacts);
    let unrelated = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &other_manifest_hex,
        &other_fingerprint,
        &other_artifacts,
    ));
    assert_eq!(unrelated, GuiVoterCastLockStateV1::NotCast);
}

// -------------------------------------------------------------------------
// M1: true no-overwrite finalization.
// -------------------------------------------------------------------------

// A. The shared finalization helper must fail (never overwrite) when the final
//    target already exists, leaving that file byte-for-byte unchanged and the
//    verified temp intact.
#[test]
fn finalization_never_overwrites_an_existing_final_target() {
    let dir = common::TestDir::new("cast-finalize-collision");
    let temp_path = dir.join("ballot.cbor.castpart");
    let final_path = dir.join("ballot.cbor");
    let sentinel = b"unrelated sentinel bytes created before finalization".to_vec();
    ok(std::fs::write(&temp_path, b"verified ballot temp bytes"));
    ok(std::fs::write(&final_path, &sentinel));

    let error = finalize_verified_cast_temp_without_overwrite(&temp_path, &final_path)
        .expect_err("finalization must fail when the final target already exists");
    assert_eq!(error.code(), "GUI_BALLOT_EXPORT_COLLISION");

    // The existing final is untouched; the verified temp is preserved.
    assert_eq!(ok(std::fs::read(&final_path)), sentinel);
    assert!(
        temp_path.exists(),
        "the verified temp must survive a collision"
    );
}

// C. Normal finalization exposes the temp as final when the target is absent.
#[test]
fn finalization_exposes_temp_as_final_when_absent() {
    let dir = common::TestDir::new("cast-finalize-normal");
    let temp_path = dir.join("ballot.cbor.castpart");
    let final_path = dir.join("ballot.cbor");
    let bytes = b"verified ballot bytes".to_vec();
    ok(std::fs::write(&temp_path, &bytes));

    ok(finalize_verified_cast_temp_without_overwrite(
        &temp_path,
        &final_path,
    ));
    assert_eq!(ok(std::fs::read(&final_path)), bytes);
    assert!(
        !temp_path.exists(),
        "the temp link is cleaned up after success"
    );
}

// B. Pending recovery must not overwrite an unrelated colliding final. Once the
//    unrelated file is removed, the SAME recorded ballot finalizes to CAST.
#[test]
fn pending_recovery_never_overwrites_final_then_finalizes_same_ballot() {
    let dir = common::TestDir::new("cast-recover-collision");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let container = ok(export_voter_credential_container_v1(
        &credential,
        PASSPHRASE,
    ));
    let artifacts = artifacts_for_public_key(public_key, b"cast-recover-collision");
    let manifest_hex = manifest_hash_hex_of(&artifacts);
    let mut session = eligible_session(&artifacts, credential);
    let digest = prepare_digest(&mut session, &artifacts, b"candidate-a");

    // A verified temp ballot + durable PENDING record, with an UNRELATED final.
    let temp_path = dir.join("ballot.cbor.castpart");
    let final_path = dir.join("ballot.cbor");
    ok(session.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &temp_path));
    ok(write_cast_record_pending_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &digest,
        &final_path,
        &temp_path,
    ));
    let sentinel = b"unrelated colliding final bytes".to_vec();
    ok(std::fs::write(&final_path, &sentinel));

    // Recovery must NOT overwrite the unrelated final; it stays cast-pending.
    let pending = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(pending, GuiVoterCastLockStateV1::CastPending);
    assert_eq!(
        ok(std::fs::read(&final_path)),
        sentinel,
        "final left unchanged"
    );
    assert!(
        temp_path.exists(),
        "the verified temp survives the collision"
    );

    // The voter is locked: no change/prepare/discard while cast-pending.
    let reunlocked = ok(import_voter_credential_container_v1(&container, PASSPHRASE));
    let mut locked = eligible_session(&artifacts, reunlocked);
    locked.apply_cast_lock_state(pending);
    assert_code(
        locked.set_selection(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            vec![lower_hex(common::candidate_id(b"candidate-b").as_bytes())],
            false,
        ),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        locked.prepare_ballot(&artifacts, ElectionLifecycleStateV1::Open),
        "GUI_BALLOT_ALREADY_CAST",
    );
    assert_code(
        locked.discard_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open),
        "GUI_BALLOT_ALREADY_CAST",
    );

    // Remove the unrelated collision; recovery finalizes the SAME ballot.
    ok(std::fs::remove_file(&final_path));
    let cast = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(cast, GuiVoterCastLockStateV1::Cast);
    assert_eq!(
        package_digest_hex_of_path(&final_path, &artifacts),
        Some(digest),
        "the finalized ballot is exactly the recorded one, not a new ballot",
    );
}

// D. Crash after successful final exposure but before promotion/cleanup: both
//    temp and final may exist. Recovery verifies the final and promotes the SAME
//    cast, never unlocking or producing a different ballot.
#[test]
fn recovery_promotes_when_final_and_temp_both_present() {
    let dir = common::TestDir::new("cast-recover-duplicate");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let fingerprint = fingerprint_for(public_key);
    let artifacts = artifacts_for_public_key(public_key, b"cast-recover-duplicate");
    let manifest_hex = manifest_hash_hex_of(&artifacts);
    let mut session = eligible_session(&artifacts, credential);
    let digest = prepare_digest(&mut session, &artifacts, b"candidate-a");

    // Final exposed AND temp still present (pre-cleanup, pre-promotion).
    let temp_path = dir.join("ballot.cbor.castpart");
    let final_path = dir.join("ballot.cbor");
    ok(session.export_prepared_ballot(&artifacts, ElectionLifecycleStateV1::Open, &final_path));
    ok(std::fs::copy(&final_path, &temp_path));
    ok(write_cast_record_pending_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &digest,
        &final_path,
        &temp_path,
    ));

    let state = ok(resolve_and_recover_cast_lock_state_v1(
        &cast_dir,
        &manifest_hex,
        &fingerprint,
        &artifacts,
    ));
    assert_eq!(state, GuiVoterCastLockStateV1::Cast);
    assert_eq!(
        package_digest_hex_of_path(&final_path, &artifacts),
        Some(digest)
    );
}

// -------------------------------------------------------------------------
// M1.5: destination filesystem-capability probe (FAT32/exFAT guard).
//
// The real export finalization uses `hard_link(verified_temp, final)`, which
// FAT32/exFAT and some network filesystems do not support. The probe runs
// BEFORE any durable PENDING cast record so an unsupported destination is
// rejected with the voter left NOT_CAST (no lock, no journal entry) and free
// to choose another location.
// -------------------------------------------------------------------------

// The pure classifier maps each error kind to a bounded user-facing code. This
// is deterministic and does not depend on the developer machine having a
// FAT32/exFAT drive attached.
#[test]
fn classify_cast_destination_probe_failure_maps_each_kind() {
    assert_eq!(
        classify_cast_destination_probe_failure_v1(&std::io::Error::from(
            std::io::ErrorKind::Unsupported
        ))
        .code(),
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
    );
    assert_eq!(
        classify_cast_destination_probe_failure_v1(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        ))
        .code(),
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
    );
    assert_eq!(
        classify_cast_destination_probe_failure_v1(&std::io::Error::from(
            std::io::ErrorKind::NotFound
        ))
        .code(),
        "GUI_FILE_NOT_FOUND",
    );
    // AlreadyExists reaching the raw classifier is an ambiguous probe outcome
    // (the phase-specific classifiers handle the meaningful AlreadyExists
    // cases), so it is reported as a probe failure, never as capability success
    // and never as a generic I/O error.
    assert_eq!(
        classify_cast_destination_probe_failure_v1(&std::io::Error::from(
            std::io::ErrorKind::AlreadyExists
        ))
        .code(),
        "GUI_BALLOT_EXPORT_PROBE_FAILED",
    );
    // Any other unexpected I/O failure is reported as a probe failure, not as
    // an unsupported filesystem, so the message never claims a filesystem
    // limitation when the cause may be transient.
    assert_eq!(
        classify_cast_destination_probe_failure_v1(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        ))
        .code(),
        "GUI_BALLOT_EXPORT_PROBE_FAILED",
    );
}

// Phase A requires ACTUAL hard_link success. An AlreadyExists on the NEW
// destination is NOT capability success — it is an unlikely name collision or a
// non-conforming filesystem and must fail closed. This is the core fix: the old
// probe falsely treated AlreadyExists as proof of support.
#[test]
fn phase_a_already_exists_is_not_capability_success() {
    // A real link created -> capability proven.
    assert!(classify_cast_destination_probe_phase_a_v1(&Ok(())).is_ok());

    // AlreadyExists on the NEW destination must NOT pass as success.
    assert_code(
        classify_cast_destination_probe_phase_a_v1(&Err(std::io::Error::from(
            std::io::ErrorKind::AlreadyExists,
        ))),
        "GUI_BALLOT_EXPORT_PROBE_FAILED",
    );

    // Unsupported filesystem -> destination unsupported (BEFORE PENDING).
    assert_code(
        classify_cast_destination_probe_phase_a_v1(&Err(std::io::Error::from(
            std::io::ErrorKind::Unsupported,
        ))),
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
    );

    // PermissionDenied -> destination unsupported.
    assert_code(
        classify_cast_destination_probe_phase_a_v1(&Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))),
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
    );

    // Other unexpected error -> probe failure (not success, not unsupported).
    assert_code(
        classify_cast_destination_probe_phase_a_v1(&Err(std::io::Error::from(
            std::io::ErrorKind::Interrupted,
        ))),
        "GUI_BALLOT_EXPORT_PROBE_FAILED",
    );
}

// Phase B verifies an existing target is never replaced. AlreadyExists is
// success; an unexpected Ok(()) (the filesystem would replace the target) must
// fail closed as unsupported.
#[test]
fn phase_b_existing_destination_must_not_be_replaced() {
    // Existing destination NOT replaced -> no-overwrite confirmed.
    assert!(
        classify_cast_destination_probe_phase_b_v1(&Err(std::io::Error::from(
            std::io::ErrorKind::AlreadyExists,
        )))
        .is_ok()
    );

    // The filesystem REPLACED an existing target -> fail closed (never allow a
    // no-overwrite violation through).
    assert_code(
        classify_cast_destination_probe_phase_b_v1(&Ok(())),
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
    );

    // Unsupported on Phase B -> destination unsupported.
    assert_code(
        classify_cast_destination_probe_phase_b_v1(&Err(std::io::Error::from(
            std::io::ErrorKind::Unsupported,
        ))),
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
    );
}

// Regression for the Phase A cleanup ownership race. The probe's chosen Phase A
// destination was nonexistent when chosen, but another process created a file
// there before our hard_link. Phase A must fail (AlreadyExists is NOT capability
// success) AND must NOT delete the raced file — cleanup ownership is armed only
// after hard_link Ok(()), so an unowned pathname is never touched.
#[test]
fn phase_a_raced_pathname_is_not_deleted_by_cleanup() {
    let dir = common::TestDir::new("cast-probe-race");
    // A probe source the helper can link from.
    let source = dir.join("probe-source");
    ok(std::fs::write(&source, b"probe source bytes"));

    // Reproduce the post-race state directly: the probe's chosen destination
    // was nonexistent when chosen, but another process won the race and created
    // a sentinel there before our hard_link. We pre-create that sentinel at the
    // exact destination path the helper will use.
    let raced_destination = dir.join("raced-destination");
    let sentinel = b"unrelated raced sentinel bytes".to_vec();
    ok(std::fs::write(&raced_destination, &sentinel));

    // Phase A sees the destination already exists -> AlreadyExists -> failure.
    // No guard is returned, so nothing is dropped and no cleanup runs.
    assert_code(
        probe_phase_a_create_link_v1(&source, &raced_destination),
        "GUI_BALLOT_EXPORT_PROBE_FAILED",
    );

    // The raced sentinel must remain present and byte-for-byte unchanged. This
    // is the core regression: the old code armed cleanup before hard_link and
    // would have deleted this file on the error-path drop.
    assert!(
        raced_destination.exists(),
        "raced sentinel must not be deleted by Phase A cleanup",
    );
    assert_eq!(
        ok(std::fs::read(&raced_destination)),
        sentinel,
        "raced sentinel bytes must remain unchanged",
    );
}

// Phase A success creates the link and the returned guard owns and removes it
// on drop. Ownership is unambiguous because the guard is armed only after
// hard_link Ok(()).
#[test]
fn phase_a_success_creates_and_cleans_up_owned_link() {
    let dir = common::TestDir::new("cast-probe-success-cleanup");
    let source = dir.join("probe-source");
    ok(std::fs::write(&source, b"probe source bytes"));
    // A genuinely nonexistent destination (simulating the normal probe path).
    let destination = dir.join("probe-destination");

    let guard = ok(probe_phase_a_create_link_v1(&source, &destination));
    // Phase A Ok means a real link was created at the destination.
    assert!(
        destination.exists(),
        "Phase A Ok means the link was created",
    );
    // Dropping the guard removes the link this process created and owns.
    drop(guard);
    assert!(
        !destination.exists(),
        "guard must clean up the link it created",
    );
}

// The live probe succeeds on a normal (NTFS / typical local) destination and
// leaves no probe artifacts behind.
#[test]
fn probe_succeeds_on_supported_destination_and_cleans_up() {
    let dir = common::TestDir::new("cast-probe-supported");
    let final_path = dir.join("ballot.cbor");

    ok(probe_cast_export_destination_supports_no_overwrite_v1(
        &final_path,
    ));

    // The probe must not leave any throwaway files in the destination dir.
    let leftovers = std::fs::read_dir(dir.path()).expect("destination dir must be readable");
    assert_eq!(
        leftovers.count(),
        0,
        "probe must clean up its throwaway files on success",
    );
}

// A non-existent destination directory is a deterministic, cross-platform
// probe failure: the probe reports it BEFORE PENDING and leaves no artifacts.
#[test]
fn probe_fails_when_destination_directory_is_missing() {
    let dir = common::TestDir::new("cast-probe-missing-dir");
    let final_path = dir.join("does-not-exist").join("ballot.cbor");

    let error = probe_cast_export_destination_supports_no_overwrite_v1(&final_path)
        .expect_err("probe must fail when the destination directory is missing");
    assert_eq!(error.code(), "GUI_FILE_NOT_FOUND");
}

// Full-path integration: a probe failure must refuse export BEFORE writing any
// durable PENDING cast record, leaving the voter NOT_CAST and still able to
// change the selection, prepare, and choose another destination.
#[test]
fn export_fails_before_pending_when_destination_probe_fails() {
    let dir = common::TestDir::new("cast-export-probe-fail");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let artifacts = artifacts_for_public_key(public_key, b"cast-probe-fail");
    let manifest_hex = manifest_hash_hex_of(&artifacts);
    let fingerprint = fingerprint_for(public_key);
    let mut session = eligible_session(&artifacts, credential);
    prepare_digest(&mut session, &artifacts, b"candidate-a");

    // Destination parent directory does not exist -> probe fails (NotFound)
    // before any durable state is written.
    let final_path = dir.join("missing-subdir").join("ballot.cbor");
    assert_code(
        session.export_and_cast_prepared_ballot(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &final_path,
            &cast_dir,
        ),
        "GUI_FILE_NOT_FOUND",
    );

    // No durable cast record was written; the voter is NOT cast.
    assert!(
        !ok(cast_record_exists_v1(
            &cast_dir,
            &manifest_hex,
            &fingerprint
        )),
        "no PENDING cast record may exist after a probe failure",
    );
    assert_eq!(
        session.cast_lock_state(),
        GuiVoterCastLockStateV1::NotCast,
        "a probe failure must not lock the voter",
    );
    assert!(
        !final_path.exists(),
        "no final ballot file may be created after a probe failure",
    );

    // The voter can still change the selection, prepare, and choose another
    // destination. (This is the whole point: unlike a post-PENDING failure on
    // FAT32, the voter is not trapped.)
    let digest_b = prepare_digest(&mut session, &artifacts, b"candidate-b");
    assert!(!digest_b.is_empty(), "voter can still prepare a ballot");
    let ok_dir = common::TestDir::new("cast-export-probe-fail-retry");
    let ok_cast_dir = ok_ensure_cast_dir(&ok_dir);
    ok(session.export_and_cast_prepared_ballot(
        &artifacts,
        ElectionLifecycleStateV1::Open,
        &ok_dir.join("ballot.cbor"),
        &ok_cast_dir,
    ));
    assert_eq!(session.cast_lock_state(), GuiVoterCastLockStateV1::Cast);
}

// A pre-existing final path must be refused BEFORE any durable cast state is
// written: the existing bytes are left unchanged, no cast record is created,
// and the voter stays NOT_CAST and can still change choice / prepare.
#[test]
fn export_refuses_pre_existing_final_path_before_pending() {
    let dir = common::TestDir::new("cast-export-preexisting-final");
    let cast_dir = ok_ensure_cast_dir(&dir);
    let credential = ok(VoterGovernanceCredentialV1::generate());
    let public_key = ok(credential.public_key_bytes());
    let artifacts = artifacts_for_public_key(public_key, b"cast-preexisting");
    let manifest_hex = manifest_hash_hex_of(&artifacts);
    let fingerprint = fingerprint_for(public_key);
    let mut session = eligible_session(&artifacts, credential);
    prepare_digest(&mut session, &artifacts, b"candidate-a");

    // An unrelated file already exists at the final path.
    let final_path = dir.join("ballot.cbor");
    let sentinel = b"unrelated pre-existing bytes".to_vec();
    ok(std::fs::write(&final_path, &sentinel));

    assert_code(
        session.export_and_cast_prepared_ballot(
            &artifacts,
            ElectionLifecycleStateV1::Open,
            &final_path,
            &cast_dir,
        ),
        "GUI_BALLOT_EXPORT_COLLISION",
    );

    // The existing file is byte-for-byte unchanged.
    assert_eq!(
        ok(std::fs::read(&final_path)),
        sentinel,
        "sentinel unchanged"
    );
    // No durable cast record was written.
    assert!(
        !ok(cast_record_exists_v1(
            &cast_dir,
            &manifest_hex,
            &fingerprint
        )),
        "no PENDING cast record may exist when the final path already exists",
    );
    assert_eq!(
        session.cast_lock_state(),
        GuiVoterCastLockStateV1::NotCast,
        "a pre-existing final path must not lock the voter",
    );

    // The voter can still change choice and prepare another ballot.
    let digest_b = prepare_digest(&mut session, &artifacts, b"candidate-b");
    assert!(
        !digest_b.is_empty(),
        "voter can still prepare after a collision"
    );
}

// -------------------------------------------------------------------------
// Helpers.
// -------------------------------------------------------------------------

fn eligible_session(
    artifacts: &GuiElectionArtifactsV1,
    credential: VoterGovernanceCredentialV1,
) -> GuiVoterSessionV1 {
    let mut session = GuiVoterSessionV1::new(artifacts);
    let status = ok(session.install_credential(credential, artifacts));
    assert!(status.can_continue, "credential must be eligible");
    session
}

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

fn ok_ensure_cast_dir(dir: &common::TestDir) -> std::path::PathBuf {
    let cast_dir = dir.join("voter-cast-locks");
    ok(tari_cc_private_ballot_gui_core::ensure_voter_cast_locks_directory_v1(&cast_dir));
    cast_dir
}

fn package_digest_hex_of_path(
    path: &std::path::Path,
    artifacts: &GuiElectionArtifactsV1,
) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let package = BallotPackageV1::from_canonical_cbor(
        &bytes,
        artifacts.candidates(),
        common::approval_limits(),
    )
    .ok()?;
    let digest = package.canonical_hash(&Blake3HashProviderV1).ok()?;
    Some(lower_hex(&digest))
}

fn verify_package(
    artifacts: &GuiElectionArtifactsV1,
    bytes: &[u8],
) -> Result<VerifiedApprovalBallotV1, ProtocolError> {
    let package = BallotPackageV1::from_canonical_cbor(
        bytes,
        artifacts.candidates(),
        common::approval_limits(),
    )?;
    let provider = Blake3HashProviderV1;
    let verifier = build_tari_triptych_verifier_from_registry_v1(artifacts.registry(), &provider)?;
    verify_approval_proof(
        artifacts.manifest(),
        package.payload(),
        package.proof(),
        &provider,
        &verifier,
    )
}

fn artifacts_for_public_key(public_key: [u8; 32], election_id: &[u8]) -> GuiElectionArtifactsV1 {
    let provider = Blake3HashProviderV1;
    let registry = registry_from_key(public_key);
    let candidates = common::candidate_set();
    let manifest = ok(ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id: ok(ElectionId::new(election_id.to_vec())),
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment: ok(registry.canonical_commitment(&provider)),
        candidate_set_commitment: ok(candidates.canonical_commitment(&provider)),
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: common::approval_limits(),
        governance_source_revision: "cast-lock-test".to_owned(),
    }));
    let manifest_bytes = ok(manifest.to_canonical_cbor());
    let candidate_bytes = ok(candidates.to_canonical_cbor());
    ok(GuiElectionArtifactsV1::from_bytes(
        &manifest_bytes,
        &registry_bytes_from_key(public_key),
        &candidate_bytes,
    ))
}

fn registry_from_key(public_key: [u8; 32]) -> RegistrySnapshot {
    ok(RegistrySnapshot::from_canonical_cbor(
        &registry_bytes_from_key(public_key),
    ))
}

fn registry_bytes_from_key(public_key: [u8; 32]) -> Vec<u8> {
    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(1).is_ok());
    assert!(writer.write_byte_string(&public_key).is_ok());
    writer.into_bytes()
}

fn open_lifecycle(artifacts: &GuiElectionArtifactsV1) -> ElectionLifecycleV1 {
    let mut lifecycle = ElectionLifecycleV1::new();
    assert!(
        lifecycle
            .freeze(artifacts.manifest_hash(), artifacts.registry_commitment())
            .is_ok()
    );
    assert!(lifecycle.open().is_ok());
    lifecycle
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

fn assert_code<T>(
    result: Result<T, tari_cc_private_ballot_gui_core::GuiCoreError>,
    expected: &str,
) {
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
