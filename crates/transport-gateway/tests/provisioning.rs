//! Provisioning / intake validation regression tests (managed-tor only).
//!
//! These prove the gateway receiver secret loaded from
//! `gateway-receiver-secret.bin` is proven against the bundle manifest AND the
//! signed descriptor by DERIVING the public key from the actual secret. A
//! mutated secret file (with manifest + descriptor unchanged) must fail closed
//! before any Tor/collector service start.
//!
//! No real Tor, no network.

#![cfg(feature = "managed-tor")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../gui-core/tests/common/mod.rs"]
mod common;

use tari_cc_private_ballot_gui_core::GuiElectionArtifactsV1;
use tari_cc_private_ballot_transport_gateway::{
    IntakeValidationErrorV1, ProvisioningErrorV1, TransportElectionBindingV1,
    generate_transport_authority_material_v1, load_organizer_private_bundle_v1,
    provision_organizer_transport_bundles_v1, validate_intake_startup_v1,
};

const GOOD_ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

fn unique_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tari-private-ballot-provision-regression-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test dir");
    dir
}

/// Provisions a valid organizer bundle bound to the canonical common-module
/// election artifacts, returning the test root and the artifacts.
fn provision_valid_bundle(
    label: &str,
) -> (
    std::path::PathBuf,
    GuiElectionArtifactsV1,
    TransportElectionBindingV1,
) {
    let dir = unique_dir(label);
    let artifacts = common::artifacts();
    let election_id = artifacts.manifest().election_id().as_bytes().to_vec();
    let manifest_hash = artifacts.manifest_hash().as_bytes().to_owned();
    let binding = TransportElectionBindingV1 {
        election_id,
        manifest_hash,
    };
    let material = generate_transport_authority_material_v1("provision-regression-root".to_owned())
        .expect("material");
    provision_organizer_transport_bundles_v1(
        &dir.join("organizer-private"),
        &dir.join("voter-public-bundle.cbor"),
        &material,
        &binding,
        GOOD_ONION.to_owned(),
        &dir.join("tor-data"),
        &dir.join("hs-dir"),
    )
    .expect("provision");
    (dir, artifacts, binding)
}

/// A valid bundle loads and passes full intake startup validation (positive
/// control proving the repair did not break the happy path).
#[test]
fn valid_bundle_loads_and_validates_intake_startup() {
    let (dir, artifacts, _binding) = provision_valid_bundle("valid-load");
    let loaded =
        load_organizer_private_bundle_v1(&dir.join("organizer-private")).expect("valid load");
    validate_intake_startup_v1(&loaded, &artifacts, Some(GOOD_ONION))
        .expect("valid bundle passes intake startup validation");
}

/// Mutating gateway-receiver-secret.bin while leaving the bundle manifest and
/// descriptor unchanged MUST fail closed at load time, before any Tor/collector
/// service start. This proves the ACTUAL secret-derived public key mismatch is
/// caught — not merely a manifest-vs-descriptor comparison.
#[test]
fn mutated_gateway_secret_fails_closed_at_load_before_network() {
    let (dir, _artifacts, _binding) = provision_valid_bundle("mutated-secret");
    let secret_path = dir
        .join("organizer-private")
        .join("gateway-receiver-secret.bin");
    let mut secret = std::fs::read(&secret_path).expect("read secret");
    assert_eq!(secret.len(), 32, "gateway receiver secret is 32 bytes");
    // Flip a bit that survives X25519 scalar clamping (clamping clears the low
    // 3 bits of byte 0 and forces bit 254, so flip a mid-byte bit). This changes
    // the derived public key while leaving the manifest and descriptor files
    // byte-for-byte unchanged.
    secret[15] ^= 0x01;
    std::fs::write(&secret_path, &secret).expect("write mutated secret");

    let result = load_organizer_private_bundle_v1(&dir.join("organizer-private"));
    assert!(
        matches!(result, Err(ProvisioningErrorV1::MalformedBundle)),
        "a mutated gateway secret must fail closed at load time before any network startup"
    );
}

/// Even if the manifest-stored public key somehow disagreed with the
/// descriptor, the secret-derived key is the authoritative comparison in
/// validate_intake_startup_v1. We prove the validation path also catches a
/// secret/descriptor mismatch by loading a valid bundle, then validating
/// against a descriptor with a DIFFERENT gateway public key. (The load-time
/// manifest check already covers the mutated-secret case above; this covers
/// the descriptor-side comparison in validate_intake_startup_v1.)
#[test]
fn validate_intake_startup_catches_descriptor_gateway_key_mismatch() {
    let (dir, artifacts, _binding) = provision_valid_bundle("descriptor-mismatch");
    let mut loaded =
        load_organizer_private_bundle_v1(&dir.join("organizer-private")).expect("valid load");
    // Replace the descriptor with one carrying a different gateway public key
    // but otherwise valid for the same election. This simulates a descriptor
    // whose gateway key disagrees with the actual secret.
    use hpke::{Kem as KemTrait, Serializable, kem::X25519HkdfSha256};
    use tari_cc_private_ballot_gui_core::{
        BatchPolicyV1, PaddingPolicyV1, TransportDescriptorV1, TransportRoutePolicyV1,
    };
    type Kem = X25519HkdfSha256;
    let (_other_secret, other_public) = Kem::gen_keypair();
    let mut other_gateway = [0u8; 32];
    other_gateway.copy_from_slice(other_public.to_bytes().as_slice());
    let authority = loaded.material.root_signing_key.clone();
    let receipt_key = loaded.material.receipt_signing_key.clone();
    let manifest_hash = loaded.binding.manifest_hash;
    let wrong_descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
        loaded.binding.election_id.clone(),
        tari_cc_private_ballot_protocol::ManifestHash::new(manifest_hash),
        1,
        TransportRoutePolicyV1::ManagedTorOrOffline,
        vec![GOOD_ONION.to_owned()],
        Vec::new(),
        other_gateway,
        "wrong-gateway".to_owned(),
        vec![receipt_key.verifying_key().to_bytes()],
        PaddingPolicyV1 {
            id: "fixed-mismatch".to_owned(),
            padded_bytes: 2048,
        },
        BatchPolicyV1 {
            id: "accepted-1".to_owned(),
            accepted_unique_floor: 1,
        },
        None,
        loaded.descriptor.root_key_id().to_owned(),
        &authority,
    )
    .expect("wrong descriptor");
    loaded.descriptor = wrong_descriptor;
    let result = validate_intake_startup_v1(&loaded, &artifacts, Some(GOOD_ONION));
    assert!(
        matches!(result, Err(IntakeValidationErrorV1::WrongGatewayKey)),
        "a descriptor whose gateway key differs from the actual secret must fail, got {result:?}"
    );
}
