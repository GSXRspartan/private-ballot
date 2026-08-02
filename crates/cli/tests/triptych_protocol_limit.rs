//! Manual Triptych protocol-limit coverage.
//!
//! The ignored test validates the 4,096-member registry and Triptych parameter
//! boundary without generating 4,096 proofs. It also confirms that a 4,097-
//! member registry is rejected with the protocol-limit validation code.

use std::time::Instant;

use tari_cc_private_ballot_protocol::{
    CanonicalCborWriter, MAX_REGISTRY_MEMBERS, ValidationCode,
    test_only::TestOnlyDeterministicHasher,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::build_tari_triptych_verifier_from_registry_v1;

const COMPRESSED_POINT_BYTES: usize = 32;
const FIXTURE_KEYS: &[u8; MAX_REGISTRY_MEMBERS * COMPRESSED_POINT_BYTES] =
    include_bytes!("fixtures/triptych_public_keys_4096.bin");

#[test]
#[ignore = "manual 4096-member registry and Triptych parameter limit test"]
fn manual_triptych_protocol_limit_accepts_4096_and_rejects_4097_members() {
    let encoded_started = Instant::now();
    let encoded = canonical_registry_bytes();
    let encoded_elapsed = encoded_started.elapsed();

    let parse_started = Instant::now();
    let Ok(registry) = RegistrySnapshot::from_canonical_cbor(&encoded) else {
        panic!("4,096-member canonical registry must parse");
    };
    let parse_elapsed = parse_started.elapsed();

    assert_eq!(registry.len(), MAX_REGISTRY_MEMBERS);

    let provider = TestOnlyDeterministicHasher;
    let commitment_started = Instant::now();
    let Ok(commitment) = registry.canonical_commitment(&provider) else {
        panic!("4,096-member registry commitment must be derivable");
    };
    let commitment_elapsed = commitment_started.elapsed();

    let parameter_started = Instant::now();
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider) else {
        panic!("4,096-member registry must construct Triptych parameters");
    };
    let parameter_elapsed = parameter_started.elapsed();

    assert_eq!(verifier.registry_commitment(), commitment);

    let mut oversized = CanonicalCborWriter::new();
    assert!(oversized.write_array_len(MAX_REGISTRY_MEMBERS + 1).is_ok());

    let oversized_result = RegistrySnapshot::from_canonical_cbor(&oversized.into_bytes());

    assert!(matches!(
        oversized_result,
        Err(error) if error.code() == ValidationCode::ProtocolLimitExceeded
    ));

    println!(
        "triptych_protocol_limit members={} fixture_bytes={} registry_bytes={} \
         encode_ms={} parse_ms={} commitment_ms={} parameter_build_ms={}",
        MAX_REGISTRY_MEMBERS,
        FIXTURE_KEYS.len(),
        encoded.len(),
        encoded_elapsed.as_millis(),
        parse_elapsed.as_millis(),
        commitment_elapsed.as_millis(),
        parameter_elapsed.as_millis(),
    );
}

fn canonical_registry_bytes() -> Vec<u8> {
    let chunks = FIXTURE_KEYS.chunks_exact(COMPRESSED_POINT_BYTES);

    assert!(chunks.remainder().is_empty());
    assert_eq!(chunks.len(), MAX_REGISTRY_MEMBERS);

    let mut writer = CanonicalCborWriter::new();

    assert!(writer.write_array_len(MAX_REGISTRY_MEMBERS).is_ok());

    for key in chunks {
        assert!(writer.write_byte_string(key).is_ok());
    }

    writer.into_bytes()
}
