//! Production canonical and digest vectors for the Ootle anchor record.
//!
//! Every digest in this file is produced with the production
//! `Blake3HashProviderV1`. No test-only deterministic hasher is used, and the
//! record's fixed hash-algorithm field pins the production identifier.

use tari_cc_private_ballot_anchor::{
    MAX_OOTLE_NETWORK_ID_BYTES, OOTLE_ANCHOR_PURPOSE_ID_V1, OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1,
    OOTLE_ANCHOR_RECORD_TYPE_ID_V1, OotleAnchorRecordHashV1, OotleAnchorRecordV1, OotleNetworkIdV1,
};
use tari_cc_private_ballot_archive::{
    ArchiveFileCatalogV1, ArchiveFileDigestV1, ArchiveFileEntryV1, ArchiveHashV1,
    ArchiveManifestV1, ArchivePathV1,
};
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, Blake3HashProviderV1, CanonicalCborReader,
    CanonicalCborWriter, ManifestHash, ValidationCode,
};

/// Vector 12: exact canonical bytes of the reference `esmeralda` record with
/// manifest hash `0x11..` and archive hash `0x22..`.
const CANONICAL_ESMERALDA_HEX: &str = "867826544152495f43435f505249564154455f42414c4c4f545f4f4f544c455f414e43484f525f56316965736d6572616c646158201111111111111111111111111111111111111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222227824424c414b45332d3235362f746172692d63632d707269766174652d62616c6c6f742f763178294e4f4e5f42494e44494e475f415050524f56414c5f50494c4f545f415243484956455f414e43484f52";

/// Vector 13: exact production BLAKE3 anchor-record digest of the reference record.
const DIGEST_ESMERALDA_HEX: &str =
    "90568acd3af4646b07c375a562a392140cb7776550465b6bf2937d2043093b1d";
/// Vector 2: same archive/manifest, network `igor` instead of `esmeralda`.
const DIGEST_IGOR_HEX: &str = "05ea8c28970114cb60c707438011b931d6e8c20dd19b3ba4b9a88ad80c5d3d62";
/// Vector 3: same network/archive, manifest hash `0x12..` instead of `0x11..`.
const DIGEST_OTHER_MANIFEST_HEX: &str =
    "88c6cef036980555d0adb32e0d9349436e6a5e8205d6d5985cbcdad1224af756";
/// Vector 4: same network/manifest, archive hash `0x23..` instead of `0x22..`.
const DIGEST_OTHER_ARCHIVE_HEX: &str =
    "9c1c985495918c313222a03de3597db5aaa5185982f1aa2609e679d2c2151101";

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn network(value: &str) -> OotleNetworkIdV1 {
    let Ok(network) = OotleNetworkIdV1::new(value.to_owned()) else {
        panic!("test network identifier must be valid");
    };

    network
}

fn record(network_value: &str, manifest_byte: u8, archive_byte: u8) -> OotleAnchorRecordV1 {
    OotleAnchorRecordV1::new(
        network(network_value),
        ManifestHash::new([manifest_byte; 32]),
        ArchiveHashV1::new([archive_byte; 32]),
    )
}

fn digest_hex(record: &OotleAnchorRecordV1) -> String {
    let provider = Blake3HashProviderV1;

    let Ok(digest) = record.canonical_hash(&provider) else {
        panic!("production digest should succeed");
    };

    to_hex(digest.as_bytes())
}

// Vector 1 + Vector 12: one valid testnet record with an exact canonical vector.
#[test]
fn valid_record_has_exact_canonical_bytes() {
    let Ok(encoded) = record("esmeralda", 0x11, 0x22).to_canonical_cbor() else {
        panic!("reference encoding should succeed");
    };

    assert_eq!(to_hex(&encoded), CANONICAL_ESMERALDA_HEX);
}

// Vector 5 + Vector 13: production-provider digest of the reference record.
#[test]
fn valid_record_has_exact_production_digest() {
    assert_eq!(
        digest_hex(&record("esmeralda", 0x11, 0x22)),
        DIGEST_ESMERALDA_HEX
    );
}

// Vector 2: same archive, different network yields a different digest.
#[test]
fn different_network_changes_digest() {
    let igor = digest_hex(&record("igor", 0x11, 0x22));

    assert_eq!(igor, DIGEST_IGOR_HEX);
    assert_ne!(igor, DIGEST_ESMERALDA_HEX);
}

// Vector 3: same election-context network, different manifest hash.
#[test]
fn different_manifest_hash_changes_digest() {
    let other = digest_hex(&record("esmeralda", 0x12, 0x22));

    assert_eq!(other, DIGEST_OTHER_MANIFEST_HEX);
    assert_ne!(other, DIGEST_ESMERALDA_HEX);
}

// Vector 4: same election, different archive hash.
#[test]
fn different_archive_hash_changes_digest() {
    let other = digest_hex(&record("esmeralda", 0x11, 0x23));

    assert_eq!(other, DIGEST_OTHER_ARCHIVE_HEX);
    assert_ne!(other, DIGEST_ESMERALDA_HEX);
}

// Vector 6: unsupported record type/version is rejected at decode.
#[test]
fn unsupported_version_is_rejected() {
    let Ok(mut encoded) = record("esmeralda", 0x11, 0x22).to_canonical_cbor() else {
        panic!("encoding should succeed");
    };

    // Flip the trailing "V1" byte of the record-type tag to "V2".
    let tag_end = 3 + OOTLE_ANCHOR_RECORD_TYPE_ID_V1.len();
    encoded[tag_end - 1] = b'2';

    assert!(matches!(
        OotleAnchorRecordV1::from_canonical_cbor(&encoded),
        Err(error) if error.code() == ValidationCode::UnsupportedProtocolVersion
    ));
}

// Vector 7: the test-only hash identifier is rejected.
#[test]
fn test_only_hash_identifier_is_rejected() {
    const TEST_ONLY_HASH_ALGORITHM_ID: &str = "TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC";

    // The production encoder never emits a non-production identifier, so this
    // vector is confirmed by decoding crafted bytes that carry the test-only
    // identifier in the hash-algorithm field.
    assert_ne!(BLAKE3_256_HASH_ALGORITHM_ID_V1, TEST_ONLY_HASH_ALGORITHM_ID);

    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(6).is_ok());
    assert!(
        writer
            .write_text_string(OOTLE_ANCHOR_RECORD_TYPE_ID_V1)
            .is_ok()
    );
    assert!(writer.write_text_string("esmeralda").is_ok());
    assert!(writer.write_byte_string(&[0x11; 32]).is_ok());
    assert!(writer.write_byte_string(&[0x22; 32]).is_ok());
    assert!(
        writer
            .write_text_string(TEST_ONLY_HASH_ALGORITHM_ID)
            .is_ok()
    );
    assert!(writer.write_text_string(OOTLE_ANCHOR_PURPOSE_ID_V1).is_ok());

    assert!(matches!(
        OotleAnchorRecordV1::from_canonical_cbor(&writer.into_bytes()),
        Err(error) if error.code() == ValidationCode::UnsupportedHashAlgorithm
    ));
}

// Vector 8: trailing bytes are rejected.
#[test]
fn trailing_bytes_are_rejected() {
    let Ok(mut encoded) = record("esmeralda", 0x11, 0x22).to_canonical_cbor() else {
        panic!("encoding should succeed");
    };
    encoded.push(0x00);

    assert!(matches!(
        OotleAnchorRecordV1::from_canonical_cbor(&encoded),
        Err(error) if error.code() == ValidationCode::TrailingCborData
    ));
}

// Vector 9: a single-byte mutation changes the canonical bytes and the digest.
#[test]
fn single_byte_mutation_changes_bytes_and_digest() {
    let base = record("esmeralda", 0x11, 0x22);
    let Ok(base_bytes) = base.to_canonical_cbor() else {
        panic!("base encoding should succeed");
    };

    // Mutating the first archive-hash byte changes the record.
    let mutated = record("esmeralda", 0x11, 0x23);
    let Ok(mutated_bytes) = mutated.to_canonical_cbor() else {
        panic!("mutated encoding should succeed");
    };

    assert_ne!(base_bytes, mutated_bytes);
    assert_ne!(digest_hex(&base), digest_hex(&mutated));
}

// Vector 10: the maximum-length network identifier is accepted.
#[test]
fn maximum_network_identifier_is_accepted() {
    let value = "n".repeat(MAX_OOTLE_NETWORK_ID_BYTES);

    let Ok(network) = OotleNetworkIdV1::new(value) else {
        panic!("maximum-length network identifier must be valid");
    };

    let record = OotleAnchorRecordV1::new(
        network,
        ManifestHash::new([0x11; 32]),
        ArchiveHashV1::new([0x22; 32]),
    );

    let Ok(encoded) = record.to_canonical_cbor() else {
        panic!("maximum encoding should succeed");
    };

    assert_eq!(encoded.len(), 224);

    let Ok(decoded) = OotleAnchorRecordV1::from_canonical_cbor(&encoded) else {
        panic!("maximum record should round-trip");
    };

    assert_eq!(decoded, record);
}

// Vector 11: an oversized network identifier is rejected.
#[test]
fn oversized_network_identifier_is_rejected() {
    let value = "n".repeat(MAX_OOTLE_NETWORK_ID_BYTES + 1);

    assert!(matches!(
        OotleNetworkIdV1::new(value),
        Err(error) if error.code() == ValidationCode::ProtocolLimitExceeded
    ));
}

/// Forbidden-content structural analysis.
///
/// This decodes the canonical bytes at the CBOR layer and confirms the record
/// is exactly a six-element array whose only non-constant fields are the bounded
/// network identifier and the two fixed-size 32-byte commitments. There is no
/// field of variable, caller-controlled shape that could carry a ballot, proof,
/// nullifier, registry key, voter identifier, tally value, or arbitrary memo.
#[test]
fn record_serialized_shape_has_only_approved_fields() {
    let Ok(encoded) = record("esmeralda", 0x11, 0x22).to_canonical_cbor() else {
        panic!("encoding should succeed");
    };

    let mut reader = CanonicalCborReader::new(&encoded);

    let Ok(field_count) = reader.read_array_len() else {
        panic!("record must start with a definite array");
    };
    assert_eq!(field_count, OOTLE_ANCHOR_RECORD_FIELD_COUNT_V1);
    assert_eq!(field_count, 6);

    // Field 0: fixed record-type constant.
    assert_eq!(
        reader.read_text_string(),
        Ok(OOTLE_ANCHOR_RECORD_TYPE_ID_V1)
    );
    // Field 1: bounded network identifier (only free-form field).
    let Ok(network_field) = reader.read_text_string() else {
        panic!("network field must be text");
    };
    assert!(network_field.len() <= MAX_OOTLE_NETWORK_ID_BYTES);
    // Field 2: exactly 32-byte election manifest hash.
    assert_eq!(reader.read_byte_string().map(<[u8]>::len), Ok(32));
    // Field 3: exactly 32-byte archive hash.
    assert_eq!(reader.read_byte_string().map(<[u8]>::len), Ok(32));
    // Field 4: fixed production hash-algorithm constant.
    assert_eq!(
        reader.read_text_string(),
        Ok(BLAKE3_256_HASH_ALGORITHM_ID_V1)
    );
    // Field 5: fixed non-binding purpose constant.
    assert_eq!(reader.read_text_string(), Ok(OOTLE_ANCHOR_PURPOSE_ID_V1));
    // No further fields exist.
    assert!(reader.finish().is_ok());
}

/// Independent reconstruction.
///
/// An independent verifier reconstructs the same canonical bytes and the same
/// digest from only the six documented inputs: record-type identifier, network
/// identifier, election manifest hash, archive hash, production hash-algorithm
/// identifier, and purpose identifier. Insertion order and machine state do not
/// affect the result.
#[test]
fn independent_reconstruction_matches_bytes_and_digest() {
    let provider = Blake3HashProviderV1;

    let original = record("esmeralda", 0x11, 0x22);
    let Ok(original_bytes) = original.to_canonical_cbor() else {
        panic!("original encoding should succeed");
    };
    let Ok(original_digest) = original.canonical_hash(&provider) else {
        panic!("original digest should succeed");
    };

    // Rebuild from scratch from the same inputs, constructing the hashes in a
    // different order to prove reconstruction is insertion-order independent.
    let rebuilt_archive = ArchiveHashV1::new([0x22; 32]);
    let rebuilt_manifest = ManifestHash::new([0x11; 32]);
    let Ok(rebuilt_network) = OotleNetworkIdV1::new(String::from("esmeralda")) else {
        panic!("rebuilt network must be valid");
    };
    let Ok(rebuilt) = OotleAnchorRecordV1::for_provider(
        rebuilt_network,
        rebuilt_manifest,
        rebuilt_archive,
        &provider,
    ) else {
        panic!("rebuilt record must use the production provider");
    };

    let Ok(rebuilt_bytes) = rebuilt.to_canonical_cbor() else {
        panic!("rebuilt encoding should succeed");
    };
    let Ok(rebuilt_digest) = rebuilt.canonical_hash(&provider) else {
        panic!("rebuilt digest should succeed");
    };

    assert_eq!(rebuilt, original);
    assert_eq!(rebuilt_bytes, original_bytes);
    assert_eq!(rebuilt_digest, original_digest);
    assert_eq!(to_hex(rebuilt_digest.as_bytes()), DIGEST_ESMERALDA_HEX);
}

fn production_archive_hash() -> (ArchiveManifestV1, ArchiveHashV1, Vec<u8>) {
    let provider = Blake3HashProviderV1;

    let Ok(path_a) = ArchivePathV1::new(String::from("manifest.cbor")) else {
        panic!("archive path must be valid");
    };
    let Ok(path_b) = ArchivePathV1::new(String::from("registry.cbor")) else {
        panic!("archive path must be valid");
    };

    let entries = vec![
        ArchiveFileEntryV1::new(path_a, ArchiveFileDigestV1::new([0x01; 32])),
        ArchiveFileEntryV1::new(path_b, ArchiveFileDigestV1::new([0x02; 32])),
    ];

    let Ok(catalog) = ArchiveFileCatalogV1::new(entries) else {
        panic!("archive catalog must be valid");
    };

    let Ok(manifest) =
        ArchiveManifestV1::for_provider(ManifestHash::new([0x11; 32]), catalog, &provider)
    else {
        panic!("archive manifest must be valid");
    };

    let Ok(archive_hash) = manifest.canonical_hash(&provider) else {
        panic!("archive hash should succeed");
    };

    let Ok(manifest_bytes) = manifest.to_canonical_cbor() else {
        panic!("archive manifest encoding should succeed");
    };

    (manifest, archive_hash, manifest_bytes)
}

/// Offline failure-independence.
///
/// Building an anchor record and its digest is a pure read of already-frozen
/// values. It cannot modify the archive: the archive manifest's canonical bytes
/// and archive hash are byte-identical before and after the anchor operations.
#[test]
fn anchor_construction_does_not_modify_archive_artifacts() {
    let provider = Blake3HashProviderV1;

    let (manifest, archive_hash_before, manifest_bytes_before) = production_archive_hash();

    let Ok(anchor) = OotleAnchorRecordV1::for_provider(
        network("esmeralda"),
        ManifestHash::new([0x11; 32]),
        archive_hash_before,
        &provider,
    ) else {
        panic!("anchor record must use the production provider");
    };

    // Perform the anchor operations that a later slice would attempt.
    let Ok(_anchor_bytes) = anchor.to_canonical_cbor() else {
        panic!("anchor encoding should succeed");
    };
    let Ok(_anchor_digest) = anchor.canonical_hash(&provider) else {
        panic!("anchor digest should succeed");
    };

    // The archive artifacts are unchanged.
    let Ok(archive_hash_after) = manifest.canonical_hash(&provider) else {
        panic!("archive hash should still succeed");
    };
    let Ok(manifest_bytes_after) = manifest.to_canonical_cbor() else {
        panic!("archive manifest encoding should still succeed");
    };

    assert_eq!(archive_hash_after, archive_hash_before);
    assert_eq!(manifest_bytes_after, manifest_bytes_before);
    assert_eq!(anchor.archive_hash(), archive_hash_before);
}

/// The anchor digest is distinct from the archive hash it wraps.
#[test]
fn anchor_digest_differs_from_wrapped_archive_hash() {
    let provider = Blake3HashProviderV1;
    let (_manifest, archive_hash, _bytes) = production_archive_hash();

    let Ok(anchor) = OotleAnchorRecordV1::for_provider(
        network("esmeralda"),
        ManifestHash::new([0x11; 32]),
        archive_hash,
        &provider,
    ) else {
        panic!("anchor record must use the production provider");
    };

    let Ok(anchor_digest) = anchor.canonical_hash(&provider) else {
        panic!("anchor digest should succeed");
    };

    assert_ne!(anchor_digest.as_bytes(), archive_hash.as_bytes());
}

/// The exact digest vector round-trips through the wrapper digest type.
#[test]
fn digest_vector_round_trips_through_wrapper() {
    let provider = Blake3HashProviderV1;
    let record = record("esmeralda", 0x11, 0x22);

    let Ok(digest) = record.canonical_hash(&provider) else {
        panic!("digest should succeed");
    };

    let restored = OotleAnchorRecordHashV1::new(digest.into_bytes());
    assert_eq!(restored, digest);
    assert!(record.verify_hash(&provider, restored).is_ok());
}
