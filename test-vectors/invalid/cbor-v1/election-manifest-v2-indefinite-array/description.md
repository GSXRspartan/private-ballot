# election-manifest-v2-indefinite-array

The top-level ElectionManifestV2 array uses CBOR indefinite length and must be rejected before canonicalization.

- Object family: `election-manifest-v2`
- Decoder target: `ElectionManifestV2::from_canonical_cbor`
- Expected rejection code: `NON_CANONICAL_CBOR`
- Encoded byte length: 228
