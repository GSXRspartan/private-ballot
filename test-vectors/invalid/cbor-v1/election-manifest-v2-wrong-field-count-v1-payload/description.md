# election-manifest-v2-wrong-field-count-v1-payload

A valid nine-field ElectionManifestV1-shaped payload is presented to the ElectionManifestV2 decoder.

- Object family: `election-manifest-v2`
- Decoder target: `ElectionManifestV2::from_canonical_cbor`
- Expected rejection code: `INVALID_CBOR`
- Encoded byte length: 191
