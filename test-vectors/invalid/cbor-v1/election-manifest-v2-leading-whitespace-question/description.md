# election-manifest-v2-leading-whitespace-question

The proposal question starts with whitespace and must be rejected exactly as supplied.

- Object family: `election-manifest-v2`
- Decoder target: `ElectionManifestV2::from_canonical_cbor`
- Expected rejection code: `INVALID_PROPOSAL_QUESTION`
- Encoded byte length: 202
