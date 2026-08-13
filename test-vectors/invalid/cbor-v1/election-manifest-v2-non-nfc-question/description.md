# election-manifest-v2-non-nfc-question

The proposal question uses a decomposed accent and must be rejected without NFC normalization.

- Object family: `election-manifest-v2`
- Decoder target: `ElectionManifestV2::from_canonical_cbor`
- Expected rejection code: `NON_NFC_PROPOSAL_QUESTION`
- Encoded byte length: 199
