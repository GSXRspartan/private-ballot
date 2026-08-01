# trailing-registry-data

A valid one-member registry is followed by an unrelated trailing byte.

- Decoder target: `registry-snapshot`
- Expected rejection code: `TRAILING_CBOR_DATA`
- Encoded byte length: 4
