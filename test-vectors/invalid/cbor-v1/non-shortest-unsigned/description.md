# non-shortest-unsigned

Unsigned integer 23 is encoded using an unnecessary additional byte.

- Decoder target: `generic-unsigned`
- Expected rejection code: `NON_CANONICAL_CBOR`
- Encoded byte length: 2
