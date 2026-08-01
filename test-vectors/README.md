# Phase 2 protocol test vectors

This directory contains public deterministic vectors for the offline private
ballot protocol.

The first published corpus is `invalid/cbor-v1`. It contains hostile canonical
CBOR inputs consumed by a Rust integration test outside the crates that
implement the corresponding decoders.

Directory profile:

```text
test-vectors/
  README.md
  COVERAGE.md
  schema/
  invalid/
    cbor-v1/
```

Each invalid CBOR case contains:

```text
description.md
input.json
invalid.cbor
invalid.hex
expected.json
```

`invalid.cbor` is authoritative. `invalid.hex` is a human-readable rendering of
the same bytes. Invalid objects do not receive protocol hashes because decoding
must fail before an object becomes authoritative.

These vectors use no voter identity, wallet address, network address, device
identifier, client fingerprint, receipt timestamp, private key, wallet seed, or
other transport metadata.
