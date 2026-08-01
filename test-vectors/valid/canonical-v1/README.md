# Canonical V1 valid decision vectors

This directory contains authoritative deterministic CBOR fixtures for the currently implemented public, non-binding approval protocol.

The protocol is intentionally exercised as two product scenarios:

1. **Candidate election**
   - stable candidate identifiers;
   - separate human-readable candidate names;
   - one or more approved candidates;
   - optional abstention through an empty approval payload.

2. **Ballot measure**
   - stable `approve` and `reject` option identifiers;
   - a single selected position;
   - optional abstention through an empty approval payload.

The current Rust type name `CandidateSet` represents the canonical selectable-option set for both scenarios. It does not limit the product to candidate elections.

Published object families in this directory include:

- registry snapshots;
- selectable-option sets;
- approval payloads;
- election manifests;
- proof-bearing ballot packages;
- archive manifests.

Each case follows `test-vectors/schema/valid-case-v1.md`.

`canonical.cbor` is authoritative. JSON, Markdown, and hexadecimal files are presentation artifacts.

All decision vectors remain public, non-binding pilot fixtures. Ballot-package proofs use:

`TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS`

All hashes use:

`TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC`

Neither test provider establishes anonymity, production authorization, cryptographic integrity, or suitability for binding elections.
