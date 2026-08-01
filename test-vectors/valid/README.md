# Valid Phase 2 canonical vectors

This directory contains authoritative deterministic CBOR vectors that must decode and re-encode byte-for-byte.

The first valid corpus is `canonical-v1` and begins with three currently implemented core object families:

- registry snapshots;
- candidate sets used for general governance options;
- approval-ballot payloads.

Each case follows `test-vectors/schema/valid-case-v1.md`.

`canonical.cbor` is authoritative. JSON, Markdown, and hexadecimal files are presentation artifacts.

The committed hash metadata currently uses:

`TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC`

That provider is deterministic test plumbing only. It does not establish cryptographic security, anonymous eligibility, or suitability for binding elections.
