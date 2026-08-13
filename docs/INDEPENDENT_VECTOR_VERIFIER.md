# Independent Canonical Vector Verifier

## Purpose

`tools/independent_vector_verifier.py` is a dependency-free Python reference
verifier for the checked-in Phase 2 valid canonical vectors.

It provides a second implementation boundary for:

- strict deterministic CBOR parsing;
- schema-shape validation;
- decode and re-encode byte identity;
- lowercase hexadecimal agreement;
- domain-separated test-hash agreement;
- candidate-election and ballot-measure coverage.

## Independence boundary

The verifier uses only the Python standard library.

It does not import, link, execute, or bind to:

- `tari-cc-private-ballot-protocol`;
- `tari-cc-private-ballot-registry`;
- `tari-cc-private-ballot-ballot`;
- `tari-cc-private-ballot-archive`;
- `tari-cc-private-ballot-crypto`;
- `tari-cc-private-ballot-verifier`;
- any Rust canonical encoder or decoder.

The Python implementation reproduces the supported deterministic CBOR subset
and the explicit test-only hash framing directly from the published protocol
rules.

## Run the verifier

From the repository root:

```text
python -B tools/independent_vector_verifier.py --root . --check-report test-vectors/valid/independent-verification-v1.json
```

To regenerate the deterministic report:

```text
python -B tools/independent_vector_verifier.py --root . --report test-vectors/valid/independent-verification-v1.json
```

The `v1` suffix in `independent-verification-v1.json` and in the report schema
identifies the independent verification report format version. It does not mean
the report only covers `ElectionManifestV1` objects; the current report also
includes `ElectionManifestV2` cases.

Run its unit and repository tests with:

```text
python -B -m unittest discover -s tools -p "test_independent_vector_verifier.py" -v
```

These commands use no network access and require no third-party Python
packages.

## Verified object families

The current verifier covers:

1. registry snapshots;
2. selectable-option candidate sets;
3. approval ballot payloads;
4. election manifests;
5. version-two election manifests with a hash-bound proposal question;
6. proof-bearing ballot packages;
7. archive manifests.

The published decision examples cover both:

- candidate elections;
- ballot measures.

## Canonicality checks

The verifier independently enforces:

- shortest unsigned-integer and length encodings;
- definite-length byte strings, text strings, arrays, and maps;
- valid UTF-8 text;
- complete input consumption;
- deterministic map-key order where maps occur;
- exact schema array lengths and field types;
- version-two proposal-question bounds without trimming or normalization;
- canonical ordering for registries, selectable options, approvals, and archive
  paths;
- nested canonical approval payloads inside ballot packages.

## Test-only warning

The checked-in proof suite remains:

`TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS`

The checked-in hash provider remains:

`TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC`

The verifier proves deterministic cross-implementation agreement for test
plumbing. It does not establish cryptographic integrity, anonymous eligibility,
authorization, or suitability for binding elections.
