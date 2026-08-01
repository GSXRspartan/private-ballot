# Semantic rejection corpus V1

This corpus exercises deterministic protocol failures that require constructed
version-one objects, lifecycle state, proof-verification state, replay state, or
archive hash state.

Each case contains:

```text
description.md
scenario.json
expected.json
```

Unlike the hostile CBOR corpus, these cases do not claim that `scenario.json`
is an authoritative protocol object. The Rust integration harness constructs
the scenario exclusively through published crate APIs and compares the exact
stable `ValidationCode`.

The corpus contains no voter identity, wallet address, network address, device
identifier, private key, wallet seed, authorization header, or receipt
timestamp.
