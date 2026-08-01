# Valid canonical vector schema V1

Each valid canonical case contains six files.

## `description.md`

Human-readable intent and the canonical object family.

## `input.json`

Presentation metadata describing:

- schema identifier;
- stable vector identifier;
- canonical object family;
- intentionally noncanonical constructor input order, when applicable.

JSON is not authoritative protocol data.

## `canonical.cbor`

Exact authoritative deterministic CBOR bytes.

## `canonical.hex`

Lowercase hexadecimal rendering of `canonical.cbor`, with no separators.

## `expected.json`

Expected successful decode information containing:

- `accepted: true`;
- decoder target;
- canonical byte length;
- deterministic CBOR profile identifier.

## `expected-hashes.json`

Exact domain-separated digest metadata containing:

- test hash-provider identifier;
- versioned hash-domain label;
- lowercase raw digest bytes rendered as hexadecimal.

The current hash provider is explicitly non-cryptographic and is used only for deterministic Phase 2 plumbing. These vectors do not establish production anonymity, authorization, or binding-election suitability.
