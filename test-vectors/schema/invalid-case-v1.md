# Invalid CBOR vector schema V1

Each case directory contains five files.

## `description.md`

Human-readable intent and the expected rejection classification.

## `input.json`

Metadata describing:

- schema identifier;
- stable vector identifier;
- decoder target;
- encoding;
- byte length.

## `invalid.cbor`

Exact hostile bytes supplied to the selected decoder.

## `invalid.hex`

Lowercase hexadecimal rendering of `invalid.cbor` with no separators.

## `expected.json`

Expected outcome containing:

- `accepted: false`;
- exact stable `expected_rejection_code`;
- the same decoder target used by `input.json`.

A test must compare the binary and hexadecimal forms and must assert the exact
`ValidationCode`, not merely that some error occurred.
