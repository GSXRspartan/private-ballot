# Security Policy

## Supported Status

Private Ballot is v0.1.0 Alpha independent open-source software for
non-binding governance pilots on Esmeralda testnet. It is not production
election software.

## Sensitive Material

Never disclose or attach:

- voter credential files or passphrases;
- walletd API keys, wallet databases, account state, seeds, or mnemonics;
- Tor onion-service keys or transport authority private keys;
- live election archives unless explicitly sanitized and approved;
- LocalAppData runtime state or Ootle evidence sidecars from a real run.

## Reporting

Before a public repository exists, report vulnerabilities directly to the
maintainer out of band. After publication, this file should be updated with the
canonical private reporting address or GitHub Security Advisories process.

## Threat Model

The finalized archive is the authoritative verification artifact. Ootle
anchoring is optional, organizer-side, fee-bearing, and limited to public
aggregate evidence. Voters never submit Ootle transactions through this app.

The current transport and privacy limits are documented in
`docs/transport/PRIVATE_BALLOT_TRANSPORT_THREAT_MODEL_V1.md`. In particular,
network anonymity depends on route choice, operator logging, Tor assumptions,
and timing/volume characteristics; it is not a blanket promise that nobody can
correlate participation.

## Public Release Gate

Before GitHub publication, confirm:

- no live archives, sidecars, credentials, wallet state, Tor keys, or private
  transport material are tracked or staged;
- root-level scratch/handoff/audit files have been intentionally curated;
- a project license and third-party attribution policy are selected;
- Windows release binaries have documented hashes and provenance;
- Linux and macOS builds have been tested separately.
