# START HERE

This repository is the starting point for the Tari CC Private Ballot project.

## Current status

- Phase 0: repository bootstrap — complete
- Phase 1: protocol/threat-model draft — active, not yet approved
- Phase 2: offline Rust reference implementation — not started
- Phase 3: harmless non-binding pilot — not started
- Phase 4: Tari Ootle testnet anchor — not started
- Phase 5: independent review and MVP release — not started

The repository bootstrap is complete and Phase 1 is active. The current
documents are a draft. Nothing here has been approved by Tari governance, and
Phase 1 is not complete.

## First session checklist

1. Copy this folder to your normal Codex/project location.
2. Rename it to `tari-cc-private-ballot`.
3. Initialize Git locally.
4. Read the Phase 1 documents:
   - `PHASE_STATUS.md`
   - `ROADMAP.md`
   - `docs/PHASE1_PROTOCOL_SPEC_v0.1.md`
   - `docs/OPEN_QUESTIONS.md`
   - `docs/decisions/ADR-0001-offline-authority-ootle-anchor.md`
   - `docs/decisions/ADR-0002-governance-keys.md`
   - `docs/decisions/ADR-0003-governance-source-and-mvp-scope.md`
5. Update or resolve the Phase 1 decisions and record any remaining
   governance and cryptography questions in `docs/OPEN_QUESTIONS.md`.
6. Inspect the diff to confirm only the intended documentation changed.
7. Only then create the initial preservation commit.

Do not create a baseline commit until the governance-source alignment patch
has been reviewed. Do not start any cryptographic implementation or Ootle
integration yet:

- Do not implement ring signatures yet.
- Do not connect walletd, an indexer, or Ootle yet.

## Initial deliverable

The first deliverable is a reviewable protocol package, not working election
software. Phase 2 begins only after the manifest, registry, ballot schemas,
archive format, and threat model are internally consistent.
