# ADR-0006: Phase 4 Ootle testnet anchor prototype scope

## Status

Accepted for the Phase 4 prototype. Narrows and reconciles the earlier roadmap
phase numbering. Extends, and does not replace, [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md).

## Context

- [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md) established that the
  complete offline archive is authoritative and that Ootle stores only
  append-only commitments and lifecycle state, never voter identities.
- The original `ROADMAP.md` assigned Ootle testnet anchoring to Phase 5 and
  described it as an optional on-chain template, while the active branch and the
  Phase 4 Slice 4A1 gap inventory treat the harmless, non-binding Ootle testnet
  anchor prototype as Phase 4 work.
- Slice 4A1 concluded that the minimum viable anchor payload already exists as
  the completed `ArchiveHashV1`, that it transitively commits to the election
  manifest hash, registry commitment, candidate-set commitment, and archive
  file digests, and that a transaction-level anchor does not require a custom
  Ootle template.

## Decision

1. Phase 4 covers the harmless, non-binding Ootle testnet anchor prototype. Any
   prior wording that placed the anchor prototype in a later phase is superseded
   and renumbered into Phase 4.
2. The anchor prototype wraps the existing completed `ArchiveHashV1`. It does
   not introduce a new election commitment and does not change any Phase 1-3
   canonical format, hashing, or Triptych behaviour.
3. The offline canonical archive and the independent verifier remain the sole
   authoritative validity path. A failure to construct, submit, or finalize an
   anchor cannot change the offline election outcome.
4. Slice 4A2 delivers only the offline canonical anchor record, its production
   BLAKE3 digest, and deterministic vectors. It adds no Ootle, walletd, indexer,
   HTTP, RPC, async-runtime, or networking dependency, and no custom Ootle
   template or component.
5. Later Phase 4 slices own transaction construction, signing, submission, and
   receipt binding. The transaction-level `Instruction::EmitLog` carrier
   identified in Slice 4A1 supersedes the earlier "optional template" framing for
   the prototype. A dedicated template remains a possible later concern for
   cross-election aggregate state, not a prototype requirement.

## Consequences

- Binding governance use remains unauthorized. The prototype is non-binding.
- Independent cryptographic and implementation review remains required before any
  binding use, as in the existing roadmap exit gates.
- The anchor proves only that a specific commitment was submitted and finalized
  on the selected ledger. It does not prove ballot validity, tally correctness,
  organizer honesty, voter anonymity, or archive availability.
- A testnet reset requires transparent re-anchoring of the unchanged
  `ArchiveHashV1`, never a rebuild of the historical election package, per
  [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md).
