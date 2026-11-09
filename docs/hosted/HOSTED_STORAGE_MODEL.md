# Hosted Storage Model (Phase 12)

## Semantic categories (interface now, implementation later)

| Category | Semantics |
|---|---|
| Public election package | Immutable, hash-addressed, append-only |
| Opaque ballot envelopes | Append-only/auditable; never updated or deleted except by election close |
| Receipt state | `receipt_id → envelope hash + status`; idempotent writes |
| Finalized archive | Immutable, content-addressed |
| Ootle publication state | Anchor lifecycle snapshots (same shape as `AnchorLifecycleState`) |
| Deployment registry | `DeploymentRegistry` (see `crates/deployment-registry`) |

The skeleton provides `HostedStorage` with one test implementation (`InMemoryStorage`) and no persistence. No external database is introduced in Stage 1: Stage 2 decides between an embedded store and a managed store based on the VPS threat model (a database is a new trust boundary; it must hold envelopes and registry data only — never plaintext).

## Never stored

- Ballot plaintext
- Voter secret keys
- Triptych secret witness material
- Wallet private keys / bearer tokens

These never cross the API boundary (see `HOSTED_API_V1.md`). The storage trait has no method that accepts them.

## Append-only / auditable semantics

Ballots and election evidence use append-only semantics so results can be re-verified from the stored envelope sequence. Reads never mutate. Receipt state transitions are forward-only (`pending → accepted/rejected`), matching `AnchorLifecycleState`.

## Migration from desktop

Desktop archives remain the source of truth for finalized elections. The hosted backend serves copies referenced by hash; it never invents a new archive format. A hosted ballot payload, once finalized, produces the same canonical archive the desktop verifier accepts (shared domain core).
