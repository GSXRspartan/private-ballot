# ADR-0012: Multi-shell / Tari Universe Tapplet boundary

## Status

Proposed (2026-08-19); pending review. Extends
[ADR-0007](ADR-0007-phase5-gui-stack-and-rust-boundary.md) and does not replace
[ADR-0001](ADR-0001-offline-authority-ootle-anchor.md),
[ADR-0006](ADR-0006-phase4-ootle-anchor-prototype-scope.md), or
[ADR-0009](ADR-0009-private-ballot-internet-transport.md) through
[ADR-0011](ADR-0011-transport-commitment-archive-binding.md). This ADR ratifies
an architectural boundary. It changes no canonical format, no cryptography, no
lifecycle rule, and no source code.

## Context

The standalone desktop application is the reference implementation. It has
passed a complete real one-computer workflow — create, freeze, organizer
managed-Tor intake, voter transport-bundle export, open, credential/eligibility,
anonymous eligibility proof, real private ballot submission over Tor,
authenticated organizer receipt, authoritative reconciliation, application
restart, durable election recovery, private-intake restart, accepted-ballot
survival across restart, close, participation disclosure, deterministic tally,
mark-verified, finalize, final-archive write, and independent archive
replay/verification — plus the guided Vote and Manage Election UX regression.
Its behavior is the baseline every future shell must preserve.

A prior read-only Tapplet-readiness audit established the following, which this
ADR ratifies:

1. The protocol/core area is already largely shell-independent. Election
   definitions, ballot formats, canonical CBOR, domain-separated hashing,
   Triptych-style eligibility proofs, election binding, election-bound
   nullifier/linkability rules, replay/duplicate protection, tallying, archive
   integrity, and verification perform no filesystem, network, process, or UI
   operations.
2. `gui-core` is the main application facade. It holds portable composition
   logic, but some parts are currently native because they perform path-based
   persistence (workspaces, credentials, cast-locks, private-intake inbox,
   archive writing) and because the facade currently has dependency edges into
   native/networked Ootle adapter crates.
3. The React frontend already routes native calls through a relatively clean
   `api/client.ts` boundary rather than scattered direct shell invocations.
4. Managed Tor and native process management belong to the standalone shell. A
   Tari Universe Tapplet must not be assumed to inherit native, Tauri, or
   process privileges.
5. Ootle anchoring is already conceptually adapter-shaped and must remain
   optional and outside the canonical election protocol
   (consistent with [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md)).
6. Current Tari Universe / Tapplet host APIs are evolving. Portability work must
   distinguish `AVAILABLE NOW`, `DOCUMENTED BUT EXPERIMENTAL`,
   `PROPOSED / NOT YET AVAILABLE`, and `UNKNOWN`, and must not treat proposed,
   unstable, undocumented, or unavailable Universe APIs as protocol
   requirements.

The target architecture is a shared protocol/core beneath interchangeable
shells:

```
                     Shared protocol / core
                              |
              +---------------+---------------+
              |                               |
        Standalone shell             Tari Universe shell
      (native / offline)              (Tapplet adapter)
```

This is an architectural boundary, not a folder-layout mandate. The repository
need not be reorganized to resemble the diagram.

## Decision

1. **One canonical protocol.** There is exactly one Tari Private Ballot
   protocol. There is no standalone protocol, no Tapplet protocol, no
   Tapplet-specific proof or archive format, no Tapplet-specific election ID, no
   separate nullifier behavior, and no independently drifting implementation.
   Standalone, Tapplet, CLI, the independent verifier, and any future shell use
   the same canonical election format, voter-registry semantics,
   option/candidate set, ballot format, proof statement, election binding,
   nullifier/linkability behavior, duplicate/replay rules, tally semantics,
   archive format, canonical encoding, domain-separated hashes, and verification
   behavior. A shell adapts I/O and presentation; it never redefines protocol
   semantics.

2. **Standalone remains first-class.** Tari Universe compatibility is an
   additional distribution/shell target, not a replacement. The standalone
   application must remain able to create elections, enroll voter public keys,
   create credentials, prepare ballots, export ballots, import ballots, submit
   privately over Tor where supported, tally, write archives, verify archives,
   and operate independently and offline. Tari Universe must never become
   required for protocol correctness.

3. **Offline-first and independent verification are preserved.** A Tapplet must
   not become the only way to create a canonical election, cast or export a
   canonical ballot, inspect the election record, verify an archive, reproduce
   canonical hashes, or verify the tally. The independent verifier remains
   independent of Tari Universe. A finalized archive remains independently
   verifiable without trusting the organizer UI, Tari Universe, a Tapplet host,
   an Ootle anchor, or any hosted service — extending
   [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md) to every shell.

4. **A Tapplet host is an execution environment, not part of the protocol
   trusted computing base.** Tari Universe and any Tapplet host are treated as
   execution environments. The protocol does not rely on the host to determine
   eligibility, proof validity, nullifier validity, first-valid-ballot behavior,
   the tally result, canonical hashes, archive integrity, or election finality;
   each of these remains independently checkable from canonical bytes. This is
   architectural minimization of trust, not an assertion that the host is
   adversarial: if Universe later provides wallet, signing, or submission
   functionality, the host may be trusted only to perform the specific,
   explicitly authorized host operation the user approved, and never to
   adjudicate protocol correctness.

5. **Tapplet compatibility must not weaken security.** Any new
   shell, storage, or environment backend must preserve proof verification,
   election binding, nullifier semantics, replay resistance, duplicate
   protection, first-valid-ballot behavior, cast-lock semantics, credential
   integrity, canonical encoding, tamper detection, archive integrity, verifier
   agreement, and fail-closed behavior. Portability is not permission to replace
   security-sensitive persistence with weaker best-effort behavior. If a future
   storage or host backend cannot provide the guarantees the cast-lock design
   depends on (durable, atomic, no-silent-overwrite first-valid acceptance),
   that backend is not acceptable until equivalent guarantees are demonstrated.

6. **Environment concerns live in the shell/adapter layer.** The following are
   shell/adapter responsibilities, outside the canonical protocol: filesystem
   and path selection; app-data directories; persistent application storage;
   credential persistence; the cast-lock persistence *implementation*; archive
   import/export; native file dialogs; clipboard availability; browser/webview
   storage; managed Tor and process spawning; localhost and local network
   services; walletd/indexer RPC; Tari Universe host APIs; and Ootle transaction
   submission. Abstractions are introduced only where they carry genuine
   portability or trust value, not for architectural aesthetics.

7. **Storage direction (intent only; not implemented here).** A future storage
   seam in `gui-core` may support the existing native filesystem/app-data
   implementation, a deterministic in-memory implementation for shared tests,
   and — only if suitable guarantees exist — a future Tapplet-compatible
   persistence backend. Under any backend, canonical byte formats, credential
   cryptography, cast-lock semantics, archive hashing, and nullifier/replay
   rules are unchanged. A likely implementation name (for example
   `StorageProvider`) is an implementation detail, not a consensus-level
   requirement; the exact type or trait name is left to the implementing slice.

8. **Frontend / shell-API direction (intent only; not implemented here).** The
   shared React UI should consume a shell-neutral application-API boundary, with
   the current `api/client.ts` centralization as the starting point. A future
   structure may conceptually place a single application-API surface between the
   shared UI and each shell (standalone Tauri shell, Tapplet shell). UI shells
   must contain no protocol logic and must not duplicate consensus-critical
   validation. Exact filenames or class names (for example `BallotAppApi`) are
   not mandated by this ADR.

9. **Managed Tor / private transport is a standalone-shell capability.** The
   proven standalone managed-Tor design remains intact and standalone-owned. A
   Tapplet must not be assumed able to spawn `tor`, bind a localhost SOCKS port,
   open local listeners, or reach arbitrary native process APIs. A future
   Tapplet private-transport mechanism may exist only if Tari Universe provides
   an appropriate documented host capability; no such capability has been
   established as of this ADR. Where no equivalent capability exists, a Tapplet
   may expose fewer delivery options while still producing the exact same
   canonical encrypted ballot package. No transport may define a different
   ballot protocol, and offline/manual encrypted ballot delivery remains valid
   (consistent with [ADR-0009](ADR-0009-private-ballot-internet-transport.md)).

10. **Ootle / anchor boundary.** Ootle anchoring is optional, aggregate, and
    organizer-side; individual voters need not create an Ootle transaction. The
    canonical election and archive remain valid when anchoring is unavailable,
    and Ootle is never the source of truth for election results. The current
    native walletd/indexer path remains valid for the standalone shell. A future
    Tari Universe anchor adapter may be built only if stable, documented host
    APIs exist. Conceptually the finalized-archive commitment sits above an
    anchor abstraction with a standalone walletd implementation today and a
    possible future Universe host-provider implementation; Tari Universe is never
    required for archive finality. This preserves
    [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md) and
    [ADR-0006](ADR-0006-phase4-ootle-anchor-prototype-scope.md).

11. **Tari Universe API-stability rule.** Future implementation work must
    classify each relevant Universe/Tapplet capability as `AVAILABLE NOW`,
    `DOCUMENTED BUT EXPERIMENTAL`, `PROPOSED / NOT YET AVAILABLE`, or `UNKNOWN`.
    Only a sufficiently stable `AVAILABLE NOW` API may become an implementation
    dependency without a separate architecture decision. Open GitHub issues,
    proposals, roadmap statements, unmerged pull requests, obsolete `tarijs`
    APIs, and undocumented internal APIs are not stable platform contracts. The
    review must also distinguish *what Tari Universe itself can do* from *what an
    embedded Tapplet is permitted to do*: a native Universe capability does not
    imply Tapplet access. For any capability whose Tapplet-facing surface is not
    yet settled, the correct statement is "No stable/documented Tapplet host API
    has been established for this capability as of this ADR," not a claim that it
    is permanently impossible.

12. **Cross-shell conformance.** The same canonical test vectors should run
    across the standalone build, the independent verifier, the CLI/reference
    build, and any future Tapplet/shared-core build. Identical inputs must yield
    identical relevant outputs — canonical hashes, election IDs, proof
    verification results, nullifier behavior, ballot validation results, tally,
    and archive verification. No shell may redefine protocol semantics, and
    divergence in any of these outputs is a release blocker.

13. **Release model.** The eventual release model is a single Tari Private Ballot
    v1.x line comprising a standalone Windows build, standalone Linux/macOS where
    supported, a Tari Universe Tapplet, and the independent verifier — all
    corresponding to the same repository, the same protocol version, and the same
    tag/commit and canonical formats where practical. A separately drifting
    repository (for example `private-ballot-tapplet-fork`) is rejected unless an
    extraordinary future reason requires a separate repository and a new ADR
    approves it.

## Non-goals

This ADR does not implement a Tapplet; does not define Tari Universe APIs; does
not guarantee that current Universe supports every standalone feature; does not
replace managed Tor; does not replace the standalone filesystem; does not change
canonical formats, cryptography, nullifier rules, cast-lock rules, or archive
semantics; does not make Ootle mandatory; does not mandate a repository
reorganization; does not require WebAssembly specifically; does not require any
specific storage backend; and does not require all standalone features to exist
inside a Tapplet immediately.

## Consequences

Positive: one protocol implementation with lower drift risk; preserved
standalone/offline independence; a clearer path to future shell integration;
compile-time opportunities for network-free verifier/core builds once
dependency seams exist; and clearer, minimized trust boundaries.

Costs: some native I/O must eventually move behind explicit seams; alternate
storage backends require shared conformance tests before they are trusted;
initial Tapplet functionality may be a subset of standalone functionality; some
Universe integrations must wait for stable, documented host APIs; and the
project accepts additional shell/adapter maintenance.

## Follow-up phases

This ADR records general direction only; it is not a project tracker, and phases
may evolve as Tari Universe APIs evolve.

- **Phase A** — Preserve and complete the standalone reference implementation.
- **Phase B** — Ratify the multi-shell boundary with this ADR.
- **Phase C** — Introduce only the necessary environment/storage/dependency
  seams; likely work includes a storage-provider seam, a `gui-core`
  dependency/feature split, bytes-based archive verification, and a
  frontend shell/API implementation boundary.
- **Phase D** — Complete and stabilize the standalone Ootle anchor.
- **Phase E** — Build a minimal Tari Universe dev Tapplet and empirically verify
  actual host constraints.
- **Phase F** — Reuse the shared UI.
- **Phase G** — Connect the Tapplet shell to shared protocol/application
  functionality.
- **Phase H** — Optional Universe wallet/Ootle integration, only if stable,
  documented host APIs exist.
- **Phase I** — Cross-shell conformance tests.
- **Phase J** — Release multiple shells from one versioned codebase.

## References

Cited for context on the evolving Tari Universe / Tapplet platform, not as
stable platform contracts (see Decision 11):

- Tari Universe — `https://github.com/tari-project/universe`
- tari.js toolkit — `https://github.com/tari-project/tari.js`
- Tari Ootle documentation — `https://ootle.tari.com/`

Prior decisions this ADR builds on: ADR-0001 (offline archive authoritative,
Ootle as anchor), ADR-0006 (Phase 4 Ootle anchor prototype scope), ADR-0007
(GUI stack and Rust application boundary), ADR-0009 (private ballot internet
transport), ADR-0010 (transport crypto and trust root), ADR-0011 (transport
commitment archive binding).
