# ADR-0007: Phase 5 GUI stack and Rust application boundary

## Status

Accepted for Phase 5 Slice 5A2. Governs the GUI application architecture.
Extends, and does not replace, [ADR-0001](ADR-0001-offline-authority-ootle-anchor.md)
and [ADR-0006](ADR-0006-phase4-ootle-anchor-prototype-scope.md).

## Context

- The project backend is library-first: every election and anchor capability
  is a public Rust API. There is no meaningful election CLI; the only
  user-facing binary is the Phase 4 anchor operator application.
- The Phase 5 architecture review (2026-08-06/07) established that the GUI
  must sit on top of the existing crates without duplicating cryptography,
  canonical encoding, walletd logic, lifecycle logic, or verification logic,
  and that protocol logic must never be reimplemented in JavaScript or
  TypeScript.
- The application is local-only by default; only the optional, non-binding
  Ootle anchor flow ever contacts walletd or an indexer, and only through the
  existing Phase 4 adapters.

## Decision

1. **UI stack.** The desktop application will use **Tauri 2 + React +
   TypeScript + Vite**, Windows-first with macOS/Linux portability. The
   system WebView is used; no bundled browser, no Node runtime in the shipped
   application.
2. **Rust boundary.** The GUI calls the backend **in process** through a
   dedicated facade crate, `crates/gui-core`
   (`tari-cc-private-ballot-gui-core`), exposed to the shell as typed Tauri
   commands in a later slice. There is **no local HTTP server**, **no CLI
   stdout parsing**, and **no shelling out** to project binaries from the
   GUI.
3. **No cryptography in JavaScript.** All canonical CBOR, hashing, proof
   generation/verification, tallying, archive construction, replay
   verification, and anchor lifecycle logic remain in the existing Rust
   crates. The frontend receives only plain, bounded view models.
4. **Secrets remain in Rust.** The voter governance secret scalar and the
   walletd bearer token never cross into the frontend and are never persisted
   by the application. gui-core exposes no secret-bearing fields in any view
   model; a source-policy test enforces this.
5. **File-based ballot submission remains the MVP mechanism.** The voter
   exports a canonical ballot package file and delivers it to the organizer
   out of band. No voter network submission protocol is created.
6. **No single-file election container.** The election package remains the
   three existing canonical artifacts (manifest, registry, candidate set).
   gui-core loads them as separate files and validates their cross-bindings.
7. **Voter credential handling.** The GUI MVP imports an existing voter
   credential per session and forgets it. Voter key generation is deferred to
   a separate reviewed slice before 5A6 (see the 5A2 review report's design
   note). Credential persistence is not built.
8. **Anchor backend reuse.** The Phase 4 anchor stack (config, driver,
   snapshot, evidence) is reused directly. gui-core provides only structured,
   read-only inspection wrappers equivalent to the CLI modes; it does not
   redesign the monolithic driver, the lifecycle, or the network adapters.

## Consequences

- The future Tauri shell contains no protocol logic and can be replaced
  without touching the backend.
- gui-core is additive: no Phase 1-4 crate depends on it and no Phase 1-4
  behavior changes.
- DTO serialization (e.g. serde) is deferred until the shell slice that
  needs it; gui-core adds no serialization dependency speculatively.
- Offline verification remains complete without Ootle; the anchor remains an
  optional, non-binding commitment proof.
