# Pre-GitHub Release Audit

Date: 2026-09-03

Scope: source repository only. Preserved live artifacts under an operator's
external evidence tree and local V2 evidence under
`%LOCALAPPDATA%\Private Ballot` on the operator's own machine were not
modified. No wallet request,
transaction submission, template publish, GitHub push, or release upload was
performed.

## Repository Inventory

| Area | Classification | Notes |
| --- | --- | --- |
| `crates/` | Public source/tests | Rust protocol, archive, verifier, transport, GUI core, and Ootle adapters. |
| `gui/` | Public source/tests | Tauri 2 desktop shell, React UI, package lock, icons, and frontend tests. |
| `templates/` | Public source plus release-template metadata | Template source is source; compiled WASM is a release asset. |
| `docs/` | Public documentation | Architecture, runbooks, reviews, and controlled-alpha docs. |
| `test-vectors/` | Public tests | Canonical valid/invalid public fixtures. |
| `tools/`, `scripts/`, `fuzz/` | Developer tools | Keep, but document entry points clearly. |
| `third_party/tari-triptych/` | Public third-party source | BSD-3-Clause vendored dependency; keep license with source. |
| Root `AUDIT_*`, `PERFORMANCE_*`, `HANDOFF_*`, `CONTROLLED_ALPHA_*` files | Dev-only/unsure | Useful engineering evidence, but not curated for public root publication. |
| `target/`, `gui/dist/`, `gui/node_modules/`, `gui/src-tauri/target/`, `scale-qualification-results/` | Local/generated | Ignored; do not publish as source. |

## Keep / Release Asset / Dev-Only / Remove Matrix

| Artifact | Source | GitHub Release | Dev-only | Never publish |
| --- | --- | --- | --- | --- |
| Rust crates | yes | no | no | no |
| GUI source and tests | yes | no | no | no |
| Public test vectors | yes | no | no | no |
| Windows EXE/MSI/NSIS | no | yes | no | no |
| V2 template WASM | no | optional, with hashes/provenance | no | no |
| Walletd binary | no | only after license/provenance decision | no | never with wallet state |
| Load-test harness source | yes, preferably under documented tooling | no | yes | no |
| Load-test generated CSV/logs | no | no | yes | no |
| Preserved 500-voter archive | no | no | no | yes, unless separately sanitized/approved |
| LocalAppData V2 evidence sidecar | no | no | no | yes, unless separately sanitized/approved |
| Root scratch/handoff reports | no, unless curated | no | yes | maybe, if private context remains |

## Current Blockers

- The working tree is heavily dirty and includes many untracked source, test,
  documentation, CSV, patch, and handoff files. Publication should wait until
  each is intentionally staged, moved, ignored, or removed.
- No project-level license exists.
- No complete third-party attribution/notice file exists.
- Git history contains development commits that match sensitive-keyword grep
  patterns and must be reviewed before the same history is made public.
- Linux and macOS builds have not been validated from this tree.

## Legacy V1

Historical V1 verification compatibility remains intentional. V1 publishing UX
is not part of the normal alpha path. Do not remove V1 receipt, evidence, or
archive verification code merely because the visible UI prefers V2.

## Walletd Distribution

The development runtime observed locally was an isolated
maintainer-managed `walletd v0.39.2` install kept in a dedicated,
never-shipped folder on the maintainer's machine, SHA-256
`0B833CBF3ECBF8D3D33DAFF8CECCA900C602436A3C22A7D8ECD65014FC932C3A`.
Only the binary was present in that runtime folder; no local license/provenance
file was present there. Conservative release stance: do not bundle walletd in
the repository or installer until upstream license, provenance, and update
process are documented.

## V2 Template / WASM

Source belongs in `templates/ootle-anchor-event-template-v2`. Compiled WASM
belongs in release assets only when accompanied by hashes and provenance.
Current controlled-alpha authoritative hashes:

| Algorithm | Digest |
| --- | --- |
| SHA-256 | `022beeaea7805775192623c87970c03cd384732b37666d1d95a79a967fa44d49` |
| BLAKE3-256 | `475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc` |

Current Esmeralda template address:
`template_f49e19743d7f9a92f7c675619412ce2b50efe55514ee9012f2e9cdab25f8e214`.
No publish action was performed by this audit.

## Decisions Needed Before Publication

- Choose project license.
- Decide whether root audit/performance/handoff files are public docs, private
  handoff notes, or disposable scratch.
- Decide walletd distribution model: user-provided, helper-installed, bundled
  release asset, or external prerequisite.
- Confirm Tari name/logo/trademark language with the independent-community
  disclaimer.
- Decide whether generated guide artwork needs explicit attribution metadata.
- Run the next cross-platform build phase on Linux and macOS.
