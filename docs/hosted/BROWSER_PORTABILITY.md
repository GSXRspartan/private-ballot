# Browser Portability Assessment (Phase 14)

Classification per component. “Browser-ready” means pure Rust with no OS dependency; “WASM-portable” means it compiles to `wasm32-unknown-unknown` with an identified blocker; never “unsafe for hosted” applies to secrets handling.

| Component | Class | Notes |
|---|---|---|
| Triptych proof **verification** | WASM-PORTABLE | Pure cryptography (`third_party/tari-triptych` + `crates/crypto`); no OS calls. Blocker: ensure no `getrandom`/std-only code paths; use browser CSPRNG |
| Triptych proof **generation** | WASM-PORTABLE | Same as verification + a secure RNG. **Do not expose secrets to avoid a port** — port the RNG properly |
| Nullifier construction | WASM-PORTABLE | Hash + domain frame only |
| Archive verification | BROWSER-READY | Pure data + hashing (`crates/archive`, `crates/verifier`, `crates/protocol`) |
| Ballot envelope creation | WASM-PORTABLE | Depends on proof generation + serialization |
| Cryptographic RNG | NEEDS WRAPPER | `wasm-bindgen` + `web-sys` CSPRNG, or a `getrandom` wasm feature. Never a deterministic test RNG in production |
| Key handling | NEEDS WRAPPER | WebCrypto (non-extractable keys where the protocol allows); voter secrets live in memory only, never in `localStorage` |
| Canonical serialization | BROWSER-READY | `crates/protocol` + CBOR (`minicbor` compiles to wasm) |
| BLAKE3 | BROWSER-READY | `blake3` crate supports wasm; `crates/protocol::Blake3HashProviderV1` is the only hash entry point |
| QR/invite handling | NEEDS WRAPPER | Browser camera/QR via JS; parsing itself is pure |
| Tally verification | BROWSER-READY | `crates/tally` + `crates/verifier` |
| Ootle receipt verification | WASM-PORTABLE | `crates/anchor-transport` (pure) + CBOR decode; **not** the walletd/indexer HTTP clients (server-only) |
| Ootle transaction **building** | SERVER-ONLY (or WASM with work) | Depends on `tari_ootle_transaction::UnsignedTransaction` CBOR framing; not needed in the browser for voting. Anchor *publication* stays server-side |
| Managed Tor, Tauri, Credential Manager, filesystem dialogs, process spawning | DESKTOP-ONLY | No browser equivalent; hosted mode never claims them |
| Any secret export (witness, private key) to avoid a port | UNSAFE FOR HOSTED MODE | Forbidden. Secrets stay in the browser; the server receives envelopes only |

## Exact crates / blockers

- `blake3` 1.x (already in graph): wasm-compatible.
- `minicbor` 2.3.1 (aligned in Stage 1): wasm-compatible.
- `third_party/tari-triptych`: verify `getrandom` usage; gate OS RNG behind a trait.
- `tari_template_lib*` / `tari_ootle_transaction`: **not** browser crates (WASM template ABI is a wasm32 target for templates, not for browsers). Browser code must not link `tari_ootle_transaction`.
- TypeScript SDK (`@tari-project/ootle` 0.11.0, `@tari-project/ootle-indexer`, `@tari-project/ootle-wallet-daemon-signer`): Node ≥ 22 currently needs `--experimental-wasm-modules` under tsx/plain node (see npm page). The browser path uses the Rust WASM core once ported; the TS SDK is an interim reference, not the secrecy boundary.
- Host SDKs must decode the V2 template definition layout (v0.50.0 note: ootle-go/py/ts). Stage 2 re-validates the TS indexer client against Protocol V1 `Encoded` types before depending on it.

## Design rule

Where browser support requires WASM, identify the exact crates (above) and the blocker. Where it would require exposing a secret, mark UNSAFE and keep the operation in the browser.
