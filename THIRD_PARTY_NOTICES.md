# Third-Party Notices

Private Ballot is dual-licensed under `MIT OR Apache-2.0` (see the
top-level [LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT), and
[LICENSE-APACHE](LICENSE-APACHE) files). This document records the
third-party components incorporated into or shipped alongside the project,
together with what could be verified locally. It is not a legal opinion and
is not a substitute for the machine-readable transitive reports under
[docs/release/licenses/](docs/release/licenses/), which cover every crate and
npm package the current lockfiles resolve.

Anything whose attribution or license needs a real Windows release build to
confirm is called out under `RELEASE-BUILD CONFIRMATION REQUIRED`.

## Vendored source

### `third_party/tari-triptych/` — Tari Triptych (vendored)

- Package: `triptych` `0.1.1`
- Copyright: The Tari Project
- License: BSD-3-Clause
- Upstream: <https://github.com/tari-project/triptych>
- License text: [`third_party/tari-triptych/LICENSE`](third_party/tari-triptych/LICENSE)

The vendored source is used verbatim by the Triptych verifier path
(`crates/crypto/src/triptych_verifier.rs`). It is NOT relicensed under the
project's MIT/Apache-2.0 grant.

## Derived design assets

### CSS color tokens — from tari-project/tari-ootle

- Source: <https://github.com/tari-project/tari-ootle>, path
  `applications/theming/lib/theme/colors.ts`
- Copyright: The Tari Project
- License: BSD-3-Clause
- Used by: [`gui/src/styles/global.css`](gui/src/styles/global.css) — the
  `--tari-purple-*`, `--tari-bg-*`, `--tari-grey-*`, `--tari-green-*`,
  `--tari-orange-*`, `--tari-red-*`, and `--tari-blue-*` scales are the
  official Tari brand scales, taken verbatim.

The rest of the design system (component tokens, layout tokens, typography
stack, dark-mode semantic overrides, application emblem) is original
project-owned work under `MIT OR Apache-2.0`.

## Rust dependencies

Every crate the top-level workspace resolves is listed in
[docs/release/licenses/rust-workspace-licenses.csv](docs/release/licenses/rust-workspace-licenses.csv);
every crate the detached Tauri shell resolves is listed in
[docs/release/licenses/rust-src-tauri-licenses.csv](docs/release/licenses/rust-src-tauri-licenses.csv).
See [docs/release/licenses/README.md](docs/release/licenses/README.md) for
the license-family breakdown and the regeneration recipe.

Called-out non-MIT/Apache/BSD/ISC entries (all permissive and compatible):

| Category | Where | Notes |
| --- | --- | --- |
| MPL-2.0 | `webauthn-rs*` family (Tauri, `x64-windows-static-md`) | Weak file-level copyleft. Not modified. Unmodified use / distribution is fine. |
| MPL-2.0 | `cssparser`, `cssparser-macros`, `dtoa-short`, `option-ext`, `selectors` (Tauri deps) | Same. |
| MPL-2.0 | `lightningcss` (dev-only via Vite) | Build-time only; not shipped in the bundle. |
| BlueOak-1.0.0 | `minicbor`, `minicbor-derive` | Permissive. |
| WTFPL | `newtype-ops` | Permissive. |
| CDLA-Permissive-2.0 | `webpki-root-certs` | Permissive. |
| BSL-1.0 | `xxhash-rust` | Boost Software License, permissive. |
| Multi-license including LGPL | `r-efi` (`MIT OR Apache-2.0 OR LGPL-2.1-or-later`) | Recipient may pick MIT or Apache-2.0; LGPL never activates. |

No GPL, AGPL, SSPL, BUSL, Commons-Clause, source-available, or non-commercial
crate was found in either lockfile.

## npm dependencies (Tauri frontend)

Full production and dev graphs are captured in:

* [docs/release/licenses/npm-production-licenses.json](docs/release/licenses/npm-production-licenses.json)
  — 8 packages, all permissive.
* [docs/release/licenses/npm-all-licenses.json](docs/release/licenses/npm-all-licenses.json)
  — 29 packages, adds the Vite / TypeScript / Tauri-CLI build toolchain.

Direct production dependencies (from [gui/package.json](gui/package.json)):

| Package | Version (declared) | License |
| --- | --- | --- |
| `@fontsource/poppins` | ^5.3.0 | OFL-1.1 (font: Google Fonts Poppins) |
| `@tauri-apps/api` | 2.11.1 | Apache-2.0 OR MIT |
| `@tauri-apps/plugin-dialog` | 2.7.1 | MIT OR Apache-2.0 |
| `react` | 19.2.7 | MIT |
| `react-dom` | 19.2.7 | MIT |
| `uqr` | ^0.1.3 | MIT |

Direct devDependencies:

| Package | Version (declared) | License |
| --- | --- | --- |
| `@tauri-apps/cli` | 2.11.4 | Apache-2.0 OR MIT |
| `@types/react` | 19.2.17 | MIT |
| `@types/react-dom` | 19.2.3 | MIT |
| `@vitejs/plugin-react` | 6.0.3 | MIT |
| `typescript` | 6.0.3 | Apache-2.0 |
| `vite` | 8.2.0 | MIT |

## Fonts and artwork

- Poppins (variable + static faces) — SIL Open Font License 1.1, via
  `@fontsource/poppins`. The full license text is distributed inside the
  npm package (`node_modules/@fontsource/poppins/LICENSE`).
- In-app Guide diagrams and other Guide artwork under
  `gui/src/assets/guide/` are original project-owned work under
  `MIT OR Apache-2.0` unless a specific file is annotated otherwise.
- App icons under `gui/src-tauri/icons/`: origin recorded in
  [docs/release/BRAND_TRADEMARK_REVIEW.md](docs/release/BRAND_TRADEMARK_REVIEW.md).
  Icons are project-owned art under `MIT OR Apache-2.0`. See the brand /
  trademark note below.

## QR code library

`uqr` (MIT) is the only QR-code library currently pulled in; it is imported
by the frontend for offline ballot QR encoding. No separate binary
attribution is required beyond the MIT text in the npm package.

## External runtime prerequisites (not bundled)

### walletd (Tari Ootle wallet daemon)

`walletd` is an external Tari Ootle runtime. The current MSI/NSIS installer
does **not** bundle or redistribute the `walletd` binary. Operators install
their own compatible walletd (currently pinned to v0.39.2 on Esmeralda) and
point Private Ballot at the resulting local JSON-RPC endpoint
(default `http://127.0.0.1:5100/json_rpc`). See
[docs/OPERATOR_SETUP.md](docs/OPERATOR_SETUP.md) and
[docs/development/WALLETD_DISTRIBUTION_RECOMMENDATION.md](docs/development/WALLETD_DISTRIBUTION_RECOMMENDATION.md).

If a future release chooses to ship walletd as a companion release asset,
its upstream license and provenance must be recorded here before the change.

### Tor

Tor is an external runtime. The current MSI/NSIS installer does **not**
bundle or redistribute a `tor.exe` binary. The application optionally spawns
an operator-selected `tor.exe` (validated absolute path, no shell, no PATH
lookup, no download) as a managed child process, and connects to its
loopback SOCKS listener. See
[docs/OPERATOR_SETUP.md](docs/OPERATOR_SETUP.md) for the supported
installation shape and [docs/TOR_ONE_COMPUTER_TEST.md](docs/TOR_ONE_COMPUTER_TEST.md)
for the test harness.

The physical multi-machine voter load driver
([docs/DISTRIBUTED_VOTER_LOAD_DRIVER.md](docs/DISTRIBUTED_VOTER_LOAD_DRIVER.md))
also expects an operator-supplied local Tor SOCKS listener (default
`127.0.0.1:9050`, e.g. as installed by Tor Browser / Tor Expert Bundle);
it never starts Tor itself.

The in-process scale-qualification benchmark
([tools/load-test/RUN_SCALE_QUALIFICATION.ps1](tools/load-test/RUN_SCALE_QUALIFICATION.ps1))
does **not** use Tor at all — it is a cryptographic and I/O micro-benchmark
that runs against per-scale scratch directories.

If a future release chooses to ship Tor as a companion release asset, its
upstream license and provenance must be recorded here before the change.

## Ootle event-template WASM

`templates/ootle-anchor-event-template-v2/` is project-owned source under
`MIT OR Apache-2.0`. The compiled `.wasm` produced from it is a release
asset (see
[docs/CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md](docs/CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md)
for the recorded hash) and inherits the project license. The upstream Tari
Ootle template runtime that loads the WASM is not redistributed as source
by this project. Anchoring publishes are optional, organizer-side, and
fee-bearing.

## Test vectors and public fixtures

Public test vectors under `test-vectors/` are project-generated and released
under the project license (`MIT OR Apache-2.0`). They must never contain any
real voter credential, wallet API key, wallet database, private key, seed
phrase, mnemonic, Tor onion-service key, or private transport-authority key.

## Brand / trademark

The word mark "Tari" appears in in-app text and in some technical
identifiers purely to describe the Tari Ootle technology this project
integrates with (Tari Ootle walletd, the Tari Ootle indexer, the Tari
Triptych implementation, and the optional Tari Ootle public anchor).
Private Ballot is an independent open-source project; it is not affiliated
with or endorsed by Tari Labs. Trademark permission — including whether
the application emblem may continue to use Tari brand colors in its
current form — is a separate question tracked in
[docs/release/BRAND_TRADEMARK_REVIEW.md](docs/release/BRAND_TRADEMARK_REVIEW.md).
The project license does not grant trademark rights.

## RELEASE-BUILD CONFIRMATION REQUIRED

Items that need a real Windows release build to record deterministically:

- Exact OpenSSL major.minor.patch version resolved by the operator's vcpkg
  checkout, and confirmation of static linking. See
  [docs/release/licenses/WINDOWS_NATIVE_DEPENDENCIES.md](docs/release/licenses/WINDOWS_NATIVE_DEPENDENCIES.md).
- Copy of the OpenSSL Apache-2.0 LICENSE text placed alongside the shipped
  installer, and referenced from the Windows Add/Remove Programs entry.
- Per-icon file provenance in `gui/src-tauri/icons/` — record the current
  state in `docs/release/BRAND_TRADEMARK_REVIEW.md` as icons stabilise.
- `SHA256SUMS` for every release asset (already in the alpha packaging
  checklist).
