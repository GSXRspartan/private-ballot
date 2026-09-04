# Private Ballot

Private Ballot is privacy-preserving, verifiable voting software with
optional public anchoring on Tari Ootle. It is a desktop application and
protocol workspace for running non-binding governance pilot ballots. It is
offline-first: the finalized election archive is the authoritative
verification artifact, and an optional Tari Ootle anchor can commit public
aggregate evidence on Esmeralda testnet.

Status: **v0.1.0 Alpha, Governance Pilot, Esmeralda Testnet.** Private
Ballot is an **Independent Open-Source Project**. It is **not affiliated
with or endorsed by Tari Labs**, and it is not production election
software. Do not use it for binding governance, treasury, charter,
employment, or legal decisions.

License: **MIT OR Apache-2.0** (at the recipient's option). See
[LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT), and
[LICENSE-APACHE](LICENSE-APACHE). Third-party components retain their own
licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the
machine-readable reports under
[docs/release/licenses/](docs/release/licenses/).

## Privacy Model

The app separates three ideas that are easy to blur:

- Voter eligibility is proven with a Triptych-style membership proof.
- Ballot delivery privacy depends on the chosen submission route (managed
  Tor by default) and organizer logging discipline.
- Final verification depends on the complete offline archive, not on
  Ootle.

Individual votes are never published to Ootle. The V2 anchor path
publishes a public aggregate digest and scalar summary only, with detached
evidence that can be checked against the finalized archive. Voters do not
submit Ootle transactions; optional anchoring is organizer-side and
fee-bearing.

## Workflow

Organizers create and freeze an election, enroll voter public enrollment
keys, open intake, close voting, verify accepted ballots, finalize the
archive, and optionally anchor public aggregate evidence on Ootle.

Voters create an encrypted credential file, give the organizer only the
public enrollment key, load the issued election package, choose a route,
cast once, and keep their receipt and credential private.

## External requirements (not bundled)

Private Ballot is a self-contained desktop app for the parts of the
protocol it owns, but a real pilot needs one or two external runtimes that
the installer does **not** ship:

- **Tor** — required for private ballot intake (organizer) and private
  submission (voter). Install [Tor Browser](https://www.torproject.org/download/)
  or the [Tor Expert Bundle](https://www.torproject.org/download/tor/)
  and point the app at its `tor.exe`. The app validates the path and
  launches Tor as a child process; it never resolves `tor` from `PATH`
  and never downloads Tor for you.
- **Tari Ootle `walletd`** (v0.39.2 on Esmeralda) — required only if you
  want to publish an optional public anchor. Voters do not need walletd
  and do not need tTARI. The app talks to walletd on loopback at
  `http://127.0.0.1:5100/json_rpc`.
- **tTARI** — Esmeralda testnet TARI, only for the organizer publishing
  an anchor, only enough to cover the transaction fee.

See [docs/OPERATOR_SETUP.md](docs/OPERATOR_SETUP.md) for a step-by-step
setup guide for organizers, voters, and developers.

## Repository Layout

- `crates/` - Rust protocol, archive, verifier, transport, GUI-core,
  Ootle adapter, and controlled-alpha tooling crates.
- `gui/` - Tauri 2 desktop shell and React frontend.
- `templates/` - Tari Ootle template source. Compiled WASM belongs in
  release assets, not ordinary source.
- `docs/` - architecture, runbooks, threat model notes, decisions, and
  release audit records.
- `test-vectors/` - public canonical valid/invalid vectors.
- `tools/`, `scripts/`, `fuzz/` - developer/auditor tooling.
- `third_party/tari-triptych/` - vendored Triptych implementation,
  licensed under BSD-3-Clause.

## Build And Test

Frontend checks:

```powershell
cd gui
npx tsc --noEmit
npm test
```

Focused V2 anchor lifecycle checks:

```powershell
cargo +1.97.1-x86_64-pc-windows-msvc test -p tari-cc-private-ballot-gui-core --test live_anchor_v2 --test live_anchor_v2_lifecycle
```

Windows package build (developer only — MSVC BuildTools + vcpkg required):

```powershell
cd gui
$env:RUSTUP_TOOLCHAIN = '1.97.1-x86_64-pc-windows-msvc'
$env:VCPKG_ROOT = 'C:\path\to\vcpkg'          # your local vcpkg checkout
$env:VCPKG_DEFAULT_TRIPLET = 'x64-windows-static-md'
$env:VCPKGRS_TRIPLET = 'x64-windows-static-md'
$env:VCPKG_VISUAL_STUDIO_PATH = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools'
$env:OPENSSL_DIR = "$($env:VCPKG_ROOT)\installed\x64-windows-static-md"
npm run tauri build
```

The generated `.exe`, `.msi`, `.wasm`, and checksum files are release
assets. They should be attached to a GitHub Release only after provenance
and checksums are recorded.

## Qualified platforms

- **Windows 11 x64** — currently qualified; the scale-qualification harness
  has passed at 100 voters and been run at additional scales during
  release preparation (see
  [docs/development/load-testing/](docs/development/load-testing/) and
  `scale-qualification-results/` for recorded runs).
- **Linux / macOS** — not currently qualified. The code is cross-platform
  by construction (the Tauri 2 shell and every Rust crate build on Linux
  and macOS), but a real release build and per-platform test pass have
  not been performed for the alpha.

## Verification

The archive verifier and GUI evidence screens are intended to let an
auditor replay the finalized archive, recompute the tally, inspect legacy
V1 anchor evidence, and verify V2 public-summary evidence. Historical V1
verification compatibility remains intentionally supported; V1 publishing
UX is not part of the normal alpha workflow.

See [docs/INDEPENDENT_VECTOR_VERIFIER.md](docs/INDEPENDENT_VECTOR_VERIFIER.md),
[docs/CONTROLLED_ALPHA_RUNBOOK.md](docs/CONTROLLED_ALPHA_RUNBOOK.md), and
[templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md](templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md).

## Security

Read [SECURITY.md](SECURITY.md) before operating a pilot. The current
threat-model material lives mainly under [docs/transport/](docs/transport/);
it documents organizer trust boundaries, transport assumptions, logging
limits, archive authority, and alpha limitations.

Never commit live election archives, voter credentials, wallet databases,
wallet API keys, LocalAppData runtime state, Tor service keys, transport
authority private keys, or Ootle evidence sidecars from a real run.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are dual-licensed
under `MIT OR Apache-2.0` unless you explicitly state otherwise; there is
no CLA and no DCO sign-off requirement.
