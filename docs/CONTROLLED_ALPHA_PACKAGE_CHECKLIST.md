# Controlled-Alpha Package Checklist

Build: **Private Ballot 0.1.0**, x64 Windows. Toolchain
`1.97.1-x86_64-pc-windows-msvc`. All paths are on the build machine; copy the
listed artifacts into the distribution folder alongside `SHA256SUMS`.

## CURRENT RELEASE CANDIDATE — Private Ballot 0.1.0 (2026-09-03)

Freshly rebuilt after the public product rename (Tari Private Ballot →
**Private Ballot**, status **Independent Open-Source Project**). Native V2
template WASM bytes are unchanged from the historical qualification run —
they are re-staged under the new branded release filename without a
rebuild.

| # | Item | Path | Size (bytes) | SHA-256 |
|---|------|------|--------------|---------|
| 1 | GUI executable (raw) | `gui/src-tauri/target/release/tari-cc-private-ballot-gui.exe` | 32661504 | `9FFACDB2F59F93B7039027F2BAF28724A1360A7B2130D29DE97CB2A2E853875A` |
| 2 | GUI installer (MSI) | `gui/src-tauri/target/release/bundle/msi/Private Ballot_0.1.0_x64_en-US.msi` | 17604608 | `6F00AB43172993083F37F405E540493FD7CB5565FC64A118E66EED50AF7F1C13` |
| 3 | GUI installer (NSIS setup) | `gui/src-tauri/target/release/bundle/nsis/Private Ballot_0.1.0_x64-setup.exe` | 11819986 | `B6B56B1E0F35CA29F3D37440A4CE0161BA2F22AD6592D7B56507F68F437D8598` |
| 4 | V2 Ootle anchor release asset (WASM) | `release-staging/private_ballot_ootle_anchor_v2.wasm` | 60714 | `022BEEAEA7805775192623C87970C03CD384732B37666D1D95A79A967FA44D49` |
| 5 | Controlled-alpha runbook | `docs/CONTROLLED_ALPHA_RUNBOOK.md` | — | (text; covered by SHA256SUMS if bundled) |
| 6 | Release notes | `docs/CONTROLLED_ALPHA_RELEASE_NOTES.md` | — | (text; covered by SHA256SUMS if bundled) |
| 7 | Checksum file | `SHA256SUMS` (see scratchpad copy) | — | self |

### Cargo package identifier note

The internal Cargo crate names retain the historical `tari-cc-private-ballot-*`
prefix as a stable compatibility identifier; the raw executable filename
therefore is `tari-cc-private-ballot-gui.exe` even though the public product
is now branded as **Private Ballot**. This is intentional and MUST NOT be
renamed as part of a branding pass — see the "internal compatibility
identifiers" clause in [../CONTROLLED_ALPHA_RELEASE_NOTES.md](CONTROLLED_ALPHA_RELEASE_NOTES.md)
and [release/BRAND_TRADEMARK_REVIEW.md](release/BRAND_TRADEMARK_REVIEW.md).

### V2 template WASM — anchor digest (bytes frozen from earlier qualification)

- **SHA-256** (packaging checksum):
  `022BEEAEA7805775192623C87970C03CD384732B37666D1D95A79A967FA44D49`
- **BLAKE3-256** (the *anchor artifact digest* the GUI/verifier use —
  `template_wasm_digest_for_bytes_v1` = unkeyed BLAKE3-256, lowercase hex):
  `475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc`
- Re-derive the BLAKE3 digest in-product via **Advanced anchor settings →
  select the V2 WASM** (`inspect_template_wasm`); it must equal the value
  above.

### Release-asset filename (bytes must remain identical)

For public release packaging, publish the exact already-qualified V2 WASM
bytes under a generic Private Ballot filename — the historical Cargo output
filename (`tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm`) is
an internal build artifact name and is not exposed as the primary branded
release asset.

Public release asset name (either form is acceptable; the current
release-staging copy uses the first):

```
private_ballot_ootle_anchor_v2.wasm
private_ballot_ootle_anchor_event_template_v2.wasm
```

Recipe (Windows PowerShell) — copies the exact bytes and verifies both
digests are unchanged:

```powershell
$src = "templates/ootle-anchor-event-template-v2/target/wasm32-unknown-unknown/release/tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm"
$dst = "release-staging/private_ballot_ootle_anchor_v2.wasm"
New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
Copy-Item -LiteralPath $src -Destination $dst -Force
(Get-FileHash $dst -Algorithm SHA256).Hash  # must equal 022BEEAEA…FA44D49
```

Constraints:

- Do **not** rebuild the WASM to obtain the new filename — the compiled
  bytes must remain bit-identical to the qualified deployment.
- Do **not** rename the deployed on-chain module/function/event
  identifiers, canonical hashing domains, archive/evidence schemas, or the
  `TARI_CC_PRIVATE_BALLOT_*` protocol constants. Those are stable protocol
  identifiers and are frozen; see
  [release/BRAND_TRADEMARK_REVIEW.md](release/BRAND_TRADEMARK_REVIEW.md).
- Do **not** republish the template. The already-deployed
  `template_f49e19743d7f9a92f7c675619412ce2b50efe55514ee9012f2e9cdab25f8e214`
  remains authoritative.
- The renamed release asset must hash exactly to
  `022BEEAEA7805775192623C87970C03CD384732B37666D1D95A79A967FA44D49`
  (SHA-256) and
  `475421a448be977dbf13c37d91b0ed9ef9c4d43f75da438ec64ea9cff38c66cc`
  (BLAKE3-256).

## HISTORICAL BUILD SNAPSHOT — before public product rename

> Captured against the previous public product name ("Tari Private Ballot").
> Retained here as historical evidence for cross-version reproducibility
> checks. The installer artifact filenames and MSI/NSIS/EXE hashes below are
> superseded by the CURRENT RELEASE CANDIDATE section above; only the V2
> template WASM digests carry forward unchanged (see that section).

| # | Item | Path | Size (bytes) | SHA-256 |
|---|------|------|--------------|---------|
| 1 | GUI executable (raw) | `gui/src-tauri/target/release/tari-cc-private-ballot-gui.exe` | 30430208 | `54FFB05DF576FE7753A5B22C440AC5594939D4999C843322F921E1E4F103A162` |
| 2 | GUI installer (MSI) | `gui/src-tauri/target/release/bundle/msi/Tari Private Ballot_0.1.0_x64_en-US.msi` | 14053376 | `F64D0646AD6CD169178E215452785FB9E418FBA96534BE167C49BBF7B15162DC` |
| 3 | GUI installer (NSIS setup) | `gui/src-tauri/target/release/bundle/nsis/Tari Private Ballot_0.1.0_x64-setup.exe` | 11184384 | `794B2D941C0420D4BD1FDA30098F9E3981E5569A0FC6998E5B2A484FB97D51F0` |
| 4 | V2 template WASM (build output) | `templates/ootle-anchor-event-template-v2/target/wasm32-unknown-unknown/release/tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm` | 61546 | `022BEEAEA7805775192623C87970C03CD384732B37666D1D95A79A967FA44D49` |

## walletd runtime dependency

Not bundled. Operators supply their own Tari Ootle wallet daemon (walletd) and
its API key — see runbook §3. The GUI never ships or manages walletd.

## License / third-party notices

Project license is **MIT OR Apache-2.0** (see `LICENSE`, `LICENSE-MIT`,
`LICENSE-APACHE`). Third-party attributions are recorded in
[../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md), with the
per-dependency machine-readable reports in
[release/licenses/](release/licenses/) (Rust workspace CSV, Rust src-tauri
CSV, npm-all-licenses, npm-production-licenses, plus the Windows native
dependency note that captures the OpenSSL 3.6.3 static-linked build).

## Notes

- The Tauri release target is the **detached** `gui/src-tauri/target`, not the
  top-level workspace `target`.
- MSI (WiX) and NSIS installers are both produced (`bundle.targets = "all"`).
  Ship whichever the alpha operators prefer; the raw `.exe` is for portable use.
- Installers are **unsigned**. Code-signing is a packaging to-do before wider
  distribution (Windows SmartScreen will warn on unsigned installers).
