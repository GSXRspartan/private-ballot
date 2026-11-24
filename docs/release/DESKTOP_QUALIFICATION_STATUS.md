# Desktop release qualification status — Windows Tauri build

Record for the Desktop (Windows, Tauri) release track. Updated after the
gaming-PC migration rebuild on branch `review/web-mainnet-anchor-6a936d9`.

## Build provenance (2026-11-23)

Rebuilt from final source after the remote-intake repair commit (`a4d99ab`)
— the previous laptop installer predated that source change and is superseded.

- Toolchain: Rust `1.97.1-x86_64-pc-windows-msvc`, MSVC Build Tools 2022
  (VC tools 14.44.35207), OpenSSL 3.6.5 via vcpkg `x64-windows-static-md`.
- Build command: `npm run tauri build` (gui/), `CARGO_TARGET_DIR` on the
  internal NVMe SSD, source on the external E: drive.
- Artifacts (not committed; kept out of Git deliberately):
  - `Private Ballot_0.1.0_x64-setup.exe` (NSIS, 11,876,851 bytes)
    SHA-256 `DAECFEE1B4622678BF984A2C27416CD21345A59F37EA5895B52D78B44C4BC1CA`
  - `Private Ballot_0.1.0_x64_en-US.msi` (14,966,784 bytes)
    SHA-256 `CE68841B86F0280BB7CFA921D89530AD0D50C59F984A0B88AC3EFDD3370751ED`
- Installers are unsigned (no code-signing certificate configured in
  `tauri.conf.json`); do not distribute until signing is decided.

## Automated verification completed

- Desktop Rust suite (`tari-cc-private-ballot-gui`): 105/105, including the
  six repaired `organizer_tor_intake` source-snapshot tests.
- Workspace suites: hosted 77/77 (after availability hardening), gui-core
  and anchor-transport all green.
- GUI frontend: `tsc --noEmit` clean (part of the release build), 1147/1147
  node tests.
- Hosted Web: 120/120 node tests.
- Launch smoke test: the release EXE starts, creates the "Private Ballot"
  window with a full WebView2 render tree, and stops cleanly. This confirms
  launch, resource loading, and the single-manifest fix only.

## NOT yet verified (manual procedure required)

A complete organizer/voter GUI workflow has never been executed against this
build. Compilation and launch are not release qualification. Until the
procedure below is executed and passes on a clean Windows machine, the
Desktop track is NOT release-qualified and no installer may be published.

Manual procedure (est. 30–45 minutes; no wallet or Mainnet transaction
required):

1. Install via the NSIS setup EXE on a clean Windows profile (or run the
   portable EXE). Confirm WebView2 bootstrap and shortcut creation.
2. Organizer election lifecycle: create an election, import/export the
   Hosted descriptor request/response round-trip, freeze the registry,
   open voting, submit organizer lifecycle transitions, close and finalize.
   Confirm every irreversible action prompts explicit confirmation.
3. Voter workflow: import the voter credential artifact (verify a wrong
   passphrase is rejected), cast a ballot through the GUI against a local
   managed-Tor organizer, confirm the receipt is accepted, and confirm a
   second vote by the same credential is rejected as a duplicate nullifier.
4. Tor transport: start managed-local intake with a real `tor.exe`, confirm
   the owned-child lifecycle (start, stop, app-exit reaps the child; check
   Task Manager for orphaned `tor.exe`). If available, exercise
   external-remote mode against a separately run Tor daemon and confirm
   the new readiness status check reports UNAVAILABLE-then-ready correctly.
5. Archive import and verification: export the finalized archive, verify it
   in the app (ARCHIVE VERIFIED), and confirm a tampered archive file fails.
6. Anchor verification screen: load a saved Mainnet anchor evidence payload
   (read-only; do NOT publish any new transaction) and confirm the app shows
   the verified anchor for election `pb-staging-browser-e2e-1795362392453`.
7. Error handling: force each failure once — busy collector port, missing
   descriptor response before intake, invalid onion hostname — and confirm
   bounded, specific, retryable error messages with no path/secret leakage.
8. Secrets boundaries: confirm organizer transport material exists only
   under the per-election `organizer-private` directory and voter
   credentials are passphrase-encrypted at rest.

## Standing audit findings relevant to this track

- Organizer transport secrets are stored as plaintext files under the
  per-user AppData tree (audit MEDIUM-1). Same-user malware can read them;
  Windows per-user ACLs are the only current protection. Mitigation options:
  DPAPI/keyring protection, matching the walletd key handling.
- `test_remote_organizer_tor` is not organizer-authority-gated (audit
  LOW-3): a compromised webview gains a bounded network-probing oracle.
- Unsigned installers (LOW-4) and `downloadBootstrapper` WebView2 mode.
- None of these are release blockers for staging use, but MEDIUM-1 should
  be resolved before any public installer distribution.
