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
- Re-verified on the Windows laptop on 2026-11-24 from source `cebdff9` using
  the existing `D:\pb-target` Cargo cache (no installer rebuild): GUI Rust
  `cargo test --release --locked` 105/105; GUI node `npm test` 1147/1147;
  hosted-web `npm test` 120/120; `npx tsc --noEmit` clean in both projects.
- Source fixes in this branch do not touch the Desktop binary: hosted rate-map
  hardening, hosted enrollment-scrub fail-closed, removal of an unused hosted
  schema constant, anchor encoder `expect()` removal, and a scoped PR CI
  workflow. Hosted 78/78, the anchor integration-vector suite 16/16, and
  anchor clippy all pass.
  Consequently no new installer is justified by source changes.

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

### Action-by-action manual test script

No human GUI session was available on this laptop, so none of the following
was executed. Each step must be performed on a clean Windows profile and
recorded with logs/screenshots that contain no wallet secrets, ballot choices
tied to real identities, or private keys.

1. Run `Private Ballot_0.1.0_x64-setup.exe`; expected: WebView2 bootstrap,
   Start-menu shortcut, application opens to Home with no crash.
2. Home → Create election: enter a disposable id such as
   `desktop-qual-<UTC stamp>`; expected: draft created and listed.
3. Manage election → configuration: set a two-option approval question and
   authorized slot count 2; expected: values persist after restart.
4. Organizer → enrollment slots / invitations: create two invitations;
   expected: plaintext invitations shown once, verifiers stored, no secrets in
   logs; attempt to issue a third against one slot and expect rejection.
5. Enroll two voters with generated credentials; import one voter credential
   with a deliberately wrong passphrase and expect rejection without state
   change, then with the correct passphrase and expect success.
6. Organizer → freeze registry; expected: explicit confirmation prompt and
   status `REGISTRY_FROZEN`; verify enrollment linkage was scrubbed.
7. Organizer → open voting; cast one ballot per voter through the GUI using
   a local managed-Tor organizer; expected: receipts accepted.
8. Replay the same credential's ballot; expected: duplicate-nullifier rejection.
9. Organizer → close and finalize; expected: archive produced and verified
   in-app (`ARCHIVE VERIFIED`); import a tampered copy and expect failure.
10. Anchor screen → load the saved read-only Mainnet anchor evidence for
    `pb-staging-browser-e2e-1795362392453`; expected: verified anchor shown;
    do NOT publish or submit anything.
11. Tor transport: start/stop managed intake, close the app, and check Task
    Manager for orphaned `tor.exe`; expected: no orphans, readiness shows
    UNAVAILABLE-then-ready.
12. Error states: busy collector port, missing descriptor response, invalid
    onion hostname; expected: bounded specific retryable messages with no
    path or secret leakage.
13. Inspect `%APPDATA%` per-election tree; expected organizer transport
    material only under `organizer-private`, voter containers passphrase
    encrypted. This confirms the documented MEDIUM-1 limitation still applies.

Steps 1–13 require human clicks and a real `tor.exe`; they are the only
remaining blocker for Desktop release qualification (plus installer signing).

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
