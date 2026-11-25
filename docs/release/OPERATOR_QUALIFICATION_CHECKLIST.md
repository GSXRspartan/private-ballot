# Operator qualification checklist (human interaction required)

NOT PERFORMED. This is the exact checklist for the remaining human-only
qualification. Do not mark any item PASS without observing it in the real GUI
or browser. Capture logs/screenshots that contain no wallet secrets, private
keys, voter passphrases, or real voter identities.

## Actual built Desktop artifacts

- Portable launch-smoke app: `D:\pb-target\release\tari-cc-private-ballot-gui.exe`
  SHA-256 `B402857C780426F22A5D4E90AD0E72978CAC3F0DB84D1267F4229E41E0EFF37F`.
  This is for launch smoke only, not a qualified installer.
- The reviewed NSIS installer recorded in `DESKTOP_QUALIFICATION_STATUS.md` is
  `Private Ballot_0.1.0_x64-setup.exe`, 11,876,851 bytes, SHA-256
  `DAECFEE1B4622678BF984A2C27416CD21345A59F37EA5895B52D78B44C4BC1CA`.
  It is **not present on this laptop**; the local `D:\pb-target` installer has
  different bytes and must not be used. Obtain the reviewed artifact from the
  gaming-PC release assets before qualification.
- All installers are unsigned and are **not** for distribution. No Desktop
  source change occurred after the reviewed build; backend/CI changes do not
  affect it.

Start the app on a clean Windows profile:

```powershell
& "D:\pb-target\release\tari-cc-private-ballot-gui.exe"
```

or run the NSIS setup EXE and launch the Start-menu shortcut.

## Desktop 13-step workflow

| # | Action | PASS | FAIL |
|---|---|---|---|
| 1 | Install/run EXE | WebView2 bootstraps, shortcut created, Home opens, no crash | Any crash, blank window, missing WebView2 |
| 2 | Home → Create election with disposable id `desktop-qual-<UTC>` | Draft created and listed | Duplicate/rejected id without reason |
| 3 | Configure two-option approval question, authorized slot count 2 | Values persist after app restart | Values lost or wrong limits |
| 4 | Create two invitations; try a third against one slot | Two plaintext invitations shown once, verifiers stored, third rejected | Secret logged, third issued, or no rejection |
| 5 | Enroll two voters; import one credential with wrong passphrase, then correct | Wrong passphrase rejected with no state change; correct import succeeds | State changes on wrong passphrase or import fails |
| 6 | Organizer → freeze registry | Explicit confirmation prompt; status `REGISTRY_FROZEN`; linkage scrubbed | Freezes without prompt or linkage remains |
| 7 | Organizer → open voting | Status becomes open; ballots accepted | Premature close or acceptance failure |
| 8 | Cast one ballot per voter via local managed Tor | Both receipts accepted | Any receipt rejected or proof error |
| 9 | Replay the same credential/ballot | Duplicate-nullifier rejection, no second count | Double count or new receipt |
| 10 | Close and finalize; export archive; verify in-app; import a deliberately tampered copy | Final archive produced, `ARCHIVE VERIFIED`, tampered copy rejected | Finalize/verify fails or tampered archive accepted |
| 11 | Read-only Mainnet anchor evidence for `pb-staging-browser-e2e-1795362392453` | App shows verified anchor; nothing published | Resubmission, signing, or new transaction |
| 12 | Tor lifecycle + error states: start/stop intake, close app, check Task Manager; busy port, missing descriptor, invalid onion | No orphan `tor.exe`; readiness UNAVAILABLE→ready; bounded specific errors with no paths/secrets | Orphan process, hang, or leaked path/secret |
| 13 | Inspect `%APPDATA%` per-election tree | Transport material only under `organizer-private`; voter containers passphrase-encrypted | Plaintext voter credentials or misplaced secrets |

Steps 1–13 are human-only; a PASS log must be produced by the operator. The
Desktop track stays NOT RELEASE-READY until they pass and the installer is signed.

## Live Web Tari Universe — non-spending checklist

Prerequisite: the user's own wallet and browser. Never request a recovery
phrase, seed, private key, or password. Never click publish/approve/submit.

| # | Action | Expected output | Status |
|---|---|---|---|
| 1 | In Tari Universe, open its dApp catalogue and launch `https://private-ballot-staging.ghostgate.boo` from inside the wallet | Page loads embedded; ordinary tab reports "Not running inside Tari Universe" | PASS (human, 2026-11-25, after COEP/CORP repair) |
| 2 | Check Settings → Tari Wallet | Tari Universe entry discovered via `window.tariUniverse` / `window.tariProviders` / embedded `window.tari`; document CSP allows `frame-ancestors 'self' https://universe.tari.mw` plus COEP/CORP | PASS (human, 2026-11-25) |
| 3 | Click Connect Tari Universe; approve the wallet popup | Connected status; one authorized account; `tari_getNetwork` reports `mainnet`; capabilities populated | PASS (human, 2026-11-25): one authorized account, Mainnet |
| 4 | On finalized election `pb-staging-browser-e2e-1795362392453`, run only the fee preflight / estimate action | Exactly one `tari_signAndSubmitTransaction` with `dryRun: true`; no approval popup; fee estimate ≤ 5000 µT | PASS (human, 2026-11-25): 3466 µT / 0.003466 TARI; adjusted minimum 3478 µT / 0.003478 TARI; cap 5000 µT / 0.005 TARI; ceiling 10 TARI. `dryRunIsLocal` was not recorded. |
| 5 | Non-spending failure paths: decline connection, switch network if available, disconnect, reload and re-probe | Bounded 4001/4100/4200 errors; no auto-reconnect; no request resubmission | PENDING human; adapter audited and regressions added |
| 6 | Stop | No funded transaction, no new anchor, no approval or submit action | PASS (no transaction submitted) |

Fee read-back limitation: the Universe provider exposes no post-approval fee
read-back, so the quote does not prove funded execution or on-chain `maxFee`
enforcement. Funded transaction authorization is NOT qualified for Universe.

## Evidence and stop conditions

Stop immediately on any crash, secret exposure, funded/signing request,
unexpected network, or duplicate submission. Record only status text, hashes,
and non-sensitive screenshots. Do not post the contest draft or publish
installers.
