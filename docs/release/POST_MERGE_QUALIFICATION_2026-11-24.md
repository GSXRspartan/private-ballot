# Post-merge development qualification record — 2026-11-24

Branch `feat/desktop-universe-qualification`, based on merged `main` at PR #1.
This record covers the remaining Desktop and live Universe qualification work.
It deliberately does **not** claim any manual GUI or wallet success.

## Phase 1 — post-merge source verification

- STARTING HEAD: `fa5597f4f6490693a485bdb879d1d0bde8de18f6` (merge commit of PR #1).
- CURRENT BRANCH: `feat/desktop-universe-qualification` (created from merged main).
- Commit `fa5597f` is HEAD and is an ancestor of HEAD: confirmed.
- Working tree was clean at start (only intended documentation edits were made
  in this session).
- Build tools present: Rust/cargo `1.97.1`, Node `24.14.0`, npm `11.9.0`,
  pnpm `11.6.0`; installed Rust targets `x86_64-pc-windows-msvc`,
  `x86_64-pc-windows-gnu`, `wasm32-unknown-unknown`. `cargo-tauri` is not a
  global command; the Tauri CLI is a local devDependency in `gui/`.
- Disk: D: 458.87 GB free (repository preserved on external D:); C: 39.34 GB free.
- No unrelated Rust targets were rebuilt; the existing `D:\pb-target` Cargo
  cache was reused for Desktop checks.

## Phase 2 — Desktop end-to-end workflow

### Artifact determination

- The exact reviewed installer corresponding to merged source is the NSIS
  `Private Ballot_0.1.0_x64-setup.exe`, 11,876,851 bytes, SHA-256
  `DAECFEE1B4622678BF984A2C27416CD21345A59F37EA5895B52D78B44C4BC1CA`, built on
  the gaming PC from final source after `a4d99ab`. It is **not present on this
  laptop** and must be transferred from the gaming-PC release assets.
- The local `D:\pb-target` installer has different bytes and must not be
  substituted (`docs/release/OPERATOR_QUALIFICATION_CHECKLIST.md` §Actual built
  Desktop artifacts).
- The launch-smoke executable at
  `D:\pb-target\release\tari-cc-private-ballot-gui.exe` was hashed in this
  session as SHA-256
  `B402857C780426F22A5D4E90AD0E72978CAC3F0DB84D1267F4229E41E0EFF37F`,
  matching the documented value. It is launch-smoke only, not a qualified
  installer.
- No Desktop source change occurred after the reviewed build; backend/CI/doc
  changes do not affect the native binary, so no new installer is justified by
  source. A fresh local build is possible with the installed toolchain but would
  produce a different, unqualified artifact; it was intentionally not built or
  published to avoid substituting an unqualified installer.

### Manual workflow status

- DESKTOP MANUAL STEPS PASSED: 0 of 13. None of the human-only GUI steps in
  `docs/release/DESKTOP_QUALIFICATION_STATUS.md` §Action-by-action manual test
  script and `docs/release/OPERATOR_QUALIFICATION_CHECKLIST.md` was performed in
  this session. A real `tor.exe`, real clicks, and a clean Windows profile are
  required. No manual success is inferred from automated tests.
- DESKTOP ISSUES DISCOVERED:
  - Qualified NSIS installer is not on this laptop (transfer required).
  - Installers remain unsigned (LOW-4); organizer transport secrets remain
    plaintext at rest under per-election `organizer-private` (audit MEDIUM-1).
  - Documentation drift: both fee-preflight docs described a
    `fee_receipt.total_fees_paid` fallback that the source deliberately removed
    in favour of fail-closed handling. Corrected in this session.
  - No new runtime code defect was reproduced in this session.
- DESKTOP FIXES: corrected the two stale fee-preflight doc statements; no code
  fix was warranted because the reviewed source already fails closed.
- DESKTOP RELEASE READY: NO. Gate C remains NOT READY until 13/13 manual steps
  pass on a clean profile, the reviewed (or newly signed and qualified)
  installer is available, installer signing is decided, and MEDIUM-1 is
  addressed before public distribution.

## Phase 3 — live Tari Universe qualification

- Official docs reviewed: `https://universe.tari.mw/integrations` and the
  `tari-dapp.d.ts` provider reference. The project adapter matches the official
  contract: `window.tari` / `window.tariUniverse` / `window.tariProviders`,
  `tari#initialized`, `postMessage` bridge pinned to parent origin
  `https://universe.tari.mw`, `frame-ancestors 'self' https://universe.tari.mw`
  only on canonical dApp documents, error codes 4001/4100/4200/-32603,
  `dryRun: true` described by the wallet docs as "simulate only, never prompts,
  spends nothing", and `dryRunIsLocal` capability feature-detection.
- Existing adapter: `hosted-web/public/tari-connector.js` (bridge),
  `gui/src/wallet/provider.ts` (WindowTariProvider, strict dry-run schema,
  provider pinning), `gui/src/wallet/errors.ts`, `gui/src/wallet/network.ts`,
  `hosted-web/src/anchorSubmissionPolicy.ts` (mandatory preflight, guarded
  publish driver), `hosted-web/src/anchor.ts` and `browserAnchor.ts`
  (authorized-account, mainnet, capability revalidation before every action).
- UNIVERSE LIVE CONNECTED: NO. No real wallet connection was made; the provider
  is only reachable inside Universe's cross-origin iframe and requires the
  operator to launch the staging URL from the Universe catalogue and approve.
- UNIVERSE MAINNET VERIFIED: NO (source-level checks only: `tari_getNetwork`
  must return `mainnet` / byte `0x00`, unique `CURRENT` Mainnet V2 deployment,
  revalidated before every anchor action).
- UNIVERSE CAPABILITIES: source-level only — `transactionRequests`,
  `transactionResultLookup`, `dryRunIsLocal`; required caps are rechecked before
  each action. Not observed against a live provider.
- UNIVERSE DRY RUN: NO. No `tari_signAndSubmitTransaction` was issued. The
  adapter is limited to one `dryRun: true` call with strict
  `result.finalize.total_fees_required` parsing and a 5000 µT cap; no
  `createRequest`/`submit` fallback exists on that path.
- UNIVERSE REMAINING BLOCKERS: human in-iframe launch and approval; observe
  connected account, mainnet network, capabilities; one non-spending fee
  preflight; wallet rejection / disconnect / reload behaviour; wrong-account and
  wrong-network protections. Exact clicks and expected results are in
  `docs/release/OPERATOR_QUALIFICATION_CHECKLIST.md` §Live Web Tari Universe
  non-spending checklist and `docs/tari/wallet-integration.md`.

## Phase 4 — production release roadmap

- Created `docs/hosted/PRODUCTION_DEPLOYMENT_CHECKLIST.md`: an executable,
  unchecked checklist for a separate `ballot.ghostgate.boo` deployment covering
  Worker/DNS, isolated backend/database, authority keys, custody/recovery, rate
  limits/security, backup/restore, monitoring/alerts, operator docs, wallet
  authorization, and rollback, plus go/no-go gates and a sign-off table.
- No production deployment, DNS change, key rotation, Mainnet transaction, or
  staging-data reuse was performed.

## Phase 5 — verification, review, and commit

- Regression suites and type checks executed in this session:
  - Desktop Rust lib suite (`cargo test --release --locked --lib` in
    `gui/src-tauri`, reusing `D:\pb-target`): **105 passed, 0 failed**.
  - GUI frontend node suite (`npm test` in `gui/`): **1147 passed, 0 failed**.
  - Hosted Web node suite (`npm test` in `hosted-web/`): **120 passed, 0 failed**.
  - `npx tsc --noEmit` clean in both `gui/` and `hosted-web/`.
  - No Rust source or canonical format was changed; the two code-adjacent
    documentation corrections reflect the source's existing fail-closed
    behaviour. Automated tests do not substitute for the manual Desktop or
    live wallet procedures above.
- Five original README screenshots under `docs/images/release-v0.1.0/` were
  confirmed present, git-tracked, and unmodified.
- No secrets, private keys, recovery phrases, or binaries were added to Git.

## Live iframe-embedding fix (2026-11-25)

Human report: opening the staging app inside Tari Universe showed
"private-ballot-staging.ghostgate.boo refused to connect".

Live GET evidence before the fix: the staging document already sent
`frame-ancestors https://universe.tari.mw` and no `X-Frame-Options`, so the
initial missing-Universe-allowance hypothesis was wrong. Live GET of
`https://universe.tari.mw/` showed the parent document sends
`Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp`, with `frame-src https:`. The
staging document sent neither `Cross-Origin-Embedder-Policy` nor
`Cross-Origin-Resource-Policy`.

Browser reproduction: headless Chrome with a local stand-in parent at the exact
`https://universe.tari.mw` origin (host-resolver override, self-signed cert
ignored) reproducing the Universe parent headers loaded the staging URL in an
iframe and logged
`net::ERR_BLOCKED_BY_RESPONSE corp-not-same-origin-after-defaulted-to-same-origin-by-coep`
for the Document. That is the actual embedding blocker. The Universe `blob:`
media CSP warning and the indexer `component_…` 404 were not reproduced as the
cause; the former is enforced by Universe's own `media-src`, which we do not
control, and the app's chain reads go through the same-origin `/chain/*` proxy.

Minimal fix in `hosted-web/src-edge/worker.ts`: dApp HTML documents now send
`frame-ancestors 'self' https://universe.tari.mw` (official recommendation),
`Cross-Origin-Embedder-Policy: require-corp`, and
`Cross-Origin-Resource-Policy: cross-origin`. No script/connect/object policy,
admin block, origin-token injection, wallet postMessage origin pinning, backend,
database, key, or production setting was changed. API, admin, and asset responses
keep `frame-ancestors 'none'` with no COEP/CORP opt-in.

Staging-only deployment: Worker version `f8015e7c-3796-4613-b995-9517a4d4d8dd`
→ `864b1354-605e-4a8f-827b-ebaea1fef189`; rollback to the previous version with
`npx wrangler rollback --name private-ballot-staging`. Post-deploy live GET
verified all document headers, no `X-Frame-Options`, admin 404 (including
encoded variants), health 200, and finalized-election, archive, results, and
anchor-payload reads still 200. The same Chrome reproduction now returns 200 for
the iframe document with no CORP/COEP network failure. Hosted Web suite
125/125 passed.

## Live Tari Universe non-spending qualification (2026-11-25, human)

Human-observed PASS results in the real wallet: iframe rendering, wallet
connection, Ootle Mainnet identification, exactly one authorized account, and
one non-spending fee quote on finalized election
`pb-staging-browser-e2e-1795362392453`. Observed figures: estimated 3466 µT
(0.003466 TARI), allowance-adjusted recommended minimum 3478 µT (0.003478
TARI), authorized maximum 5000 µT (0.005 TARI), release ceiling 10 TARI, within
cap. No approval popup, funded transaction, or new anchor. `dryRunIsLocal` was
not recorded by the operator. The provider exposes no fee read-back, so the
quote does not prove funded execution or on-chain `maxFee` enforcement.
Classification: **LIVE NON-SPENDING QUALIFIED**; funded transaction
authorization remains **NOT QUALIFIED** for Universe.

Earlier missing-component 404 review: the reported `component_2a6b…` is not the
reviewed Mainnet V2 template `template_ef4d…`. A read-only GET of
`/substates/component_2a6b…` returned 200 with a verified `Up` substate, while
`/components/component_2a6b…` returned 404. The 404 was an unsupported endpoint
shape in a background lookup, not a missing anchor template and not a cause of
the fee simulation; no source fix was required.

Failure-path audit (adapter logic): 4001 rejection maps to a bounded error with
no retry; hosted panels clear wallet state on `accountsChanged`; no application
code calls `tari_disconnect`; reload/recovery is status-only and cannot
resubmit; network and account are revalidated before quote/create/submit; the
quote path issues exactly one `dryRun: true` call with a pinned provider and no
fee read-back. Focused regressions were added for probe/connect rejection,
`accountsChanged` clearing, wrong account/network at quote time, absence of
implicit disconnect, and the fee-read-back caveat. Human failure-path tests
remain pending and are specified in `docs/tari/wallet-integration.md`.
Test results after the additions: GUI 1151/1151, Hosted Web 129/129.
