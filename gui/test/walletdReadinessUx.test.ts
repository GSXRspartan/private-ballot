import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

// -----------------------------------------------------------------------------
// Readiness-state rendering — every backend readiness kind must map to a
// bounded, human-readable label. Never a raw HTTP status. The mapping is
// implemented as a string switch inside the Tari Anchor wallet panel; we
// verify the four expected labels appear in the source.
// -----------------------------------------------------------------------------

const MANAGE_ELECTION = readProjectFile("src/screens/ManageElection.tsx");
const FLAT = MANAGE_ELECTION.replace(/\s+/g, " ");

test("readiness=ready renders Ready", () => {
  assert.match(MANAGE_ELECTION, /kind === "ready"/);
  assert.match(MANAGE_ELECTION, />\s*Ready\s*\{/);
});

test("readiness=auth_rejected renders Reconnect Tari Wallet, never a raw 401", () => {
  assert.match(MANAGE_ELECTION, /kind === "auth_rejected"/);
  assert.match(MANAGE_ELECTION, /Reconnect Tari Wallet/);
  assert.doesNotMatch(MANAGE_ELECTION, /\b401\b/);
});

test("readiness=unreachable renders Start Tari Wallet", () => {
  assert.match(MANAGE_ELECTION, /kind === "unreachable"/);
  assert.match(MANAGE_ELECTION, /Start Tari Wallet/);
});

test("readiness=no_credential renders Connect Tari Wallet", () => {
  assert.match(MANAGE_ELECTION, /kind === "no_credential"/);
  assert.match(MANAGE_ELECTION, /Connect Tari Wallet/);
});

test("readiness=permission_denied is handled (reachable, missing scope)", () => {
  // A reachable walletd whose credential lacks a permission must render its
  // own state, never fall through to the unreachable branch.
  assert.match(MANAGE_ELECTION, /kind === "permission_denied"/);
  assert.match(MANAGE_ELECTION, /Accounts:Read/);
});

test("readiness=call_failed is handled (reachable, request failed)", () => {
  assert.match(MANAGE_ELECTION, /kind === "call_failed"/);
  assert.match(MANAGE_ELECTION, /walletd reachable/);
});

test("Use connected wallet only reports GUI_WALLETD_ACCOUNTS_UNAVAILABLE for true unreachability", () => {
  // The account-list error code must be the generic unavailable code only when
  // the transport actually failed; reachable-but-not-ready uses a distinct
  // NOT_READY code plus the specific cause.
  assert.match(MANAGE_ELECTION, /result\.kind === "unreachable"/);
  assert.match(MANAGE_ELECTION, /GUI_WALLETD_ACCOUNTS_NOT_READY/);
  assert.match(MANAGE_ELECTION, /walletAccountsErrorMessage\(result\.kind\)/);
});

test("connect panel guides an Accounts:Read permission for auto-fill", () => {
  assert.match(MANAGE_ELECTION, /Accounts:Read/);
});

// -----------------------------------------------------------------------------
// A "Use connected wallet" click can NEVER be a silent no-op. The reported bug
// was a click that twitched and did nothing (the backend runtime lacked the
// Tokio I/O driver, so the RPC failed before any socket opened). The frontend
// side of the guarantee: the click always drives a visible status transition
// before and after the backend call, and always invokes the backend listing.
// -----------------------------------------------------------------------------

test("Use connected wallet always drives a visible status transition", () => {
  const fn = sliceBetween(
    MANAGE_ELECTION,
    "const onUseConnectedWallet =",
    "const applyWalletAccount",
  );
  // Immediate pre-backend status (visible before any network work).
  assert.match(fn, /setWalletActionStatus\("Checking saved wallet credential/);
  // In-flight status while the backend is contacted.
  assert.match(fn, /setWalletActionStatus\("Listing wallet accounts/);
  // Terminal status derived from the classified result.
  assert.match(fn, /setWalletActionStatus\(walletActionStatusForKind\(result\.kind\)\)/);
  // The backend listing is always invoked (never a cache-only no-op).
  assert.match(fn, /await api\.listWalletdAnchorAccounts\(\)/);
});

test("Use connected wallet renders its status line to the operator", () => {
  assert.match(MANAGE_ELECTION, /data-testid="wallet-action-status"/);
  assert.match(MANAGE_ELECTION, /\{walletActionStatus\}/);
});

test("a successful account listing clears a stale wallet-unreachable banner", () => {
  const fn = sliceBetween(
    MANAGE_ELECTION,
    "const onUseConnectedWallet =",
    "const applyWalletAccount",
  );
  // After kind === ready, the prior GUI_WALLETD_* banner must be cleared.
  assert.match(fn, /clearStaleWalletError\(\)/);
});

test("no walletd/indexer button silently does nothing: each action shows busy or error", () => {
  // The wallet-dependent handlers all set a busy flag, invoke the backend, and
  // surface errors via showError — never returning without a visible effect on
  // the happy path.
  for (const handler of [
    "const onUseConnectedWallet =",
    "const onRunV2AnchorLifecycle =",
  ]) {
    const idx = MANAGE_ELECTION.indexOf(handler);
    assert.notEqual(idx, -1, `handler missing: ${handler}`);
    const body = MANAGE_ELECTION.slice(idx, idx + 2200);
    assert.match(body, /setAnchor\w*Busy\(true\)|setWalletAccountsBusy\(true\)/);
    assert.match(body, /await api\./);
    assert.match(body, /showError\(error\)|setLocalError/);
  }
});

// -----------------------------------------------------------------------------
// Read-only connection diagnostic — a secret-free escape hatch for debugging
// exactly the reported "nothing reaches walletd" symptom.
// -----------------------------------------------------------------------------

test("a read-only walletd connection diagnostic wrapper exists", () => {
  const client = readProjectFile("src/api/client.ts");
  assert.match(client, /walletdConnectionDiagnostics/);
  assert.match(client, /"walletd_connection_diagnostics"/);
});

test("the wallet panel exposes a secret-free 'Diagnose connection' control", () => {
  // Operator-facing escape hatch for the live 'won't go Ready' symptom: a
  // button that runs the read-only diagnostic and renders its non-secret fields.
  assert.match(MANAGE_ELECTION, /Diagnose connection/);
  assert.match(MANAGE_ELECTION, /onDiagnoseWalletConnection/);
  assert.match(MANAGE_ELECTION, /api\.walletdConnectionDiagnostics\(\)/);
  assert.match(MANAGE_ELECTION, /data-testid="wallet-connection-diagnostics"/);
  // It renders the classified result and credential presence, never a token.
  assert.match(MANAGE_ELECTION, /walletDiag\.final_result_kind/);
  assert.match(MANAGE_ELECTION, /walletDiag\.saved_credential/);
  assert.match(MANAGE_ELECTION, /walletDiag\.tcp_loopback_reachable/);
  assert.match(MANAGE_ELECTION, /walletDiag\.unauthenticated_wallet_get_info_result/);
  assert.match(MANAGE_ELECTION, /walletDiag\.accounts_list_attempted/);
  const diagSlice = MANAGE_ELECTION.slice(
    MANAGE_ELECTION.indexOf("anchor-wallet-panel__diag"),
    MANAGE_ELECTION.indexOf("anchor-wallet-panel__diag") + 2000,
  );
  assert.doesNotMatch(diagSlice, /token|api_key|apiKey|bearer/i);
});

test("readiness probe is refreshed after Connect / Reconnect / Forget", () => {
  const probeSites = MANAGE_ELECTION.match(/refreshWalletdReadiness\(\)/g) ?? [];
  // At least: manual Refresh button + Connect/Reconnect success (shared code
  // path) + Forget success = 3 call-sites. Any missed site would leave a
  // stale readiness label.
  assert.ok(
    probeSites.length >= 3,
    `expected at least 3 refresh sites, saw ${probeSites.length}`,
  );
});

// -----------------------------------------------------------------------------
// Required organizer-wallet attestation belongs in Guided View.
// -----------------------------------------------------------------------------

test("dedicated-wallet checkbox is exposed in the normal guided wallet flow", () => {
  const idx = MANAGE_ELECTION.indexOf(
    'data-testid="dedicated-organizer-wallet-attestation"',
  );
  assert.notEqual(idx, -1, "attested-wallet control missing");
  const control = MANAGE_ELECTION.slice(idx, idx + 900);
  const preceding = MANAGE_ELECTION.slice(Math.max(0, idx - 1200), idx);
  assert.doesNotMatch(preceding, /showAllControls\s*&&/);
  assert.doesNotMatch(control, /data-advanced="true"/);
  assert.match(control, /Dedicated organizer wallet/);
  assert.match(control, /checked=\{anchorDedicatedWallet\}/);
  assert.match(control, /setAnchorDedicatedWallet\(e\.target\.checked\)/);
  assert.ok(
    FLAT.includes(
      "Confirm this Tari wallet/account is dedicated to organizer-side election anchoring and is not being used as a voter wallet.",
    ),
  );
});

test("normal view does not mention WALLETD_AUTH_TOKEN", () => {
  // The env var is a dev/CI fallback; normal users must never see it in the
  // Tari Anchor card. The connect panel's copy names the OS credential store
  // instead.
  const anchorPanelIdx = MANAGE_ELECTION.indexOf("anchor-wallet-panel");
  const anchorPanelEnd = MANAGE_ELECTION.indexOf(
    "</div>",
    MANAGE_ELECTION.indexOf(
      "anchor-wallet-panel__perms",
      anchorPanelIdx,
    ),
  );
  const panelSlice = MANAGE_ELECTION.slice(anchorPanelIdx, anchorPanelEnd);
  assert.doesNotMatch(panelSlice, /WALLETD_AUTH_TOKEN/);
});

// -----------------------------------------------------------------------------
// Permission guidance — the connect panel must list exactly the four
// permissions the anchor flow requires and warn against Admin.
// -----------------------------------------------------------------------------

test("connect panel lists the exact minimum walletd permissions", () => {
  for (const perm of [
    "Transactions:Read",
    "TransactionRequests:Create",
    "TransactionRequests:Read",
    "TransactionRequests:Approve",
  ]) {
    assert.match(
      MANAGE_ELECTION,
      new RegExp(perm.replace(":", ":")),
      `missing permission guidance: ${perm}`,
    );
  }
});

test("connect panel warns against granting Admin", () => {
  assert.match(MANAGE_ELECTION, /Do NOT grant\s*<code>Admin<\/code>/);
});

// -----------------------------------------------------------------------------
// Stale wallet-readiness / account-error clearing (contradictory-state repair).
//
// Symptom fixed: fields prefilled + walletd reachable, yet the wallet card shows
// "Start Tari Wallet" and a leftover GUI_WALLETD_ACCOUNTS_UNAVAILABLE banner —
// stale frontend state from an earlier account-list attempt against a down
// walletd. The card must derive from the latest successful readiness/account
// result, and the stale banner must clear on any success.
// -----------------------------------------------------------------------------

function sliceBetween(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `missing marker: ${startMarker}`);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(end, -1, `missing end marker after ${startMarker}: ${endMarker}`);
  return source.slice(start, end);
}

test("clearStaleWalletError only clears wallet-context errors, never unrelated ones", () => {
  // Guarded clear: it must inspect the previous error and keep non-wallet
  // banners intact, so fixing wallet staleness never hides a different error.
  const helper = sliceBetween(
    MANAGE_ELECTION,
    "const clearStaleWalletError =",
    "const onPickManifest",
  );
  assert.match(helper, /context === "walletd"/);
  assert.match(helper, /code\.startsWith\("GUI_WALLETD"\)/);
  assert.match(helper, /setLocalError\(\(prev\)/);
});

test("after account list succeeds, wallet card is set Ready from that result", () => {
  // The wallet card derives from the latest successful account-list result, not
  // a second probe that could race or transiently fail.
  const fn = sliceBetween(
    MANAGE_ELECTION,
    "const onUseConnectedWallet =",
    "const applyWalletAccount",
  );
  assert.match(fn, /const result = await api\.listWalletdAnchorAccounts\(\)/);
  assert.match(fn, /setWalletdReadiness\(\{[\s\S]*kind: result\.kind/);
  assert.match(fn, /summary: result\.summary/);
});

test("after Use connected wallet runs, a prior wallet-account banner is cleared", () => {
  // clearLocalError at entry drops any leftover GUI_WALLETD_ACCOUNTS_* banner
  // before the fresh attempt reports its own outcome.
  const fn = sliceBetween(
    MANAGE_ELECTION,
    "const onUseConnectedWallet =",
    "await api.listWalletdAnchorAccounts",
  );
  assert.match(fn, /clearLocalError\(\)/);
});

test("a fresh Ready readiness probe clears a stale wallet-unreachable banner", () => {
  const fn = sliceBetween(
    MANAGE_ELECTION,
    "const refreshWalletdReadiness =",
    "  // Production transport authority",
  );
  assert.match(fn, /if \(readiness\.kind === "ready"\) clearStaleWalletError\(\)/);
});

test("true walletd unreachable still renders Start Tari Wallet from readiness kind", () => {
  // The card status is driven by walletdReadiness.kind, so a genuinely down
  // walletd keeps its honest label even after the stale banner is cleared.
  assert.match(MANAGE_ELECTION, /kind === "unreachable"/);
  assert.match(MANAGE_ELECTION, /Start Tari Wallet/);
});

// -----------------------------------------------------------------------------
// The normal anchor publishing surface is V2 only: there is no anchor-version
// selector, and wallet controls are shared across every anchor lifecycle step.
// -----------------------------------------------------------------------------

test("Use connected wallet gating is version-free (no anchor-version references)", () => {
  const idx = MANAGE_ELECTION.indexOf("void onUseConnectedWallet()");
  assert.notEqual(idx, -1, "Use connected wallet button missing");
  const buttonOpen = MANAGE_ELECTION.slice(Math.max(0, idx - 400), idx);
  assert.doesNotMatch(buttonOpen, /anchorVersion/);
});

test("wallet readiness derivation never reads anchor version", () => {
  const refresh = sliceBetween(
    MANAGE_ELECTION,
    "const refreshWalletdReadiness =",
    "  // Production transport authority",
  );
  assert.doesNotMatch(refresh, /anchorVersion/);
  const useWallet = sliceBetween(
    MANAGE_ELECTION,
    "const onUseConnectedWallet =",
    "const applyWalletAccount",
  );
  assert.doesNotMatch(useWallet, /anchorVersion/);
});
