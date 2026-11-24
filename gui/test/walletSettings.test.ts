import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  WALLET_LABELS,
  accountsChanged,
  checkingWalletEntry,
  connectFailed,
  connectStarted,
  connectSucceeded,
  initialWalletEntries,
  probeWalletEntry,
  walletEntryButton,
  walletEntryStatus,
} from "../src/wallet/settingsState.ts";
import type { WalletEntry } from "../src/wallet/settingsState.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function entry(kind: "sapient" | "universe", phase: WalletEntry["phase"]): WalletEntry {
  return { kind, label: WALLET_LABELS[kind], phase };
}

describe("wallet entry initial state", () => {
  it("offers both browser wallets in idle state and persists no addresses", () => {
    const entries = initialWalletEntries();
    assert.deepEqual(
      entries.map((e) => e.kind),
      ["sapient", "universe"],
    );
    for (const e of entries) {
      assert.equal(e.phase.kind, "idle");
      assert.equal(JSON.stringify(e).includes("component_"), false);
    }
  });
});

describe("probeWalletEntry", () => {
  it("maps a failed discovery to absent with the reason", () => {
    const mapped = probeWalletEntry("sapient", null, "No Tari wallet answered");
    assert.equal(mapped.phase.kind, "absent");
    if (mapped.phase.kind === "absent") {
      assert.equal(mapped.phase.reason, "No Tari wallet answered");
    }
  });

  it("maps probe states to honest phases", () => {
    const outcomes: [string, WalletEntry["phase"]["kind"]][] = [
      ["available", "ready"],
      ["needs_connect", "needs_connect"],
      ["unsupported", "unsupported"],
      ["unavailable", "unavailable"],
    ];
    for (const [state, expected] of outcomes) {
      const mapped = probeWalletEntry(
        "sapient",
        {
          available: state === "available" || state === "needs_connect",
          state: state as "available" | "needs_connect" | "unsupported" | "unavailable",
          unavailableReason: "detail",
          unusableReason: null,
          capabilities: null,
        },
        null,
      );
      assert.equal(mapped.phase.kind, expected, state);
    }
  });

  it("never labels a needs_connect wallet as absent", () => {
    const mapped = probeWalletEntry(
      "sapient",
      {
        available: true,
        state: "needs_connect",
        unavailableReason: null,
        unusableReason: "not connected",
        capabilities: null,
      },
      null,
    );
    assert.equal(mapped.phase.kind, "needs_connect");
    assert.match(walletEntryStatus(mapped), /Connect wallet/);
  });
});

describe("connect flow", () => {
  it("walks connecting -> connected(network) -> needs_connect on empty accountsChanged", () => {
    let current = checkingWalletEntry("sapient");
    current = connectStarted(current);
    assert.equal(current.phase.kind, "connecting");
    current = connectSucceeded(current, "mainnet");
    assert.deepEqual(current.phase, { kind: "connected", network: "mainnet" });
    current = accountsChanged(current, ["component_abc"]);
    assert.equal(current.phase.kind, "connected");
    current = accountsChanged(current, []);
    assert.equal(current.phase.kind, "needs_connect");
  });

  it("records a connect failure with its message", () => {
    const current = connectFailed(entry("sapient", { kind: "connecting" }), "declined");
    assert.deepEqual(current.phase, {
      kind: "connect_failed",
      message: "declined",
    });
  });

  it("shows the connected network or an honest unknown-network note", () => {
    assert.match(
      walletEntryStatus(connectSucceeded(entry("universe", { kind: "connecting" }), "esmeralda")),
      /Wallet network: esmeralda/,
    );
    assert.match(
      walletEntryStatus(connectSucceeded(entry("universe", { kind: "connecting" }), null)),
      /did not report its network/,
    );
  });

  it("ignores accountsChanged while not connected", () => {
    const current = accountsChanged(entry("sapient", { kind: "needs_connect" }), []);
    assert.equal(current.phase.kind, "needs_connect");
  });
});

describe("wallet entry button", () => {
  it("enables Connect wallet for ready and needs_connect entries", () => {
    for (const phase of [{ kind: "ready" as const }, { kind: "needs_connect" as const }]) {
      const button = walletEntryButton(entry("sapient", phase));
      assert.equal(button.hidden, false);
      assert.equal(button.disabled, false);
      assert.equal(button.label, "Connect wallet");
    }
  });

  it("disables the button while connecting and when connected", () => {
    assert.deepEqual(walletEntryButton(entry("sapient", { kind: "connecting" })), {
      label: "Waiting for wallet…",
      disabled: true,
      hidden: false,
    });
    assert.deepEqual(walletEntryButton(entry("sapient", { kind: "connected", network: "mainnet" })), {
      label: "Wallet Connected",
      disabled: true,
      hidden: false,
    });
  });

  it("hides the button for absent, unsupported, unavailable, and failed entries", () => {
    for (const phase of [
      { kind: "absent" as const, reason: "x" },
      { kind: "unsupported" as const, reason: "x" },
      { kind: "unavailable" as const, reason: "x" },
      { kind: "connect_failed" as const, message: "x" },
      { kind: "idle" as const },
      { kind: "checking" as const },
    ]) {
      assert.equal(walletEntryButton(entry("sapient", phase)).hidden, true);
    }
  });
});

// -----------------------------------------------------------------------------
// Settings screen safety assertions (source-level, per repo convention while
// no component test harness exists).
// -----------------------------------------------------------------------------

const SETTINGS = readProjectFile("src/screens/Settings.tsx");
const FLAT = SETTINGS.replace(/\s+/g, " ");

it("the browser wallet card is not rendered inside the Tauri desktop shell", () => {
  assert.match(FLAT, /!isDesktopShell\(\) \? <BrowserWalletCard \/> : null/);
});

it("the card never displays balances or persists wallet addresses", () => {
  assert.doesNotMatch(SETTINGS, /get_balances|getBalances/);
  assert.doesNotMatch(SETTINGS, /localStorage|sessionStorage/);
  assert.match(FLAT, /No balances, transaction history, or wallet contents are displayed or stored/);
});

it("connecting is explained as explicit, review-gated approval", () => {
  assert.match(FLAT, /ask the wallet to review and approve transactions you explicitly submit/);
  assert.match(FLAT, /never receives keys, seed phrases/);
});
