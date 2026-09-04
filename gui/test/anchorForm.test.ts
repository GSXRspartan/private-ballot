// Anchor operator-config form tests: cross-navigation persistence (Task D) and
// one-click connected-wallet auto-fill (Task C).
//
// The frontend has no React mount harness (ADR-0007); the pure form logic is
// exercised directly here.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_ACCOUNT_REFERENCE,
  DEFAULT_INDEXER_ENDPOINT,
  DEFAULT_WALLETD_ENDPOINT,
  anchorSidecarPaths,
  anchorFormStorageKey,
  applyConnectedWallet,
  clearAnchorFormState,
  defaultAnchorFormState,
  loadAnchorFormState,
  safeAccountReference,
  saveAnchorFormState,
  walletAccountsErrorMessage,
  walletActionStatusForKind,
  walletReadinessLabel,
  type AnchorFormState,
  type KeyValueStore,
} from "../src/anchor/anchorForm.ts";
import type {
  GuiWalletdAnchorAccountV1,
  WalletdReadinessKindV1,
} from "../src/api/types.ts";

// A minimal in-memory store standing in for window.localStorage.
class MemoryStore implements KeyValueStore {
  private map = new Map<string, string>();
  getItem(key: string): string | null {
    return this.map.has(key) ? (this.map.get(key) as string) : null;
  }
  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
}

const account: GuiWalletdAnchorAccountV1 = {
  name: "Private Ballot",
  component_address:
    "component_70f35a1b4b5bfecaafeaf946e0ffca69cae17869af9fa966fabc9a59e3e2d1d7",
  owner_public_key_hex:
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  key_index: 0,
  is_default: true,
  is_confirmed_on_chain: true,
};

describe("safeAccountReference never yields whitespace", () => {
  it("slugifies a spaced display name (the root-cause input)", () => {
    assert.equal(safeAccountReference("Private Ballot"), "private-ballot");
  });
  it("falls back to a safe constant for empty/garbage", () => {
    assert.equal(safeAccountReference(""), DEFAULT_ACCOUNT_REFERENCE);
    assert.equal(safeAccountReference("   "), DEFAULT_ACCOUNT_REFERENCE);
    assert.equal(safeAccountReference(null), DEFAULT_ACCOUNT_REFERENCE);
  });
  it("produces no whitespace for any input", () => {
    for (const input of ["a b c", "  weird__NAME!! ", "ünïcode space"]) {
      assert.ok(!/\s/.test(safeAccountReference(input)), `whitespace in ${input}`);
    }
  });
});

describe("anchorSidecarPaths derives deterministic release-safe siblings", () => {
  it("places V1 config, snapshot, and evidence beside a Windows archive directory", () => {
    const paths = anchorSidecarPaths(
      "C:\\Users\\pdark\\Documents\\Codex\\500-voter-final-archive",
    );
    assert.deepEqual(paths, {
      configPath:
        "C:\\Users\\pdark\\Documents\\Codex\\500-voter-final-archive-anchor-config.cbor",
      snapshotPath:
        "C:\\Users\\pdark\\Documents\\Codex\\500-voter-final-archive-anchor-snapshot.cbor",
      evidencePath:
        "C:\\Users\\pdark\\Documents\\Codex\\500-voter-final-archive-anchor-evidence.cbor",
    });
  });

  it("strips a trailing separator instead of placing sidecars inside the archive", () => {
    const paths = anchorSidecarPaths("C:\\Users\\pdark\\Documents\\Codex\\archive\\");
    assert.equal(
      paths.configPath,
      "C:\\Users\\pdark\\Documents\\Codex\\archive-anchor-config.cbor",
    );
    assert.doesNotMatch(paths.configPath, /archive\\-anchor-config\.cbor$/);
  });
});

describe("applyConnectedWallet fills brittle fields safely", () => {
  it("fills fee component, owner key, index, and a safe reference", () => {
    const filled = applyConnectedWallet(defaultAnchorFormState(), account, {
      network: "esmeralda",
      template_address: "template_1",
    });
    assert.equal(filled.feeComponent, account.component_address);
    assert.equal(filled.declaredSealPublicKey, account.owner_public_key_hex);
    assert.equal(filled.sealSignerKind, "account");
    assert.equal(filled.sealSignerId, "0");
    assert.equal(filled.network, "esmeralda");
    assert.equal(filled.walletdEndpoint, DEFAULT_WALLETD_ENDPOINT);
    assert.equal(filled.indexerEndpoint, DEFAULT_INDEXER_ENDPOINT);
    // The spaced display name must NOT become the account reference.
    assert.ok(!/\s/.test(filled.accountReference));
    assert.equal(filled.accountReference, "private-ballot");
  });

  it("keeps an operator-chosen non-default reference", () => {
    const state: AnchorFormState = {
      ...defaultAnchorFormState(),
      accountReference: "my-custom-ref",
    };
    const filled = applyConnectedWallet(state, account, null);
    assert.equal(filled.accountReference, "my-custom-ref");
  });

  it("replaces a default reference and never keeps whitespace", () => {
    const state: AnchorFormState = {
      ...defaultAnchorFormState(),
      accountReference: "bad ref with spaces",
    };
    const filled = applyConnectedWallet(state, account, null);
    assert.ok(!/\s/.test(filled.accountReference));
  });
});

describe("walletAccountsErrorMessage names the exact cause, never a false unreachable", () => {
  it("maps each non-ready kind to a distinct, truthful message", () => {
    // No saved credential guides the operator to reconnect + paste a key, and
    // is explicitly NOT worded as unreachable.
    assert.match(
      walletAccountsErrorMessage("no_credential"),
      /Reconnect Tari Wallet and paste a valid API key first\./,
    );
    assert.match(walletAccountsErrorMessage("auth_rejected"), /Reconnect Tari Wallet/);
    assert.match(
      walletAccountsErrorMessage("permission_denied"),
      /Accounts:Read|account-read|read accounts/i,
    );
    assert.match(walletAccountsErrorMessage("call_failed"), /reachable/i);
    assert.match(walletAccountsErrorMessage("unreachable"), /not reachable/i);
  });

  it("only 'unreachable' is worded as not reachable", () => {
    // The reported bug: a reachable walletd whose account list failed was told
    // "walletd is not reachable". These reachable kinds must NOT say that.
    for (const kind of [
      "auth_rejected",
      "permission_denied",
      "call_failed",
    ] as WalletdReadinessKindV1[]) {
      assert.doesNotMatch(
        walletAccountsErrorMessage(kind),
        /not reachable/i,
        `${kind} must not be worded as unreachable`,
      );
    }
  });

  it("permission_denied stays reachable but flags the missing scope", () => {
    const msg = walletAccountsErrorMessage("permission_denied");
    assert.doesNotMatch(msg, /not reachable/i);
    assert.match(msg, /permission/i);
  });

  it("ready yields no error message", () => {
    assert.equal(walletAccountsErrorMessage("ready"), "");
  });

  it("readiness labels cover every kind and never leak a raw status", () => {
    for (const kind of [
      "ready",
      "no_credential",
      "auth_rejected",
      "permission_denied",
      "call_failed",
      "unreachable",
    ] as WalletdReadinessKindV1[]) {
      const label = walletReadinessLabel(kind);
      assert.ok(label.length > 0, `missing label for ${kind}`);
      assert.doesNotMatch(label, /\b401\b|\b403\b|\b500\b/);
    }
  });
});

describe("walletActionStatusForKind is a terminal, secret-free status line", () => {
  it("maps each kind to the exact operator-facing status", () => {
    assert.equal(walletActionStatusForKind("ready"), "Wallet account loaded");
    assert.equal(
      walletActionStatusForKind("no_credential"),
      "No saved wallet credential",
    );
    assert.equal(
      walletActionStatusForKind("auth_rejected"),
      "Wallet API key rejected",
    );
    assert.equal(
      walletActionStatusForKind("permission_denied"),
      "Wallet API key missing Accounts:Read",
    );
    assert.match(walletActionStatusForKind("call_failed"), /reachable/i);
    assert.equal(
      walletActionStatusForKind("unreachable"),
      "Walletd is not reachable",
    );
  });

  it("only 'unreachable' is worded as not reachable", () => {
    for (const kind of [
      "ready",
      "no_credential",
      "auth_rejected",
      "permission_denied",
      "call_failed",
    ] as WalletdReadinessKindV1[]) {
      assert.doesNotMatch(
        walletActionStatusForKind(kind),
        /not reachable/i,
        `${kind} must not be worded as unreachable`,
      );
    }
  });

  it("never leaks a raw HTTP status", () => {
    for (const kind of [
      "ready",
      "no_credential",
      "auth_rejected",
      "permission_denied",
      "call_failed",
      "unreachable",
    ] as WalletdReadinessKindV1[]) {
      assert.doesNotMatch(walletActionStatusForKind(kind), /\b401\b|\b403\b|\b500\b/);
    }
  });
});

describe("form state persists across navigation", () => {
  it("round-trips through storage keyed by archive+template", () => {
    const store = new MemoryStore();
    const key = anchorFormStorageKey("archivehash", "template_addr");
    const edited: AnchorFormState = {
      ...defaultAnchorFormState(),
      feeComponent: "component_abc",
      maxFee: 4242,
      dedicatedWallet: true,
    };
    saveAnchorFormState(store, key, edited);

    // Simulate unmount/remount: a fresh load reads the persisted values.
    const reloaded = loadAnchorFormState(store, key);
    assert.equal(reloaded.feeComponent, "component_abc");
    assert.equal(reloaded.maxFee, 4242);
    assert.equal(reloaded.dedicatedWallet, true);
  });

  it("is keyed distinctly per archive and template", () => {
    assert.notEqual(
      anchorFormStorageKey("hashA", "tmpl"),
      anchorFormStorageKey("hashB", "tmpl"),
    );
    assert.notEqual(
      anchorFormStorageKey("hash", "tmplA"),
      anchorFormStorageKey("hash", "tmplB"),
    );
  });

  it("returns defaults for an unknown key or bad JSON", () => {
    const store = new MemoryStore();
    const key = anchorFormStorageKey("x", "y");
    assert.deepEqual(loadAnchorFormState(store, key), defaultAnchorFormState());
    store.setItem(key, "{not valid json");
    assert.deepEqual(loadAnchorFormState(store, key), defaultAnchorFormState());
  });

  it("Reset clears persisted state", () => {
    const store = new MemoryStore();
    const key = anchorFormStorageKey("x", "y");
    saveAnchorFormState(store, key, { ...defaultAnchorFormState(), maxFee: 9 });
    clearAnchorFormState(store, key);
    assert.deepEqual(loadAnchorFormState(store, key), defaultAnchorFormState());
  });

  it("never persists a bearer token or private key field", () => {
    const store = new MemoryStore();
    const key = anchorFormStorageKey("x", "y");
    saveAnchorFormState(store, key, defaultAnchorFormState());
    const raw = store.getItem(key) ?? "";
    for (const forbidden of ["token", "bearer", "secret", "private", "jwt", "password"]) {
      assert.ok(
        !raw.toLowerCase().includes(forbidden),
        `persisted form must not contain "${forbidden}": ${raw}`,
      );
    }
  });
});
