import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  OOTLE_NETWORK_BYTES,
  networkByteFromName,
  networkMatched,
  networkVerdict,
  networkVerdictText,
} from "../src/wallet/network.ts";

describe("ootle network byte table", () => {
  it("pins every network byte from otle-network-0.2.0", () => {
    assert.equal(OOTLE_NETWORK_BYTES.mainnet, 0x00);
    assert.equal(OOTLE_NETWORK_BYTES.stagenet, 0x01);
    assert.equal(OOTLE_NETWORK_BYTES.nextnet, 0x02);
    assert.equal(OOTLE_NETWORK_BYTES.localnet, 0x10);
    assert.equal(OOTLE_NETWORK_BYTES.igor, 0x24);
    assert.equal(OOTLE_NETWORK_BYTES.esmeralda, 0x26);
  });

  it("maps canonical names case-insensitively and trims whitespace", () => {
    assert.equal(networkByteFromName("esmeralda"), 0x26);
    assert.equal(networkByteFromName("Mainnet"), 0x00);
    assert.equal(networkByteFromName("  IGOR  "), 0x24);
  });

  it("rejects unknown and empty names", () => {
    assert.equal(networkByteFromName("solana"), null);
    assert.equal(networkByteFromName(""), null);
    assert.equal(networkByteFromName("mainnet "), 0x00);
    assert.equal(networkByteFromName("tari-mainnet"), null);
  });
});

describe("network verdict", () => {
  it("matches identical networks by byte", () => {
    const verdict = networkVerdict("esmeralda", "esmeralda");
    assert.deepEqual(verdict, { kind: "match", byte: 0x26 });
    assert.equal(networkMatched(verdict), true);
  });

  it("matches different spellings of the same network", () => {
    assert.equal(networkMatched(networkVerdict("mainnet", "Mainnet")), true);
  });

  it("fails closed on a network mismatch", () => {
    const verdict = networkVerdict("mainnet", "esmeralda");
    assert.deepEqual(verdict, {
      kind: "mismatch",
      configuredByte: 0x00,
      walletByte: 0x26,
    });
    assert.equal(networkMatched(verdict), false);
  });

  it("fails closed when the wallet reports an unknown network", () => {
    const verdict = networkVerdict("mainnet", "notarealnet");
    assert.deepEqual(verdict, {
      kind: "wallet_network_unknown",
      walletName: "notarealnet",
    });
    assert.equal(networkMatched(verdict), false);
  });

  it("fails closed when the configured network is unknown", () => {
    const verdict = networkVerdict("fakenet", "mainnet");
    assert.deepEqual(verdict, {
      kind: "configured_network_unknown",
      configuredName: "fakenet",
    });
    assert.equal(networkMatched(verdict), false);
  });

  it("renders human text for every verdict kind", () => {
    for (const verdict of [
      networkVerdict("mainnet", "mainnet"),
      networkVerdict("mainnet", "esmeralda"),
      networkVerdict("mainnet", "mystery"),
      networkVerdict("mystery", "mainnet"),
    ] as const) {
      const text = networkVerdictText(verdict);
      assert.equal(typeof text, "string");
      assert.ok(text.length > 0);
    }
    assert.match(
      networkVerdictText(networkVerdict("mainnet", "esmeralda")),
      /different Ootle network/,
    );
    assert.match(
      networkVerdictText(networkVerdict("mainnet", "mystery")),
      /unrecognized network/,
    );
  });
});
