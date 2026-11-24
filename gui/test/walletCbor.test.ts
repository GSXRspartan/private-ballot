import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { cborDecodeStrict, CborError } from "../src/wallet/cbor.ts";
import { encodeCborTextLiteral } from "../src/wallet/cborLiteral.ts";
import {
  CBOR_TEXT_LITERALS,
  EXEC_RESULT_BASE64,
} from "./anchorVectors.generated.ts";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

describe("cbor text literal encoding", () => {
  it("matches the Rust tari_bor vectors byte for byte", () => {
    for (const vector of CBOR_TEXT_LITERALS) {
      assert.equal(
        encodeCborTextLiteral(vector.value),
        vector.hex,
        `literal ${vector.key}`,
      );
    }
  });

  it("encodes the 24-byte boundary exactly like Rust", () => {
    assert.equal(encodeCborTextLiteral("a".repeat(23)), `77${"61".repeat(23)}`);
    assert.equal(
      encodeCborTextLiteral("a".repeat(24)),
      `7818${"61".repeat(24)}`,
    );
  });

  it("encodes the 256-byte boundary exactly like Rust", () => {
    assert.equal(
      encodeCborTextLiteral("b".repeat(255)).slice(0, 4),
      "78ff",
    );
    assert.equal(
      encodeCborTextLiteral("b".repeat(256)).slice(0, 6),
      "790100",
    );
  });
});

describe("cbor strict decoder", () => {
  it("decodes uints, text, bytes, arrays, maps, tags, and nulls", () => {
    const decoded = cborDecodeStrict(hexToBytes("a2616101616243010203"));
    assert.equal(decoded.type, "map");
    assert.equal(decoded.value, 2);
    assert.equal(decoded.entries[0].key.value, "a");
    assert.equal(decoded.entries[0].value.value, 1);
    assert.equal(decoded.entries[1].key.value, "b");
    assert.equal(decoded.entries[1].value.type, "bytes");
  });

  it("decodes a tagged value and null", () => {
    const decoded = cborDecodeStrict(hexToBytes("c1f6"));
    assert.equal(decoded.type, "tag");
    assert.equal(decoded.tag, 1);
    assert.equal(decoded.children[0].type, "simple");
    assert.equal(decoded.children[0].value, null);
  });

  it("decodes integers beyond the safe range as bigint", () => {
    const decoded = cborDecodeStrict(hexToBytes("1b0020000000000001"));
    assert.equal(decoded.type, "uint");
    assert.equal(decoded.value, 9007199254740993n);
  });

  it("rejects trailing bytes", () => {
    assert.throws(() => cborDecodeStrict(hexToBytes("0100")), CborError);
  });

  it("rejects empty input and indefinite lengths", () => {
    assert.throws(() => cborDecodeStrict(new Uint8Array(0)), CborError);
    assert.throws(() => cborDecodeStrict(hexToBytes("9fff")), CborError);
  });

  it("rejects truncated bodies", () => {
    assert.throws(() => cborDecodeStrict(hexToBytes("65")), CborError);
    assert.throws(() => cborDecodeStrict(hexToBytes("582101")), CborError);
  });
});

describe("execute result decoding", () => {
  it("decodes the Rust-generated fixture exactly", async () => {
    const { decodeExecuteResultBase64 } = await import("../src/wallet/executeResult.ts");
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    assert.equal(
      decoded.transactionHashHex,
      "9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
    );
    assert.equal(decoded.epoch, 7);
    assert.equal(decoded.resultVariant, "accept");
    assert.equal(decoded.events.length, 2);
    const anchor = decoded.events[0];
    assert.equal(
      anchor.templateAddressHex,
      "5f1ecbe69b1c6e8b64b97b37f32f6975be4b1e2a1d9c4a5e3f2b6c8d0a9e7f41",
    );
    assert.equal(
      anchor.topic,
      "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
    );
    assert.deepEqual(anchor.metadata, [
      {
        key: "anchor_digest_v2",
        value: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
      },
      { key: "election_id", value: "5e50e17c401682fb38dbea349a4c2713" },
      { key: "network", value: "mainnet" },
      {
        key: "public_summary",
        value:
          '{"election_id":"5e50e17c401682fb38dbea349a4c2713","questions":[{"text":"Adopt the charter?","options":["Yes","No"]}],"ballot_count":10}',
      },
    ]);
    const engine = decoded.events[1];
    assert.equal(engine.topic, "std.vault.pay_fee");
    // Native CBOR types stay native: the pay_fee amount decodes to a number.
    assert.deepEqual(engine.metadata, [
      { key: "amount", value: 123 },
      { key: "note", value: "engine event" },
    ]);
  });
});
