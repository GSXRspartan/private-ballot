import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  MICRO_TARI_PER_TARI,
  formatTariFromMicroTari,
  isMicroTariAbove,
  normalizeMicroTari,
} from "../src/wallet/feeFormat.ts";

describe("feeFormat: normalizeMicroTari", () => {
  it("accepts bigint, safe number, and canonical decimal strings", () => {
    assert.equal(normalizeMicroTari(1000n), "1000");
    assert.equal(normalizeMicroTari(1000), "1000");
    assert.equal(normalizeMicroTari("1000"), "1000");
    assert.equal(normalizeMicroTari("0"), "0");
  });

  it("rejects negative, float, unsafe, and malformed values", () => {
    assert.equal(normalizeMicroTari(-1), null);
    assert.equal(normalizeMicroTari(-1n), null);
    assert.equal(normalizeMicroTari(1.5), null);
    assert.equal(normalizeMicroTari(Number.NaN), null);
    assert.equal(normalizeMicroTari(Number.POSITIVE_INFINITY), null);
    assert.equal(normalizeMicroTari(Number.MAX_SAFE_INTEGER + 1), null);
    assert.equal(normalizeMicroTari(""), null);
    assert.equal(normalizeMicroTari("12.5"), null);
    assert.equal(normalizeMicroTari("abc"), null);
    assert.equal(normalizeMicroTari("0123"), null);
    assert.equal(normalizeMicroTari(" 5"), null);
    assert.equal(normalizeMicroTari("1e3"), null);
    assert.equal(normalizeMicroTari("0x10"), null);
    assert.equal(normalizeMicroTari(null), null);
    assert.equal(normalizeMicroTari(undefined), null);
    assert.equal(normalizeMicroTari({}), null);
  });
});

describe("feeFormat: formatTariFromMicroTari", () => {
  it("formats the documented example conversions", () => {
    assert.equal(formatTariFromMicroTari(1_000), "0.001");
    assert.equal(formatTariFromMicroTari(50_000), "0.05");
    assert.equal(formatTariFromMicroTari(1_000_000), "1");
    assert.equal(formatTariFromMicroTari(10_000_000), "10");
  });

  it("accepts bigint and decimal-string µT", () => {
    assert.equal(formatTariFromMicroTari(1_000n), "0.001");
    assert.equal(formatTariFromMicroTari("1000000"), "1");
    assert.equal(formatTariFromMicroTari("10000000"), "10");
  });

  it("trims trailing fractional zeros and omits the point when integral", () => {
    assert.equal(formatTariFromMicroTari(1_500_000), "1.5");
    assert.equal(formatTariFromMicroTari(1_230_000), "1.23");
    assert.equal(formatTariFromMicroTari(2_000_000), "2");
    assert.equal(formatTariFromMicroTari(1), "0.000001");
    assert.equal(formatTariFromMicroTari(1_000_001), "1.000001");
  });

  it("formats zero as 0", () => {
    assert.equal(formatTariFromMicroTari(0), "0");
    assert.equal(formatTariFromMicroTari("0"), "0");
  });

  it("never uses scientific notation and preserves up to six decimals", () => {
    const out = formatTariFromMicroTari(123_456_789);
    assert.equal(out, "123.456789");
    assert.ok(!/[eE]/.test(out as string), "no scientific notation");
    // Very small value keeps six decimals.
    assert.equal(formatTariFromMicroTari(1), "0.000001");
  });

  it("handles very large integers exactly (bigint string path)", () => {
    // Beyond Number.MAX_SAFE_INTEGER, via decimal string.
    const big = "123456789012345678901234567890";
    const out = formatTariFromMicroTari(big);
    assert.ok(out && out.length > 10);
    assert.ok(!/[eE]/.test(out as string));
    // Exact integer math: 1_000_000 µT = 1 TARI.
    const micro = 10_000_000_000_000_000_000n; // 10^19 µT
    assert.equal(formatTariFromMicroTari(micro), "10000000000000");
  });

  it("returns null for malformed, negative, or unsafe values", () => {
    assert.equal(formatTariFromMicroTari(-1), null);
    assert.equal(formatTariFromMicroTari(1.5), null);
    assert.equal(formatTariFromMicroTari("abc"), null);
    assert.equal(formatTariFromMicroTari(Number.MAX_SAFE_INTEGER + 1), null);
  });

  it("uses exact integer division/remainder (no float drift)", () => {
    // 1 TARI + 1 µT must be exactly "1.000001".
    assert.equal(formatTariFromMicroTari(1_000_001), "1.000001");
    // 0.1 TARI exactly.
    assert.equal(formatTariFromMicroTari(100_000), "0.1");
  });
});

describe("feeFormat: isMicroTariAbove", () => {
  it("compares exactly", () => {
    assert.equal(isMicroTariAbove(1_000_001, 1_000_000), true);
    assert.equal(isMicroTariAbove(1_000_000, 1_000_000), false);
    assert.equal(isMicroTariAbove(999_999, 1_000_000), false);
  });

  it("supports bigint/string/number forms", () => {
    assert.equal(isMicroTariAbove(2_000_000n, "1000000"), true);
    assert.equal(isMicroTariAbove("1500000", 1_000_000), true);
  });

  it("returns false for malformed values", () => {
    assert.equal(isMicroTariAbove("abc", 1000), false);
    assert.equal(isMicroTariAbove(1000, "abc"), false);
    assert.equal(isMicroTariAbove(-1, 1000), false);
  });

  it("supports very large integers exactly", () => {
    const big = "100000000000000000000000";
    assert.equal(isMicroTariAbove(big, "1"), true);
    assert.equal(isMicroTariAbove(big, big), false);
  });
});

describe("feeFormat: MICRO_TARI_PER_TARI", () => {
  it("is exactly one million", () => {
    assert.equal(MICRO_TARI_PER_TARI, 1_000_000);
  });
});