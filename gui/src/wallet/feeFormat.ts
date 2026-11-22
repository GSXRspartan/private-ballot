/**
 * Exact, bigint-safe TARI fee formatting.
 *
 * All internal fee accounting, wallet API requests, comparisons, and enforcement
 * are in integer microTARI (µT). This module converts a microTARI amount to a
 * human-readable TARI string for DISPLAY ONLY, using integer division and
 * remainder — never floating point. 1 TARI = 1,000,000 µT.
 */

/** 1 TARI = 1,000,000 microTARI. */
export const MICRO_TARI_PER_TARI = 1_000_000;

/** Maximum number of fractional digits (6) — matches TARI's 10^-6 divisibility. */
const MAX_FRACTION_DIGITS = 6;

/**
 * Validates and normalizes a non-negative integer microTARI value.
 *
 * Accepts `bigint`, a validated decimal string (canonical `0` or a non-zero digit
 * sequence), or a safe non-negative integer `number`. Rejects negatives, floats,
 * scientific notation, hex, empty strings, and unsafe (>2^53) numbers.
 *
 * Returns the canonical decimal string (no leading zeros except "0"), or `null`
 * when the value is malformed or unsafe.
 */
export function normalizeMicroTari(value: unknown): string | null {
  if (typeof value === "bigint") {
    return value >= 0n ? value.toString() : null;
  }
  if (typeof value === "number") {
    // Only exact, safe, non-negative integers are accepted. Floats, NaN,
    // Infinity, and unsafe integers are rejected.
    return Number.isSafeInteger(value) && value >= 0 ? String(value) : null;
  }
  if (typeof value === "string") {
    // Canonical decimal integer string: "0" or [1-9][0-9]*. No leading zeros,
    // no sign, no decimal point, no exponent, no whitespace.
    if (/^(0|[1-9]\d*)$/.test(value)) {
      // Reject values beyond the safe integer range for exactness.
      try {
        const asBig = BigInt(value);
        if (asBig > BigInt(Number.MAX_SAFE_INTEGER)) {
          // Still representable exactly as a bigint string; allow it because
          // the caller opted into a string (bigint-safe path). This preserves
          // arbitrarily large exact values for display.
          return asBig.toString();
        }
        return asBig.toString();
      } catch {
        return null;
      }
    }
    return null;
  }
  return null;
}

/**
 * Formats a microTARI amount as a TARI string with up to six decimal places.
 *
 * - Uses exact integer division/remainder (no floating point).
 * - Trims trailing zeros in the fractional part; omits the point when integral.
 * - Never uses scientific notation.
 * - Returns `null` for malformed, negative, or unsafe values (never guesses).
 *
 * Examples:
 *   1_000      -> "0.001"
 *   50_000     -> "0.05"
 *   1_000_000  -> "1"
 *   10_000_000 -> "10"
 *   1          -> "0.000001"
 */
export function formatTariFromMicroTari(value: unknown): string | null {
  const normalized = normalizeMicroTari(value);
  if (normalized === null) return null;
  const micro = BigInt(normalized);
  const whole = micro / BigInt(MICRO_TARI_PER_TARI);
  const remainder = micro % BigInt(MICRO_TARI_PER_TARI);
  if (remainder === 0n) {
    return whole.toString();
  }
  const frac = remainder
    .toString()
    .padStart(MAX_FRACTION_DIGITS, "0")
    .replace(/0+$/, "");
  return `${whole.toString()}.${frac}`;
}

/**
 * Compares two microTARI amounts exactly. Returns true when `a > b`.
 * Both values are normalized first; malformed values compare as not-greater.
 */
export function isMicroTariAbove(a: unknown, b: unknown): boolean {
  const na = normalizeMicroTari(a);
  const nb = normalizeMicroTari(b);
  if (na === null || nb === null) return false;
  return BigInt(na) > BigInt(nb);
}