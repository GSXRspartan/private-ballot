// Donation section regression tests (About screen "Donate to the dev").
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Where no React harness exists, GUI behaviors are pinned by semantic
// source assertions (identifiable elements and attributes), never by
// fragile pixel analysis.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { encode } from "uqr";

import {
  DONATION_DISCLAIMER,
  DONATION_XTM_ADDRESS,
  DONATION_YAT,
} from "../src/branding/donation.ts";

const EXPECTED_XTM =
  "1259DG2v4nxMugUpj3pgSheEEhVZmoExr44GhpnC9FGVwiJscmwo2oYnzFTQWxcsHBYjmupCBaWUsNf5gDttKw2Xmg4";
const EXPECTED_YAT = "🐱🔒🌙🔒🐱";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

// -------------------------------------------------------------------------
// Public donation constants: exact, full, never truncated
// -------------------------------------------------------------------------

describe("public donation constants", () => {
  it("pins the exact full XTM one-sided receive address", () => {
    assert.equal(DONATION_XTM_ADDRESS, EXPECTED_XTM);
    assert.equal(DONATION_XTM_ADDRESS.length, EXPECTED_XTM.length);
  });

  it("pins the exact Yat Unicode emoji sequence", () => {
    assert.equal(DONATION_YAT, EXPECTED_YAT);
    // Codepoint-exact: cat, lock, moon, lock, cat — never normalized,
    // reordered, replaced, or converted.
    assert.equal(DONATION_YAT, "\u{1F431}\u{1F512}\u{1F319}\u{1F512}\u{1F431}");
    assert.equal([...DONATION_YAT].length, 5);
  });

  it("states donations never affect voting, verification, access, or results", () => {
    assert.match(DONATION_DISCLAIMER, /never affect voting, verification, access, or election results/);
    assert.match(DONATION_DISCLAIMER, /optional/);
  });

  it("keeps the donation constants module free of any backend/wallet imports", () => {
    const source = readProjectFile("src/branding/donation.ts");
    assert.doesNotMatch(source, /^import /m);
    assert.doesNotMatch(source, /invoke\(|api\/client/);
  });
});

// -------------------------------------------------------------------------
// About screen donation section
// -------------------------------------------------------------------------

describe("About donation section", () => {
  const about = readProjectFile("src/screens/About.tsx");

  it('contains "Donate to the dev" (single developer, never "team")', () => {
    assert.match(about, /Donate to the dev/);
    assert.doesNotMatch(about, /dev team|the team|development fund/i);
  });

  it("renders the donation disclaimer", () => {
    assert.match(about, /DONATION_DISCLAIMER/);
  });

  it("places the donation card after the Scope notice (bottom of the page)", () => {
    assert.ok(
      about.indexOf("Scope.") < about.indexOf("Donate to the dev"),
      "donation card must be visually subordinate at the bottom",
    );
  });

  it("copies the full exact XTM address via the shared safe clipboard helper", () => {
    assert.match(about, /value=\{DONATION_XTM_ADDRESS\}/);
    assert.match(about, /CopyButton/);
    // The helper copies its `value` verbatim through the async clipboard API.
    const ui = readProjectFile("src/components/ui.tsx");
    assert.match(ui, /navigator\.clipboard\.writeText\(value\)/);
    // Subtle, non-permanent, non-color-only feedback.
    assert.match(ui, /Copied/);
    assert.match(ui, /setTimeout/);
  });

  it("copies the exact Yat string", () => {
    assert.match(about, /value=\{DONATION_YAT\}/);
  });

  it("displays the full XTM address without truncation", () => {
    assert.match(about, /\{DONATION_XTM_ADDRESS\}/);
    const css = readProjectFile("src/styles/global.css");
    const address = css.match(/\.donate-address\s*\{[^}]*\}/);
    assert.ok(address, "missing .donate-address rule");
    assert.match(address[0], /overflow-wrap:\s*anywhere/);
    assert.doesNotMatch(address[0], /text-overflow:\s*ellipsis/);
  });

  it("displays the exact Yat as native Unicode text (never an image)", () => {
    assert.match(about, /\{DONATION_YAT\}/);
    assert.doesNotMatch(about, /<img[^>]*yat/i);
  });

  it("provides the required accessible names", () => {
    assert.match(about, /Copy XTM donation address/);
    assert.match(about, /Copy Yat/);
    assert.match(about, /Show XTM QR code|Show \$\{qrToggleLabel\}/);
    assert.match(about, /XTM QR code/);
    assert.match(about, /Yat QR code/);
    assert.match(about, /aria-expanded/);
    assert.match(about, /aria-controls/);
  });

  it("mentions other supported addresses only through the Yat", () => {
    assert.match(about, /Other supported donation addresses are available through the Yat/);
  });

  it("never shows BTC/ETH/SOL/XMR/Polygon/BNB or other donation addresses", () => {
    for (const source of [about, readProjectFile("src/branding/donation.ts")]) {
      assert.doesNotMatch(source, /\bBTC\b|\bbitcoin\b/i);
      assert.doesNotMatch(source, /\bETH\b|\bethereum\b/i);
      assert.doesNotMatch(source, /\bSOL\b|\bsolana\b/i);
      assert.doesNotMatch(source, /\bXMR\b|\bmonero\b/i);
      assert.doesNotMatch(source, /polygon|matic/i);
      assert.doesNotMatch(source, /\bBNB\b|\bbinance\b/i);
      // No base58/bech32-looking crypto address other than the XTM one.
      const scrubbed = source.split(EXPECTED_XTM).join("");
      const addresses = scrubbed.match(/[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[0-9a-fA-F]{40}|bc1[a-z0-9]{20,}/g) ?? [];
      assert.deepEqual(addresses, []);
    }
  });

  it("introduces no secret or credential material", () => {
    // Scope: the donation constants module and the donation section of
    // About only. (The pre-existing Architecture card legitimately explains
    // that private keys stay behind the backend boundary.)
    const donationSection = about.slice(about.indexOf("Donate to the dev"));
    for (const source of [donationSection, readProjectFile("src/branding/donation.ts")]) {
      assert.doesNotMatch(source, /private.?key|seed|mnemonic|passphrase|password/i);
      assert.doesNotMatch(source, /view.?key|spend.?key/i);
      assert.doesNotMatch(source, /api.?key|access.?token|bearer/i);
      assert.doesNotMatch(source, /wallet\.(db|dat)|console_wallet|Tari Universe/i);
    }
  });

  it("keeps the existing About branding and disclaimer intact", () => {
    assert.match(about, /COMMUNITY_DISCLAIMER/);
    assert.match(about, /Open-source acknowledgements/);
    assert.match(about, /Project identity/);
    assert.match(about, /Architecture/);
    const identity = readProjectFile("src/branding/identity.ts");
    assert.match(identity, /not affiliated with or endorsed by Tari Labs/i);
  });
});

// -------------------------------------------------------------------------
// QR generation: local, exact payload, scanner-safe colors
// -------------------------------------------------------------------------

describe("QR code generation", () => {
  const qr = readProjectFile("src/components/QrCode.tsx");

  it("encodes locally with no remote API, image service, or analytics", () => {
    assert.match(qr, /from "uqr"/);
    assert.doesNotMatch(qr, /fetch\(|http:\/\/|https:\/\/|<img/);
  });

  it("encodes the exact component value, not a shortened or wrapped form", () => {
    assert.match(qr, /encode\(value/);
    // About passes the exact constants straight into the QR component.
    const about = readProjectFile("src/screens/About.tsx");
    assert.match(about, /<QrCode value=\{value\} label=\{qrLabel\} \/>/);
  });

  it("renders dark modules on white with a quiet zone in both themes", () => {
    assert.match(qr, /fill="#ffffff"/);
    assert.match(qr, /fill="#000000"/);
    assert.match(qr, /QUIET_ZONE = 4/);
    assert.doesNotMatch(qr, /invert:\s*true/);
  });

  it("gives the QR an accessible text equivalent", () => {
    assert.match(qr, /role="img"/);
    assert.match(qr, /aria-label=\{label\}/);
  });

  it("encodes the exact XTM address payload", () => {
    const result = encode(DONATION_XTM_ADDRESS, { ecc: "M", border: 0 });
    assert.ok(result.size >= 21);
    assert.equal(result.data.length, result.size);
    assert.ok(result.data.every((row) => row.length === result.size));
    // Deterministic: re-encoding the same literal yields the same matrix.
    const again = encode(EXPECTED_XTM, { ecc: "M", border: 0 });
    assert.deepEqual(result.data, again.data);
    // Encoding actually depends on the payload (not a fixed image).
    const other = encode(`${EXPECTED_XTM}x`, { ecc: "M", border: 0 });
    assert.notDeepEqual(result.data, other.data);
  });

  it("encodes the exact Yat payload (Unicode preserved)", () => {
    const result = encode(DONATION_YAT, { ecc: "M", border: 0 });
    assert.ok(result.size >= 21);
    assert.equal(result.data.length, result.size);
    const again = encode(EXPECTED_YAT, { ecc: "M", border: 0 });
    assert.deepEqual(result.data, again.data);
    // Distinct payload from the XTM QR.
    const xtm = encode(DONATION_XTM_ADDRESS, { ecc: "M", border: 0 });
    assert.notDeepEqual(result.data, xtm.data);
  });
});

// -------------------------------------------------------------------------
// Isolation: donating never touches election or wallet functionality
// -------------------------------------------------------------------------

describe("donation isolation", () => {
  it("adds no donation UI outside the About screen", () => {
    for (const file of [
      "src/screens/Home.tsx",
      "src/screens/Vote.tsx",
      "src/screens/CreateElection.tsx",
      "src/screens/ManageElection.tsx",
      "src/screens/Archive.tsx",
      "src/screens/Anchor.tsx",
      "src/screens/Evidence.tsx",
      "src/screens/Settings.tsx",
      "src/components/AppFrame.tsx",
    ]) {
      const source = readProjectFile(file);
      assert.doesNotMatch(source, /donat/i, `${file} references donations`);
    }
  });

  it("leaves the production CSP unchanged", () => {
    const config = JSON.parse(readProjectFile("src-tauri/tauri.conf.json"));
    assert.equal(
      config.app.security.csp,
      "default-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' data:; style-src 'self'; font-src 'self'; script-src 'self'",
    );
  });
});
