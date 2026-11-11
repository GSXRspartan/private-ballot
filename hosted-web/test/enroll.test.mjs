import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(__dirname, "../src/enroll.ts"), "utf8");

// Security invariants verified against the source text.

test("invitation never placed in URL or querystring", () => {
  assert.doesNotMatch(src, /location\.search.*invit/i, "invitation must not be placed in search params");
  assert.doesNotMatch(src, /location\.href.*invit/i, "invitation must not be placed in href");
  assert.doesNotMatch(src, /location\.hash.*invit/i, "invitation must not be placed in hash");
  assert.doesNotMatch(src, /encodeURIComponent.*invitationSecret/,
    "invitation secret must not be URI-encoded for a URL");
});

test("invitation never written to browser storage", () => {
  assert.doesNotMatch(src, /localStorage\.setItem.*invit/i, "invitation must not go to localStorage");
  assert.doesNotMatch(src, /sessionStorage\.setItem.*invit/i, "invitation must not go to sessionStorage");
  assert.doesNotMatch(src, /indexedDB.*invit/i, "invitation must not go to IndexedDB");
});

test("private credential never sent to backend", () => {
  // The body sent to /enroll must include public_key_hex; secretKeyHex must not appear in
  // the JSON.stringify call that builds the POST body.
  assert.match(src, /public_key_hex.*publicKeyHex/, "public key must be in enroll body");
  assert.doesNotMatch(src, /invitation_secret_hex.*secretKeyHex/,
    "private credential must not be sent as invitation secret");
  // The only key sent alongside invitation_secret_hex must be public_key_hex
  const enrollBodyMatch = src.match(/JSON\.stringify\(\{([^}]+)\}\)/);
  if (enrollBodyMatch) {
    assert.doesNotMatch(enrollBodyMatch[1], /secretKeyHex/,
      "secretKeyHex must not appear inside the enroll request body");
  }
});

test("private credential never written to browser storage", () => {
  assert.doesNotMatch(src, /localStorage\.setItem.*secret/i, "secret must not go to localStorage");
  assert.doesNotMatch(src, /sessionStorage\.setItem.*secret/i, "secret must not go to sessionStorage");
});

test("invitation cleared from memory after successful enrollment", () => {
  // After a successful enrollment (res.ok), invitationSecret must be set to empty string.
  // The clear must appear inside the if (res.ok) block, i.e. after the check.
  const okIdx = src.indexOf("if (res.ok)");
  assert.ok(okIdx >= 0, "must have if (res.ok) block");
  // Find the LAST occurrence of invitationSecret = "" (inside the success block, not module init)
  let lastClearIdx = -1;
  let searchFrom = 0;
  while (true) {
    const idx = src.indexOf('invitationSecret = ""', searchFrom);
    if (idx < 0) break;
    lastClearIdx = idx;
    searchFrom = idx + 1;
  }
  assert.ok(lastClearIdx > okIdx,
    "invitation clear must occur after the if (res.ok) check (last occurrence must be inside the success handler)");
});

test("no third-party runtime dependencies", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf8"));
  assert.equal(pkg.dependencies, undefined);
});

test("enroll.ts imports only credential and registry-verification WASM functions", () => {
  // Must NOT import create_ballot_package (private secret is passed to that fn in voting UI)
  assert.doesNotMatch(src, /create_ballot_package/, "enroll.ts must not import ballot creation");
  // Must import the safe credential and canonical registry commitment functions.
  assert.match(src, /generate_secret_key/, "must import generate_secret_key");
  assert.match(src, /public_key_for_secret/, "must import public_key_for_secret");
  assert.match(src, /compute_registry_commitment/, "must import canonical registry commitment function");
});

test("no console.log of secrets in enroll.ts", () => {
  // Check that no console.log call directly references secret or invitation variables
  const logLines = src.split("\n").filter((l) => l.includes("console.log"));
  for (const line of logLines) {
    assert.doesNotMatch(line, /secretKeyHex|invitationSecret/,
      `console.log must not reference secrets: ${line}`);
  }
});

test("privacy notice and credential safety warning present", () => {
  assert.match(src, /reduced network-metadata privacy/i, "privacy notice required");
  assert.match(src, /never sent to the server|never leaves your device/i, "server isolation claim required");
  assert.match(src, /KEEP THIS VOTING CREDENTIAL SAFE/i, "credential safety warning required");
  assert.match(src, /memory-only/i, "memory-only warning required");
});

test("enrollment step machine covers all required states", () => {
  assert.match(src, /invitation_entry/, "step: invitation_entry");
  assert.match(src, /generate_credential/, "step: generate_credential");
  assert.match(src, /confirm_credential/, "step: confirm_credential");
  assert.match(src, /receipt/, "step: receipt");
  assert.match(src, /wait_freeze/, "step: wait_freeze");
  assert.match(src, /frozen/, "step: frozen");
});

test("conflict and 401 errors handled without revealing internals", () => {
  // credential_conflict handled
  assert.match(src, /credential_conflict/, "must handle credential_conflict");
  // 401 handled
  assert.match(src, /status === 401/, "must handle 401");
  // enrollment_closed handled
  assert.match(src, /enrollment_closed/, "must handle enrollment_closed");
});

test("frozen registry is verified locally and mismatches fail closed", () => {
  assert.match(src, /registry_cbor_hex/, "must obtain canonical frozen registry bytes");
  assert.match(src, /compute_registry_commitment/, "must use WASM commitment computation");
  assert.match(src, /integrity_failure/, "must show integrity failure state");
  assert.match(src, /Voting and proof generation are blocked/, "must fail closed on mismatch");
});
