import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  artifactFileName,
  buildVoterCredentialArtifact,
  parseVoterCredentialArtifact,
  HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA,
} from "../src/voterCredentialArtifact.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const enrollSrc = fs.readFileSync(path.join(__dirname, "../src/enroll.ts"), "utf8");
const voteSrc = fs.readFileSync(path.join(__dirname, "../src/main.ts"), "utf8");
const artifactSrc = fs.readFileSync(path.join(__dirname, "../src/voterCredentialArtifact.ts"), "utf8");

const ELECTION = "e2e-election";
const SECRET_A = "aa".repeat(32);
const SECRET_B = "bb".repeat(32);
// Deterministic stand-in for the canonical WASM public-key derivation: the
// artifact contract only requires a matching (secret -> public) derivation
// with the same 64-hex shape the real derivation produces.
const derive = (secretHex) => secretHex.split("").reverse().join("");
const PUBLIC_A = derive(SECRET_A);

function validArtifactText({ electionId = ELECTION, secret = SECRET_A } = {}) {
  return JSON.stringify(
    buildVoterCredentialArtifact(electionId, derive(secret), secret, "2026-11-19T00:00:00Z")
  );
}

test("enroll produces a durable, downloadable credential artifact", () => {
  const artifact = buildVoterCredentialArtifact(
    ELECTION,
    PUBLIC_A,
    SECRET_A,
    "2026-11-19T00:00:00Z"
  );
  assert.equal(artifact.schema, HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA);
  const parsed = parseVoterCredentialArtifact(
    JSON.stringify(artifact),
    ELECTION,
    derive
  );
  assert.ok(parsed.ok, JSON.stringify(parsed));
  assert.equal(parsed.secret_key_hex, SECRET_A);
  assert.equal(artifactFileName(ELECTION), `private-ballot-voter-${ELECTION}-credential-v1.json`);
});

test("fresh vote-page context can import the artifact without page state", () => {
  // Simulates the voter leaving the page: only the file text survives.
  const text = JSON.stringify(
    buildVoterCredentialArtifact(ELECTION, PUBLIC_A, SECRET_A, "2026-11-19T00:00:00Z")
  );
  const parsed = parseVoterCredentialArtifact(text, ELECTION, derive);
  assert.ok(parsed.ok);
  assert.equal(parsed.secret_key_hex, SECRET_A);
});

test("imported credential carries the secret the vote flow needs", () => {
  // The shipped vote flow passes this secret into create_ballot_package via
  // the #secret input; validation returns exactly that value.
  const parsed = parseVoterCredentialArtifact(validArtifactText(), ELECTION, derive);
  assert.ok(parsed.ok);
  assert.equal(parsed.secret_key_hex.length, 64);
});

test("wrong-election credential rejected", () => {
  const parsed = parseVoterCredentialArtifact(validArtifactText(), "other-election", derive);
  assert.equal(parsed.ok, false);
  if (!parsed.ok) assert.match(parsed.error, /different election/);
});

test("malformed artifacts rejected", () => {
  const cases = [
    "not json at all",
    "[]",
    "null",
    JSON.stringify({ schema: "other-schema" }),
    JSON.stringify({ schema: HOSTED_VOTER_CREDENTIAL_ARTIFACT_SCHEMA }),
    JSON.stringify(buildVoterCredentialArtifact(ELECTION, "zz", SECRET_A, "x")),
    JSON.stringify(buildVoterCredentialArtifact(ELECTION, PUBLIC_A, "nothex", "x")),
  ];
  for (const text of cases) {
    const parsed = parseVoterCredentialArtifact(text, ELECTION, derive);
    assert.equal(parsed.ok, false, text);
  }
});

test("altered artifact rejected: secret and public key must stay consistent", () => {
  const tamperedSecret = JSON.parse(validArtifactText());
  tamperedSecret.secret_key_hex = SECRET_B;
  const parsedSecret = parseVoterCredentialArtifact(
    JSON.stringify(tamperedSecret),
    ELECTION,
    derive
  );
  assert.equal(parsedSecret.ok, false);

  const tamperedKey = JSON.parse(validArtifactText());
  tamperedKey.public_key_hex = derive(SECRET_B);
  const parsedKey = parseVoterCredentialArtifact(
    JSON.stringify(tamperedKey),
    ELECTION,
    derive
  );
  assert.equal(parsedKey.ok, false);
});

test("voter A artifact cannot authenticate as voter B", () => {
  // B's vote page derives a different public key from B's secret; A's
  // (secret, public key) pair is only valid for A.
  const artifactA = buildVoterCredentialArtifact(ELECTION, PUBLIC_A, SECRET_A, "x");
  const bKey = derive(SECRET_B);
  const tampered = { ...artifactA, public_key_hex: bKey };
  const parsed = parseVoterCredentialArtifact(JSON.stringify(tampered), ELECTION, derive);
  assert.equal(parsed.ok, false);
});

test("two independent enrollments produce distinct artifacts", () => {
  const a = buildVoterCredentialArtifact(ELECTION, PUBLIC_A, SECRET_A, "x");
  const b = buildVoterCredentialArtifact(ELECTION, derive(SECRET_B), SECRET_B, "x");
  assert.notEqual(a.secret_key_hex, b.secret_key_hex);
  assert.notEqual(a.public_key_hex, b.public_key_hex);
});

test("artifact flow requires explicit user actions, not storage or URLs", () => {
  assert.match(enrollSrc, /btn-download-voter-credential/, "enroll page must offer the download action");
  assert.match(voteSrc, /import-credential/, "vote page must offer the import action");
  assert.match(enrollSrc, /downloadVoterCredentialArtifact/, "enroll page must call the builder");
  assert.match(voteSrc, /parseVoterCredentialArtifact/, "vote page must validate the artifact");
});

test("no credential secret in URL, browser storage, or console output", () => {
  for (const [name, src] of [["enroll", enrollSrc], ["vote", voteSrc], ["artifact", artifactSrc]]) {
    assert.doesNotMatch(src, /localStorage\.setItem/i, `${name}: no localStorage`);
    assert.doesNotMatch(src, /sessionStorage\.setItem/i, `${name}: no sessionStorage`);
    assert.doesNotMatch(src, /console\.log|console\.info|console\.debug/i, `${name}: no console logging`);
    assert.doesNotMatch(src, /location\.search/i, `${name}: no query strings`);
  }
  // The only fetch the vote page makes with a secret is none: the secret is
  // consumed locally by WASM; no fetch call appears inside the import flow.
  assert.doesNotMatch(artifactSrc, /fetch\(/, "artifact module never performs network calls");
});

test("page navigation/restart no longer makes enrollment unusable", () => {
  // The artifact is a standalone file: validate a string that came from disk,
  // with no dependence on any page/session state beyond the election id.
  const savedFileText = validArtifactText();
  const parsed = parseVoterCredentialArtifact(savedFileText, ELECTION, derive);
  assert.ok(parsed.ok);
});
