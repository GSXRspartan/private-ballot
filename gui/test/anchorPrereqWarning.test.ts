// Anchor prerequisite warning + checklist tests.
//
// The frontend has no React mount harness (ADR-0007), so these pin the source
// invariants: a prominent "verify results first" warning with a full checklist
// appears while the verified/finalized archive is missing, points the operator
// to the Archive menu, and the V2 anchor Build/Prepare/Submit controls stay
// gated on the archive being ready.
//
// Run with: npm test

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const MANAGE_ELECTION = readFileSync(
  new URL("../src/screens/ManageElection.tsx", import.meta.url),
  "utf8",
);
// Whitespace-flattened copy for prose assertions (JSX wraps text across lines).
const FLAT = MANAGE_ELECTION.replace(/\s+/g, " ");

test("warning title and body use the required wording", () => {
  assert.ok(FLAT.includes("Verify ballot results before anchoring"));
  assert.ok(
    FLAT.includes(
      "Anchoring is locked until the election is finalized and the archive has been verified.",
    ),
  );
  assert.ok(
    FLAT.includes(
      "The Ootle anchor is built from the verified archive hash and final tally.",
    ),
  );
});

test("warning points the operator to the Archive menu and the verify step", () => {
  assert.ok(
    FLAT.includes(
      "Open the Archive menu, verify the results, then return here to prepare the anchor.",
    ),
  );
});

test("warning renders only while the verified archive is missing", () => {
  assert.match(
    MANAGE_ELECTION,
    /const anchorLockedUntilVerifiedArchive = !archiveReadyForAnchor;/,
  );
  assert.match(MANAGE_ELECTION, /\{anchorLockedUntilVerifiedArchive && \(/);
});

test("checklist lists all guided prerequisites including wallet attestation", () => {
  for (const label of [
    "Election finalized",
    "Archive written",
    "Archive verified",
    "Wallet connected",
    "Dedicated organizer wallet",
    "Deployment locked",
    "Anchor prepared",
    "Publish approved",
  ]) {
    assert.ok(FLAT.includes(`label: "${label}"`), `checklist missing: ${label}`);
  }
  assert.match(MANAGE_ELECTION, /className="anchor-prereq-checklist"/);
  assert.match(MANAGE_ELECTION, /!item\.done && <span className="prereq-status"> — required<\/span>/);
});

test("the Archive verified item is bound to the real archive-ready state", () => {
  assert.match(
    MANAGE_ELECTION,
    /\{ label: "Archive verified", done: archiveReadyForAnchor \}/,
  );
});

test("the dedicated-wallet item is bound to the authoritative attestation state", () => {
  assert.match(
    MANAGE_ELECTION,
    /\{ label: "Dedicated organizer wallet", done: anchorDedicatedWallet \}/,
  );
});

test("V2 anchor Build stays disabled until the verified archive exists", () => {
  // V2 build (first anchor step) requires the ready archive AND a locked deployment.
  assert.match(
    MANAGE_ELECTION,
    /disabled=\{!canAct \|\| !archiveReadyForAnchor \|\| !trustedDeploymentV2 \|\| anchorV2Busy\}/,
  );
});

test("the anchor section is not hidden silently while locked", () => {
  const cardIdx = MANAGE_ELECTION.indexOf('<Card title="Tari Anchor">');
  const warnIdx = MANAGE_ELECTION.indexOf("Verify ballot results before anchoring");
  assert.notEqual(cardIdx, -1, "Tari Anchor card missing");
  assert.ok(warnIdx > cardIdx, "warning lives inside the Tari Anchor card");
});

test("V2 anchor is the only normal publishing surface (no V1 selector, no legacy publish button)", () => {
  // No V1/V2 selector radios.
  assert.doesNotMatch(MANAGE_ELECTION, /setAnchorVersion\("v1"\)/);
  assert.doesNotMatch(MANAGE_ELECTION, /setAnchorVersion\("v2"\)/);
  // No legacy V1 "Publish Tari Anchor" or "Publish aggregate anchor" buttons.
  assert.doesNotMatch(MANAGE_ELECTION, /Publish Tari Anchor</);
  assert.doesNotMatch(MANAGE_ELECTION, /Publish aggregate anchor</);
  // Aggregate-summary notice reflects the V2-only messaging.
  assert.ok(
    FLAT.includes(
      "This anchor publishes the readable public aggregate election summary.",
    ),
  );
  assert.ok(FLAT.includes("Individual votes are NEVER published"));
});

test("checklist derives from V2 anchor state only", () => {
  assert.match(MANAGE_ELECTION, /const anchorDeploymentLocked = trustedDeploymentV2 !== null;/);
  assert.match(MANAGE_ELECTION, /const anchorPreparedForVersion = anchorV2Preparation !== null;/);
  assert.match(
    MANAGE_ELECTION,
    /const anchorPublishApproved = anchorV2StepResult\?\.receipt_verified === true;/,
  );
});
