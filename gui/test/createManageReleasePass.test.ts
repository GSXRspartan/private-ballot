// Regression tests pinning the Create Election + Manage Election
// pre-release UX correction pass.
//
// The pass moves voter-credential management off the organizer creation
// screen, simplifies the election-identifier wording, moves the governance
// source revision input into the Governance step, and — on Manage Election —
// makes the Next step, top anchor status, terminal completion view, wallet
// controls, deployment replacement, and technical fields state-aware so a
// receipt-verified anchor for a verified archive never renders alongside
// fresh "Ready to publish" preparation controls.
//
// These assertions never touch cryptography, election manifest schema, the
// archive format, the V2 anchor protocol, or transport authority — they pin
// PRESENTATION only. Protocol/backend behavior is unchanged.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { nextOrganizerStep } from "../src/lifecycle.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const createElection = readProjectFile("src/screens/CreateElection.tsx");
const manage = readProjectFile("src/screens/ManageElection.tsx");
const vote = readProjectFile("src/screens/Vote.tsx");

// -------------------------------------------------------------------------
// CREATE ELECTION
// -------------------------------------------------------------------------

describe("Create Election voter-credential removal", () => {
  it("does not render the Voter credential bootstrap on Create Election", () => {
    assert.doesNotMatch(createElection, /VoterCredentialCard/);
    assert.doesNotMatch(createElection, /Voter credential bootstrap/);
    assert.doesNotMatch(createElection, /voterGovernanceCredentialStatus/);
  });
  it("does not import the VoterCredentialCard component on Create Election", () => {
    assert.doesNotMatch(
      createElection,
      /from ["']\.\.\/components\/VoterCredentialCard["']/,
    );
  });
  it("keeps VoterCredentialCard available on Vote", () => {
    assert.match(vote, /VoterCredentialCard/);
    assert.match(vote, /from ["']\.\.\/components\/VoterCredentialCard["']/);
  });
});

describe("Create Election identifier wording", () => {
  it("renames the identifier label to Election ID", () => {
    assert.match(createElection, /<Card title="Election ID">/);
    assert.match(createElection, />\s*Election ID\s*<\/label>/);
    assert.doesNotMatch(createElection, /Election identifier \(text\)/);
    assert.doesNotMatch(createElection, /<Card title="Election identifier">/);
  });
  it("keeps the underlying setDraftBasics field wiring intact", () => {
    assert.match(createElection, /api\.setDraftBasics\(electionIdText, proposalQuestion, governanceRevision\)/);
  });
});

describe("Create Election Governance source belongs to Step 2", () => {
  it("removes the Governance source card from Basics", () => {
    // Basics no longer owns the governance-revision input field, and no
    // longer nests a top-level "Governance source" card of its own inside
    // BasicsStep.
    const basicsStep = createElection.slice(
      createElection.indexOf("function BasicsStep("),
      createElection.indexOf("function GovernanceStep("),
    );
    assert.ok(basicsStep.length > 0, "BasicsStep function must exist");
    assert.doesNotMatch(basicsStep, /Governance source revision/);
    assert.doesNotMatch(basicsStep, /<Card title="Governance source">/);
  });
  it("keeps the governance-revision input on the Governance step", () => {
    const govStep = createElection.slice(
      createElection.indexOf("function GovernanceStep("),
      createElection.indexOf("function VotersStep("),
    );
    assert.match(govStep, /Governance source revision/);
    assert.match(govStep, /id="governance-source-revision"/);
  });
  it("keeps the seven-step wizard order", () => {
    assert.match(createElection, /id: "basics", label: "Basics"/);
    assert.match(createElection, /id: "governance", label: "Governance source"/);
    assert.match(createElection, /id: "voters", label: "Eligible voters"/);
    assert.match(createElection, /id: "options", label: "Ballot options"/);
    assert.match(createElection, /id: "rules", label: "Voting rules"/);
    assert.match(createElection, /id: "review", label: "Review"/);
    assert.match(createElection, /id: "frozen", label: "Freeze & Export"/);
  });
  it("does not require the governance revision to leave Basics", () => {
    // Only election ID and ballot question are required to advance from
    // Basics — the governance revision is captured on Step 2.
    assert.match(createElection, /election ID and ballot question are required/);
  });
  it("keeps Freeze/export semantics unchanged", () => {
    assert.match(createElection, /api\.freezeElection\(\)/);
    assert.match(createElection, /api\.exportElectionArtifacts\(dir\)/);
  });
});

// -------------------------------------------------------------------------
// MANAGE ELECTION — Next step state machine
// -------------------------------------------------------------------------

describe("Manage Election Next step is state-aware", () => {
  it("verified archive + verified anchor => Election complete", () => {
    const step = nextOrganizerStep({
      lifecycle: "FINALIZED",
      tallyComputed: true,
      archiveVerified: true,
      anchorVerified: true,
    });
    assert.match(step.title, /^Election complete$/);
    assert.match(step.body, /verified final archive is authoritative/);
    assert.match(step.body, /receipt verified/);
  });
  it("verified archive without an anchor => election is complete, anchor optional", () => {
    const step = nextOrganizerStep({
      lifecycle: "FINALIZED",
      tallyComputed: true,
      archiveVerified: true,
    });
    assert.match(step.title, /^Election record verified$/);
    assert.match(step.body, /anchoring is optional and non-binding/);
  });
  it("finalized unverified archive => Next Step requests archive verification", () => {
    const step = nextOrganizerStep({
      lifecycle: "FINALIZED",
      tallyComputed: true,
      archiveVerified: false,
    });
    assert.match(step.title, /^Verify final archive$/);
    assert.match(step.body, /Open Archive and independently verify the final record/);
  });
  it("existing submitted but unverified anchor => Next Step requests anchor verification", () => {
    const step = nextOrganizerStep({
      lifecycle: "FINALIZED",
      tallyComputed: true,
      archiveVerified: true,
      anchorSubmittedButUnverified: true,
    });
    assert.match(step.title, /^Verify existing anchor$/);
    assert.match(step.body, /Verify its receipt on the Anchor screen/);
  });
  it("wires the anchor-aware Next Step inputs on Manage Election", () => {
    assert.match(manage, /const anchorReceiptVerifiedTerminal =/);
    assert.match(manage, /const anchorSubmittedButUnverifiedTerminal =/);
    assert.match(manage, /archiveVerified: archiveReadyForAnchor/);
    assert.match(manage, /anchorSubmittedButUnverified: anchorSubmittedButUnverifiedTerminal/);
    assert.match(manage, /anchorVerified: anchorReceiptVerifiedTerminal/);
  });
});

// -------------------------------------------------------------------------
// MANAGE ELECTION — Anchor terminal completion view
// -------------------------------------------------------------------------

describe("Manage Election Anchor terminal state wins over fresh preparation", () => {
  it("receipt_verified renders the Anchored · Verified top status", () => {
    // The top status literal AND its precedence over the fresh
    // "Ready to publish" / "Waiting for final archive" branches.
    assert.match(manage, /"Anchored · Verified"/);
    assert.match(
      manage,
      /const anchorStatusText = anchorReceiptVerifiedTerminal[\s\S]*\?\s*"Anchored · Verified"/,
    );
  });
  it("does not render Ready to publish for a receipt-verified anchor", () => {
    // The Ready to publish branch is only reached when both terminal cases
    // are false — the ternary structure guarantees that.
    const branch = manage.match(/const anchorStatusText = [\s\S]*?"Ready to publish"/);
    assert.ok(branch, "Ready to publish branch must still exist");
    assert.match(
      branch![0],
      /anchorReceiptVerifiedTerminal[\s\S]*anchorSubmittedButUnverifiedTerminal/,
      "Ready to publish must be after both terminal checks",
    );
  });
  it("keeps the transaction, receipt, and evidence path visible on the terminal summary", () => {
    // The recovery panel that carries the terminal summary must present the
    // transaction hash, the receipt verification, and the evidence file.
    const recovery = manage.slice(
      manage.indexOf('data-testid="anchor-v2-existing-recovery-panel"'),
    );
    assert.match(recovery, /Anchored · Verified/);
    assert.match(recovery, /label="Transaction"/);
    assert.match(recovery, /label="Receipt verification"/);
    assert.match(recovery, /label="Evidence file"/);
    assert.match(recovery, /anchorV2Hydrated\.evidence_path/);
    assert.match(recovery, /label="Canonical public summary"/);
    assert.match(recovery, /label="Anchor digest"/);
  });
});

// -------------------------------------------------------------------------
// MANAGE ELECTION — wallet controls / deployment / technical fields
// -------------------------------------------------------------------------

describe("Manage Election wallet controls after terminal anchor", () => {
  it("suppresses the fresh wallet-setup assistant when receipt_verified", () => {
    // The anchor-setup-assistant (Use connected wallet / Reset / dedicated
    // attestation) is gated on !anchorReceiptVerifiedTerminal so a completed
    // anchor never shows fresh preparation controls.
    assert.match(
      manage,
      /!anchorReceiptVerifiedTerminal &&[\s\S]*<div className="anchor-setup-assistant">/,
    );
  });
  it("moves the wallet connection panel under Advanced when receipt_verified", () => {
    assert.match(
      manage,
      /anchorReceiptVerifiedTerminal \?\s*\(\s*<DetailsSection summary="Advanced: wallet connection">\s*\{walletPanelJsx\}/,
    );
  });
  it("keeps the wallet panel available for the fresh (unanchored) flow", () => {
    // The else branch of the terminal-verified check renders walletPanelJsx
    // directly for the normal (still-anchoring) case.
    assert.match(manage, /\)\s*:\s*\(\s*walletPanelJsx\s*\)/);
  });
});

describe("Manage Election deployment replacement is under Advanced", () => {
  it("moves the Unlock/replace anchor deployment button into an Advanced disclosure", () => {
    assert.match(
      manage,
      /<DetailsSection summary="Advanced: replace anchor deployment">[\s\S]*Unlock \/ replace anchor deployment/,
    );
  });
  it("keeps the destructive red styling and confirmation on the replace button", () => {
    // The replace button still uses btn-danger and still opens the existing
    // confirm dialog rather than issuing a destructive command directly.
    const advanced = manage.match(
      /<DetailsSection summary="Advanced: replace anchor deployment">[\s\S]*?<\/DetailsSection>/,
    );
    assert.ok(advanced, "Advanced replace disclosure must exist");
    assert.match(advanced![0], /className="btn btn-danger"/);
    assert.match(advanced![0], /setConfirmUnlockDeploymentV2\(true\)/);
  });
  it("annotates the replacement flow when a verified anchor already exists", () => {
    assert.match(
      manage,
      /This deployment produced the verified anchor for this archive\./,
    );
    assert.match(
      manage,
      /Replacing it does not alter the historical transaction/,
    );
  });
});

describe("Manage Election technical anchor fields are progressive", () => {
  it("keeps the human-useful anchor fields in the terminal summary", () => {
    const recovery = manage.slice(
      manage.indexOf('data-testid="anchor-v2-existing-recovery-panel"'),
    );
    assert.match(recovery, /label="Transaction"/);
    assert.match(recovery, /label="Blockchain transaction"/);
    assert.match(recovery, /label="Receipt verification"/);
    assert.match(recovery, /label="Evidence file"/);
  });
  it("moves wallet_request_id, lifecycle phase, and template details under Advanced", () => {
    const recovery = manage.slice(
      manage.indexOf('data-testid="anchor-v2-existing-recovery-panel"'),
    );
    const advanced = recovery.match(
      /<DetailsSection summary="Advanced: technical anchor fields">[\s\S]*?<\/DetailsSection>/,
    );
    assert.ok(advanced, "Advanced technical anchor fields disclosure must exist");
    assert.match(advanced![0], /label="Wallet request ID"/);
    assert.match(advanced![0], /label="Lifecycle phase"/);
    assert.match(advanced![0], /label="Template module"/);
    assert.match(advanced![0], /label="Template function"/);
    assert.match(advanced![0], /label="Template event topic"/);
    assert.match(advanced![0], /label="Template address"/);
    assert.match(advanced![0], /label="Artifact digest"/);
  });
});

// -------------------------------------------------------------------------
// MANAGE ELECTION — Final archive terminal verified state
// -------------------------------------------------------------------------

describe("Manage Election Final archive recognizes verified existing archive", () => {
  it("leads the Final archive card with a verified terminal summary", () => {
    const finalArchiveCard = manage.slice(manage.indexOf('<Card title="Final archive">'));
    assert.match(
      finalArchiveCard,
      /verifiedFinalArchive && \(\s*<>\s*<Notice tone="ok">\s*<strong>Final archive verified<\/strong>/,
    );
    assert.match(finalArchiveCard, /data-testid="final-archive-verified-summary"/);
    assert.match(finalArchiveCard, /verifiedFinalArchive\.directory/);
    assert.match(finalArchiveCard, /verifiedFinalArchive\.archive_hash_hex/);
    assert.match(finalArchiveCard, /verifiedFinalArchive\.file_count/);
  });
  it("hides the misleading anchor-eligible warning when the existing archive is verified", () => {
    // The transportBindingProvenanceAvailable === false warning is gated on
    // !verifiedFinalArchive in the normal-view branch so it never implies the
    // existing verified archive is defective. It stays available under the
    // "Create another final archive" disclosure where a new-archive attempt
    // would actually fail.
    assert.match(
      manage,
      /transportBindingProvenanceAvailable === false && !verifiedFinalArchive/,
    );
  });
  it("keeps the archive-creation warning where it is genuinely relevant", () => {
    // The "Create another final archive" DetailsSection still carries the
    // transportBindingProvenanceAvailable warning for the new-archive path.
    const advanced = manage.match(
      /<DetailsSection summary="Create another final archive">[\s\S]*?<\/DetailsSection>/,
    );
    assert.ok(advanced, "Create another final archive disclosure must exist");
    assert.match(
      advanced![0],
      /transportBindingProvenanceAvailable === false/,
    );
  });
  it("moves archive-creation controls into an Advanced disclosure when a verified archive exists", () => {
    const advanced = manage.match(
      /<DetailsSection summary="Create another final archive">[\s\S]*?<\/DetailsSection>/,
    );
    assert.ok(advanced);
    assert.match(advanced![0], /id="archive-dir-alt"/);
    assert.match(advanced![0], /Write another final archive/);
  });
});

// -------------------------------------------------------------------------
// MANAGE ELECTION — Progress-so-far duplication reduction
// -------------------------------------------------------------------------

describe("Manage Election reduces duplicate progress information", () => {
  it("does not push lifecycle-row-only entries into the Progress so far summary", () => {
    // The compact lifecycle row (organizerLifecycleSteps) already shows
    // Voting opened / Voting closed / Result verified / Election finalized.
    // The Progress so far card must not repeat those literals.
    const completed = manage.slice(
      manage.indexOf("const completedSummaries: string[] = []"),
      manage.indexOf("const trustedDeploymentV2 ="),
    );
    assert.doesNotMatch(completed, /"Voting opened"/);
    assert.doesNotMatch(completed, /"Voting closed"/);
    assert.doesNotMatch(completed, /"Result verified"/);
    assert.doesNotMatch(completed, /"Election finalized"/);
  });
  it("still surfaces additive milestones not covered by the lifecycle row", () => {
    const completed = manage.slice(
      manage.indexOf("const completedSummaries: string[] = []"),
      manage.indexOf("const trustedDeploymentV2 ="),
    );
    assert.match(completed, /"Private intake configured"/);
    assert.match(completed, /"Voter materials available"/);
    assert.match(completed, /"Tally computed"/);
    assert.match(completed, /"Final archive written and verified"/);
  });
  it("keeps the compact lifecycle ProgressSteps row intact", () => {
    assert.match(manage, /label="Election lifecycle"/);
    assert.match(manage, /steps=\{organizerLifecycleSteps\(lifecycle\)\}/);
  });
});

// -------------------------------------------------------------------------
// MANAGE ELECTION — read-only rendering never issues wallet operations
// -------------------------------------------------------------------------

describe("Manage Election read-only render performs no wallet write operations", () => {
  it("does not invoke create/approve/submit wallet operations at module top level", () => {
    // A read-only recovery/hydration must not trigger wallet request
    // creation, approval, or transaction submission. Those APIs are only
    // called from explicit onClick handlers, never from top-level code.
    const topLevel = manage.slice(0, manage.indexOf("return ("));
    // The V2 lifecycle command name that would create/submit/approve.
    assert.doesNotMatch(topLevel, /api\.runV2LiveAnchorStep\(/);
    // The recovery command is invoked only from onRecoverExistingV2Anchor,
    // which is bound to an explicit onClick.
    assert.doesNotMatch(topLevel, /api\.recoverV2LiveAnchor\([^)]*\);/);
  });
});
