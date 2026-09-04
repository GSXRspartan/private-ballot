// Vote / Archive / Anchor pre-release pass — pure regressions.
//
// Runs under node --test with TypeScript type stripping (see package.json).
// No React harness exists (ADR-0007); UI behaviors are additionally pinned by
// semantic source assertions in this file.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  createCredentialIsFutureElectionOnly,
  isVoterReadOnlyLifecycle,
  votingClosedBanner,
} from "../src/voterTerminalState.ts";
import {
  summarizeV2AnchorState,
  v2AnchorBadgeLabel,
  v2AnchorBadgeTone,
} from "../src/anchor/v2AnchorStatus.ts";
import type { GuiV2LiveAnchorHydratedStateV1 } from "../src/api/types.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const archive = readProjectFile("src/screens/Archive.tsx");
const anchor = readProjectFile("src/screens/Anchor.tsx");
const credentialCard = readProjectFile("src/components/VoterCredentialCard.tsx");

// ---------------------------------------------------------------------------
// VOTE: terminal state + workflow ordering
// ---------------------------------------------------------------------------

describe("Vote terminal-state helper", () => {
  it("returns a Voting closed banner for FINALIZED with a final-record next step", () => {
    const banner = votingClosedBanner("FINALIZED");
    assert.ok(banner, "banner should be present for FINALIZED");
    assert.equal(banner.title, "Voting closed");
    assert.match(banner.body, /finalized/);
    assert.equal(banner.offersFinalRecord, true);
  });

  it("returns a Voting closed banner for CLOSED/VERIFIED without a final-record step", () => {
    for (const state of ["CLOSED", "VERIFIED"]) {
      const banner = votingClosedBanner(state);
      assert.ok(banner, `banner should be present for ${state}`);
      assert.equal(banner.title, "Voting closed");
      assert.match(banner.body, /Responses can no longer be chosen/);
      assert.equal(banner.offersFinalRecord, false);
    }
  });

  it("returns no banner for OPEN, FROZEN, DRAFT, or an unknown state", () => {
    for (const state of ["OPEN", "FROZEN", "DRAFT", null, undefined, "MYSTERY"]) {
      assert.equal(votingClosedBanner(state), null, `no banner for ${state}`);
      assert.equal(isVoterReadOnlyLifecycle(state), false);
    }
  });

  it("isVoterReadOnlyLifecycle mirrors the terminal banner", () => {
    for (const state of ["CLOSED", "VERIFIED", "FINALIZED"]) {
      assert.equal(isVoterReadOnlyLifecycle(state), true, state);
    }
  });

  it("Create credential is future-election-only once frozen or later", () => {
    for (const state of ["FROZEN", "OPEN", "CLOSED", "VERIFIED", "FINALIZED"]) {
      assert.equal(createCredentialIsFutureElectionOnly(state), true, state);
    }
    for (const state of ["DRAFT", null, undefined, "MYSTERY"]) {
      assert.equal(createCredentialIsFutureElectionOnly(state), false, String(state));
    }
  });
});

describe("Vote screen source pins", () => {
  it("renders a prominent Voting closed banner using the shared helper", () => {
    assert.match(vote, /votingClosedBanner\(election\?\.lifecycle_state\)/);
    assert.match(vote, /voting-closed-banner/);
    assert.match(vote, /Verify final record on Archive/);
  });

  it("How voting works ordering matches the final Guide", () => {
    // The Guide order (Create → Share pubkey → Load package → Configure →
    // Prove eligibility → Create+submit → Receipt → Verify later) is echoed
    // verbatim as the ordered "How voting works" mini-guide.
    const create = vote.indexOf("Create or load your private voter credential.");
    const share = vote.indexOf(
      "Share only your public enrollment key with the organizer, before freeze.",
    );
    const load = vote.indexOf("Load the election package.");
    const configure = vote.indexOf(
      "Configure the ballot-office connection and check status.",
    );
    const prove = vote.indexOf("Prove you are eligible anonymously.");
    const submit = vote.indexOf("Create and submit your anonymous ballot.");
    const receipt = vote.indexOf("Receive an authenticated organizer receipt.");
    const verify = vote.indexOf("Verify the final record later.");
    for (const [name, position] of [
      ["create", create],
      ["share", share],
      ["load", load],
      ["configure", configure],
      ["prove", prove],
      ["submit", submit],
      ["receipt", receipt],
      ["verify", verify],
    ] as const) {
      assert.ok(position >= 0, `missing step: ${name}`);
    }
    assert.ok(create < share, "share follows create");
    assert.ok(share < load, "load follows share");
    assert.ok(load < configure, "configure follows load");
    assert.ok(configure < prove, "prove follows configure");
    assert.ok(prove < submit, "submit follows prove");
    assert.ok(submit < receipt, "receipt follows submit");
    assert.ok(receipt < verify, "verify follows receipt");
  });

  it("Review election card is read-only for closed/finalized elections", () => {
    assert.match(vote, /isVoterReadOnlyLifecycle\(election\?\.lifecycle_state\)/);
    // Read-only branch offers the final-record next step for FINALIZED only.
    assert.match(vote, /Verify final record on Archive/);
    // Interactive branch (OPEN etc.) keeps the confirm+Continue action.
    assert.match(vote, /I have reviewed the election details above and confirmed/);
  });

  it("VoterCredentialCard receives the election lifecycle so Create can be demoted", () => {
    assert.match(vote, /electionLifecycleState=\{election\?\.lifecycle_state \?\? null\}/);
    // The credential card retains the wallet-seed warning and the frozen-election notice.
    assert.match(credentialCard, /Import credential/);
    assert.match(credentialCard, /Unlock saved credential/);
    // A "For a future election" disclosure hosts Create when the election is
    // already frozen (or later) — Create itself never disappears entirely.
    assert.match(credentialCard, /For a future election/);
    assert.match(credentialCard, /A newly created credential cannot make you eligible/);
    // The pure gate is what decides.
    assert.match(credentialCard, /createCredentialIsFutureElectionOnly\(/);
  });

  it("no vote action can be introduced after CLOSED/FINALIZED (no naked Continue in read-only branch)", () => {
    // The read-only branch does not offer the ballot progression button.
    const readOnlySection = vote.slice(vote.indexOf("isVoterReadOnlyLifecycle(election"));
    // The closer of the immediate ternary (`) : (`) is where the OPEN branch
    // begins. We slice up to that so we're only inspecting the read-only side.
    const openBranchStart = readOnlySection.indexOf(") : (");
    const readOnly = readOnlySection.slice(0, openBranchStart);
    assert.doesNotMatch(readOnly, /onEnterCredentialStage/);
    assert.doesNotMatch(readOnly, /I have reviewed the election details/);
  });
});

// ---------------------------------------------------------------------------
// V2 anchor summary helper
// ---------------------------------------------------------------------------

const baseHydrated: GuiV2LiveAnchorHydratedStateV1 = {
  lifecycle_present: false,
  evidence_present: false,
  failure_present: false,
  archive_directory: "C:/tmp/archive",
  lifecycle_path: "C:/tmp/lifecycle.json",
  evidence_path: "C:/tmp/evidence.json",
  failure_path: "C:/tmp/failure.json",
  payload_hex: null,
  expected_digest_hex: null,
  network: null,
  template_address: null,
  template_module: null,
  template_function: null,
  template_topic: null,
  template_artifact_digest_hex: null,
  fee_component: null,
  seal_signer_kind: null,
  seal_signer_id: null,
  max_fee: null,
  estimated_required_fee: null,
  selected_max_fee: null,
  max_epoch: null,
  walletd_request_id: null,
  phase: null,
  transaction_id: null,
  failure_reason: null,
  recoverable: false,
  blocks_fresh_publish: false,
  receipt_verified: false,
};

describe("V2 anchor summary", () => {
  it("returns null when no state is provided", () => {
    assert.equal(summarizeV2AnchorState(null), null);
  });

  it("maps a verified lifecycle to Anchored · Verified", () => {
    const s = summarizeV2AnchorState({
      ...baseHydrated,
      lifecycle_present: true,
      evidence_present: true,
      receipt_verified: true,
      phase: "RECEIPT_VERIFIED",
      transaction_id: "abc",
      network: "esmeralda",
    });
    assert.ok(s);
    assert.equal(s.kind, "verified");
    assert.equal(v2AnchorBadgeLabel(s.kind), "Anchored · Verified");
    assert.equal(v2AnchorBadgeTone(s.kind), "ok");
    assert.equal(s.transactionId, "abc");
    assert.equal(s.network, "esmeralda");
  });

  it("maps a missing lifecycle+evidence to no-anchor (neutral tone)", () => {
    const s = summarizeV2AnchorState(baseHydrated);
    assert.ok(s);
    assert.equal(s.kind, "no-anchor");
    assert.equal(v2AnchorBadgeTone(s.kind), "neutral");
    assert.match(v2AnchorBadgeLabel(s.kind), /No Ootle anchor/);
  });

  it("maps a submitted-unverified lifecycle to a pending warning", () => {
    const s = summarizeV2AnchorState({
      ...baseHydrated,
      lifecycle_present: true,
      phase: "POLLING_RECEIPT",
      transaction_id: "tx123",
      recoverable: false,
    });
    assert.ok(s);
    assert.equal(s.kind, "submitted-unverified");
    assert.equal(v2AnchorBadgeTone(s.kind), "warn");
  });

  it("maps a recoverable lifecycle to recoverable", () => {
    const s = summarizeV2AnchorState({
      ...baseHydrated,
      lifecycle_present: true,
      phase: "POLLING_RECEIPT",
      transaction_id: "tx123",
      recoverable: true,
    });
    assert.ok(s);
    assert.equal(s.kind, "recoverable");
    assert.equal(v2AnchorBadgeTone(s.kind), "warn");
  });

  it("maps a terminal FAILED lifecycle to failed", () => {
    const s = summarizeV2AnchorState({
      ...baseHydrated,
      lifecycle_present: true,
      phase: "FAILED",
      failure_reason: "something",
    });
    assert.ok(s);
    assert.equal(s.kind, "failed");
    assert.equal(v2AnchorBadgeTone(s.kind), "error");
  });
});

// ---------------------------------------------------------------------------
// ARCHIVE screen source pins
// ---------------------------------------------------------------------------

describe("Archive screen pre-release polish", () => {
  it("promotes the ARCHIVE VERIFIED summary above the technical details", () => {
    const verifiedIdx = archive.indexOf("ARCHIVE VERIFIED");
    const advancedIdx = archive.indexOf("Advanced verification details");
    assert.ok(verifiedIdx > 0, "primary verified card must exist");
    assert.ok(
      advancedIdx > verifiedIdx,
      "technical details must live below the primary summary",
    );
    // Auditor detail is retained, not deleted.
    assert.match(archive, /Registry and catalog files/);
    assert.match(archive, /Show verified file catalogue/);
    assert.match(archive, /Recomputed tally — technical detail/);
    // Machine IDs live in the technical detail only; the plain summary lists
    // labels + counts.
    assert.match(archive, /Recomputed tally — summary/);
  });

  it("hydrates the current V2 anchor state from the existing read-only API", () => {
    assert.match(archive, /inspectV2LiveAnchorState/);
    assert.match(archive, /summarizeV2AnchorState/);
    // No walletd/publish action lives on Archive.
    assert.doesNotMatch(archive, /runV2LiveAnchorLifecycleStep|prepareV2AnchorPublish/);
    assert.doesNotMatch(archive, /Publish anchor|Submit anchor|Approve wallet/);
  });

  it("moves the legacy V1 CBOR check under an Advanced disclosure and relabels it", () => {
    const advancedIdx = archive.indexOf("Legacy V1 verification");
    assert.ok(advancedIdx > 0, "Legacy V1 disclosure must exist");
    assert.match(archive, /Check legacy V1 anchor record/);
    // The primary anchor card is not the legacy path.
    const anchorCardIdx = archive.indexOf('<Card title="Ootle anchor">');
    assert.ok(anchorCardIdx >= 0);
    assert.ok(anchorCardIdx < advancedIdx, "V2 anchor card must precede legacy V1 disclosure");
  });

  it("renders a neutral no-anchor state and a warn recovery state", () => {
    assert.match(archive, /No Ootle anchor published/);
    assert.match(archive, /Anchor submitted · verification pending|verification pending/);
    assert.match(archive, /Anchoring is optional and non-binding/);
  });

  it("keeps failure verification details visible when verification fails", () => {
    assert.match(archive, /ARCHIVE VERIFICATION FAILED/);
    assert.match(archive, /result\.failure_stage/);
    assert.match(archive, /Files that failed the catalog check/);
  });
});

// ---------------------------------------------------------------------------
// ANCHOR screen source pins
// ---------------------------------------------------------------------------

describe("Anchor screen pre-release polish", () => {
  it("is a read-only V2 status page — no wallet/publish/create controls", () => {
    for (const forbidden of [
      "runV2LiveAnchorLifecycleStep",
      "prepareV2AnchorPublish",
      "buildV2PublicAnchorPayload",
      "writeLiveAnchorConfig",
    ]) {
      assert.ok(!anchor.includes(forbidden), `Anchor must not reference ${forbidden}`);
    }
    assert.doesNotMatch(anchor, /Publish anchor|Submit anchor|Approve wallet|Start Tari Wallet/i);
    // Read-only hydration is the only anchor API on this screen.
    assert.match(anchor, /inspectV2LiveAnchorState/);
    assert.match(anchor, /summarizeV2AnchorState/);
  });

  it("gates the anchor status card behind a verified archive selected on Archive", () => {
    assert.match(anchor, /Verify a final archive first/);
    assert.match(anchor, /Open Archive/);
    // Navigation is delegated to the parent (no direct routing surface here).
    assert.match(anchor, /onNavigate\?\.\("archive"\)/);
    assert.match(anchor, /onNavigate\?\.\("manage"\)/);
  });

  it("renders Anchored · Verified for a verified V2 lifecycle", () => {
    assert.match(anchor, /Tari Ootle anchor/);
    assert.match(anchor, /v2AnchorBadgeLabel\(v2Summary\.kind\)/);
    assert.match(anchor, /Receipt/);
    assert.match(anchor, /Canonical public summary/);
    assert.match(anchor, /Anchor digest/);
    assert.match(anchor, /Evidence path/);
  });

  it("renders a neutral no-anchor state pointing to Manage Election for optional publish", () => {
    assert.match(anchor, /No Ootle anchor published for this archive/);
    assert.match(anchor, /Anchoring is optional/);
    assert.match(anchor, /Open Manage Election/);
  });

  it("renders a submitted-unverified state that never offers a fresh publish", () => {
    assert.match(anchor, /Existing anchor needs verification/);
    assert.doesNotMatch(anchor, /Submit another transaction|New anchor request/);
  });

  it("moves anchor-config.cbor and anchor-snapshot.cbor under Legacy V1 verification", () => {
    const legacyIdx = anchor.indexOf("Legacy V1 anchor verification");
    assert.ok(legacyIdx > 0, "Legacy V1 disclosure must exist on Anchor");
    // The file-picker placeholders (`anchor-config.cbor` / `anchor-snapshot.cbor`)
    // must live INSIDE the legacy disclosure. `indexOf` might catch the same
    // string in a comment above it, so we search from the legacy anchor
    // instead.
    const configIdx = anchor.indexOf('placeholder="anchor-config.cbor"');
    const snapshotIdx = anchor.indexOf('placeholder="anchor-snapshot.cbor"');
    assert.ok(configIdx > legacyIdx, "anchor-config.cbor input must live inside the legacy disclosure");
    assert.ok(
      snapshotIdx > legacyIdx,
      "anchor-snapshot.cbor input must live inside the legacy disclosure",
    );
    // Historical inspection APIs stay wired up under the legacy disclosure.
    assert.match(anchor, /inspectAnchorConfig/);
    assert.match(anchor, /inspectAnchorSnapshot/);
  });
});

// ---------------------------------------------------------------------------
// Cross-page consistency
// ---------------------------------------------------------------------------

describe("cross-page consistency", () => {
  it("Vote never claims voting can proceed while lifecycle is terminal", () => {
    // The banner is placed above the workflow; the terminal-state helper is
    // the only source of the banner's visibility, so there is no other path
    // that could contradict it.
    assert.match(vote, /votingClosedBanner\(election\?\.lifecycle_state\)/);
  });

  it("Archive V2 anchor card and Anchor page use the same shared helpers", () => {
    assert.match(archive, /summarizeV2AnchorState/);
    assert.match(archive, /v2AnchorBadgeLabel/);
    assert.match(archive, /v2AnchorBadgeTone/);
    assert.match(anchor, /summarizeV2AnchorState/);
    assert.match(anchor, /v2AnchorBadgeLabel/);
    assert.match(anchor, /v2AnchorBadgeTone/);
  });
});
