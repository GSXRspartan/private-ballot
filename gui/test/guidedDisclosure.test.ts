// Guided progressive-disclosure regression tests (Vote + Manage Election).
//
// Pins the guided-UX pass: only the current voter stage is fully expanded in
// guided mode, completed stages collapse to compact summaries, future stages
// do not render as full workflow cards, the "Show all" escape hatches are
// presentation-only, and the organizer workspace is driven by the REAL
// lifecycle. All gates, commands, cast-lock semantics, and backend behavior
// are unchanged — these tests assert the disclosure layer only.
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Where no React harness exists, GUI behaviors are pinned by semantic source
// assertions (identifiable elements and attributes), never fragile pixel
// analysis.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  reviewStageReached,
  voteStageReached,
  voterStages,
  type VoterStageReconstructionInput,
} from "../src/voterProgress.ts";
import {
  organizerGuidedControls,
  organizerPhaseHeading,
  sealedParticipationText,
} from "../src/lifecycle.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const manage = readProjectFile("src/screens/ManageElection.tsx");

// -------------------------------------------------------------------------
// VOTE: guided-mode structure
// -------------------------------------------------------------------------

describe("vote guided-mode derivation", () => {
  it("derives the guided stages from the SAME existing workflow/session inputs", () => {
    assert.match(vote, /const guidedStages = voterStages\(\{/);
    assert.match(vote, /const currentStageKey =/);
    assert.match(vote, /guidedStages\.find\(\(stage\) => stage\.state === "current"\)/);
    assert.match(vote, /const guidedStageDone =/);
    // The same inputs as the progress indicator; nothing new is fetched. The
    // review/vote gates are RECONSTRUCTED from durable/session backend signals
    // so navigation or a restart never snaps the workflow back (Failure 1).
    for (const input of [
      "electionLoaded: election !== null",
      "reviewPassed: reviewReached",
      "identityReady: canProceedAfterCredential(credential)",
      "voteEntered: voteReached",
      'ballotReady: workflow?.prepared_ballot.state === "Ready"',
      "castState,",
    ]) {
      assert.ok(vote.includes(input), `guided derivation missing input: ${input}`);
    }
    // Reconstruction is derived from backend state, not just the mount-reset
    // in-component gate booleans.
    assert.match(vote, /reviewStageReached\(credentialStage, stageReconstruction\)/);
    assert.match(vote, /voteStageReached\(selectionStage, stageReconstruction\)/);
    assert.match(vote, /credentialLoaded: !!credential\?\.credential_loaded/);
    assert.match(vote, /selectionLoaded: !!selection\?\.selection_loaded/);
    // The Vote screen re-reads the authoritative workflow on entry so the
    // reconstruction has real state to work from after navigation/restart.
    assert.match(vote, /void refreshWorkflow\(false\)/);
    // The progress indicator reuses the SAME reconstructed stages (single
    // source of truth), so the bar and the cards can never disagree.
    assert.match(vote, /steps=\{guidedStages\}/);
  });

  it("keeps the five-stage indicator functional with aria-current", () => {
    const steps = voterStages({
      electionLoaded: true,
      reviewPassed: false,
      identityReady: false,
      voteEntered: false,
      choiceMade: false,
      ballotReady: false,
      castState: "NOT_CAST",
    });
    assert.equal(steps.filter((s) => s.state === "current").length, 1);
    const progress = readProjectFile("src/components/ProgressSteps.tsx");
    assert.match(progress, /aria-current=\{step\.state === "current" \? "step" : undefined\}/);
  });
});

// -------------------------------------------------------------------------
// VOTE: guided-stage reconstruction across navigation / restart (Failure 1)
// -------------------------------------------------------------------------

describe("voter guided-stage reconstruction", () => {
  const none: VoterStageReconstructionInput = {
    credentialLoaded: false,
    identityReady: false,
    selectionLoaded: false,
    ballotReady: false,
    castLocked: false,
  };

  it("without any backend progress, only the in-component gate advances", () => {
    assert.equal(reviewStageReached(false, none), false);
    assert.equal(reviewStageReached(true, none), true);
    assert.equal(voteStageReached(false, none), false);
    assert.equal(voteStageReached(true, none), true);
  });

  it("navigation with an intact backend session keeps the voter past Review and Vote", () => {
    // Same-process navigation: the backend session still holds the loaded
    // credential + selection even though credentialStage/selectionStage reset.
    const intact: VoterStageReconstructionInput = {
      ...none,
      credentialLoaded: true,
      identityReady: true,
      selectionLoaded: true,
    };
    assert.equal(reviewStageReached(false, intact), true);
    assert.equal(voteStageReached(false, intact), true);
  });

  it("restart before submission: identity durable, selection lost → back to Vote, not the start", () => {
    // Only the durable credential survives a restart of an unsubmitted ballot;
    // the session selection/prepared ballot are gone (no ballot was created).
    const restarted: VoterStageReconstructionInput = {
      ...none,
      credentialLoaded: true,
      identityReady: true,
    };
    assert.equal(reviewStageReached(false, restarted), true, "review stays passed");
    assert.equal(voteStageReached(false, restarted), false, "returns to Vote to re-select");
  });

  it("a durable locked ballot (CAST_PENDING/CAST) keeps Review and Vote reached after restart", () => {
    // A locked ballot implies the credential was used; on restart it is
    // re-installed from the durable store and re-verified eligible.
    const locked: VoterStageReconstructionInput = {
      ...none,
      credentialLoaded: true,
      identityReady: true,
      castLocked: true,
    };
    assert.equal(reviewStageReached(false, locked), true);
    assert.equal(voteStageReached(false, locked), true);
    // And the derived stages land on Submit, never earlier.
    const stages = voterStages({
      electionLoaded: true,
      reviewPassed: reviewStageReached(false, locked),
      identityReady: true,
      voteEntered: voteStageReached(false, locked),
      choiceMade: false,
      ballotReady: false,
      castState: "CAST_PENDING",
    });
    const current = stages.filter((s) => s.state === "current");
    assert.equal(current.length, 1);
    assert.equal(current[0].key, "Submit");
  });

  it("reconstruction is monotonic and never fabricates progress beyond signals", () => {
    // A prepared ballot implies Vote reached; it must NOT imply CAST.
    const prepared: VoterStageReconstructionInput = { ...none, ballotReady: true };
    assert.equal(voteStageReached(false, prepared), true);
    const stages = voterStages({
      electionLoaded: true,
      reviewPassed: reviewStageReached(false, prepared),
      identityReady: true,
      voteEntered: voteStageReached(false, prepared),
      choiceMade: false,
      ballotReady: true,
      castState: "NOT_CAST",
    });
    // Submit is the current (not done) stage; a crash never forges a CAST.
    assert.ok(stages.every((s) => !(s.key === "Submit" && s.state === "done")));
  });
});

describe("vote guided-mode visibility", () => {
  it("renders a stage fully only when current, reviewed, or in show-all mode", () => {
    assert.match(vote, /const stageExpanded = \(key: string\) =>/);
    assert.match(vote, /showAllSteps \|\| currentStageKey === key \|\| reviewStage === key/);
    // Election / Identity / Vote stages each use the guided collapse pattern:
    // a completed stage shows its summary instead of the full card, and a
    // non-expanded non-current stage renders nothing.
    const guidedBranches =
      vote.match(
        /!showAllSteps && guidedStageDone\("[A-Za-z]+"\) && reviewStage !== "[A-Za-z]+" \? \(/g,
      ) ?? [];
    assert.ok(
      guidedBranches.length >= 3,
      "Election, Identity, and Vote stages all use guided collapse",
    );
    const nullFallbacks = vote.match(/\) : null\s*\}?/g) ?? [];
    assert.ok(nullFallbacks.length >= 3, "hidden stages render nothing in guided mode");
  });

  it("collapses completed stages into compact checkmarked summaries", () => {
    assert.match(vote, /function GuidedStageSummary\(/);
    assert.match(vote, /<h3 className="card-title">✓ \{title\}<\/h3>/);
    // Election summary: name + ballot question + Review details.
    assert.match(vote, /title="Election reviewed"/);
    assert.match(vote, /confirmation\.bound\.proposal_question \?\? ""/);
    // Identity summary: credential verified locally.
    assert.match(vote, /title="Eligible to vote"/);
    assert.match(vote, /Credential verified locally/);
    // Vote summary: the choice + a Change my choice review control.
    assert.match(vote, /title="Response selected"/);
    assert.match(vote, /Your choice: \$\{voteChoiceText\}/);
    // Every summary offers a deliberate review control.
    assert.match(vote, /reviewLabel="Review details"/);
    assert.match(vote, /onReview=\{\(\) => setReviewStage\("Election"\)\}/);
    assert.match(vote, /onReview=\{\(\) => setReviewStage\("Identity"\)\}/);
  });

  it("keeps the Privacy stage as the proof card while current and the prepared review once done", () => {
    // While Privacy is current the proof-generation card renders in full.
    assert.match(vote, /\{\(showAllSteps \|\| currentStageKey === "Privacy"\) && \(/);
    // Once prepared, the prepared-ballot review is the completed-stage summary
    // and the proof-generation card no longer occupies the page (guided mode).
    assert.match(vote, /\{workflow\?\.prepared_ballot\.summary && \(/);
    assert.match(vote, /<Card title="Your anonymous ballot is ready">/);
  });

  it("gates the private-submission card to the Submit stage (or a locked ballot)", () => {
    assert.match(vote, /const submitStageVisible =/);
    assert.match(vote, /showAllSteps \|\| currentStageKey === "Submit" \|\| castLocked/);
    assert.match(vote, /\}\) && submitStageVisible && \(/);
  });

  it("collapses offline delivery by default unless no online route is available", () => {
    assert.match(vote, /<summary className="details-summary">Other delivery options<\/summary>/);
    assert.match(vote, /open=\{offlineOpenOverride \?\? !onlineRouteAvailable\}/);
    // The offline route itself is unchanged.
    assert.match(vote, /Offline submission/);
    assert.match(vote, /Nothing is sent over the network/);
    assert.match(vote, />\s*Save encrypted ballot file\s*</);
  });
});

describe("vote Show all steps escape hatch", () => {
  it("exists as a presentation-only toggle with aria-pressed", () => {
    assert.match(vote, /aria-pressed=\{showAllSteps\}/);
    assert.match(vote, /Show all steps/);
    assert.match(vote, /Show guided steps/);
  });

  it("changes no workflow state, bypasses no gate, and invokes no command", () => {
    const toggle = vote.slice(
      vote.indexOf("aria-pressed={showAllSteps}"),
      vote.indexOf("aria-pressed={showAllSteps}") + 500,
    );
    assert.match(toggle, /setShowAllSteps\(\(current\) => !current\)/);
    assert.doesNotMatch(toggle, /api\.|runLifecycle|setBusy|setCredentialStage|setSelectionStage/);
  });
});

describe("vote stage transitions and cast states in guided mode", () => {
  const base = {
    electionLoaded: true,
    reviewPassed: true,
    identityReady: true,
    voteEntered: true,
    choiceMade: true,
    ballotReady: false,
    castState: "NOT_CAST" as const,
  };

  it("walks Election → Identity → Vote → Privacy → Submit exactly with the real gates", () => {
    // Each derivation maps to one current stage at a time.
    for (const input of [
      { ...base, reviewPassed: false, identityReady: false, voteEntered: false, choiceMade: false },
      { ...base, identityReady: false, voteEntered: false, choiceMade: false },
      { ...base, choiceMade: false },
      base,
      { ...base, ballotReady: true },
    ]) {
      const current = voterStages(input).filter((s) => s.state === "current");
      assert.equal(current.length, 1, "exactly one current stage at a time");
    }
    const labels = [
      voterStages({ ...base, reviewPassed: false, identityReady: false, voteEntered: false, choiceMade: false }),
      voterStages({ ...base, identityReady: false, voteEntered: false, choiceMade: false }),
      voterStages({ ...base, choiceMade: false }),
      voterStages(base),
      voterStages({ ...base, ballotReady: true }),
    ].map((stages) => stages.find((s) => s.state === "current")?.label);
    assert.deepEqual(labels, ["Election", "Identity", "Vote", "Privacy", "Submit"]);
  });

  it("Change my choice returns the workflow to the pre-release stage", () => {
    // After reconsideration the ballot is no longer Ready: Privacy becomes
    // current again and Submit returns to a future (hidden) stage.
    const stages = voterStages({ ...base, ballotReady: false });
    assert.equal(stages.find((s) => s.state === "current")?.label, "Privacy");
    assert.equal(stages[4]?.state, "todo");
    // The existing command path is used; no alternate path exists.
    assert.match(vote, /await api\.changeMyBallotChoice\(\)/);
  });

  it("CAST_PENDING keeps Submit current and the locked recovery card outside guided hiding", () => {
    const stages = voterStages({ ...base, castState: "CAST_PENDING" });
    assert.equal(stages.find((s) => s.state === "current")?.label, "Submit");
    // The locked card renders whenever castLocked, never hidden by guided mode.
    assert.match(vote, /\{castLocked \? \(\s*<Card title=\{ballotCast \? "Ballot cast" : "Finishing your ballot submission"\}>/);
    // The submission surface stays visible for a locked ballot.
    assert.match(vote, /currentStageKey === "Submit" \|\| castLocked/);
  });

  it("CAST completes all five stages and keeps the terminal card prominent", () => {
    const stages = voterStages({ ...base, castState: "CAST" });
    assert.ok(stages.every((s) => s.state === "done"));
    // The terminal cast card is the castLocked branch — not gated by guided
    // stage visibility — and still points to the archive for final inclusion.
    assert.match(vote, /Your ballot was accepted ✓/);
    assert.match(vote, /Final inclusion can be independently checked from the published\s+election archive/);
    assert.match(vote, /Receipt details/);
  });
});

describe("vote technical details remain available", () => {
  it("keeps every technical disclosure", () => {
    for (const summary of [
      'summary="Technical details"',
      'summary="Election details"',
      'summary="How does anonymous eligibility work?"',
      'summary="Advanced connection details"',
      'summary="Receipt details"',
    ]) {
      assert.ok(vote.includes(summary), `missing disclosure: ${summary}`);
    }
  });
});

// -------------------------------------------------------------------------
// MANAGE: lifecycle-driven guided workspace
// -------------------------------------------------------------------------

describe("organizer guided control matrix", () => {
  it("FROZEN shows prepare-voting controls prominently and hides later phases", () => {
    const controls = organizerGuidedControls("FROZEN");
    assert.ok(controls !== null);
    for (const key of ["intake", "materials", "open"]) {
      assert.ok(controls.includes(key as never), `FROZEN must show ${key}`);
    }
    for (const key of ["close", "tally", "verify", "finalArchive", "anchor"]) {
      assert.ok(!controls.includes(key as never), `FROZEN must not show ${key}`);
    }
  });

  it("OPEN shows intake/status/close prominently and hides the results phases", () => {
    const controls = organizerGuidedControls("OPEN");
    assert.ok(controls !== null);
    for (const key of ["intake", "office", "materials", "participation", "close"]) {
      assert.ok(controls.includes(key as never), `OPEN must show ${key}`);
    }
    for (const key of ["open", "tally", "verify", "finalArchive", "anchor"]) {
      assert.ok(!controls.includes(key as never), `OPEN must not show ${key}`);
    }
  });

  it("CLOSED shows participation/tally/verify prominently", () => {
    const controls = organizerGuidedControls("CLOSED");
    assert.ok(controls !== null);
    for (const key of ["participation", "tally", "verify"]) {
      assert.ok(controls.includes(key as never), `CLOSED must show ${key}`);
    }
    for (const key of ["open", "close", "intake", "materials", "finalArchive", "anchor"]) {
      assert.ok(!controls.includes(key as never), `CLOSED must not show ${key}`);
    }
  });

  it("VERIFIED exposes the result and finalize prominently", () => {
    const controls = organizerGuidedControls("VERIFIED");
    assert.ok(controls !== null);
    assert.ok(controls.includes("tally"));
    assert.ok(controls.includes("finalArchive"));
    assert.ok(!controls.includes("verify"));
    assert.ok(!controls.includes("anchor"));
  });

  it("FINALIZED exposes the archive and optional anchor prominently", () => {
    const controls = organizerGuidedControls("FINALIZED");
    assert.ok(controls !== null);
    assert.ok(controls.includes("finalArchive"));
    assert.ok(controls.includes("anchor"));
    assert.ok(!controls.includes("open"));
    assert.ok(!controls.includes("close"));
    assert.ok(!controls.includes("verify"));
  });

  it("falls back to the full control surface for null/unknown lifecycles", () => {
    for (const state of [null, undefined, "DRAFT", "SOMETHING_ELSE"]) {
      assert.equal(organizerGuidedControls(state), null);
    }
  });

  it("gives each phase a truthful primary heading", () => {
    assert.equal(organizerPhaseHeading("FROZEN"), "Prepare voting");
    assert.equal(organizerPhaseHeading("OPEN"), "Voting is open");
    assert.equal(organizerPhaseHeading("CLOSED"), "Verify the result");
    assert.equal(organizerPhaseHeading("VERIFIED"), "Finish the election");
    assert.equal(organizerPhaseHeading("FINALIZED"), "Publish and verify the record");
    assert.equal(organizerPhaseHeading(null), null);
    assert.equal(organizerPhaseHeading("DRAFT"), null);
  });
});

describe("organizer guided-mode rendering", () => {
  it("gates lifecycle-specific control cards through the guided matrix", () => {
    for (const key of [
      "intake",
      "materials",
      "office",
      "participation",
      "open",
      "close",
      "tally",
      "verify",
      "finalArchive",
    ]) {
      assert.ok(
        manage.includes(`{showControl("${key}") && (`),
        `card not gated through showControl: ${key}`,
      );
    }
    // The gate is presentation-only: show-all restores the full surface.
    assert.match(manage, /const guidedControls = showAllControls \? null : organizerGuidedControls\(lifecycle\)/);
    assert.match(manage, /guidedControls === null \|\| guidedControls\.includes\(control\)/);
    // The anchor card remains visible, but raw production authority controls
    // live behind the dedicated advanced disclosure.
    assert.match(manage, /<Card title="Tari Anchor">/);
    assert.match(manage, /Advanced: technical release verification/);
  });

  it("shows the phase heading only in guided mode (organizer context only)", () => {
    assert.match(manage, /const phaseHeading = guidedMode \? organizerPhaseHeading\(lifecycle\) : null/);
    // Role-gated: an imported voter election never renders organizer guidance.
    assert.match(
      manage,
      /\{isOrganizer && guidedMode && phaseHeading !== null && \(/,
    );
  });

  it("renders the Results heading only when a results-phase control is relevant", () => {
    assert.match(manage, /const resultsVisible =/);
    // Role-gated: an imported voter election never renders organizer guidance.
    assert.match(manage, /\{isOrganizer && resultsVisible && \(/);
  });

  it("lists compact completed-phase summaries derived from existing state", () => {
    assert.match(manage, /<Card title="Progress so far">/);
    assert.match(manage, /Private intake configured/);
    assert.match(manage, /Voter materials available/);
    assert.match(manage, /Voting opened/);
    assert.match(manage, /Voting closed/);
    assert.match(manage, /Tally computed/);
    assert.match(manage, /Result verified/);
    assert.match(manage, /Election finalized/);
    assert.match(manage, /Final archive written/);
    // Completion is derived, never inferred: intake/materials summaries require
    // the provisioned-transport flag, tally the session tally, archive the
    // selected verified archive result.
    assert.match(manage, /organizerStatus\?\.transport_provisioned && !showControl\("intake"\)/);
    assert.match(manage, /tally !== null && !showControl\("tally"\)/);
    assert.match(manage, /archiveReadyForAnchor && !showControl\("finalArchive"\)/);
  });
});

describe("organizer Show all election controls escape hatch", () => {
  it("exists as a presentation-only toggle with aria-pressed", () => {
    assert.match(manage, /aria-pressed=\{showAllControls\}/);
    assert.match(manage, /Show all election controls/);
    assert.match(manage, /Show guided view/);
  });

  it("changes no state, bypasses no gate, and invokes no command", () => {
    const toggle = manage.slice(
      manage.indexOf("aria-pressed={showAllControls}"),
      manage.indexOf("aria-pressed={showAllControls}") + 500,
    );
    assert.match(toggle, /setShowAllControls\(\(current\) => !current\)/);
    assert.doesNotMatch(toggle, /api\.|runLifecycle|setLifecycleBusy/);
  });

  it("reveals hidden controls without enabling them (gates unchanged)", () => {
    // Every lifecycle gate stays exactly as before; show-all only re-renders.
    assert.match(manage, /disabled=\{!canAct \|\| lifecycle !== "FROZEN"\}/);
    assert.match(manage, /disabled=\{!canAct \|\| lifecycle !== "OPEN" \|\| lifecycleBusy\}/);
    assert.match(manage, /disabled=\{!canAct \|\| !tallyAvailable\}/);
    assert.match(manage, /disabled=\{!canAct \|\| lifecycle !== "CLOSED"\}/);
    assert.match(manage, /disabled=\{!canAct \|\| lifecycle !== "VERIFIED" \|\| lifecycleBusy\}/);
    assert.match(manage, /disabled=\{!canAct \|\| !archiveDir \|\| !finalArchiveAvailable\}/);
  });
});

describe("FROZEN participation wording", () => {
  it("never says 'Hidden while voting is open' before voting opens", () => {
    assert.equal(sealedParticipationText("OPEN"), "Hidden while voting is open");
    assert.equal(sealedParticipationText("FROZEN"), "Voting has not opened yet");
    assert.equal(sealedParticipationText("DRAFT"), "Voting has not opened yet");
    // Other states never fabricate a value or a reason.
    assert.equal(sealedParticipationText("CLOSED"), "Hidden");
    assert.equal(sealedParticipationText(null), "Hidden");
  });

  it("uses the lifecycle-aware label everywhere the sealed state renders", () => {
    // No unconditional OPEN wording remains in the organizer screen source.
    const matches = manage.match(/Hidden while voting is open/g) ?? [];
    for (const match of matches) {
      const idx = manage.indexOf(match);
      const before = manage.slice(0, idx);
      assert.ok(
        before.lastIndexOf('lifecycle === "OPEN"') > before.lastIndexOf("</Card>"),
        "the OPEN wording may render only under an explicit OPEN lifecycle gate",
      );
    }
    assert.match(manage, /sealedParticipationText\(lifecycle\)/);
    assert.match(manage, /sealedLabel=\{sealedParticipationText\(lifecycle\)\}/);
    // And no fabricated authoritative zero is invented for the sealed count.
    assert.doesNotMatch(manage, /No ballots accepted yet/);
  });
});

describe("organizer technical-details compression", () => {
  it("collapses the entire technical election section by default", () => {
    const idx = manage.indexOf('summary="Election technical details"');
    assert.ok(idx >= 0, "Election technical details disclosure must exist");
    for (const content of [
      "Election overview",
      "Manifest schema",
      "Proof suite",
      "Registry commitment",
      "Option-set commitment",
      "Election ID (canonical)",
      "Machine ID",
      "Governance source",
      "Eligible voters",
      "Advanced details",
    ]) {
      assert.ok(
        manage.indexOf(content) > idx,
        `${content} must render inside the collapsed technical section`,
      );
    }
  });
});

describe("organizer VERIFIED/FINALIZED phase content", () => {
  it("shows the finalization warning beside the finalize action in VERIFIED", () => {
    assert.match(manage, /\{lifecycle === "VERIFIED" && \(\s*<Notice tone="warn">/);
    assert.match(manage, /Finalizing is permanent/);
    // The explicit danger confirmation remains the safeguard.
    assert.match(manage, /Finalize this election\?/);
    assert.match(manage, /confirmTone="danger"/);
  });

  it("keeps the Ootle anchor optional and aggregate-only", () => {
    assert.match(manage, /Optional public integrity anchor/);
    assert.match(manage, /Anchoring is optional and\s+non-binding/);
  });
});

// -------------------------------------------------------------------------
// No backend/API invocation changed
// -------------------------------------------------------------------------

describe("guided disclosure adds no backend surface", () => {
  it("introduces no new API calls on either screen", () => {
    const voteApiCalls = vote.match(/api\.[a-zA-Z]+\(/g) ?? [];
    const manageApiCalls = manage.match(/api\.[a-zA-Z]+\(/g) ?? [];
    const allowedVote = new Set([
      "api.voterConfirmation(",
      "api.computeGovernanceDocumentDigest(",
      "api.voterGovernanceCredentialStatus(",
      "api.listSavedVoterCredentials(",
      "api.createDurableVoterCredential(",
      "api.unlockSavedVoterCredential(",
      "api.importVoterCredential(",
      "api.backupVoterCredential(",
      "api.clearVoterCredentialFromMemory(",
      "api.deleteSavedVoterCredential(",
      "api.voterWorkflowStatus(",
      "api.voterBallotSelectionStatus(",
      "api.clearVoterBallotSelection(",
      "api.setVoterBallotSelection(",
      "api.prepareVoterBallot(",
      "api.exportPreparedVoterBallot(",
      "api.changeMyBallotChoice(",
      "api.submitPreparedVoterBallotPrivately(",
      "api.retryPrivateSubmission(",
      "api.privateTransportAvailability(",
      "api.managedTorStatus(",
      "api.configureManagedTor(",
      "api.startManagedTor(",
      "api.stopManagedTor(",
      "api.testRemoteTorConnection(",
      "api.voterTorStatus(",
      "api.importElectionStatusArtifact(",
      "api.fetchElectionStatusPrivate(",
    ]);
    for (const call of new Set(voteApiCalls)) {
      assert.ok(allowedVote.has(call), `unexpected Vote API call: ${call}`);
    }
    const allowedManage = new Set([
      "api.intakeBallotPackage(",
      "api.currentTally(",
      "api.syncPrivateIntake(",
      "api.privateIntakeInboxPath(",
      "api.organizerTorStatus(",
      "api.startPrivateIntake(",
      "api.stopPrivateIntake(",
      "api.exportVoterTransportBundle(",
      "api.exportElectionStatusArtifact(",
      "api.writeFinalizedArchive(",
      "api.anchorDeploymentCapabilities(",
      "api.verifyArchive(",
      "api.trustedOotleDeploymentStatus(",
      "api.inspectTemplateWasm(",
      "api.lockTrustedOotleDeployment(",
      "api.unlockTrustedOotleDeployment(",
      "api.writeLiveAnchorConfig(",
      "api.validateLiveAnchorOperatorConfig(",
      "api.listWalletdAnchorAccounts(",
      "api.buildV2PublicAnchorPayload(",
      "api.verifyV2PublicAnchorEvidence(",
      "api.runLiveAnchorLifecycleStep(",
      // Walletd connect/readiness surface for the anchor setup assistant
      // (auto-fill + read-only preflight). These are safe: connect/reconnect
      // take the raw key as a WRITE-ONLY argument that never comes back, and
      // status/readiness return only booleans/labels/endpoints — never the
      // bearer token (see WalletdCredentialStatusV1 / WalletdReadinessV1).
      "api.walletdCredentialStatus(",
      "api.connectWalletd(",
      "api.reconnectWalletd(",
      "api.forgetWalletd(",
      "api.walletdReadiness(",
      // Read-only connection diagnostic: returns only non-secret fields
      // (endpoint, credential-presence boolean, attempted flag, classified
      // kind, account count/name) — never the bearer token or API key.
      "api.walletdConnectionDiagnostics(",
      // Production transport authority PUBLIC-root setup/review. Safe: the
      // request carries only a public-key hex, and the readiness result exposes
      // only a key id, network, and public-key fingerprint — never a private
      // key. Backend fails closed when unconfigured and rejects fake/test roots.
      "api.productionTransportAuthorityStatus(",
      "api.configureProductionTransportAuthorityRoot(",
      "api.forgetProductionTransportAuthorityRoot(",
    ]);
    for (const call of new Set(manageApiCalls)) {
      assert.ok(allowedManage.has(call), `unexpected Manage API call: ${call}`);
    }
  });

  it("changes no Rust/backend files", () => {
    // This test file is the guard: the guided pass is frontend-only. The
    // workflow runs git diff --stat separately; here we assert the screens
    // never import server/protocol modules directly.
    for (const source of [vote, manage]) {
      assert.doesNotMatch(source, /fetch\(|invoke\(|\.prove\(/i);
    }
  });
});
