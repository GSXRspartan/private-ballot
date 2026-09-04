// UI/UX simplification pass regression tests (Vote + Manage Election).
//
// Pins the presentation/interaction-hierarchy pass: the voter progression is
// derived ONLY from the existing workflow/session state, the plain-language
// submission wording stays honest (no archive-inclusion overclaim), the
// CAST_PENDING recovery stays locked, the organizer lifecycle/next-step are
// derived from the real lifecycle, and the irreversible organizer actions keep
// explicit danger confirmations. Protocol/backend behavior is unchanged.
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

import { voterStages } from "../src/voterProgress.ts";
import {
  nextOrganizerStep,
  organizerLifecycleSteps,
} from "../src/lifecycle.ts";
import { privateSubmissionStatus } from "../src/privateSubmission.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const manage = readProjectFile("src/screens/ManageElection.tsx");

// -------------------------------------------------------------------------
// VOTE: progression reflects the existing workflow state (never invented)
// -------------------------------------------------------------------------

describe("voter progression derivation", () => {
  const base = {
    electionLoaded: true,
    reviewPassed: false,
    identityReady: false,
    voteEntered: false,
    choiceMade: false,
    ballotReady: false,
    castState: "NOT_CAST" as const,
  };

  it("starts at Election with everything else subdued", () => {
    const stages = voterStages(base);
    assert.deepEqual(
      stages.map((s) => [s.label, s.state]),
      [
        ["Election", "current"],
        ["Identity", "todo"],
        ["Vote", "todo"],
        ["Privacy", "todo"],
        ["Submit", "todo"],
      ],
    );
  });

  it("walks forward exactly with the real gates, one current stage at a time", () => {
    const afterReview = voterStages({ ...base, reviewPassed: true });
    assert.equal(afterReview[0]?.state, "done");
    assert.equal(afterReview[1]?.state, "current");
    assert.equal(afterReview[2]?.state, "todo");

    const afterIdentity = voterStages({
      ...base,
      reviewPassed: true,
      identityReady: true,
      voteEntered: true,
    });
    assert.equal(afterIdentity[1]?.state, "done");
    assert.equal(afterIdentity[2]?.state, "current");
    assert.equal(afterIdentity[3]?.state, "todo");

    const afterChoice = voterStages({
      ...base,
      reviewPassed: true,
      identityReady: true,
      voteEntered: true,
      choiceMade: true,
    });
    assert.equal(afterChoice[2]?.state, "done");
    assert.equal(afterChoice[3]?.state, "current");
    assert.equal(afterChoice[4]?.state, "todo");

    const afterPrepare = voterStages({
      ...base,
      reviewPassed: true,
      identityReady: true,
      voteEntered: true,
      choiceMade: true,
      ballotReady: true,
    });
    assert.equal(afterPrepare[3]?.state, "done");
    assert.equal(afterPrepare[4]?.state, "current");

    const afterCast = voterStages({
      ...base,
      reviewPassed: true,
      identityReady: true,
      voteEntered: true,
      choiceMade: true,
      castState: "CAST",
    });
    assert.ok(afterCast.every((s) => s.state === "done"));
  });

  it("keeps Vote/Privacy done and Submit current while CAST_PENDING", () => {
    const stages = voterStages({
      ...base,
      reviewPassed: true,
      identityReady: true,
      voteEntered: true,
      castState: "CAST_PENDING",
    });
    assert.equal(stages[2]?.state, "done");
    assert.equal(stages[3]?.state, "done");
    assert.equal(stages[4]?.state, "current");
  });

  it("moves Privacy back to current after Change my choice (proof must be recreated)", () => {
    const stages = voterStages({
      ...base,
      reviewPassed: true,
      identityReady: true,
      voteEntered: true,
      choiceMade: true,
      ballotReady: false,
    });
    assert.equal(stages[2]?.state, "done");
    assert.equal(stages[3]?.state, "current");
    assert.equal(stages[4]?.state, "todo");
  });

  it("renders on the Vote screen from the derived stages (no separate state)", () => {
    assert.match(vote, /<ProgressSteps/);
    assert.match(vote, /label="Voting progress"/);
    // The indicator reuses the SAME reconstructed guidedStages as the workflow
    // cards (single source of truth), which is derived from the existing
    // screen/workflow state — nothing new is fetched or persisted.
    assert.match(vote, /steps=\{guidedStages\}/);
    assert.match(vote, /const guidedStages = voterStages\(\{/);
    assert.match(vote, /identityReady: canProceedAfterCredential\(credential\)/);
    assert.match(vote, /ballotReady: workflow\?\.prepared_ballot\.state === "Ready"/);
    assert.match(vote, /castState,/);
  });
});

// -------------------------------------------------------------------------
// VOTE: response stage + prepared review
// -------------------------------------------------------------------------

describe("vote response and prepared review presentation", () => {
  it("keeps the canonical question and choices in the response card", () => {
    assert.match(vote, /<Card title="Choose your response">/);
    assert.match(vote, /confirmation\.bound\.proposal_question/);
    assert.match(vote, /selection-option selection-option-choice/);
    // The plain reassurance stays next to the choices.
    assert.match(vote, /You can change your choice\s+until you submit or save your anonymous ballot\./);
  });

  it("shows the prepared ballot as a review card with election and choice", () => {
    assert.match(vote, /<Card title="Your anonymous ballot is ready">/);
    assert.match(vote, /<Field label="Your choice">/);
    assert.match(vote, /selected_display_labels\.join/);
    assert.match(vote, /confirmation\.bound\.election_id_text \?\?\s+confirmation\.bound\.election_id_hex/);
    assert.match(vote, /Continue to private delivery below/);
  });

  it("keeps Change my choice available in the review card, before the boundary only", () => {
    // Exactly one Change my choice ACTION (button) remains, in the prepared
    // review card; the guided Vote-stage summary additionally offers a
    // "Change my choice" REVIEW control (a summary label, not a second
    // button) that re-expands the existing live response editor.
    const matches = vote.match(/>\s*Change my choice\s*</g) ?? [];
    assert.equal(matches.length, 1, "exactly one Change my choice action");
    // The action lives in the prepared review card, i.e. after the ready title.
    const readyIdx = vote.indexOf('<Card title="Your anonymous ballot is ready">');
    const changeIdx = vote.indexOf("Change my choice", readyIdx);
    assert.ok(readyIdx >= 0 && changeIdx > readyIdx, "Change my choice is in the review card");
    assert.match(vote, /void onChangeChoice\(\)/);
    // The guided summary's review control re-expands the Vote stage in place
    // (the existing live-editing behavior; no new command path).
    assert.match(vote, /reviewLabel="Change my choice"/);
    assert.match(vote, /onReview=\{\(\) => setReviewStage\("Vote"\)\}/);
  });
});

// -------------------------------------------------------------------------
// VOTE: privacy stage wording
// -------------------------------------------------------------------------

describe("privacy stage plain language", () => {
  it("leads with the three guarantees and keeps the exact existing action", () => {
    assert.match(vote, /<Card title="Protect your vote">/);
    assert.match(vote, /✓ Your eligibility is proven anonymously\./);
    assert.match(vote, /✓ Your identity is not included with your choice\./);
    assert.match(
      vote,
      /✓ The same credential cannot produce two accepted ballots in this\s+election\./,
    );
    assert.match(vote, />\s*Create anonymous eligibility proof\s*</);
    assert.match(vote, /Creating your anonymous eligibility proof…/);
  });

  it("keeps the honest not-permanently-sealed limitation next to the proof", () => {
    assert.match(vote, /not\s+permanently sealed/);
    assert.match(vote, /How does anonymous eligibility work\?/);
    assert.match(vote, /Tari Triptych/);
  });
});

// -------------------------------------------------------------------------
// VOTE: private submission progressive disclosure
// -------------------------------------------------------------------------

describe("private Tor normal UI and progressive disclosure", () => {
  it("leads with the plain-language submission card", () => {
    assert.match(vote, /<Card title="Submit your ballot privately">/);
    assert.match(vote, /Submit vote privately/);
    assert.match(vote, /Connect privately/);
    assert.match(vote, /Tor installed/);
    assert.match(vote, /Ballot office/);
    assert.match(vote, /Verified for this election ✓/);
    assert.match(vote, /Select ballot-office connection file/);
  });

  it("hides transport internals under Advanced connection details", () => {
    const idx = vote.indexOf('summary="Advanced connection details"');
    assert.ok(idx >= 0, "Advanced connection details disclosure must exist");
    for (const diagnostic of ["onion_hostname", "descriptor_fingerprint", "socks_addr"]) {
      assert.ok(
        vote.indexOf(diagnostic) > idx,
        `${diagnostic} must render inside Advanced connection details`,
      );
    }
    // Process status and the resolved tor.exe path are diagnostics too.
    assert.match(vote, /Connection process:/);
    assert.match(vote, /resolved_tor_path/);
  });

  it("shows bounded exact-retry progress without implying a new ballot", () => {
    assert.match(vote, /Retry \{autoRetryAttempt\} of/);
    assert.match(vote, /re-sends the same\s*\n?\s*encrypted ballot/i);
    assert.match(vote, /never creates\s*\n?\s*another vote/i);
    assert.match(vote, /Your vote is locked\./);
    assert.match(vote, /Stop retrying/);
  });

  it("paints the sending status only during an actual submission", () => {
    // A dedicated `submitting` state (not the shared `busy`) drives the
    // SUBMITTING phase, so proof creation/export never shows "sending".
    assert.match(vote, /const \[submitting, setSubmitting\]/);
    assert.match(vote, /busy: submitting,/);
    const s = privateSubmissionStatus({
      castState: "NOT_CAST",
      configured: true,
      torRunning: true,
      busy: true,
      lastReceiptState: null,
    });
    assert.match(s.title, /Sending your encrypted ballot privately/);
  });
});

// -------------------------------------------------------------------------
// VOTE: CAST_PENDING stays locked; dead Tor exposes reconnect
// -------------------------------------------------------------------------

describe("CAST_PENDING presentation", () => {
  it("is unmistakably locked with an exact-retry path", () => {
    const s = privateSubmissionStatus({
      castState: "CAST_PENDING",
      configured: true,
      torRunning: true,
      busy: false,
      lastReceiptState: null,
    });
    assert.equal(s.phase, "PENDING");
    assert.match(s.title, /Delivery wasn't confirmed/);
    assert.match(s.detail, /safely locked/);
    assert.match(s.detail, /this exact encrypted submission/);
    assert.match(s.detail, /no new ballot will be created/i);
  });

  it("offers Retry private submission plus reconnect when the connection stopped", () => {
    assert.match(vote, /Retry private submission/);
    assert.match(vote, /Private connection stopped\./);
    assert.match(vote, /Reconnect privately/);
    // The pending block never prepares or submits a new ballot.
    const pendingBlock = vote.slice(
      vote.indexOf("{castPending && ("),
      vote.indexOf('summary="Advanced connection details"'),
    );
    assert.doesNotMatch(pendingBlock, /onGenerateProof|prepareVoterBallot|Change my choice/);
  });

  it("a stopped connection is never presented as ready", () => {
    const s = privateSubmissionStatus({
      castState: "NOT_CAST",
      configured: true,
      torRunning: false,
      busy: false,
      lastReceiptState: null,
    });
    assert.equal(s.phase, "READY_TO_START");
    assert.notEqual(s.phase, "READY");
  });
});

// -------------------------------------------------------------------------
// VOTE: authenticated receipt success honesty + offline route kept
// -------------------------------------------------------------------------

describe("authenticated receipt presentation", () => {
  it("says accepted with receipt, and points to the archive for final inclusion", () => {
    const s = privateSubmissionStatus({
      castState: "CAST",
      configured: false,
      torRunning: false,
      busy: false,
      lastReceiptState: null,
    });
    assert.match(s.title, /ballot was accepted/i);
    assert.match(s.detail, /authenticated receipt/);
    // No finalization/anchoring/inclusion claim in the status helper.
    assert.doesNotMatch(`${s.title} ${s.detail}`, /finalized|anchored|included|counted/i);
    // The cast card points at the published archive for final inclusion.
    assert.match(vote, /Final inclusion can be independently checked from the published\s+election archive/);
    assert.match(vote, /Receipt details/);
  });

  it("keeps the offline delivery route available but subordinate", () => {
    assert.match(vote, /Other delivery options/);
    assert.match(vote, /Offline submission/);
    assert.match(vote, /Nothing is sent over the network/);
    assert.match(vote, />\s*Save encrypted ballot file\s*</);
    // The irreversible boundary confirmation remains.
    assert.match(vote, /Save this ballot file\?/);
    assert.match(vote, /confirmCast && \(/);
  });
});

// -------------------------------------------------------------------------
// MANAGE: lifecycle progression reflects the real lifecycle only
// -------------------------------------------------------------------------

describe("organizer lifecycle progression", () => {
  it("maps the real lifecycle onto the steps without inventing completion", () => {
    const labels = organizerLifecycleSteps("OPEN").map((s) => [s.label, s.state]);
    assert.deepEqual(labels, [
      ["Created", "done"],
      ["Frozen", "done"],
      ["Open", "current"],
      ["Closed", "todo"],
      ["Verified", "todo"],
      ["Finalized", "todo"],
    ]);
    // FINALIZED is terminal and genuinely complete.
    assert.ok(organizerLifecycleSteps("FINALIZED").every((s) => s.state === "done"));
    // FROZEN: only Created is behind the organizer.
    const frozen = organizerLifecycleSteps("FROZEN");
    assert.equal(frozen[0]?.state, "done");
    assert.equal(frozen[1]?.state, "current");
    // DRAFT is only "Created" in progress; nothing is done.
    const draft = organizerLifecycleSteps("DRAFT");
    assert.equal(draft[0]?.state, "current");
    assert.ok(draft.slice(1).every((s) => s.state === "todo"));
    // Unknown/null states never claim progress.
    for (const state of [null, undefined, "SOMETHING_ELSE"]) {
      const steps = organizerLifecycleSteps(state);
      assert.equal(steps[0]?.state, "current");
      assert.ok(steps.slice(1).every((s) => s.state === "todo"));
    }
  });

  it("renders on Manage Election from the actual lifecycle", () => {
    assert.match(manage, /<ProgressSteps/);
    assert.match(manage, /label="Election lifecycle"/);
    assert.match(manage, /steps=\{organizerLifecycleSteps\(lifecycle\)\}/);
  });
});

// -------------------------------------------------------------------------
// MANAGE: Next step derives from the real lifecycle
// -------------------------------------------------------------------------

describe("organizer next step derivation", () => {
  it("guides each real lifecycle state", () => {
    assert.match(
      nextOrganizerStep({ lifecycle: "FROZEN", tallyComputed: false, archiveVerified: false }).body,
      /Start private intake, distribute the voter materials, then open voting\./,
    );
    assert.match(
      nextOrganizerStep({ lifecycle: "OPEN", tallyComputed: false, archiveVerified: false }).body,
      /Private intake can receive ballots/,
    );
    assert.match(
      nextOrganizerStep({ lifecycle: "CLOSED", tallyComputed: false, archiveVerified: false }).body,
      /No additional ballots can be accepted\. Compute the tally when ready\./,
    );
    assert.match(
      nextOrganizerStep({ lifecycle: "CLOSED", tallyComputed: true, archiveVerified: false }).body,
      /mark verification complete/,
    );
    assert.match(
      nextOrganizerStep({ lifecycle: "VERIFIED", tallyComputed: true, archiveVerified: false }).body,
      /Finalize the election/,
    );
    // FINALIZED, archive not yet verified: send the operator to Archive to
    // verify the record.
    assert.match(
      nextOrganizerStep({ lifecycle: "FINALIZED", tallyComputed: true, archiveVerified: false })
        .title,
      /Verify final archive/,
    );
    assert.match(
      nextOrganizerStep({ lifecycle: "FINALIZED", tallyComputed: true, archiveVerified: false })
        .body,
      /Open Archive and independently verify the final record/,
    );
    // FINALIZED with a verified archive but no anchor at all: the election
    // record is complete; the Tari Ootle anchor is optional.
    assert.match(
      nextOrganizerStep({ lifecycle: "FINALIZED", tallyComputed: true, archiveVerified: true })
        .title,
      /Election record verified/,
    );
    assert.match(
      nextOrganizerStep({ lifecycle: "FINALIZED", tallyComputed: true, archiveVerified: true })
        .body,
      /anchoring is optional and non-binding/,
    );
    // FINALIZED with a verified archive and an anchor submitted but not yet
    // receipt-verified: request receipt verification.
    assert.match(
      nextOrganizerStep({
        lifecycle: "FINALIZED",
        tallyComputed: true,
        archiveVerified: true,
        anchorSubmittedButUnverified: true,
      }).title,
      /Verify existing anchor/,
    );
    // FINALIZED with a verified archive and a receipt-verified anchor: done.
    assert.match(
      nextOrganizerStep({
        lifecycle: "FINALIZED",
        tallyComputed: true,
        archiveVerified: true,
        anchorVerified: true,
      }).title,
      /Election complete/,
    );
  });

  it("renders the derived next step on Manage Election", () => {
    assert.match(manage, /<Card title="Next step">/);
    assert.match(manage, /nextOrganizerStep\(\{/);
    assert.match(manage, /\{nextStep\.body\}/);
  });
});

// -------------------------------------------------------------------------
// MANAGE: intake presentation
// -------------------------------------------------------------------------

describe("organizer intake presentation", () => {
  it("shows a plain readiness pill and keeps the two counters distinct", () => {
    // The pill says "Running" (local readiness), never "Ready" implying proven
    // remote onion reachability, which the app cannot know.
    assert.match(manage, /<Pill tone="ok">Running ✓<\/Pill>/);
    assert.match(manage, /label="Election accepted ballots"/);
    assert.match(manage, /participation\?\.accepted_ballots/);
    assert.match(manage, /label="Received this intake session"/);
    assert.match(manage, /resets\s*\n?\s*to 0 whenever intake restarts/);
  });

  it("never implies starting intake opens voting", () => {
    assert.match(manage, /Starting intake does not open voting/);
  });

  it("keeps manual Sync available but recovery-oriented", () => {
    assert.match(manage, /Recovery \/ manual actions/);
    assert.match(manage, /Sync accepted ballots/);
    // The recovery group precedes the manual button (the button label is
    // rendered as button text, after the group heading).
    const groupIdx = manage.indexOf("Recovery / manual actions");
    const buttonIdx = manage.indexOf('className="btn btn-secondary"', groupIdx);
    assert.ok(groupIdx >= 0 && buttonIdx > groupIdx, "manual Sync lives under the recovery group");
    assert.match(manage.slice(groupIdx, buttonIdx + 400), /Sync accepted ballots/);
  });

  it("keeps organizer Tor diagnostics collapsed under Advanced Tor diagnostics", () => {
    const idx = manage.indexOf('summary="Advanced Tor diagnostics"');
    assert.ok(idx >= 0, "Advanced Tor diagnostics disclosure must exist");
    for (const diagnostic of ["onion_hostname", "descriptor_fingerprint", "collector_addr", "tor_data_dir"]) {
      assert.ok(
        manage.indexOf(diagnostic) > idx,
        `${diagnostic} must render inside Advanced Tor diagnostics`,
      );
    }
  });
});

// -------------------------------------------------------------------------
// MANAGE: voter materials + participation + Ootle subordination
// -------------------------------------------------------------------------

describe("voter materials, participation, and Ootle subordination", () => {
  it("groups what voters need with the existing bundle export", () => {
    assert.match(manage, /<Card title="Voter materials">/);
    assert.match(manage, /The frozen election package/);
    assert.match(manage, /The voter transport bundle/);
    assert.match(manage, /Export voter transport bundle/);
    assert.match(manage, /api\.exportVoterTransportBundle/);
  });

  it("presents sealed participation as intentional, not broken", () => {
    assert.match(manage, /Participation is hidden while voting is open/);
    assert.match(manage, /intentional, not missing\s+data/);
    // Disclosed participation still shows the real counts after close.
    assert.match(manage, /of \{participation\.eligible_voters\} eligible voters/);
  });

  it("keeps Ootle optional and aggregate-only, never required for voting", () => {
    assert.match(manage, /Optional public integrity anchor/);
    assert.match(manage, /Individual votes are not written to Ootle/);
    assert.match(manage, /Anchoring is optional and\s+non-binding/);
  });
});

// -------------------------------------------------------------------------
// MANAGE: irreversible actions stay confirmed and gated
// -------------------------------------------------------------------------

describe("irreversible organizer actions", () => {
  it("keeps CLOSE behind an explicit danger confirmation", () => {
    assert.match(manage, /Close voting\?/);
    assert.match(manage, /No additional ballots can be accepted after this election is closed\./);
    assert.match(manage, /confirmLabel="Close voting permanently"/);
    assert.match(manage, /confirmTone="danger"/);
    assert.match(manage, /void onConfirmClose\(\)/);
  });

  it("puts FINALIZE behind an explicit danger confirmation too", () => {
    assert.match(manage, /Finalize this election\?/);
    assert.match(manage, /The verified result and finalized election record become permanent\./);
    assert.match(manage, /confirmLabel="Finalize election"/);
    assert.match(manage, /setConfirmFinalize\(true\)/);
    assert.match(manage, /void onConfirmFinalize\(\)/);
    // The confirmation runs the SAME existing lifecycle action; no new transition.
    const handler = manage.slice(
      manage.indexOf("const onConfirmFinalize"),
      manage.indexOf("// Shared load controls"),
    );
    assert.match(handler, /runLifecycle\("finalize"\)/);
    assert.doesNotMatch(handler, /runLifecycle\("(open|close|verify)"\)/);
  });

  it("keeps the results workflow gates tied to the real lifecycle", () => {
    // Tally only after close; verify only from CLOSED; finalize only from
    // VERIFIED; final archive only from FINALIZED. Presentation changed, the
    // gates did not.
    assert.match(manage, /disabled=\{!canAct \|\| !tallyAvailable\}/);
    assert.match(manage, /disabled=\{!canAct \|\| lifecycle !== "CLOSED"\}/);
    assert.match(manage, /disabled=\{!canAct \|\| lifecycle !== "VERIFIED" \|\| lifecycleBusy\}/);
    assert.match(manage, /disabled=\{!canAct \|\| !archiveDir \|\| !finalArchiveAvailable\}/);
    // The existing progression remains visible in order.
    assert.match(manage, /Compute tally/);
    assert.match(manage, /Mark verified/);
    assert.match(manage, /Write final archive/);
  });

  it("marks opening voting as irreversible in plain language", () => {
    assert.match(manage, /Opening voting cannot be undone\./);
  });
});
