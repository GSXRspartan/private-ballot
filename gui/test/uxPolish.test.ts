// Post-smoke voter/organizer UX polish regression tests.
//
// Pins the semantic/security wording of the GUI polish pass: the primary
// voter UI stays free of raw machine IDs and internal protocol state, the
// privacy notice stays visible without overclaiming, the prepared ballot
// has exactly one primary save action, hidden participation never renders
// as a misleading 0%, and the built-in Guide covers both roles accurately.
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

import { selectionInstructionText } from "../src/ballot/ballotTypes.ts";
import { lifecyclePlainText } from "../src/lifecycle.ts";
import {
  aggregateStateText,
  receiptStateIsAccepted,
  receiptStateText,
  workflowStateText,
  workflowTone,
} from "../src/voterWorkflow.ts";
import { describeError } from "../src/api/errorDisplay.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const manage = readProjectFile("src/screens/ManageElection.tsx");
const home = readProjectFile("src/screens/Home.tsx");
const track = readProjectFile("src/components/ParticipationTrack.tsx");
const guide = readProjectFile("src/screens/Guide.tsx");
const credentialCard = readProjectFile("src/components/VoterCredentialCard.tsx");
const app = readProjectFile("src/App.tsx");
const frame = readProjectFile("src/components/AppFrame.tsx");
const types = readProjectFile("src/api/types.ts");
const archive = readProjectFile("src/screens/Archive.tsx");
const client = readProjectFile("src/api/client.ts");
const tauriShell = readProjectFile("src-tauri/src/lib.rs");
const styles = readProjectFile("src/styles/global.css");

// -------------------------------------------------------------------------
// Anchor layout contracts
// -------------------------------------------------------------------------

describe("organizer Anchor responsive layout", () => {
  it("keeps the Tari Wallet panel in the normal (non-advanced) anchor surface", () => {
    const cardStart = manage.indexOf('<Card title="Tari Anchor">');
    const advancedStart = manage.indexOf('<DetailsSection summary="Advanced: technical release verification">');
    const walletPanelUse = manage.indexOf('{walletPanelJsx}');

    assert.ok(cardStart >= 0, "Tari Anchor card is present");
    assert.ok(advancedStart > cardStart, "advanced disclosure follows the normal card summary");
    assert.ok(walletPanelUse > cardStart, "wallet panel is rendered in the anchor card");
    assert.ok(
      walletPanelUse < advancedStart,
      "wallet panel is part of the normal (non-advanced) flow",
    );
  });

  it("keeps production transport authority behind the Advanced disclosure only", () => {
    const advancedStart = manage.indexOf('<DetailsSection summary="Advanced: technical release verification">');
    const prodAuthority = manage.indexOf('className="production-authority-panel"');
    assert.ok(advancedStart >= 0, "advanced disclosure present");
    assert.ok(prodAuthority > advancedStart, "production authority is advanced-only");
  });

  it("contains long Anchor values and collapses before the app frame gets cramped", () => {
    assert.match(styles, /\.card\[aria-label="Tari Anchor"\] \.hash \{\s*display: inline-block;\s*max-width: 100%;/);
  });
});

// -------------------------------------------------------------------------
// Primary voter UI: no raw machine IDs, no internal protocol state
// -------------------------------------------------------------------------

describe("voter primary UI hides machine identifiers", () => {
  it("does not render option machine IDs in the primary selection rows", () => {
    assert.doesNotMatch(vote, /selection-option-id/);
  });

  it("keeps machine IDs available under a Technical details disclosure", () => {
    assert.match(vote, /Technical details/);
    assert.match(vote, /Option machine IDs/);
    // The only machine-ID rendering left is inside details disclosures.
    for (const match of vote.matchAll(/machine_id_text \?\?/g)) {
      const before = vote.slice(0, match.index);
      assert.ok(
        before.lastIndexOf("Technical details") > before.lastIndexOf("</DetailsSection>"),
        "machine ID rendered outside a Technical details disclosure",
      );
    }
  });

  it("never exposes internal workflow state identifiers to voters", () => {
    assert.doesNotMatch(vote, /SelectionReady/);
    assert.doesNotMatch(vote, /SelectionIncomplete/);
    assert.doesNotMatch(vote, /PreparedBallotReady/);
    assert.doesNotMatch(vote, /PreparingProof/);
  });

  it("shows human workflow status instead of raw states", () => {
    assert.match(vote, /workflowStateText\(workflow\?\.workflow_state\)/);
  });

  it("keeps raw enum identifiers only in the pure presentation helper", () => {
    const helper = readProjectFile("src/voterWorkflow.ts");
    assert.match(helper, /case "SelectionReady":/);
    assert.match(helper, /case "SelectionIncomplete":/);
  });
});

describe("workflowStateText plain-language mapping", () => {
  it("maps every internal state to a human status", () => {
    assert.equal(workflowStateText("SelectionReady"), "Your response is ready.");
    assert.equal(
      workflowStateText("SelectionIncomplete"),
      "Choose a response to continue.",
    );
    assert.equal(workflowStateText("PreparedBallotReady"), "Your ballot is prepared.");
    assert.match(workflowStateText("PreparingProof"), /Preparing your ballot/);
    assert.match(workflowStateText("ReviewRequired"), /Review the election/);
    assert.match(workflowStateText("CredentialMissing"), /credential/);
    assert.match(workflowStateText("CredentialNotEligible"), /not eligible/);
    assert.equal(workflowStateText(null), "Choose a response to continue.");
  });

  it("never implies a selection was submitted", () => {
    for (const state of [
      "SelectionReady",
      "SelectionIncomplete",
      "PreparedBallotReady",
    ] as const) {
      assert.doesNotMatch(workflowStateText(state), /submitted|counted|recorded|cast/i);
    }
  });

  it("keeps tone mapping aligned with the human status", () => {
    assert.equal(workflowTone("SelectionReady"), "ok");
    assert.equal(workflowTone("SelectionIncomplete"), "neutral");
    assert.equal(workflowTone("CredentialNotEligible"), "warn");
  });
});

describe("selectionInstructionText derives wording from actual rules", () => {
  it("says 'Choose one option.' for an exactly-one election", () => {
    const text = selectionInstructionText({
      approval_min: 1,
      approval_max: 1,
      abstention_allowed: false,
    });
    assert.match(text, /Choose one option\./);
    assert.doesNotMatch(text, /one or more/);
  });

  it("says 'Choose up to N' when zero minimum with abstention", () => {
    assert.match(
      selectionInstructionText({ approval_min: 0, approval_max: 3, abstention_allowed: true }),
      /Choose up to 3 options\./,
    );
  });

  it("says 'Choose between N and M' for a range", () => {
    assert.match(
      selectionInstructionText({ approval_min: 1, approval_max: 3, abstention_allowed: false }),
      /Choose between 1 and 3 options\./,
    );
  });

  it("states abstention plainly in both directions", () => {
    assert.match(
      selectionInstructionText({ approval_min: 1, approval_max: 1, abstention_allowed: true }),
      /You may abstain/,
    );
    assert.match(
      selectionInstructionText({ approval_min: 1, approval_max: 1, abstention_allowed: false }),
      /Abstaining is not allowed\./,
    );
  });

  it("is used as the primary instruction on the Vote screen", () => {
    assert.match(vote, /selectionInstructionText\(selection \?\? confirmation\.bound\)/);
    assert.doesNotMatch(vote, /Approve one or more ballot options/);
  });
});

describe("lifecycle plain-language label", () => {
  it("maps machine states to human sentences", () => {
    assert.equal(lifecyclePlainText("OPEN"), "Voting is open");
    assert.equal(lifecyclePlainText("CLOSED"), "Voting is closed");
    assert.match(lifecyclePlainText("FROZEN"), /Locked/);
  });
});

// -------------------------------------------------------------------------
// Privacy notice: visible by default, no overclaiming
// -------------------------------------------------------------------------

describe("privacy notice accuracy", () => {
  it("stays visible by default (not collapsed) on the Vote screen", () => {
    assert.match(vote, /<div className="notice notice-info privacy-notice" role="note">/);
    assert.match(vote, /What privacy does this provide\?/);
  });

  it("never overclaims anonymity anywhere on the Vote screen", () => {
    assert.doesNotMatch(vote, /fully anonymous/i);
    assert.doesNotMatch(vote, /untraceable/i);
    assert.doesNotMatch(vote, /permanently private/i);
    assert.doesNotMatch(vote, /permanently secret/i);
    assert.doesNotMatch(vote, /anonymous from everyone/i);
  });

  it("does not claim network anonymity from the eligibility proof", () => {
    assert.doesNotMatch(vote, /proof (hides|protects|conceals) your (network|IP|connection)/i);
  });
});

// -------------------------------------------------------------------------
// Prepared ballot: one obvious primary save action, honest next step
// -------------------------------------------------------------------------

describe("prepared ballot save action", () => {
  it("has exactly one primary Save encrypted ballot file action", () => {
    const matches = vote.match(/>\s*Save encrypted ballot file\s*</g) ?? [];
    assert.equal(matches.length, 1, "expected exactly one 'Save encrypted ballot file' action");
    const idx = vote.indexOf("Save encrypted ballot file");
    const before = vote.slice(Math.max(0, idx - 400), idx);
    assert.match(before, /btn btn-primary/);
  });

  it("states the offline next step without overclaiming", () => {
    assert.match(vote, /Deliver the exported ballot file through the election's approved intake\s+method\./);
    assert.doesNotMatch(vote, /vote (has been |is )?(counted|recorded|anchored)/i);
    assert.doesNotMatch(vote, /submitted to Ootle/i);
  });

  it("keeps Rust-only export semantics (native dialog, no-overwrite path forwarding)", () => {
    assert.match(vote, /requestAndExportPreparedBallot\(/);
    assert.match(vote, /api\.exportPreparedVoterBallot\(path\)/);
  });

  it("moves unsupported production transport messaging behind details", () => {
    assert.doesNotMatch(
      vote,
      /<Notice[^>]*>\s*\{transport\.message\}/,
      "backend transport availability message must not render as a prominent notice",
    );
    assert.match(vote, /Transport details/);
    assert.match(vote, /Online private submission is not available in this build\./);
  });
});

// -------------------------------------------------------------------------
// Receipt / INCLUDED / ANCHORED honesty
// -------------------------------------------------------------------------

describe("receipt state honesty", () => {
  it("presents receipt states only from real backend results, never as pending promises", () => {
    // The Vote screen itself never invents INCLUDED/ANCHORED states.
    assert.doesNotMatch(vote, /"INCLUDED"|"ANCHORED"|"RECEIVED"|"ACCEPTED"/);
    // Receipt text comes from the shared helper applied to a backend result.
    assert.match(vote, /receiptStateText\(privateResult\.receipt_state\)/);
  });

  it("keeps voter receipt helpers limited to voter workflow states", () => {
    const helper = readProjectFile("src/voterWorkflow.ts");
    assert.match(helper, /Accepted: the ballot passed election validation/);
    assert.doesNotMatch(receiptStateText("INCLUDED"), /Included:/);
    assert.doesNotMatch(receiptStateText("ANCHORED"), /Anchored:/);
    assert.equal(receiptStateIsAccepted("INCLUDED"), false);
    assert.equal(receiptStateIsAccepted("ANCHORED"), false);
  });

  it("describes organizer aggregate states with a separate helper", () => {
    assert.match(aggregateStateText("INCLUDED"), /aggregate record/);
    assert.match(aggregateStateText("ANCHORED"), /verified FINALIZED archive/);
    assert.doesNotMatch(aggregateStateText("ANCHORED"), /voter transaction/i);
  });
});

// -------------------------------------------------------------------------
// Built-in Guide
// -------------------------------------------------------------------------

describe("built-in guide", () => {
  it("exists as a sidebar destination", () => {
    assert.match(frame, /\{ id: "guide", label: "Guide", group: "Overview" \}/);
    assert.match(app, /\{section === "guide" && <Guide \/>\}/);
    assert.match(app, /guide: "Guide"/);
  });

  it("has an obvious Voter path and an Organizer / Ballot Office path", () => {
    assert.match(guide, /<Card title="Voter">/);
    assert.match(guide, /<Card title="Organizer \/ Ballot Office">/);
  });

  it("warns that the private voting credential must never be shared", () => {
    assert.match(guide, /Never share your private voting credential/);
  });

  it("describes Ootle anchoring as aggregate and organizer-side, not a voter transaction", () => {
    assert.match(guide, /Ootle anchoring is aggregate and organizer-side\./);
    assert.match(guide, /Voters never\s+send an Ootle transaction/);
  });

  it("explains acceptance, inclusion, and anchoring accurately", () => {
    assert.match(guide, /accepted by the organizer/);
    assert.match(guide, /Inclusion and Ootle anchoring are later checked/);
    assert.match(guide, /published archive/);
  });

  it("contains Finalize before Write final archive", () => {
    assert.ok(
      guide.indexOf("Finalize the election") < guide.indexOf("Write the final archive"),
      "Guide must order finalization before final archive writing",
    );
  });

  it("identifies the irreversible organizer actions", () => {
    assert.match(guide, /Freezing is irreversible/);
    assert.match(guide, /Closing is irreversible/);
    assert.match(guide, /Finalizing is irreversible/);
  });

  it("explains bound V2 question semantics without overstating legacy V1 files", () => {
    assert.match(guide, /question and response choices are cryptographically bound/);
    assert.match(guide, /legacy files honestly say when no canonical question exists/);
  });

  it("states the ballot-content privacy limitation without overclaiming", () => {
    assert.match(guide, /Ballot content is not permanently secret\./);
    assert.match(guide, /Network anonymity depends on the submission route/);
    assert.doesNotMatch(guide, /fully anonymous|untraceable|permanently private/i);
  });

  it("documents durable credential recovery and describes private online transport as optional with an offline fallback", () => {
    assert.match(guide, /encrypted credential file or backup plus the\s+passphrase/);
    // The bottom notice describes private online submission as OPTIONAL (Tor can
    // be managed for both roles) with an offline fallback — no stale
    // "experimental / conditionally shown" framing.
    const notice = guide.slice(guide.indexOf("<Notice tone=\"info\">"));
    assert.match(notice, /Private online submission is optional/);
    assert.match(notice, /Offline encrypted\s+ballot-file delivery remains available as a fallback/);
    assert.match(notice, /Tor protects the delivery path/);
    assert.doesNotMatch(notice, /intended finished product/);
    assert.doesNotMatch(notice, /still shown only when the backend reports/);
  });
});

// -------------------------------------------------------------------------
// No frontend-only election question/title field
// -------------------------------------------------------------------------

describe("no frontend-only election question", () => {
  it("adds only the canonical proposal question to the bound voter view model", () => {
    const bound = types.slice(
      types.indexOf("GuiVoterBoundFieldsV1 {"),
      types.indexOf("GuiVoterBoundFieldsV1 {") + 600,
    );
    assert.match(bound, /proposal_question: string \| null/);
    assert.doesNotMatch(bound, /\btitle\b/i);
  });

  it("shows only cryptographically bound question data on the Vote screen", () => {
    assert.match(vote, /confirmation\.bound\.election_id_text \?\? confirmation\.bound\.election_id_hex/);
    assert.match(vote, /confirmation\.bound\.proposal_question/);
    assert.match(vote, /confirmation\.no_proposal_question_notice/);
  });
});

// -------------------------------------------------------------------------
// Participation honesty: hidden never renders as a misleading 0%
// -------------------------------------------------------------------------

describe("hidden participation presentation", () => {
  it("shows a truthful lifecycle-aware sealed label instead of a numeric value", () => {
    // Manage Election derives the sealed label from the REAL lifecycle: the
    // "Hidden while voting is open" wording is truthful only while OPEN;
    // FROZEN says "Voting has not opened yet" and never fabricates a zero.
    assert.match(manage, /sealedParticipationText\(lifecycle\)/);
    assert.match(home, /Hidden while voting is open/);
    // The track takes the label as a prop; the OPEN default is unchanged.
    assert.match(track, /disclosed \? pctLabel : sealedLabel/);
    assert.match(track, /sealedLabel = "Hidden while voting is open"/);
  });

  it("removes the stale present-tense small-electorate message once voting is closed", () => {
    // The present-tense message is gated to the OPEN lifecycle only.
    assert.match(
      manage,
      /small_electorate && !participationSealed && lifecycle === "OPEN"[\s\S]*?live detail is hidden while voting is open\./,
    );
    // After close, the message switches to past tense.
    assert.match(manage, /live detail was hidden while voting was open\./);
    assert.match(home, /live detail was hidden while voting was open\./);
  });

  it("keeps a single period after the policy label", () => {
    assert.doesNotMatch(manage, /Policy\.\./);
    assert.doesNotMatch(home, /Policy\.\./);
  });
});

// -------------------------------------------------------------------------
// Durable election workspace resume
// -------------------------------------------------------------------------

describe("durable election workspace resume", () => {
  it("shows resumable workspaces on Home without internal paths", () => {
    assert.match(home, /Resume Election/);
    assert.match(home, /workspaces\.slice\(0, 5\)/);
    assert.match(home, /workspace\.workspace_id/);
    // Slice 1: the workspace count is a display-only stored-package count
    // (no proof replay), renamed from accepted_ballot_count.
    assert.match(home, /workspace\.stored_ballot_count/);
    assert.match(home, /workspace\.question_preview/);
    assert.match(home, /Recovery state saved locally/);
    assert.doesNotMatch(home, /workspace\.(path|directory|absolute)/);
  });

  it("resumes through the backend-issued public workspace id", () => {
    const workspaceClient = client.slice(
      client.indexOf("listElectionWorkspaces"),
      client.indexOf("openVoting"),
    );
    assert.match(home, /resumeElectionWorkspace\(workspaceId\)/);
    assert.match(home, /onNavigate\?\.\("create"\)/);
    assert.match(home, /onNavigate\?\.\("manage"\)/);
    assert.match(client, /"list_election_workspaces"/);
    assert.match(client, /"resume_election_workspace"/);
    assert.match(tauriShell, /fn list_election_workspaces\(/);
    assert.match(tauriShell, /fn resume_election_workspace\(/);
    assert.doesNotMatch(workspaceClient, /workspacePath|workspace_path|directory/);
  });

  it("does not add voter-choice or workspace state to web storage", () => {
    const stored = [
      ...home.matchAll(/localStorage|sessionStorage/g),
      ...vote.matchAll(/localStorage|sessionStorage/g),
      ...client.matchAll(/localStorage|sessionStorage/g),
    ];
    assert.equal(stored.length, 0);
    assert.doesNotMatch(home, /selectedChoice|selected_choice|ballotChoice|ballot_choice/);
    assert.doesNotMatch(vote, /localStorage\.setItem|sessionStorage\.setItem/);
  });
});

// -------------------------------------------------------------------------
// Export / archive folder error wording
// -------------------------------------------------------------------------

describe("export folder error wording", () => {
  it("titles a refused non-empty export folder accurately", () => {
    const display = describeError({
      code: "GUI_EXPORT_TARGET_NOT_EMPTY",
      category: "FILE_IO",
      context: "export-directory",
      message: "the export target directory already contains files",
    });
    assert.equal(display.title, "Export folder is not empty");
    assert.match(display.message, /new or empty folder/);
    assert.match(display.message, /mixed or overwritten/);
    assert.equal(display.nextStep, "Choose or create a new empty folder, then try again.");
    assert.notEqual(display.title, "File could not be read");
  });

  it("maps a refused non-empty final archive folder to clear repair wording", () => {
    const display = describeError({
      code: "GUI_ARCHIVE_TARGET_NOT_EMPTY",
      category: "FILE_IO",
      context: "archive-directory",
      message: "the archive target directory already contains files",
    });
    assert.equal(display.title, "Folder is not empty");
    assert.match(display.message, /Final archives can only be written to a new or empty folder/);
    assert.match(display.message, /prevents files from different election records/);
    assert.match(display.message, /mixed or overwritten/);
    assert.equal(display.nextStep, "Choose or create a new empty folder, then try again.");
  });
});

// -------------------------------------------------------------------------
// Archive result: scannable top level, rejected ballots kept visible
// -------------------------------------------------------------------------

describe("archive result presentation", () => {
  it("offers a scannable top-level result", () => {
    // Primary top-level result: simple "ARCHIVE VERIFIED" summary with the
    // scannable facts (accepted, rejected, hash, tally, files).
    assert.match(archive, /ARCHIVE VERIFIED/);
    assert.match(archive, /Accepted ballots/);
    assert.match(archive, /Rejected ballots/);
    assert.match(archive, /Archive hash/);
    assert.match(archive, /Tally/);
    assert.match(archive, /Files verified/);
  });

  it("separates archive integrity from election finality", () => {
    // Simple finalized/intermediate wording sits in the top-level summary; the
    // "not eligible for live Ootle anchoring" auditor language moved out with
    // the old "Result at a glance" surface intentionally.
    assert.match(archive, /Finalized election verified/);
    assert.match(archive, /Intermediate archive verified/);
  });

  it("uses finalized archive command for Manage Election archive writes", () => {
    assert.match(manage, /api\.writeFinalizedArchive\(/);
    assert.match(client, /"write_finalized_archive"/);
    assert.match(tauriShell, /fn write_finalized_archive\(/);
    assert.match(tauriShell, /write_finalized_archive_v1_with_governance_document\(/);
    assert.match(tauriShell, /write_finalized_archive,/);
    assert.doesNotMatch(manage, /api\.writeArchiveWithGovernanceDocument\(/);
  });

  it("orders Finalize before Write final archive in Manage Election", () => {
    const finalArchiveCard = manage.slice(manage.indexOf('<Card title="Final archive">'));
    assert.ok(
      finalArchiveCard.indexOf("Finalize") < finalArchiveCard.indexOf("Write final archive"),
      "Manage Election must present Finalize before Write final archive",
    );
  });

  it("shows final archive write errors next to the action without duplicating the global banner", () => {
    assert.match(manage, /const finalArchiveError =/);
    assert.match(
      manage,
      /<BackendErrorNotice error=\{finalArchiveError \? null : localError\}/,
    );
    assert.match(
      manage,
      /<BackendErrorNotice error=\{finalArchiveError \? localError : null\}/,
    );
  });

  it("confirms archive write and separately surfaces anchor-ready verification", () => {
    // The Final archive card presents a distinct terminal "verified" summary
    // (leading the card when a verified archive already exists) AND a
    // write-success surface for the fresh-write path. Both must be present so
    // an organizer sees the right thing whether the archive is a session-fresh
    // write or a recovered verified archive.
    const finalArchiveCard = manage.slice(manage.indexOf('<Card title="Final archive">'));
    // Terminal verified summary: leads the card when a verified archive exists.
    assert.match(finalArchiveCard, /Final archive verified/);
    assert.match(finalArchiveCard, /verifiedFinalArchive\.directory/);
    assert.match(finalArchiveCard, /verifiedFinalArchive\.archive_hash_hex/);
    // Fresh-write success confirmation still appears for the create-new path.
    assert.match(finalArchiveCard, /Final archive written/);
    assert.match(finalArchiveCard, /archiveResult\.directory/);
    assert.match(
      finalArchiveCard,
      /independent\s+verification of the finalized transport binding/,
    );
  });

  it("keeps chooser cancellation harmless for archive and export actions", () => {
    assert.match(manage, /if \(picked !== null\) setArchiveDir\(picked\)/);
    assert.match(archive, /if \(picked !== null\) setDirectory\(picked\)/);
    assert.match(archive, /if \(picked !== null\) setAnchorEvidencePath\(picked\)/);
    const createExport = readProjectFile("src/screens/CreateElection.tsx");
    assert.match(createExport, /if \(!dir\) return/);
  });

  it("surfaces archive_finalized in aggregate anchor verification", () => {
    assert.match(types, /archive_finalized: boolean/);
    assert.match(types, /finalized: boolean/);
    assert.match(types, /transport_accepted_count: number \| null/);
    assert.match(types, /transport_reduced_anonymity: boolean \| null/);
    assert.match(archive, /transportAnchor\.archive_finalized/);
    assert.match(archive, /aggregateStateText\(transportAnchor\.state\)/);
  });

  it("never hides rejected-ballot counts (valid audit evidence)", () => {
    assert.match(archive, /Rejected ballots/);
    assert.match(archive, /result\.rejected_count/);
    assert.match(archive, /never hidden/);
  });
});

// -------------------------------------------------------------------------
// Credential presentation
// -------------------------------------------------------------------------

describe("credential presentation", () => {
  it("collapses to a compact loaded state when the credential is unlocked", () => {
    assert.match(credentialCard, /Credential loaded/);
  });

  it("explains that a new credential cannot join a frozen registry by itself", () => {
    assert.match(credentialCard, /cannot add it to the\s+registry/);
    assert.match(credentialCard, /public enrollment key the organizer enrolled/);
  });

  it("routes visible credential creation through durable commands", () => {
    // Voter credential management no longer appears on Create Election — that
    // is an organizer screen and voter private-credential controls belong on
    // Vote. Assert the durable command is wired on Vote and that Create
    // Election does not render voter-credential controls at all.
    const create = readProjectFile("src/screens/CreateElection.tsx");
    assert.match(credentialCard, /Create credential/);
    assert.match(vote, /api\.createDurableVoterCredential\(passphrase\)/);
    assert.doesNotMatch(vote, /generatePendingVoterGovernanceCredential/);
    assert.doesNotMatch(create, /generatePendingVoterGovernanceCredential/);
    assert.doesNotMatch(create, /VoterCredentialCard/);
    assert.doesNotMatch(create, /Voter credential bootstrap/);
  });
});

describe("finalized archive error wording", () => {
  it("gives GUI_ARCHIVE_NOT_FINALIZED a specific next step", () => {
    const display = describeError({
      code: "GUI_ARCHIVE_NOT_FINALIZED",
      category: "INVALID_LIFECYCLE_TRANSITION",
      context: "archive-directory",
      message: "a finalized archive can only be written from a FINALIZED election",
    });
    assert.equal(display.title, "Election is not finalized");
    assert.equal(
      display.nextStep,
      "Finalize the verified election before writing the final archive.",
    );
  });
});

// -------------------------------------------------------------------------
// Create → Manage lifecycle steering (Phase E)
// -------------------------------------------------------------------------

describe("create election steers to Manage Election", () => {
  const create = readProjectFile("src/screens/CreateElection.tsx");
  it("makes Continue to Manage Election the primary post-freeze action", () => {
    assert.match(create, />\s*Continue to Manage Election\s*</);
    // Open Voting is demoted to a secondary action here; Manage Election is the
    // authoritative lifecycle place.
    assert.match(create, /Manage Election.*lifecycle|lifecycle.*Manage Election/s);
  });
});

// -------------------------------------------------------------------------
// Home local-workspace management: Resume + safe Delete (Phase F)
// -------------------------------------------------------------------------

describe("home workspace resume and delete", () => {
  it("offers Resume and Delete per workspace", () => {
    assert.match(home, />\s*Resume\s*</);
    assert.match(home, />\s*Delete\s*</);
    assert.match(home, /deleteElectionWorkspace\(/);
  });

  it("disables duplicate Resume clicks and shows a busy state", () => {
    assert.match(home, /resumingWorkspaceId/);
    assert.match(home, /if \(resumingWorkspaceId !== null\) return/);
    assert.match(home, /disabled=\{resumingWorkspaceId !== null\}/);
    assert.match(home, /Resuming and verifying election\.\.\./);
    assert.match(home, /role="status"/);
    assert.match(home, /aria-live="polite"/);
  });

  it("guards delete behind an explicit confirmation naming the local workspace", () => {
    assert.match(home, /Delete local election workspace\?/);
    assert.match(home, /removes the local organizer workspace from this device/);
    assert.match(home, /finalized archives outside the app-data workspace are not/);
    assert.match(home, /confirmTone="danger"/);
  });

  it("wires the delete command through the shell with a confined backend", () => {
    assert.match(client, /"delete_election_workspace"/);
    assert.match(tauriShell, /fn delete_election_workspace\(/);
    // The backend refuses to delete the workspace currently loaded in-session.
    assert.match(tauriShell, /GUI_WORKSPACE_DELETE_ACTIVE/);
  });
});

// -------------------------------------------------------------------------
// One-folder election loader with a manual fallback (Phase G)
// -------------------------------------------------------------------------

describe("one-folder election loader", () => {
  it("offers Select Election Folder as the primary Manage Election load flow", () => {
    assert.match(manage, />\s*Select Election Folder\s*</);
    assert.match(manage, /loadElectionFolder\(/);
    // The three-file loader is kept under an Advanced / manual section.
    assert.match(manage, /Advanced \/ manual load/);
    // The picker copy warns not to open the folder first (folder-picker UX fix).
    assert.match(manage, /do not open it first/);
  });

  it("wires the folder command and reuses the shared backend validation", () => {
    assert.match(client, /"load_election_folder"/);
    assert.match(tauriShell, /async fn load_election_folder\(/);
    // No election validation is duplicated in TypeScript; the backend resolves
    // the three canonical files and reuses the shared load path.
    assert.match(tauriShell, /load_election_from_paths_blocking\(/);
    assert.match(tauriShell, /election-manifest\.cbor/);
    assert.match(tauriShell, /GUI_ELECTION_FOLDER_INCOMPLETE/);
  });
});
