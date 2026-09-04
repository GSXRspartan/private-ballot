// Ballot-office connection / distributed lifecycle regression tests.
//
// The physical two-computer test (two-computer-try-03) found a circular voter
// dead end: the FROZEN voter was told to import a signed election status or
// check via the private connection, but BOTH routes authenticate against the
// transport-bundle-pinned ballot-office authority, and the transport-bundle
// picker lived inside the private-submission card, which is gated to
// prepared/CAST_PENDING state. FROZEN -> needs OPEN -> needs pinned authority
// -> needs transport bundle -> hidden until prepared -> needs OPEN. Dead end.
//
// The repair separates BALLOT-OFFICE CONNECTION / LIFECYCLE CONFIGURATION from
// BALLOT SUBMISSION: a dedicated "Ballot office connection" card is visible as
// soon as an election is loaded (independent of guided stage, prepared-ballot
// state, and durable cast state), while the private SUBMISSION card remains
// gated exactly as before.
//
// Where no React harness exists, behavior is pinned by semantic source
// assertions plus direct unit tests of the pure visibility helper; each such
// test is labeled below. Backend invariants are additionally covered
// behaviorally by crates/gui-core/tests/voter_transport_lifecycle.rs.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  ballotOfficeConnectionVisible,
  managedTorCardVisible,
} from "../src/privateSubmission.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const css = readProjectFile("src/styles/global.css");
const guide = readProjectFile("src/screens/Guide.tsx");
const client = readProjectFile("src/api/client.ts");
const dialog = readProjectFile("src/api/dialog.ts");
const statusCommands = readProjectFile("src-tauri/src/election_status_commands.rs");

/** The dedicated connection card's JSX slice (from its marker comment to the
 *  end of its Card element). Used to prove it carries no submission gating. */
function connectionCardSlice(): string {
  const start = vote.indexOf("BALLOT OFFICE CONNECTION");
  assert.ok(start >= 0, "connection card marker comment must exist");
  const end = vote.indexOf("</Card>", start);
  assert.ok(end > start, "connection card must be closed");
  return vote.slice(start, end);
}

// ---------------------------------------------------------------------------
// A/M. Visibility of the connection setup is independent of workflow progress.
// (Behavioral on the pure helper + structural on the call site.)
// ---------------------------------------------------------------------------

describe("ballot-office connection visibility", () => {
  it("is visible for a loaded election with the feature present", () => {
    assert.equal(
      ballotOfficeConnectionVisible({ electionLoaded: true, featurePresent: true }),
      true,
    );
  });

  it("is invisible only when nothing is loaded or the feature is absent", () => {
    assert.equal(
      ballotOfficeConnectionVisible({ electionLoaded: false, featurePresent: true }),
      false,
    );
    assert.equal(
      ballotOfficeConnectionVisible({ electionLoaded: true, featurePresent: false }),
      false,
    );
  });

  it("takes NO prepared/cast/guided inputs at all (dead-end cannot regress)", () => {
    // The helper's input type has exactly two fields: there is no way to gate
    // this card on prepared-ballot or cast state again without changing the
    // contract under test.
    const source = readProjectFile("src/privateSubmission.ts");
    const ifaceStart = source.indexOf("export interface BallotOfficeConnectionVisibilityInput");
    const ifaceEnd = source.indexOf("}", ifaceStart);
    const iface = source.slice(ifaceStart, ifaceEnd);
    assert.match(iface, /electionLoaded: boolean/);
    assert.match(iface, /featurePresent: boolean/);
    assert.doesNotMatch(iface, /prepared|cast|Ready|stage/i);
  });

  it("renders the card outside every guided-stage conditional (source assertion)", () => {
    // The dedicated card must not sit inside the confirmation/stage blocks that
    // collapse during guided mode, and must not consult any presentation gate.
    const card = connectionCardSlice();
    for (const forbidden of [
      "submitStageVisible",
      "showAllSteps",
      "currentStageKey",
      "managedTorCardVisible",
    ]) {
      assert.ok(
        !card.includes(forbidden),
        `connection card must not depend on ${forbidden}`,
      );
    }
    // It renders before the guided stage cards begin.
    const cardStart = vote.indexOf('title="Ballot office connection"');
    const stagesStart = vote.indexOf("{confirmation && (");
    assert.ok(cardStart >= 0 && stagesStart > cardStart, "card precedes guided stages");
  });

  it("the submission card keeps its own separate gating (source assertion)", () => {
    assert.match(
      vote,
      /managedTorCardVisible\(\{\s*featurePresent: managedTorFeaturePresent,[\s\S]*?castState,\s*\}\)\s*&&\s*submitStageVisible\s*&&\s*\(\s*<Card title="Submit your ballot privately">/,
    );
    assert.equal(managedTorCardVisible({ featurePresent: true, preparedReady: false, castState: "NOT_CAST" }), false);
    assert.equal(managedTorCardVisible({ featurePresent: true, preparedReady: true, castState: "NOT_CAST" }), true);
  });
});

// ---------------------------------------------------------------------------
// B/I. Configuration reuses the EXISTING bundle backend path (no parallel
// trust mechanism). (Source assertions on handler wiring.)
// ---------------------------------------------------------------------------

describe("connection setup reuses existing backend calls", () => {
  it("offers Select ballot-office connection file through the existing picker", () => {
    const card = connectionCardSlice();
    assert.match(card, /Select ballot-office connection file/);
    assert.match(vote, /onBrowseVoterBundle[\s\S]*?pickVoterTransportBundle\(\)/);
    assert.match(dialog, /export async function pickVoterTransportBundle/);
  });

  it("configure/connect invoke api.configureManagedTor and api.startManagedTor only", () => {
    const connect = vote.slice(
      vote.indexOf("async function onConnectPrivately"),
      vote.indexOf("async function onBrowseTorExe"),
    );
    assert.match(connect, /api\.configureManagedTor\(torExePath, "", voterBundlePath\)/);
    assert.match(connect, /await api\.startManagedTor\(\)/);
    assert.match(client, /"configure_managed_tor"/);
    assert.match(client, /"start_managed_tor"/);
    // No frontend cryptography/trust logic exists: Rust owns all verification.
    assert.doesNotMatch(vote, /ed25519|verify_strict|SigningKey|nacl|tweetnacl/);
    assert.doesNotMatch(vote, /verify_and_accept_descriptor|descriptor\.verify/);
  });

  it("no clearnet fallback anywhere in the voter screen or pickers", () => {
    assert.doesNotMatch(vote, /http:\/\//);
    assert.doesNotMatch(dialog, /http:\/\//);
    assert.match(vote, /no clearnet fallback exists/);
  });
});

// ---------------------------------------------------------------------------
// C/D/E/K/L + H/G backend invariants pinned at the shell boundary, with the
// behavioral counterparts living in crates/gui-core/tests/.
// ---------------------------------------------------------------------------

describe("lifecycle authority invariants remain intact", () => {
  it("status import stays fail-closed without a trusted authority (G)", () => {
    assert.match(statusCommands, /GUI_ELECTION_STATUS_NO_TRUSTED_AUTHORITY/);
    assert.match(
      statusCommands,
      /configure the ballot-office transport bundle first/,
    );
    // Trust comes ONLY from the configured anchor or a persisted acceptance.
    assert.match(statusCommands, /configured_transport_root_anchor/);
  });

  it("private status check requires the configured running connection (H)", () => {
    const fetchFn = statusCommands.slice(
      statusCommands.indexOf("pub async fn fetch_election_status_private"),
      statusCommands.length,
    );
    assert.match(fetchFn, /running_transport_endpoint/);
    assert.match(fetchFn, /GUI_ELECTION_STATUS_NO_PRIVATE_CONNECTION/);
  });

  it("bundle configuration stays election-bound and organizer commands stay gated (K/L)", () => {
    const managedTor = readProjectFile("src-tauri/src/managed_tor.rs");
    assert.match(managedTor, /GUI_VOTER_BUNDLE_WRONG_ELECTION/);
    assert.match(managedTor, /verify_and_accept_descriptor/);
    // Configure never mutates the voter session (existing invariant, restated).
    const start = managedTor.indexOf("pub fn configure_managed_tor");
    const body = managedTor.slice(start, managedTor.indexOf("\n}", start));
    assert.doesNotMatch(
      body,
      /state\.voter|set_selection|prepare_ballot|discard_prepared|generate_credential/,
    );
  });
});

// ---------------------------------------------------------------------------
// FROZEN lifecycle-update reachability before preparation (H).
// ---------------------------------------------------------------------------

describe("FROZEN lifecycle updates reachable before preparation", () => {
  it("connection card offers both lifecycle routes while FROZEN", () => {
    const card = connectionCardSlice();
    assert.match(card, /Check whether voting has opened/);
    assert.match(card, /Import signed election status…/);
    assert.match(card, /void onImportElectionStatus\(\)/);
    assert.match(card, /Check via private connection/);
    assert.match(card, /void onFetchElectionStatusPrivate\(\)/);
    // The private check enables purely on configuration — no prepared/cast
    // condition appears on that button inside the connection card.
    const checkIdx = card.indexOf("Check via private connection");
    const buttonStart = card.lastIndexOf("<button", checkIdx);
    const disabledAttr = card.slice(buttonStart, checkIdx);
    assert.match(disabledAttr, /statusImportBusy \|\| !managedTorStatus\?\.configured/);
    assert.doesNotMatch(disabledAttr, /prepared|cast/i);
  });

  it("both lifecycle routes share ONE handler pair (no duplicated trust decision)", () => {
    const occurrences = vote.match(/void onFetchElectionStatusPrivate\(\)/g) ?? [];
    assert.ok(occurrences.length >= 2, "notice + connection card reuse the same handler");
    assert.equal((vote.match(/async function onFetchElectionStatusPrivate/g) ?? []).length, 1);
    assert.equal((vote.match(/async function onImportElectionStatus/g) ?? []).length, 1);
  });
});

// ---------------------------------------------------------------------------
// O. Election-folder primary loader on the Vote screen reuses the shared
// backend one-folder loader. (Source assertions.)
// ---------------------------------------------------------------------------

describe("voter election-folder primary loader", () => {
  it("makes Select Election Folder the primary load action", () => {
    const loadCard = vote.slice(
      vote.indexOf('<Card title="Load Election">'),
      vote.indexOf("</Card>", vote.indexOf('<Card title="Load Election">')),
    );
    assert.match(loadCard, />\s*Select Election Folder\s*</);
    assert.match(loadCard, /className="btn btn-primary"[\s\S]*?onVoterLoadElectionFolder/);
    assert.match(vote, /do not open it/);
  });

  it("routes through the SAME AppState/backend folder command, no second validator", () => {
    const handler = vote.slice(
      vote.indexOf("async function onVoterLoadElectionFolder"),
      vote.indexOf("async function loadConfirmation"),
    );
    assert.match(handler, /pickDirectory\(/);
    assert.match(handler, /await loadElectionFolder\(folder\)/);
    assert.doesNotMatch(handler, /api\.loadElection\(|from_bytes|validate/);
    // The backend command resolves canonical files and shares the load path.
    assert.match(client, /"load_election_folder"/);
    const tauriShell = readProjectFile("src-tauri/src/lib.rs");
    assert.match(tauriShell, /async fn load_election_folder\(/);
    assert.match(tauriShell, /load_election_from_paths_blocking\(/);
  });

  it("keeps individual file selection as a manual fallback disclosure", () => {
    const loadCard = vote.slice(
      vote.indexOf('<Card title="Load Election">'),
      vote.indexOf("</Card>", vote.indexOf('<Card title="Load Election">')),
    );
    assert.match(loadCard, /Manual file selection \(three files\)/);
    assert.match(loadCard, />\s*Load Election\s*</);
  });
});

// ---------------------------------------------------------------------------
// P/Q. Wide-window layout root cause stays fixed structurally.
// ---------------------------------------------------------------------------

describe("wide-window Vote-screen layout", () => {
  it("verified-election field-list contains ONLY Field rows (no stray prose)", () => {
    const cardStart = vote.indexOf("<Card title={BOUND_SECTION_LABEL}>");
    assert.ok(cardStart >= 0, "verified details card exists");
    const gridStart = vote.indexOf('<div className="field-list">', cardStart);
    const gridEnd = vote.indexOf("</div>", gridStart);
    const grid = vote.slice(gridStart, gridEnd);
    assert.match(grid, /<Field label="Election">/);
    assert.match(grid, /<Field label="Ballot question">/);
    assert.match(grid, /<Field label="How many to choose">/);
    assert.doesNotMatch(grid, /<Notice/);
    // The lifecycle notices still exist — just OUTSIDE the grid now.
    assert.match(vote, /Voting has not opened yet\./);
  });

  it("keeps the value-majority grid template and adds the stray-child guard", () => {
    assert.match(css, /grid-template-columns: minmax\(7\.5rem, max-content\) minmax\(0, 1fr\);/);
    assert.match(css, /\.field-list > :not\(\.field-label\):not\(\.field-value\)/);
    const guard = css.slice(css.indexOf(".field-list > :not(.field-label)"));
    assert.match(guard, /grid-column: 1 \/ -1;/);
  });

  it("narrow breakpoints still stack and wrap appropriately", () => {
    assert.match(css, /@media \(max-width: 44rem\)[\s\S]*?minmax\(6\.5rem, max-content\) minmax\(0, 1fr\)/);
    assert.match(css, /@media \(max-width: 34rem\)/);
    // Centering cap unchanged: useful width, centered, not full-bleed.
    assert.match(css, /max-width: 72rem/);
  });
});

// ---------------------------------------------------------------------------
// R. Guide content: prerequisite, both lifecycle paths, distinctions, and no
// mandatory signed-status-file claim.
// ---------------------------------------------------------------------------

describe("guide covers the distributed lifecycle flow", () => {
  it("explains the ballot-office connection prerequisite before checking open", () => {
    assert.match(guide, /Receive the ballot-office connection file/);
    assert.match(guide, /pinned ballot-office\s+authority|pins the public key of the office/s);
  });

  it("presents private check AND signed-status import as equivalent alternatives", () => {
    assert.match(guide, /check through your private connection/);
    assert.match(guide, /import a signed election-status file/);
    assert.match(guide, /You do not need both/);
  });

  it("never claims importing a signed status file is mandatory for all voters", () => {
    assert.doesNotMatch(guide, /must import a signed/);
    assert.match(guide, /not a requirement for every voter/);
  });

  it("distinguishes network privacy, eligibility anonymity, and office authentication", () => {
    assert.match(guide, /Tor[\s\S]{0,200}network metadata/);
    assert.match(guide, /Triptych-style proof hides which eligible/);
    assert.match(guide, /pinned ballot-office[\s\S]*?authenticates/);
    assert.doesNotMatch(guide, /Tor alone provides voting anonymity/);
  });

  it("keeps receipt-vs-archive honesty and optional aggregate organizer-side anchoring", () => {
    assert.match(guide, /does not by itself claim final archive inclusion/);
    assert.match(guide, /aggregate[\s\S]*?organizer-side/);
    assert.match(guide, /Voters never\s+send an Ootle transaction/);
  });

  it("organizer steps cover intake, bundle export, open, and offline signed statuses", () => {
    assert.match(guide, /Start private intake/);
    assert.match(guide, /Share the frozen election\s+files together with the voter-safe transport bundle/);
    assert.match(guide, /check the current state privately/);
    assert.match(guide, /signed election status statement/);
    assert.match(guide, /offline\/manual alternative/);
  });

  it("Vote mini-guide includes the connection + status step and it precedes ballot creation", () => {
    // The Guide-aligned mini-guide folds "learn when OPEN" into the
    // "Configure the ballot-office connection and check status" step, so
    // configuring the pinned authority necessarily happens before creating
    // and submitting a ballot.
    const connectStep = vote.indexOf("Configure the ballot-office connection and check status.");
    const submitStep = vote.indexOf("Create and submit your anonymous ballot.");
    assert.ok(connectStep >= 0, "mini-guide has a connection + status step");
    assert.ok(submitStep > connectStep, "ballot creation comes after configuring");
  });
});
