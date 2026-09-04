// Branding, plain-language, and GUI-polish regression tests (pre-5A13 pass).
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Where no React harness exists, GUI behaviors are pinned by semantic
// source assertions (identifiable elements and attributes), never by
// fragile pixel analysis.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import {
  APP_IDENTITY_TAG,
  APP_NAME,
  APP_VERSION,
  COMMUNITY_DISCLAIMER,
} from "../src/branding/identity.ts";
import { describeError } from "../src/api/errorDisplay.ts";
import {
  aggregateStateText,
  receiptStateIsAccepted,
  receiptStateText,
} from "../src/voterWorkflow.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

// -------------------------------------------------------------------------
// Emblem assets: the exact approved artwork, never redrawn
// -------------------------------------------------------------------------

describe("emblem assets", () => {
  const emblemAssets = [
    "public/private-ballot-logo-dark.png",
    "public/private-ballot-logo-light.png",
    "public/private-ballot-mark-dark.png",
    "public/private-ballot-mark-light.png",
    "design/private-ballot-logo-reference.png",
    "design/private-ballot-icon-1024.png",
  ];

  it("ships the exact logo artwork and crops derived directly from it", () => {
    for (const asset of emblemAssets) {
      assert.ok(
        existsSync(new URL(`../${asset}`, import.meta.url)),
        `${asset} is missing`,
      );
    }
  });

  it("renders the exact artwork via <img>, never redrawn vector art", () => {
    const component = readProjectFile("src/branding/PrivateBallotEmblem.tsx");
    assert.match(component, /<img/);
    assert.match(component, /private-ballot-logo-/);
    assert.match(component, /private-ballot-mark-/);
    // No redrawn/reinterpreted geometry may come back.
    assert.ok(!component.includes("<svg"), "component redraws the emblem");
    assert.ok(!component.includes("<circle"), "component redraws the emblem");
    assert.equal(
      existsSync(new URL("../src/branding/emblem.ts", import.meta.url)),
      false,
      "redrawn emblem geometry module still exists",
    );
    assert.equal(
      existsSync(new URL("../src/branding/emblemSvg.ts", import.meta.url)),
      false,
      "redrawn emblem SVG builder still exists",
    );
  });

  it("uses the emblem component in the header and About branding areas", () => {
    assert.match(readProjectFile("src/components/AppFrame.tsx"), /PrivateBallotEmblem/);
    assert.match(readProjectFile("src/screens/About.tsx"), /PrivateBallotEmblem/);
  });
});

// -------------------------------------------------------------------------
// Public product identity
// -------------------------------------------------------------------------

describe("public product identity", () => {
  it("keeps the product name primary and the qualifier separate", () => {
    assert.equal(APP_NAME, "Private Ballot");
    assert.equal(APP_IDENTITY_TAG, "Independent Open-Source Project");
    assert.match(
      COMMUNITY_DISCLAIMER,
      /independent open-source project.*not affiliated with or endorsed by Tari Labs/i,
    );
  });

  it("keeps the frontend version in step with package.json", () => {
    const pkg = JSON.parse(readProjectFile("package.json"));
    assert.equal(APP_VERSION, pkg.version);
  });

  it("no longer uses the official Tari logo as application identity", () => {
    assert.equal(
      existsSync(new URL("../src/branding/TariLogo.tsx", import.meta.url)),
      false,
    );
    for (const file of ["src/components/AppFrame.tsx", "src/screens/About.tsx"]) {
      assert.ok(!readProjectFile(file).includes("TariLogo"), `${file} references TariLogo`);
    }
  });

  it("retains legitimate textual Tari ecosystem references", () => {
    const about = readProjectFile("src/screens/About.tsx");
    assert.match(about, /Tari ecosystem/);
    assert.match(about, /Tari Triptych/);
    assert.match(readProjectFile("src/styles/global.css"), /Tari/);
  });

  it("shows the Independent Open-Source Project subtitle in the header and About", () => {
    for (const file of [
      "src/components/AppFrame.tsx",
      "src/screens/About.tsx",
    ]) {
      assert.ok(
        readProjectFile(file).includes("APP_IDENTITY_TAG"),
        `${file} does not present the Independent Open-Source Project qualifier`,
      );
    }
  });

  it("does not repeat the full branding lockup in the Home empty state", () => {
    const home = readProjectFile("src/screens/Home.tsx");
    // The app header already carries the emblem + name + subtitle lockup;
    // the Home empty state focuses on the user's next task instead.
    assert.ok(!home.includes("APP_IDENTITY_TAG"), "Home repeats the subtitle");
    assert.ok(!home.includes("PrivateBallotEmblem"), "Home repeats the emblem");
    assert.match(home, /No election loaded/);
    assert.match(home, /Load an election shared by an organizer/);
    assert.match(home, /Load Election/);
    assert.match(home, /Create Election/);
  });

  it("keeps the native window title free of the subtitle qualifier", () => {
    const config = JSON.parse(readProjectFile("src-tauri/tauri.conf.json"));
    assert.equal(config.app.windows[0].title, "Private Ballot");
  });
});

// -------------------------------------------------------------------------
// Sidebar visual hierarchy (section labels vs clickable items)
// -------------------------------------------------------------------------

describe("sidebar visual hierarchy", () => {
  const css = readProjectFile("src/styles/global.css");

  it("styles section headings as small, muted, uppercase labels", () => {
    const group = css.match(/\.nav-group\s*\{[^}]*\}/);
    assert.ok(group, "missing .nav-group rule");
    assert.match(group[0], /text-transform:\s*uppercase/);
    assert.match(group[0], /letter-spacing/);
    assert.match(group[0], /color:\s*var\(--text-secondary\)/);
    assert.match(group[0], /font-size:\s*0\.6875rem/);
  });

  it("gives the selected navigation item a non-color-only selected state", () => {
    const selected = css.match(/\.nav-item\[aria-current="page"\]\s*\{[^}]*\}/);
    assert.ok(selected, "missing selected nav-item rule");
    assert.match(selected[0], /font-weight:\s*600/);
    assert.match(selected[0], /box-shadow:\s*inset 3px 0 0 0/, "no left accent bar");
    assert.match(selected[0], /background:\s*var\(--accent-bg\)/);
  });

  it("keeps navigation behavior unchanged (buttons, aria-current)", () => {
    const frame = readProjectFile("src/components/AppFrame.tsx");
    assert.match(frame, /aria-current=\{section === item\.id \? "page" : undefined\}/);
    assert.match(frame, /onClick=\{\(\) => onNavigate\(item\.id\)\}/);
  });
});

// -------------------------------------------------------------------------
// Production CSP pin (must remain unchanged by this pass)
// -------------------------------------------------------------------------

describe("production CSP", () => {
  it("is unchanged", () => {
    const config = JSON.parse(readProjectFile("src-tauri/tauri.conf.json"));
    assert.equal(
      config.app.security.csp,
      "default-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' data:; style-src 'self'; font-src 'self'; script-src 'self'",
    );
  });
});

// -------------------------------------------------------------------------
// GUI behavior pins (semantic source assertions)
// -------------------------------------------------------------------------

describe("startup and navigation error behavior", () => {
  it("treats no-active-election as a normal state, not a red error", () => {
    const state = readProjectFile("src/state/AppState.tsx");
    assert.match(state, /GUI_NO_ACTIVE_ELECTION/);
    assert.match(state, /NORMAL application state/);
  });

  it("clears stale errors on navigation", () => {
    const app = readProjectFile("src/App.tsx");
    assert.match(app, /dismissError\(\)/);
  });

  it("shows only one no-election status in the header", () => {
    const frame = readProjectFile("src/components/AppFrame.tsx");
    // The lifecycle pill is rendered only inside the loaded-election branch.
    assert.match(frame, /\{election \? \(/);
    assert.ok(!frame.includes("election?.lifecycle_state ?? null"));
    assert.match(frame, /No election loaded/);
  });
});

describe("voter-facing load election", () => {
  it("gives the Vote screen its own Load Election action reusing the shared loader", () => {
    const vote = readProjectFile("src/screens/Vote.tsx");
    assert.match(vote, /loadElection\(loadManifestPath, loadRegistryPath, loadOptionSetPath\)/);
    assert.match(vote, /Load Election/);
  });
});

describe("error presentation", () => {
  it("keeps diagnostic codes available under Technical details", () => {
    const ui = readProjectFile("src/components/ui.tsx");
    assert.match(ui, /Technical details/);
    assert.match(ui, /Error code/);
  });

  it("provides a plain-language next step for every known category", () => {
    const categories = [
      "INVALID_INPUT",
      "UNSUPPORTED_FORMAT",
      "BINDING_MISMATCH",
      "PROOF_FAILURE",
      "DUPLICATE_BALLOT",
      "INVALID_LIFECYCLE_TRANSITION",
      "ARCHIVE_INTEGRITY",
      "FILE_IO",
      "ANCHOR_ARTIFACT_INTEGRITY",
      "UNAVAILABLE",
      "SOMETHING_ELSE",
    ];
    for (const category of categories) {
      const display = describeError({
        code: "GUI_TEST",
        category,
        context: null,
        message: "bounded message",
      });
      assert.ok(display.title.length > 0);
      assert.ok(display.nextStep.length > 0, `no next step for ${category}`);
      assert.equal(display.code, "GUI_TEST");
      assert.equal(display.category, category);
    }
  });
});

describe("close voting confirmation", () => {
  it("requires explicit confirmation styled as irreversible", () => {
    const manage = readProjectFile("src/screens/ManageElection.tsx");
    assert.match(manage, /Close voting\?/);
    assert.match(manage, /This cannot be undone/);
    assert.match(manage, /confirmTone="danger"/);
    assert.match(manage, /ConfirmDialog/);
  });
});

describe("developer diagnostics footer", () => {
  it("hides technical footer details unless diagnostics are enabled", () => {
    const frame = readProjectFile("src/components/AppFrame.tsx");
    assert.match(frame, /settings\.devDiagnostics && \(/);
    assert.match(frame, /APP_VERSION/);
  });
});

describe("theme switching", () => {
  it("keeps automatic, light, and dark theme options", () => {
    const settings = readProjectFile("src/screens/Settings.tsx");
    assert.match(settings, /value: "system"/);
    assert.match(settings, /value: "light"/);
    assert.match(settings, /value: "dark"/);
  });

  it("does not claim contrast certification", () => {
    const settings = readProjectFile("src/screens/Settings.tsx");
    assert.doesNotMatch(settings, /contrast-checked/i);
  });
});

// -------------------------------------------------------------------------
// Submission receipt states (never collapsed into one generic success)
// -------------------------------------------------------------------------

describe("submission status wording", () => {
  it("explains each receipt state in ordinary language", () => {
    assert.match(receiptStateText("RECEIVED"), /reached the transport system/);
    assert.match(receiptStateText("ACCEPTED"), /passed election validation/);
    assert.match(receiptStateText("REJECTED"), /not accepted/);
    assert.match(receiptStateText("OFFLINE_EXPORT"), /no online submission/);
  });

  it("keeps voter receipts separate from aggregate archive states", () => {
    assert.equal(receiptStateIsAccepted("INCLUDED"), false);
    assert.equal(receiptStateIsAccepted("ANCHORED"), false);
    assert.doesNotMatch(receiptStateText("INCLUDED"), /finalized election record/);
    assert.doesNotMatch(receiptStateText("ANCHORED"), /anchor evidence/);
    assert.match(aggregateStateText("INCLUDED"), /aggregate record/);
    assert.match(aggregateStateText("ANCHORED"), /verified FINALIZED archive/);
    assert.doesNotMatch(aggregateStateText("ANCHORED"), /voter transaction/i);
  });

  it("distinguishes accepted states from in-progress ones", () => {
    assert.equal(receiptStateIsAccepted("ACCEPTED"), true);
    assert.equal(receiptStateIsAccepted("RECEIVED"), false);
    assert.equal(receiptStateIsAccepted("REJECTED"), false);
    assert.equal(receiptStateIsAccepted("OFFLINE_EXPORT"), false);
  });
});

// -------------------------------------------------------------------------
// Privacy wording accuracy
// -------------------------------------------------------------------------

describe("privacy wording", () => {
  it("never claims permanent ballot secrecy on the Vote screen", () => {
    const vote = readProjectFile("src/screens/Vote.tsx");
    assert.match(vote, /without revealing which eligible voter you are/);
    assert.match(vote, /not\s+permanently sealed/);
    assert.doesNotMatch(vote, /permanently secret/i);
    assert.doesNotMatch(vote, /coercion.resistan/i);
  });
});

// -------------------------------------------------------------------------
// Final polish pass (page lede width, plain wording, prerequisites, pickers)
// -------------------------------------------------------------------------

describe("page lede width", () => {
  it("lets the lede use the natural content width (no narrow cap)", () => {
    const css = readProjectFile("src/styles/global.css");
    const lede = css.match(/\.screen-lede\s*\{[^}]*\}/);
    assert.ok(lede, "missing .screen-lede rule");
    assert.doesNotMatch(lede[0], /max-width/, "lede still has a narrow max-width");
  });
});

describe("theme toggle action wording", () => {
  it("states the action, not the current state", () => {
    const frame = readProjectFile("src/components/AppFrame.tsx");
    assert.match(frame, /Switch to light/);
    assert.match(frame, /Switch to dark/);
    assert.doesNotMatch(frame, />Light theme</);
    assert.doesNotMatch(frame, />Dark theme</);
  });
});

describe("plain-language election file labels", () => {
  for (const file of ["src/screens/ManageElection.tsx", "src/screens/Vote.tsx"]) {
    it(`${file} uses plain primary labels`, () => {
      const source = readProjectFile(file);
      assert.match(source, /Election definition/);
      assert.match(source, /Eligible voter list/);
      assert.match(source, /Ballot options/);
      // Manifest/registry terminology stays under Technical details only.
      assert.doesNotMatch(source, />Election definition \(manifest\)</);
      assert.doesNotMatch(source, />Eligible voter list \(registry\)</);
      assert.doesNotMatch(source, />Election manifest</);
      assert.doesNotMatch(source, />Voter registry</);
    });

    it(`${file} uses the Browse-style file picker presentation`, () => {
      const source = readProjectFile(file);
      assert.doesNotMatch(source, /Choose file</);
      assert.match(source, /Browse/);
    });
  }
});

describe("prerequisite guidance", () => {
  it("explains why Manage Election controls are unavailable before loading", () => {
    const manage = readProjectFile("src/screens/ManageElection.tsx");
    assert.match(manage, /Load an election to enable these controls\./);
    // The manual three-file loader now lives under Advanced; the folder loader
    // is the primary path.
    assert.match(manage, /Choose all three election files to load manually\./);
    assert.match(manage, />\s*Select Election Folder\s*</);
  });

  it("explains missing-file prerequisites on Vote, Archive, Anchor, and Evidence", () => {
    assert.match(
      readProjectFile("src/screens/Vote.tsx"),
      /Choose all required election files to continue\./,
    );
    assert.match(readProjectFile("src/screens/Archive.tsx"), /Choose an archive directory/);
    assert.match(
      readProjectFile("src/screens/Anchor.tsx"),
      /Choose an anchor config file to continue\./,
    );
    assert.match(
      readProjectFile("src/screens/Evidence.tsx"),
      /Choose an evidence file to continue\./,
    );
  });
});

describe("plain primary wording", () => {
  it("keeps the archive anchor check understandable", () => {
    // Current V2 anchor status is auto-hydrated and shown as "Anchored ·
    // Verified" / neutral / recovery states. The legacy CBOR path is now
    // under Advanced with a clearly-labelled legacy action.
    const archive = readProjectFile("src/screens/Archive.tsx");
    assert.match(archive, /Anchored · Verified|Ootle anchor/);
    assert.match(archive, /Check legacy V1 anchor record/);
    assert.doesNotMatch(archive, /Final transport anchor/);
  });

  it("keeps the Evidence intro nontechnical", () => {
    const evidence = readProjectFile("src/screens/Evidence.tsx");
    assert.match(
      evidence,
      /links this election archive to its Ootle anchor record/,
    );
    assert.match(evidence, /does not determine or change the election result/);
  });

  it("keeps the Home intro free of permanent-secrecy implications", () => {
    const home = readProjectFile("src/screens/Home.tsx");
    assert.match(home, /without revealing which voter\s+cast a ballot/);
    assert.match(home, /can be independently verified/);
    assert.match(home, /does not determine the result/);
    assert.doesNotMatch(home, /permanently/i);
  });

  it("keeps the ballot-type and governance-source explanations plain", () => {
    const create = readProjectFile("src/screens/CreateElection.tsx");
    assert.match(create, /the voting and verification rules\s+stay the same/);
    assert.match(create, /The election files are the source of truth/);
  });
});
