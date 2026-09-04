// Guide workflow-diagram regression tests. The overview at the top of the
// Guide is now a theme-matched raster PNG (dark/light) with a click-to-enlarge
// lightbox; the previous inline WorkflowDiagram SVG is gone.
//
// These tests run under Node's built-in test runner with TypeScript type
// stripping and read the source files as text (no browser DOM).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

function projectPath(path: string): string {
  return fileURLToPath(new URL(`../${path}`, import.meta.url));
}
function readProjectFile(path: string): string {
  return readFileSync(projectPath(path), "utf8");
}

const guide = readProjectFile("src/screens/Guide.tsx");
const css = readProjectFile("src/styles/global.css");
const home = readProjectFile("src/screens/Home.tsx");

// -------------------------------------------------------------------------
// Theme-matched image pair (dark/light PNGs)
// -------------------------------------------------------------------------

describe("guide workflow diagram uses theme-matched PNG assets", () => {
  it("has both replacement image files on disk", () => {
    for (const asset of [
      "src/assets/guide/private-ballot-flow-dark-updated.png",
      "src/assets/guide/private-ballot-flow-light-updated.png",
    ]) {
      const p = projectPath(asset);
      assert.ok(existsSync(p), `missing asset: ${asset}`);
      assert.ok(statSync(p).size > 1024, `asset appears empty: ${asset}`);
    }
  });

  it("imports the dark and light PNGs from the guide assets folder", () => {
    assert.match(
      guide,
      /import\s+flowDiagramDarkUrl\s+from\s+["']\.\.\/assets\/guide\/private-ballot-flow-dark-updated\.png["']/,
    );
    assert.match(
      guide,
      /import\s+flowDiagramLightUrl\s+from\s+["']\.\.\/assets\/guide\/private-ballot-flow-light-updated\.png["']/,
    );
  });

  it("selects the image from the active theme (dark => dark, light => light)", () => {
    assert.match(guide, /useTheme\s*\(\s*\)/);
    assert.match(
      guide,
      /resolved\s*===\s*"dark"\s*\?\s*flowDiagramDarkUrl\s*:\s*flowDiagramLightUrl/,
    );
  });

  it("renders the diagram as an <img>, not an inline SVG", () => {
    assert.match(guide, /<img[^>]*className="guide-flow-image"/);
    assert.doesNotMatch(guide, /<svg[^>]*className="guide-flow-diagram"/);
  });

  it("removed the obsolete WorkflowDiagram / FlowStep / FlowArrow components", () => {
    assert.doesNotMatch(guide, /WorkflowDiagram/);
    assert.doesNotMatch(guide, /\bFlowStep\b/);
    assert.doesNotMatch(guide, /\bFlowArrow\b/);
    assert.doesNotMatch(guide, /guide-arrowhead/);
  });

  it("removed the obsolete inline-SVG CSS classes", () => {
    for (const cls of [
      ".guide-flow-lane-heading",
      ".guide-flow-legend",
      ".guide-flow-title",
      ".guide-flow-body",
      ".guide-flow-arrow",
      ".guide-flow-box",
      ".guide-flow-box--office",
      ".guide-flow-box--voter",
      ".guide-flow-box--anchor",
      ".guide-flow-box--terminal",
    ]) {
      assert.ok(!css.includes(cls), `stale SVG-only CSS rule kept: ${cls}`);
    }
  });
});

// -------------------------------------------------------------------------
// Accessibility: figure has an accessible name, and the image carries the
// specified plain-language alt text.
// -------------------------------------------------------------------------

describe("guide workflow diagram accessibility", () => {
  it("uses the specified plain-language alt text", () => {
    const alt = guide.match(/const FLOW_DIAGRAM_ALT =([\s\S]*?);/);
    assert.ok(alt, "missing FLOW_DIAGRAM_ALT constant");
    assert.match(alt[1], /How Private Ballot works/);
    assert.match(alt[1], /organizer setup/);
    assert.match(alt[1], /private voter flow/);
    assert.match(alt[1], /archive verification/);
    assert.match(alt[1], /Tari Ootle anchoring/);
    assert.match(guide, /alt=\{FLOW_DIAGRAM_ALT\}/);
  });

  it("figure has an accessible workflow-overview label", () => {
    assert.match(guide, /aria-label="Workflow overview"/);
  });
});

// -------------------------------------------------------------------------
// Sizing: image is responsive, preserves aspect ratio, cannot overflow.
// -------------------------------------------------------------------------

describe("guide workflow diagram sizing", () => {
  it("uses a responsive image rule (width 100%, max-width 100%, height auto)", () => {
    const rule = css.match(/\.guide-flow-image\s*\{[^}]*\}/);
    assert.ok(rule, "missing .guide-flow-image rule");
    assert.match(rule[0], /width:\s*100%/);
    assert.match(rule[0], /max-width:\s*100%/);
    assert.match(rule[0], /height:\s*auto/);
  });

  it("keeps the wide, symmetric-breakout wrapper (min()/calc, margin/translate)", () => {
    const rule = css.match(/\.guide-flow\s*\{[^}]*\}/);
    assert.ok(rule, "missing .guide-flow rule");
    assert.match(rule[0], /width:\s*min\(/);
    assert.match(rule[0], /calc\(100vw\s*-\s*var\(--nav-width\)/);
    assert.match(rule[0], /margin-inline:\s*50%/);
    assert.match(rule[0], /transform:\s*translateX\(-50%\)/);
  });
});

// -------------------------------------------------------------------------
// Click-to-enlarge lightbox
// -------------------------------------------------------------------------

describe("guide diagram click-to-enlarge lightbox", () => {
  it("wraps the image in a button that opens the lightbox", () => {
    assert.match(guide, /<button[^>]*className="guide-flow-trigger"/);
    assert.match(guide, /onClick=\{openLightbox\}/);
    assert.match(guide, /aria-label="Enlarge workflow diagram"/);
  });

  it("renders a GuideDiagramLightbox when lightboxOpen is true", () => {
    assert.match(guide, /function GuideDiagramLightbox\(/);
    assert.match(guide, /\{lightboxOpen && \(\s*<GuideDiagramLightbox/);
  });

  it("lightbox is a modal dialog with an accessible name", () => {
    assert.match(guide, /role="dialog"/);
    assert.match(guide, /aria-modal="true"/);
    assert.match(guide, /aria-label="Workflow diagram"/);
  });

  it("Escape and the Close button both dismiss the lightbox", () => {
    // Escape wiring inside GuideDiagramLightbox.
    assert.match(guide, /event\.key === "Escape"/);
    assert.match(guide, /onClose\(\)/);
    // Visible Close button.
    assert.match(guide, />\s*Close\s*</);
  });

  it("clicking the backdrop closes the lightbox; clicking the image does not", () => {
    assert.match(
      guide,
      /className="guide-lightbox-backdrop"[\s\S]*?onClick=\{onClose\}/,
    );
    assert.match(guide, /onClick=\{\(event\) => event\.stopPropagation\(\)\}/);
  });

  it("lightbox image is sized to fit the viewport while preserving aspect ratio", () => {
    const rule = css.match(/\.guide-lightbox-image\s*\{[^}]*\}/);
    assert.ok(rule, "missing .guide-lightbox-image rule");
    assert.match(rule[0], /max-width:\s*100%/);
    assert.match(rule[0], /max-height:/);
    assert.match(rule[0], /object-fit:\s*contain/);
  });
});

// -------------------------------------------------------------------------
// Placement and privacy callout — the surrounding Guide continues to be the
// detailed authoritative how-to underneath the visual overview.
// -------------------------------------------------------------------------

describe("guide workflow diagram placement", () => {
  it("sits near the top, before the detailed role sections", () => {
    const lede = guide.indexOf("screen-lede");
    const figure = guide.indexOf('<figure className="guide-flow"');
    const voterCard = guide.indexOf('title="Voter"');
    assert.ok(lede >= 0 && figure > lede, "figure must follow the lede");
    assert.ok(voterCard > figure, "figure must precede the detailed sections");
  });
});

describe("guide workflow diagram privacy callout", () => {
  it("says individual votes are never published to Tari Ootle", () => {
    assert.match(guide, /Individual votes are never published to Tari Ootle/);
    assert.match(guide, /independently verified offline archive is authoritative/i);
    assert.match(guide, /Anchoring on Ootle is\s*optional and non-binding/i);
  });

  it("keeps the existing detailed Guide sections", () => {
    assert.match(guide, /title="Voter"/);
    assert.match(guide, /title="Organizer \/ Ballot Office"/);
    assert.match(guide, /title="Privacy and safety"/);
  });

  it("does not overstate privacy", () => {
    assert.doesNotMatch(guide, /votes are secret end-to-end/i);
    assert.doesNotMatch(guide, /nobody can ever see your vote/i);
  });
});

// -------------------------------------------------------------------------
// Credential-model wording accuracy
// -------------------------------------------------------------------------

describe("guide credential-model wording", () => {
  it("never says the organizer or ballot office generates private voter credentials", () => {
    assert.doesNotMatch(
      guide,
      /(organizer|ballot office)[^.]{0,80}(generate|creates?|makes?|issues?|sends?|distributes?)[^.]{0,80}(private )?(voter )?credentials?/i,
    );
    assert.doesNotMatch(
      guide,
      /(send|give)s? (the )?voters? (their |the )?(private )?credentials?/i,
    );
    assert.doesNotMatch(guide, /credential bootstrap/i);
  });

  it("states the correct model: voter keeps the credential, organizer enrolls public keys", () => {
    assert.match(guide, /Give the organizer only your public\s+enrollment key/);
    assert.match(guide, /You never handle voters' private credentials/);
    assert.match(guide, /Enroll eligible voters/);
    assert.match(guide, /public/);
  });
});

// -------------------------------------------------------------------------
// Presentation-only: the Guide still calls no backend commands and stores no
// secret material. (Lightbox open state is transient local UI only.)
// -------------------------------------------------------------------------

describe("guide remains presentation-only", () => {
  it("calls no backend commands", () => {
    assert.doesNotMatch(guide, /api\./);
    assert.doesNotMatch(guide, /invoke\(/);
    assert.doesNotMatch(guide, /fetch\(/);
  });

  it("stores no secret material anywhere", () => {
    assert.doesNotMatch(guide, /localStorage|sessionStorage/);
  });
});

// -------------------------------------------------------------------------
// Home archive + anchor status: reuses the same authoritative state
// ManageElection consumes, and never invents a "ready to write archive" nor a
// "no anchor state" line for an already-verified 500-voter archive.
// -------------------------------------------------------------------------

describe("home archive status wording", () => {
  it("no longer says the finalized election is 'ready to write the final archive'", () => {
    assert.doesNotMatch(home, /ready to write the final archive/i);
  });

  it("reuses the shared archive-binding helper rather than inventing a second source of truth", () => {
    assert.match(home, /from "\.\.\/archive\/archiveBinding"/);
    assert.match(home, /boundArchiveResult\(\s*archiveView\.verification/);
  });

  it("shows a Verified pill and the archive hash for a verified final archive", () => {
    assert.match(home, /verifiedFinalArchive/);
    assert.match(home, /<Pill tone="ok">Verified<\/Pill>/);
    assert.match(
      home,
      /Field label="Archive hash"[\s\S]*?verifiedFinalArchive\.archive_hash_hex/,
    );
  });
});

describe("home anchor status hydration", () => {
  it("hydrates the persisted V2 anchor lifecycle via the existing read-only command", () => {
    assert.match(home, /api\.inspectV2LiveAnchorState\(/);
  });

  it("only runs for organizer sessions with a verified final archive", () => {
    assert.match(
      home,
      /if \(!shellAvailable \|\| !isOrganizerSession \|\| !verifiedFinalArchive\)/,
    );
  });

  it("never contacts walletd from Home hydration", () => {
    assert.doesNotMatch(home, /connectWalletd|walletdReadiness|walletd_readiness/);
    assert.doesNotMatch(home, /prepareV2AnchorPublish|runV2LiveAnchorLifecycleStep/);
  });

  it("displays 'Anchored · Verified' when the persisted lifecycle terminated with RECEIPT_VERIFIED", () => {
    assert.match(home, /anchor_?[Tt]erminalVerified|receipt_verified/);
    assert.match(home, /Anchored · Verified/);
    assert.match(home, /Receipt verified/);
    assert.match(home, /Detached evidence written/);
  });

  it("no longer says 'No anchor state loaded in this session' unconditionally", () => {
    const unconditional = /<div className="card-body">No anchor state loaded in this session<\/div>/;
    assert.doesNotMatch(home, unconditional);
  });
});
