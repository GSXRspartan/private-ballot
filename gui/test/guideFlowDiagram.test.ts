// Guide workflow-diagram regression tests: theme-matched "How Private
// Ballot Works" overview artwork near the top of the Guide screen.
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

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const guide = readProjectFile("src/screens/Guide.tsx");
const css = readProjectFile("src/styles/global.css");

// -------------------------------------------------------------------------
// Theme-matched workflow assets
// -------------------------------------------------------------------------

describe("guide workflow diagram assets", () => {
  it("references and ships the light workflow diagram asset", () => {
    assert.match(guide, /private-ballot-flow-light\.png/);
    assert.ok(
      existsSync(
        new URL("../src/assets/guide/private-ballot-flow-light.png", import.meta.url),
      ),
      "src/assets/guide/private-ballot-flow-light.png is missing",
    );
  });

  it("references and ships the dark workflow diagram asset", () => {
    assert.match(guide, /private-ballot-flow-dark\.png/);
    assert.ok(
      existsSync(
        new URL("../src/assets/guide/private-ballot-flow-dark.png", import.meta.url),
      ),
      "src/assets/guide/private-ballot-flow-dark.png is missing",
    );
  });
});

// -------------------------------------------------------------------------
// Theme selection
// -------------------------------------------------------------------------

describe("guide workflow diagram theme selection", () => {
  it("uses the existing application theme, not a separate preference", () => {
    assert.match(guide, /useTheme/);
    // No duplicated persisted theme preference in the Guide.
    assert.doesNotMatch(guide, /localStorage|sessionStorage/);
    assert.doesNotMatch(guide, /prefers-color-scheme/);
  });

  it("selects exactly one diagram src from the resolved theme", () => {
    assert.match(guide, /resolved === "dark" \? flowDiagramDark : flowDiagramLight/);
    // One <img> for the diagram; both variants are never rendered together.
    const images = guide.match(/guide-flow-diagram/g) ?? [];
    assert.equal(images.length, 1);
    // No CSS hiding trick for the wrong-theme variant.
    const rule = css.match(/\.guide-flow-diagram\s*\{[^}]*\}/);
    assert.ok(rule, "missing .guide-flow-diagram rule");
    assert.doesNotMatch(rule[0], /display:\s*none|visibility:\s*hidden/);
  });
});

// -------------------------------------------------------------------------
// Placement and responsive presentation
// -------------------------------------------------------------------------

describe("guide workflow diagram placement", () => {
  it("sits near the top, before the detailed role sections", () => {
    const lede = guide.indexOf("screen-lede");
    const diagram = guide.indexOf("guide-flow-diagram");
    const voterCard = guide.indexOf('title="Voter"');
    assert.ok(lede >= 0 && diagram > lede, "diagram must follow the lede");
    assert.ok(voterCard > diagram, "diagram must precede the detailed sections");
  });

  it("uses full content width, preserves aspect ratio, and cannot overflow", () => {
    const rule = css.match(/\.guide-flow-diagram\s*\{[^}]*\}/);
    assert.ok(rule, "missing .guide-flow-diagram rule");
    assert.match(rule[0], /width:\s*100%/);
    assert.match(rule[0], /max-width:\s*100%/);
    assert.match(rule[0], /height:\s*auto/);
  });
});

// -------------------------------------------------------------------------
// Accessibility
// -------------------------------------------------------------------------

describe("guide workflow diagram accessibility", () => {
  it("provides meaningful, non-empty alt text shared by both theme variants", () => {
    const alt = guide.match(/const FLOW_DIAGRAM_ALT =([\s\S]*?);/);
    assert.ok(alt, "missing FLOW_DIAGRAM_ALT constant");
    assert.doesNotMatch(guide, /alt=""/);
    // The alt states the essential workflow: voter creates and keeps the
    // private credential; the organizer/ballot office receives only the
    // public enrollment key.
    assert.match(alt[1], /voters create and keep their own private credentials/);
    assert.match(alt[1], /share only public enrollment keys with the ballot office/);
    assert.match(alt[1], /anonymous ballot packages/);
    assert.match(alt[1], /verifies, tallies, finalizes/);
    // A single alt constant feeds the one theme-switched <img>.
    assert.match(guide, /alt=\{FLOW_DIAGRAM_ALT\}/);
  });
});

// -------------------------------------------------------------------------
// Privacy callout
// -------------------------------------------------------------------------

describe("guide workflow diagram has no duplicate privacy callout", () => {
  it("does not repeat the credential-handling notice directly under the diagram", () => {
    // The diagram itself communicates this (and its alt text states it), and
    // the detailed "Privacy and safety" section explains it in full, so the
    // standalone notice immediately beneath the diagram is removed to avoid
    // triplicating the same sentence.
    assert.doesNotMatch(
      guide,
      /Your private voter credential stays with you\. The ballot office receives only your/,
    );
    // The figure now contains only the diagram, no nested notice.
    const figure = guide.slice(
      guide.indexOf('<figure className="guide-flow">'),
      guide.indexOf("</figure>"),
    );
    assert.doesNotMatch(figure, /<Notice/);
  });

  it("keeps the detailed privacy explanation later in the Guide", () => {
    assert.match(guide, /title="Privacy and safety"/);
    assert.match(guide, /Your public enrollment key is safe to give the organizer\./);
    assert.match(guide, /Never share your private voting credential/);
  });

  it("does not overstate privacy", () => {
    assert.doesNotMatch(guide, /votes are secret end-to-end/i);
    assert.doesNotMatch(guide, /nobody can ever see your vote/i);
  });
});

// -------------------------------------------------------------------------
// Diagram sizing: capped and centered, never edge-to-edge on wide desktop
// -------------------------------------------------------------------------

describe("guide workflow diagram sizing", () => {
  it("caps and centers the figure so it is not oversized at desktop width", () => {
    const rule = css.match(/\.guide-flow\s*\{[^}]*\}/);
    assert.ok(rule, "missing .guide-flow rule");
    // Capped in the documented ~850–900px band and horizontally centered.
    const capMatch = rule[0].match(/max-width:\s*(\d+)px/);
    assert.ok(capMatch, "guide-flow must cap max-width in px");
    const cap = Number(capMatch[1]);
    assert.ok(cap >= 850 && cap <= 900, `cap ${cap}px must be within 850–900px`);
    assert.match(rule[0], /margin:\s*[^;]*auto/);
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
    assert.doesNotMatch(guide, /(send|give)s? (the )?voters? (their |the )?(private )?credentials?/i);
    assert.doesNotMatch(guide, /credential bootstrap/i);
  });

  it("states the correct model: voter keeps the credential, organizer enrolls public keys", () => {
    assert.match(guide, /Give the organizer only your public\s+enrollment key/);
    assert.match(guide, /You never handle voters' private credentials/);
    assert.match(guide, /Enroll eligible voters/);
    assert.match(guide, /public/);
  });

  it("keeps the existing detailed Guide sections", () => {
    assert.match(guide, /title="Voter"/);
    assert.match(guide, /title="Organizer \/ Ballot Office"/);
    assert.match(guide, /title="Privacy and safety"/);
  });
});

// -------------------------------------------------------------------------
// Presentation-only: no secrets, no backend behavior
// -------------------------------------------------------------------------

describe("guide remains presentation-only", () => {
  it("introduces no credential secret, passphrase, or private key into state or storage", () => {
    assert.doesNotMatch(guide, /useState|useReducer/);
    assert.doesNotMatch(guide, /localStorage|sessionStorage/);
    // The new diagram block itself carries no secret material wording. (The
    // pre-existing detailed sections legitimately explain the passphrase.)
    const figure = guide.slice(
      guide.indexOf('<figure className="guide-flow">'),
      guide.indexOf("</figure>"),
    );
    assert.ok(figure.length > 0, "missing guide-flow figure");
    assert.doesNotMatch(figure, /passphrase|privateKey|private_key|secretKey|secret_key/);
  });

  it("calls no backend commands", () => {
    assert.doesNotMatch(guide, /api\./);
    assert.doesNotMatch(guide, /invoke\(/);
    assert.doesNotMatch(guide, /fetch\(/);
  });
});
