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
  it("provides meaningful, non-empty alt text describing the current workflow", () => {
    const alt = guide.match(/const FLOW_DIAGRAM_ALT =([\s\S]*?);/);
    assert.ok(alt, "missing FLOW_DIAGRAM_ALT constant");
    assert.doesNotMatch(guide, /alt=""/);
    // The alt states the essential CURRENT workflow: the voter keeps the private
    // credential and shares only the public enrollment key; the ballot is
    // submitted privately over Tor with an offline fallback and an authenticated
    // organizer receipt; the ballot office tallies/verifies and may anchor the
    // aggregate finalized commitment to Ootle.
    assert.match(alt[1], /keeps their own private credential/);
    assert.match(alt[1], /shares only their public enrollment key/);
    assert.match(alt[1], /privately over Tor/);
    assert.match(alt[1], /saves an encrypted ballot file for offline delivery/);
    assert.match(alt[1], /authenticated organizer receipt/);
    assert.match(alt[1], /tallies, verifies/);
    assert.match(alt[1], /anchors the aggregate finalized commitment to Tari Ootle/);
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
// Diagram sizing: a dedicated WIDE, responsive wrapper (replacement artwork)
// -------------------------------------------------------------------------

describe("guide workflow diagram sizing", () => {
  const rule = css.match(/\.guide-flow\s*\{[^}]*\}/);

  it("no longer retains the obsolete ~880px reading-column cap", () => {
    assert.ok(rule, "missing .guide-flow rule");
    // The replacement diagram is much wider/denser; the old ~850–900px cap that
    // made it artificially small must be gone.
    const caps = [...rule![0].matchAll(/max-width:\s*(\d+)px/g)].map((m) => Number(m[1]));
    assert.ok(
      caps.every((cap) => cap < 850 || cap > 900),
      `the obsolete 850–900px cap must be removed (found ${caps.join(", ")})`,
    );
  });

  it("uses a wide desktop cap in the ~1180–1280px band", () => {
    assert.ok(rule, "missing .guide-flow rule");
    const caps = [...rule![0].matchAll(/(\d+)px/g)].map((m) => Number(m[1]));
    assert.ok(
      caps.some((cap) => cap >= 1180 && cap <= 1280),
      `guide-flow must cap in ~1180–1280px (found ${caps.join(", ")})`,
    );
  });

  it("is responsive: a min()/calc width bounded by available content, never a fixed overflow", () => {
    assert.ok(rule, "missing .guide-flow rule");
    // A responsive width (min() over the available content width) means a small
    // window can never be forced wider by a fixed pixel width.
    assert.match(rule![0], /width:\s*min\(/);
    assert.match(rule![0], /calc\(100vw\s*-\s*var\(--nav-width\)/);
  });

  it("centers the figure via a symmetric breakout, not edge-to-edge", () => {
    assert.ok(rule, "missing .guide-flow rule");
    assert.match(rule![0], /margin-inline:\s*50%/);
    assert.match(rule![0], /transform:\s*translateX\(-50%\)/);
  });

  it("keeps the image itself fluid so both theme variants share one responsive wrapper", () => {
    // The single .guide-flow-diagram image rule (used by both PNGs) keeps
    // width:100% / max-width:100% / height:auto so the wrapper drives width and
    // the aspect ratio is preserved in both themes without a layout jump.
    const imgRule = css.match(/\.guide-flow-diagram\s*\{[^}]*\}/);
    assert.ok(imgRule, "missing .guide-flow-diagram rule");
    assert.match(imgRule![0], /width:\s*100%/);
    assert.match(imgRule![0], /max-width:\s*100%/);
    assert.match(imgRule![0], /height:\s*auto/);
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
