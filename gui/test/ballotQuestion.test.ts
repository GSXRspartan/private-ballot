// Issue 2 — the canonical ballot question must be visible directly inside the
// response-selection card, immediately above the selectable responses.
//
// Source-assertion tests (no React harness): the question is read from the
// canonical confirmed election binding (never a second editable copy), it is
// scoped so it disappears on unload and updates on election switch, it wraps
// cleanly, and it sits inside the "Choose your response" card above the choices.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const css = readProjectFile("src/styles/global.css");

describe("canonical ballot question beside responses", () => {
  it("renders the canonical question inside the Choose your response card, above the choices", () => {
    const card = vote.slice(
      vote.indexOf('<Card title="Choose your response">'),
      vote.indexOf("selection-fieldset"),
    );
    assert.ok(card.length > 0, "response card not found");
    assert.match(card, /confirmation\.bound\.proposal_question/);
    assert.match(card, /className="selection-question"/);
    // The question appears before the instruction line, which is before the
    // choices (selection-fieldset).
    assert.ok(
      card.indexOf("selection-question") < card.indexOf("selection-instruction"),
      "question must render above the instruction/choices",
    );
  });

  it("reads the already-loaded canonical binding, not a second editable copy", () => {
    // No local/editable question state or setter exists.
    assert.doesNotMatch(vote, /useState[^\n]*roposal_question/);
    assert.doesNotMatch(vote, /useState[^\n]*[Qq]uestion/);
    assert.doesNotMatch(vote, /setProposalQuestion|setBallotQuestion|setQuestion\b/);
  });

  it("is scoped to the confirmed election so unload/switch clears or updates it", () => {
    // The render is gated on the confirmation binding, which is reset to null on
    // every election change (and absent when no election is loaded), so a stale
    // question can never persist.
    assert.match(vote, /confirmation\.bound\.proposal_question &&/);
    // The reset effect keys on STABLE election identity (manifest hash): the
    // question is cleared on a real election switch, never on same-election
    // background refreshes that install a fresh summary object.
    assert.match(
      vote,
      /setConfirmation\(null\);[\s\S]*\}, \[electionManifestHashHex\]\);/,
    );
  });

  it("wraps long questions and stays inside its card", () => {
    const rule = css.slice(
      css.indexOf(".selection-question {"),
      css.indexOf(".selection-question {") + 220,
    );
    assert.match(rule, /overflow-wrap:\s*anywhere/);
    assert.match(rule, /word-break:\s*break-word/);
  });
});
