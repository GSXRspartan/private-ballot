// Navigation scroll-reset regression tests.
//
// A real macOS alpha report: after scrolling a long screen and navigating to
// Settings, only the bottom "Advanced / Developer diagnostics" card appeared
// to be rendered. Root cause (independently confirmed): the application shell
// — and its `#main-content` vertical scroll container — stays mounted while
// screens change, and navigation changed the active section WITHOUT resetting
// the scroll position. The browser clamps the previous screen's scroll offset
// against the shorter next screen, so the viewport can start near the bottom
// while the (unconditionally rendered) cards above remain out of view.
//
// Where no React/DOM harness exists, behavior is pinned by direct unit tests
// of the production helper plus semantic source assertions that the App shell
// wires the helper to active-SECTION changes only.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { resetMainContentScroll } from "../src/navigation/scrollReset.ts";

const appSource = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
const frameSource = readFileSync(
  new URL("../src/components/AppFrame.tsx", import.meta.url),
  "utf8",
);

function stubDocument(main: Record<string, number> | null | undefined) {
  const queried: string[] = [];
  return {
    queried,
    doc: {
      getElementById(id: string) {
        queried.push(id);
        return main ?? null;
      },
    },
  };
}

test("resetMainContentScroll zeroes the scroll container's offsets", () => {
  const main: Record<string, number> = { scrollTop: 812, scrollLeft: 34 };
  const { doc } = stubDocument(main);
  resetMainContentScroll(doc as unknown as Pick<Document, "getElementById">);
  assert.equal(main.scrollTop, 0, "scrollTop must be reset to 0");
  assert.equal(main.scrollLeft, 0, "scrollLeft must be reset to 0");
});

test("resetMainContentScroll targets exactly the persistent main content element", () => {
  const { queried, doc } = stubDocument({ scrollTop: 5, scrollLeft: 5 });
  resetMainContentScroll(doc as unknown as Pick<Document, "getElementById">);
  assert.deepEqual(queried, ["main-content"]);
});

test("resetMainContentScroll is a safe no-op when the container is absent", () => {
  const { doc } = stubDocument(null);
  assert.doesNotThrow(() =>
    resetMainContentScroll(doc as unknown as Pick<Document, "getElementById">),
  );
});

test("App resets the scroll container on every active-section change", () => {
  // The effect must be keyed by the active section so every top-level
  // navigation (home, guide, create, manage, vote, archive, anchor, evidence,
  // settings, about) deterministically starts at the top.
  assert.match(appSource, /import \{ resetMainContentScroll \} from "\.\/navigation\/scrollReset"/);
  assert.match(
    appSource,
    /useEffect\(\(\) => \{\s*resetMainContentScroll\(\);\s*\}, \[section\]\)/,
  );
});

test("the scroll reset is synchronous — no timers or animation frames", () => {
  const effect = appSource.match(/useEffect\(\(\) => \{[\s\S]*?\}, \[section\]\)/);
  assert.ok(effect, "the section-keyed effect must exist");
  assert.ok(!/setTimeout|setInterval|requestAnimationFrame/.test(effect[0]));
});

test("the persistent scroll container is unchanged in the app frame", () => {
  // The fix relies on this element: it must remain the mounted scroll
  // container with its stable id and its focus target (tabIndex={-1}).
  assert.match(frameSource, /<main className="main" id="main-content" tabIndex=\{-1\}>/);
});
