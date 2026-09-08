/**
 * Resets the persistent application-shell scroll container (`#main-content`)
 * back to the top-left corner.
 *
 * The application frame stays mounted while screens change, so without an
 * explicit reset the browser keeps the previous screen's scroll offset and
 * clamps it against the next (possibly much shorter) screen — navigation
 * could then start mid-page (reported on macOS: Settings appeared to show
 * only the bottom "Developer diagnostics" card while the other cards were
 * actually rendered above the viewport).
 *
 * This is intentionally a plain synchronous offset reset (no smooth
 * scrolling, no timers, no animation frames) so every top-level navigation
 * deterministically starts at the top. Ordinary in-screen state updates never
 * call this; only an active-section change does (see App.tsx).
 */
export function resetMainContentScroll(
  doc: Pick<Document, "getElementById"> = document,
): void {
  const main = doc.getElementById("main-content");
  if (!main) return;
  main.scrollTop = 0;
  main.scrollLeft = 0;
}
