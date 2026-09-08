import { Component, useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";

import { AppFrame, NavSection } from "./components/AppFrame";
import { resetMainContentScroll } from "./navigation/scrollReset";
import { Notice } from "./components/ui";
import { About } from "./screens/About";
import { Anchor } from "./screens/Anchor";
import { Archive } from "./screens/Archive";
import { CreateElection } from "./screens/CreateElection";
import { Evidence } from "./screens/Evidence";
import { Guide } from "./screens/Guide";
import { Home } from "./screens/Home";
import { ManageElection } from "./screens/ManageElection";
import { Settings } from "./screens/Settings";
import { Vote } from "./screens/Vote";
import { useAppState } from "./state/AppState";

const SCREEN_TITLES: Record<NavSection, string> = {
  home: "Home",
  guide: "Guide",
  create: "Create Election",
  manage: "Manage Election",
  vote: "Vote",
  archive: "Archive",
  anchor: "Anchor",
  evidence: "Evidence",
  settings: "Settings",
  about: "About",
};

/**
 * Last-resort render guard. Without an error boundary, React unmounts the
 * whole tree on any uncaught render error, leaving a completely blank
 * (white in the light theme) content area. This boundary degrades a screen
 * failure to an inline plain-language notice instead; it is keyed by the
 * active section, so navigating away and back resets it.
 */
class ScreenErrorBoundary extends Component<
  { children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return (
        <Notice tone="error">
          <strong>This screen could not be displayed.</strong> Open another
          section using the navigation, then come back to try again.
        </Notice>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  const [section, setSection] = useState<NavSection>("home");
  const { dismissError } = useAppState();

  // Navigation changes the operational context: any error caused by a
  // previous operation is no longer relevant and is cleared so stale errors
  // never persist across screens.
  const navigate = useCallback(
    (next: NavSection) => {
      setSection(next);
      dismissError();
    },
    [dismissError],
  );

  // The application shell — including the #main-content vertical scroll
  // container — stays mounted while screens change. Without an explicit
  // reset, the previous screen's scroll offset is clamped against the next
  // (possibly much shorter) screen, so navigation could start mid-page
  // (reported on macOS: Settings seemed to show only the bottom Developer
  // diagnostics card while the other cards were rendered above the viewport).
  // Only an active-SECTION change resets the scroll; ordinary state updates
  // on a screen never do. Kept synchronous: no timers or animation frames.
  useEffect(() => {
    resetMainContentScroll();
  }, [section]);

  return (
    <AppFrame section={section} onNavigate={navigate}>
      <div aria-live="polite" className="sr-only">
        {SCREEN_TITLES[section]}
      </div>
      <ScreenErrorBoundary key={section}>
        {section === "home" && <Home onNavigate={navigate} />}
        {section === "guide" && <Guide />}
        {section === "create" && <CreateElection onNavigate={navigate} />}
        {section === "manage" && <ManageElection />}
        {section === "vote" && <Vote onNavigate={navigate} />}
        {section === "archive" && <Archive onNavigate={navigate} />}
        {section === "anchor" && <Anchor onNavigate={navigate} />}
        {section === "evidence" && <Evidence onNavigate={navigate} />}
        {section === "settings" && <Settings />}
        {section === "about" && <About />}
      </ScreenErrorBoundary>
    </AppFrame>
  );
}
