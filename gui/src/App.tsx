import { useState } from "react";

import { AppFrame, NavSection } from "./components/AppFrame";
import { About } from "./screens/About";
import { Anchor } from "./screens/Anchor";
import { Archive } from "./screens/Archive";
import { CreateElection } from "./screens/CreateElection";
import { Evidence } from "./screens/Evidence";
import { Home } from "./screens/Home";
import { ManageElection } from "./screens/ManageElection";
import { Settings } from "./screens/Settings";
import { Vote } from "./screens/Vote";

const SCREEN_TITLES: Record<NavSection, string> = {
  home: "Home",
  create: "Create Election",
  manage: "Manage Election",
  vote: "Vote",
  archive: "Archive",
  anchor: "Anchor",
  evidence: "Evidence",
  settings: "Settings",
  about: "About",
};

export default function App() {
  const [section, setSection] = useState<NavSection>("home");

  return (
    <AppFrame section={section} onNavigate={setSection}>
      <div aria-live="polite" className="sr-only">
        {SCREEN_TITLES[section]}
      </div>
      {section === "home" && <Home onNavigate={setSection} />}
      {section === "create" && <CreateElection />}
      {section === "manage" && <ManageElection />}
      {section === "vote" && <Vote />}
      {section === "archive" && <Archive />}
      {section === "anchor" && <Anchor />}
      {section === "evidence" && <Evidence />}
      {section === "settings" && <Settings />}
      {section === "about" && <About />}
    </AppFrame>
  );
}
