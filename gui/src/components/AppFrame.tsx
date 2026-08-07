import React from "react";

import TariLogo from "../branding/TariLogo";
import { useAppState } from "../state/AppState";
import { useTheme } from "../theme/ThemeProvider";
import { LifecyclePill } from "./ui";

export type NavSection =
  | "home"
  | "create"
  | "manage"
  | "vote"
  | "archive"
  | "anchor"
  | "evidence"
  | "settings"
  | "about";

interface NavItem {
  id: NavSection;
  label: string;
  group: string;
}

export const NAV_ITEMS: NavItem[] = [
  { id: "home", label: "Home", group: "Overview" },
  { id: "create", label: "Create Election", group: "Organizer" },
  { id: "manage", label: "Manage Election", group: "Organizer" },
  { id: "vote", label: "Vote", group: "Voter" },
  { id: "archive", label: "Archive", group: "Verification" },
  { id: "anchor", label: "Anchor", group: "Verification" },
  { id: "evidence", label: "Evidence", group: "Verification" },
  { id: "settings", label: "Settings", group: "Application" },
  { id: "about", label: "About", group: "Application" },
];

/**
 * Application frame: left navigation, top toolbar (official Tari logo +
 * "Private Ballot" identity, lifecycle state, theme toggle), main content
 * region, and a status bar. Fully keyboard navigable.
 */
export function AppFrame({
  section,
  onNavigate,
  children,
}: {
  section: NavSection;
  onNavigate: (section: NavSection) => void;
  children: React.ReactNode;
}) {
  const { resolved, mode, setMode } = useTheme();
  const { election, shellAvailable, settings } = useAppState();

  const groups: { name: string; items: NavItem[] }[] = [];
  for (const item of NAV_ITEMS) {
    const group = groups.find((g) => g.name === item.group);
    if (group) group.items.push(item);
    else groups.push({ name: item.group, items: [item] });
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <header className="toolbar">
        <div className="brand">
          <TariLogo />
          <span className="brand-name">
            Private <span className="brand-name-accent">Ballot</span>
          </span>
        </div>
        <div className="toolbar-spacer" />
        <div className="toolbar-state">
          <LifecyclePill state={election?.lifecycle_state ?? null} />
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setMode(resolved === "dark" ? "light" : "dark")}
            aria-label={
              resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"
            }
            title={
              mode === "system"
                ? "Theme follows the operating system; click to override"
                : "Theme override active; click to switch"
            }
          >
            {resolved === "dark" ? "Light theme" : "Dark theme"}
          </button>
        </div>
      </header>

      <nav className="nav" aria-label="Primary">
        {groups.map((group) => (
          <div key={group.name}>
            <div className="nav-group" aria-hidden="true">
              {group.name}
            </div>
            <ul aria-label={group.name}>
              {group.items.map((item) => (
                <li key={item.id}>
                  <button
                    type="button"
                    className="nav-item"
                    aria-current={section === item.id ? "page" : undefined}
                    onClick={() => onNavigate(item.id)}
                  >
                    {item.label}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <main className="main" id="main-content" tabIndex={-1}>
        <div className="main-inner">{children}</div>
      </main>

      <footer className="statusbar">
        <span>
          <span className="status-label">Backend:</span>{" "}
          {shellAvailable ? "gui-core (in process)" : "not connected (browser preview)"}
        </span>
        <span>
          <span className="status-label">Lifecycle:</span>{" "}
          {election?.lifecycle_state ?? "no election"}
        </span>
        <span>
          <span className="status-label">Data directory:</span>{" "}
          {settings.dataDirectory || "not configured"}
        </span>
      </footer>
    </div>
  );
}
