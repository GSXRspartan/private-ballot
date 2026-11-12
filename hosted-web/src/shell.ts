export type HostedSection = "home" | "guide" | "create" | "manage" | "vote" | "enroll" | "archive" | "evidence" | "settings" | "about";

function navItem(
  href: string,
  label: string,
  id: HostedSection,
  section: HostedSection,
): string {
  return `
    <li>
      <a
        class="nav-item"
        href="${href}"
        ${section === id ? 'aria-current="page"' : ""}
      >
        ${label}
      </a>
    </li>
  `;
}

function disabledNavItem(label: string): string {
  return `
    <li>
      <span
        class="nav-item nav-item-disabled"
        aria-disabled="true"
        title="Available in Organizer/Desktop Mode"
      >
        <span>${label}</span>
        <span class="nav-item-badge">Desktop</span>
      </span>
    </li>
  `;
}

export function hostedShell(content: string, section: HostedSection): string {
  return `
    <div class="app-shell">
      <header class="toolbar">
        <a class="brand" href="/" aria-label="Private Ballot home">
          <picture>
            <source
              srcset="/private-ballot-mark-dark.png"
              media="(prefers-color-scheme: dark)"
            />
            <img
              src="/private-ballot-mark-light.png"
              alt=""
              aria-hidden="true"
              class="brand-emblem"
              draggable="false"
            />
          </picture>

          <span class="brand-text">
            <span class="brand-name">Private Ballot</span>
            <span class="brand-subtitle">Independent Open-Source Project</span>
          </span>
        </a>

        <div class="toolbar-spacer"></div>

        <div class="toolbar-state">
          <span class="pill pill-brand">Hosted Staging</span>
          <span class="toolbar-mode">Web Mode</span>
        </div>
      </header>

      <nav class="nav" aria-label="Primary">
        <div>
          <div class="nav-group">Overview</div>
          <ul>
            ${navItem("/", "Home", "home", section)}
            ${navItem("/guide.html", "Guide", "guide", section)}
          </ul>
        </div>

        <div>
          <div class="nav-group">Organizer</div>
          <ul>
            ${navItem("/create.html", "Create Election", "create", section)}
            ${navItem("/manage.html", "Manage Election", "manage", section)}
            ${disabledNavItem("Anchor")}
          </ul>
        </div>

        <div>
          <div class="nav-group">Voter</div>
          <ul>
            ${navItem("/enroll.html", "Enroll to Vote", "enroll", section)}
            ${navItem("/vote.html", "Vote", "vote", section)}
          </ul>
        </div>

        <div>
          <div class="nav-group">Verification</div>
          <ul>
            ${navItem("/archive.html", "Archive", "archive", section)}
            ${navItem("/evidence.html", "Evidence", "evidence", section)}
          </ul>
        </div>

        <div>
          <div class="nav-group">Application</div>
          <ul>
            ${navItem("/settings.html", "Settings", "settings", section)}
            ${navItem("/about.html", "About", "about", section)}
          </ul>
        </div>

        <div>
          <div class="nav-group">Privacy</div>
          <div class="nav-note">
            Ballot proofs and voter credentials are created locally in your browser.
          </div>
        </div>
      </nav>

      <main class="main" id="main-content">
        <div class="main-inner">
          ${content}
        </div>
      </main>

      <footer class="statusbar">
        <span>Private Ballot</span>
        <span>Hosted Staging</span>
        <span>Cryptographic ballot privacy · reduced network-metadata privacy</span>
      </footer>
    </div>
  `;
}








export type HostedTheme = "system" | "light" | "dark";

const THEME_STORAGE_KEY = "private-ballot-hosted-theme";

export function getHostedTheme(): HostedTheme {
  const stored = localStorage.getItem(THEME_STORAGE_KEY);

  if (stored === "light" || stored === "dark" || stored === "system") {
    return stored;
  }

  return "system";
}

export function applyHostedTheme(theme: HostedTheme): void {
  if (theme === "system") {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

export function setHostedTheme(theme: HostedTheme): void {
  localStorage.setItem(THEME_STORAGE_KEY, theme);
  applyHostedTheme(theme);
}

applyHostedTheme(getHostedTheme());

