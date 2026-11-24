import {
  getHostedTheme,
  hostedShell,
  setHostedTheme,
  type HostedTheme,
} from "./shell";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = hostedShell(`
  <h1 class="screen-header">Settings</h1>

  <p class="screen-lede">
    Application preferences for Hosted Mode. Settings never include voter
    credentials, invitations, ballots, wallet material, or election secrets.
  </p>

  <section class="card">
    <div class="card-title">Theme</div>

    <p class="card-body">
      Choose how Private Ballot appears on this browser.
    </p>

    <div class="theme-options" role="radiogroup" aria-label="Theme">
      <label class="theme-option">
        <input type="radio" name="theme" value="system" />
        <span class="theme-option-copy">
          <strong>Automatic</strong>
          <span>Follow the operating system light or dark preference.</span>
        </span>
      </label>

      <label class="theme-option">
        <input type="radio" name="theme" value="light" />
        <span class="theme-option-copy">
          <strong>Light</strong>
          <span>Always use the light Private Ballot theme.</span>
        </span>
      </label>

      <label class="theme-option">
        <input type="radio" name="theme" value="dark" />
        <span class="theme-option-copy">
          <strong>Dark</strong>
          <span>Always use the dark Private Ballot theme.</span>
        </span>
      </label>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Hosted privacy</div>

    <div class="field-list about-fields">
      <div class="field-row">
        <span class="field-label">Credential storage</span>
        <span class="field-value">
          Private voter credentials are not stored as an application preference.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Invitation storage</span>
        <span class="field-value">
          Enrollment invitations are not written to browser storage.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Stored preference</span>
        <span class="field-value">
          Only the selected display theme is stored by this Settings page.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Network mode</span>
        <span class="field-value">
          Hosted Mode uses normal web infrastructure and is not Tor-equivalent.
        </span>
      </div>
    </div>
  </section>
`, "settings");

const currentTheme = getHostedTheme();

document
  .querySelectorAll<HTMLInputElement>('input[name="theme"]')
  .forEach((radio) => {
    radio.checked = radio.value === currentTheme;

    radio.addEventListener("change", () => {
      if (!radio.checked) return;

      const theme = radio.value as HostedTheme;
      setHostedTheme(theme);
    });
  });
