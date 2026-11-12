import { hostedShell } from "./shell";
import {
  APP_IDENTITY_TAG,
  APP_NAME,
  APP_NETWORK_LABEL,
  APP_RELEASE_STATUS,
  APP_STATUS_LABEL,
  APP_VERSION,
  COMMUNITY_DISCLAIMER,
} from "./branding/identity";
import {
  DONATION_DISCLAIMER,
  DONATION_XTM_ADDRESS,
  DONATION_YAT,
} from "./branding/donation";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = hostedShell(`
  <h1 class="screen-header">About</h1>

  <section class="card">
    <div class="card-title">Project identity</div>

    <div class="about-identity-grid">
      <div class="about-brand">
      <picture>
        <source
          srcset="/private-ballot-logo-dark.png"
          media="(prefers-color-scheme: dark)"
        />
        <img
          class="about-logo"
          src="/private-ballot-logo-light.png"
          alt="Private Ballot"
          draggable="false"
        />
      </picture>
    </div>

      </div>

      <div class="field-list about-fields">
        <div class="field-row">
          <span class="field-label">Application</span>
        <span class="field-value">${APP_NAME}</span>
      </div>

      <div class="field-row">
        <span class="field-label">Identity</span>
        <span class="field-value">${APP_IDENTITY_TAG}</span>
      </div>

      <div class="field-row">
        <span class="field-label">Release status</span>
        <span class="field-value">
          <span class="pill pill-warn">${APP_RELEASE_STATUS}</span>
          Experimental pre-release software; not audited for production governance use.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Network</span>
        <span class="field-value">${APP_NETWORK_LABEL}</span>
      </div>

      <div class="field-row">
        <span class="field-label">Purpose</span>
        <span class="field-value">
          <span class="pill pill-brand">${APP_STATUS_LABEL}</span>
        </span>
      </div>

        <div class="field-row">
          <span class="field-label">Version</span>
          <span class="field-value">${APP_VERSION} · Hosted/Web Mode</span>
        </div>
      </div>
    </div>

    <div class="notice" role="note">
      ${COMMUNITY_DISCLAIMER}
    </div>
  </section>

  <section class="card">
    <div class="card-title">Hosted architecture</div>

    <p class="card-body">
      Private Ballot Hosted Mode separates cryptographic ballot privacy from
      network privacy.
    </p>

    <div class="field-list about-fields">
      <div class="field-row">
        <span class="field-label">Voter credential</span>
        <span class="field-value">
          Generated locally in the browser and never sent to the server.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Eligibility proof</span>
        <span class="field-value">
          Created and verified using the Private Ballot WebAssembly boundary.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Public application</span>
        <span class="field-value">
          TypeScript and Vite served through the hosted web deployment.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Ballot office</span>
        <span class="field-value">
          Hosted backend running behind the Cloudflare/VPS boundary.
        </span>
      </div>

      <div class="field-row">
        <span class="field-label">Network anonymity</span>
        <span class="field-value">
          Hosted Mode is not anonymous or Tor-equivalent. Infrastructure may
          observe connection metadata such as IP address, timing, and request size.
        </span>
      </div>
    </div>
  </section>

  <section class="card">
    <div class="card-title">Open-source acknowledgements</div>

    <p class="card-body">
      Private Ballot builds on open-source technology from the Tari ecosystem,
      including the Tari Triptych implementation, and uses Tari Ootle for
      optional public aggregate anchoring.
    </p>

    <p class="card-body">
      These are technology and license acknowledgements only. They do not make
      Private Ballot an official Tari Labs application and imply no endorsement
      of this independent open-source project.
    </p>
  </section>

  <div class="notice" role="note">
    <strong>Scope.</strong>
    This release is intended for governance pilots. Binding governance use
    requires the applicable review and authorization process.
  </div>

  <section class="card">
    <div class="card-title">Donate to the dev</div>

    <p class="card-body">${DONATION_DISCLAIMER}</p>

    <div class="donate-grid">
      <div class="donate-method">
        <h3>XTM</h3>
        <div class="donate-value">${DONATION_XTM_ADDRESS}</div>
        <button
          type="button"
          class="btn btn-secondary copy-donation"
          data-copy="${DONATION_XTM_ADDRESS}"
        >
          Copy XTM address
        </button>
      </div>

      <div class="donate-method">
        <h3>Yat</h3>
        <div class="donate-value yat-value">${DONATION_YAT}</div>
        <button
          type="button"
          class="btn btn-secondary copy-donation"
          data-copy="${DONATION_YAT}"
        >
          Copy Yat
        </button>
      </div>
    </div>
  </section>
`, "about");

document.querySelectorAll<HTMLButtonElement>(".copy-donation").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = button.dataset.copy;
    if (!value) return;

    try {
      await navigator.clipboard.writeText(value);
      const original = button.textContent;
      button.textContent = "Copied";
      window.setTimeout(() => {
        button.textContent = original;
      }, 1500);
    } catch {
      button.textContent = "Copy failed";
    }
  });
});

