import { hostedShell } from "./shell";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = hostedShell(`
  <h1 class="screen-header">Home</h1>

  <p class="screen-lede">
    Private Ballot lets eligible voters participate without revealing which
    enrolled credential cast a ballot. Election records can later be checked
    against the published archive and aggregate result.
  </p>

  <div class="notice" role="note">
    <strong>Hosted / Web Mode.</strong>
    Ballot proofs and voter credentials are created locally in your browser,
    but this hosted route provides reduced network-metadata privacy compared
    with Desktop/Tor Mode. It is not anonymous or Tor-equivalent.
  </div>

  <div class="home-actions">
    <section class="card home-action-card">
      <div class="card-title">Voter</div>
      <h2>Enroll to vote</h2>
      <p>
        Use the invitation provided by the election organizer to generate and
        enroll your public voting credential.
      </p>
      <a class="btn-link btn-primary-link" href="/enroll.html">
        Enroll to Vote
      </a>
    </section>

    <section class="card home-action-card">
      <div class="card-title">Voter</div>
      <h2>Cast a private ballot</h2>
      <p>
        Load the frozen public election package, verify it locally, create the
        eligibility proof in this browser, review the ballot, and submit it.
      </p>
      <a class="btn-link btn-primary-link" href="/vote.html">
        Open Vote
      </a>
    </section>

    <section class="card home-action-card">
      <div class="card-title">Verification</div>
      <h2>Verify the record</h2>
      <p>
        After an election closes, inspect the published archive, aggregate
        results, commitments, and optional Ootle anchor evidence.
      </p>
      <a class="btn-link btn-primary-link" href="/archive.html">Open Archive</a>
    </section>

    <section class="card home-action-card">
      <div class="card-title">Learn</div>
      <h2>How Private Ballot works</h2>
      <p>
        Follow the voter and organizer workflows, understand the privacy model,
        and see how enrollment, anonymous eligibility, receipts, archives, and
        anchoring fit together.
      </p>
      <a class="btn-link btn-primary-link" href="/guide.html">Open Guide</a>
    </section>
  </div>

  <section class="card">
    <div class="card-title">Privacy model</div>

    <div class="field-list">
      <span class="field-label">Voter credential</span>
      <span class="field-value">Generated locally and never sent to the server.</span>

      <span class="field-label">Eligibility proof</span>
      <span class="field-value">Created locally in browser WASM.</span>

      <span class="field-label">Duplicate voting</span>
      <span class="field-value">
        Election-bound linkability prevents a second accepted ballot from the
        same enrolled credential.
      </span>

      <span class="field-label">Network privacy</span>
      <span class="field-value">
        Hosted mode is not anonymous. Cloudflare/VPS infrastructure may observe
        connection metadata.
      </span>

      <span class="field-label">Ootle</span>
      <span class="field-value">
        Optional aggregate anchoring only. Individual votes are not published
        to Tari Ootle.
      </span>
    </div>
  </section>
`, "home");


