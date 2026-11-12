import { hostedShell } from "./shell";

const app = document.getElementById("app") as HTMLElement;

app.innerHTML = hostedShell(`
  <h1 class="screen-header">Guide</h1>

  <p class="screen-lede">
    How Private Ballot is meant to be used, by role. Pick the path that
    matches what you are doing: voting in an election, or running one as
    the organizer.
  </p>

  <figure class="guide-flow" aria-label="Workflow overview">
    <picture>
      <source
        srcset="/guide/private-ballot-flow-dark-updated.png"
        media="(prefers-color-scheme: dark)"
      />
      <img
        class="guide-flow-image"
        src="/guide/private-ballot-flow-light-updated.png"
        alt="How Private Ballot works: organizer setup, private voter flow, archive verification, and optional Tari Ootle anchoring."
        draggable="false"
      />
    </picture>
    <figcaption class="guide-flow-caption">
      Private Ballot workflow overview
    </figcaption>
  </figure>

  <div class="notice" role="note">
    <strong>Individual votes are never published to Tari Ootle.</strong>
    The independently verified election archive is authoritative.
    Ootle anchoring is optional and non-binding and publishes only an
    aggregate public summary bound to the archive.
  </div>

  <section class="card">
    <div class="card-title">Voter</div>
    <ol class="guide-steps">
      <li>
        <strong>Create your private voter credential.</strong>
        Your credential is your private voting identity. In Hosted Mode it
        is generated locally in this browser and is never sent to the server.
      </li>

      <li>
        <strong>Enroll your public key.</strong>
        Give the organizer only the public enrollment key. The organizer
        never receives your private credential.
      </li>

      <li>
        <strong>Load the frozen election.</strong>
        The browser obtains the public election package and verifies that
        the election definition, eligible-voter registry, and response set
        match their published commitments.
      </li>

      <li>
        <strong>Review the election.</strong>
        Confirm the election identity, question, available responses, and
        voting rules before creating a ballot.
      </li>

      <li>
        <strong>Prove anonymous eligibility.</strong>
        A Triptych-style linkable ring proof establishes that you control
        one credential from the frozen eligible set without revealing which
        enrolled public key is yours.
      </li>

      <li>
        <strong>Choose your response.</strong>
        Your selection stays local until you deliberately create and release
        the ballot package.
      </li>

      <li>
        <strong>Create the ballot and proof locally.</strong>
        The ballot, anonymous eligibility proof, and election-bound nullifier
        are created in browser WASM.
      </li>

      <li>
        <strong>Submit the ballot.</strong>
        Hosted Mode sends the canonical ballot package to the ballot office
        through the hosted infrastructure.
      </li>

      <li>
        <strong>Receive the organizer receipt.</strong>
        Acceptance confirms that the ballot office accepted that exact
        submission. It does not by itself prove later archive inclusion or
        Ootle anchoring.
      </li>

      <li>
        <strong>Check the final record.</strong>
        After finalization, the published archive and aggregate results can
        be independently checked.
      </li>
    </ol>
  </section>

  <section class="card">
    <div class="card-title">Organizer / Ballot Office</div>

    <ol class="guide-steps">
      <li>
        <strong>Define the election.</strong>
        Set the election identity, ballot question, governance source,
        available responses, and selection rules.
      </li>

      <li>
        <strong>Enroll eligible voters.</strong>
        Collect only voters' public enrollment keys.
      </li>

      <li>
        <strong>Freeze the canonical election.</strong>
        Freezing locks the election definition, voter registry, and ballot
        responses.
      </li>

      <li>
        <strong>Distribute voter materials.</strong>
        Give voters the information necessary to identify and verify the
        frozen election.
      </li>

      <li>
        <strong>Open voting.</strong>
        Opening voting is a separate lifecycle action from freezing or
        preparing the election.
      </li>

      <li>
        <strong>Receive ballots.</strong>
        Accepted submissions enter the authoritative election record.
        Election-bound linkability prevents a second accepted ballot from
        the same enrolled credential.
      </li>

      <li>
        <strong>Close voting.</strong>
        Closing is irreversible and prevents new ballots from being accepted.
      </li>

      <li>
        <strong>Tally and verify.</strong>
        Recompute the deterministic tally and verify the election record
        before finalization.
      </li>

      <li>
        <strong>Finalize and publish the archive.</strong>
        The final archive becomes the independently verifiable authoritative
        record.
      </li>

      <li>
        <strong>Optionally anchor on Tari Ootle.</strong>
        Anchoring is organizer-side and non-binding. Only aggregate election
        information and archive commitments are published, never individual
        ballots or voter identities.
      </li>
    </ol>
  </section>

  <section class="card">
    <div class="card-title">Hosted Mode</div>

    <p class="card-body">
      The hosted application replaces the desktop application's Tor-based
      voter transport with a normal browser connection through the hosted
      Cloudflare/VPS infrastructure.
    </p>

    <p class="card-body">
      Cryptographic ballot privacy remains separate from network privacy.
      Hosted Mode can preserve anonymous eligibility while still exposing
      connection metadata such as IP address, timing, and request size to
      infrastructure operators.
    </p>
  </section>

  <section class="card">
    <div class="card-title">Privacy and safety</div>

    <ul class="guide-facts">
      <li>
        <strong>Never share your private voting credential.</strong>
      </li>

      <li>
        <strong>Your public enrollment key is safe to give the organizer.</strong>
        It is not sufficient to vote without the corresponding private credential.
      </li>

      <li>
        <strong>The organizer cannot recover your private credential.</strong>
      </li>

      <li>
        <strong>Using the same credential from another device does not create
        another voting entitlement.</strong>
        Election-bound linkability prevents a second accepted ballot from the
        same enrolled credential.
      </li>

      <li>
        <strong>Anonymous eligibility and network anonymity are different.</strong>
        The eligibility proof hides which enrolled credential voted. It does
        not hide your network connection.
      </li>

      <li>
        <strong>Hosted Mode is not Tor-equivalent.</strong>
        Cloudflare/VPS infrastructure may observe connection metadata.
      </li>

      <li>
        <strong>Ootle anchoring is aggregate and organizer-side.</strong>
        Individual voters never publish their ballots to Tari Ootle.
      </li>
    </ul>
  </section>
`, "guide");
