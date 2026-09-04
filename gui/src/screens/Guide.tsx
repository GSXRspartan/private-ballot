import { useCallback, useEffect, useRef, useState } from "react";

import { Card, Notice } from "../components/ui";
import { useTheme } from "../theme/ThemeProvider";
import flowDiagramDarkUrl from "../assets/guide/private-ballot-flow-dark-updated.png";
import flowDiagramLightUrl from "../assets/guide/private-ballot-flow-light-updated.png";

/** Alt text for the workflow overview diagram — plain-language summary of the
 *  four end-to-end phases the image depicts. */
const FLOW_DIAGRAM_ALT =
  "How Private Ballot works: organizer setup, private voter flow, archive verification, and optional Tari Ootle anchoring.";

/**
 * Guide — the built-in, role-based walkthrough for the Private Ballot
 * product. It has two obvious paths (Voter and Organizer / Ballot Office)
 * written in plain language, a short explanation of the voter transport
 * bundle, and a privacy and safety section.
 *
 * The visual overview at the top is a theme-matched raster diagram (dark or
 * light PNG chosen from the active theme). It is presentation-only: the Guide
 * calls no backend commands, handles no secret material, and never claims a
 * capability that is not implemented. The click-to-enlarge lightbox is a
 * simple accessible modal — Escape and the Close button both dismiss it.
 */
export function Guide() {
  const { resolved } = useTheme();
  const diagramSrc = resolved === "dark" ? flowDiagramDarkUrl : flowDiagramLightUrl;
  const [lightboxOpen, setLightboxOpen] = useState(false);
  const closeLightbox = useCallback(() => setLightboxOpen(false), []);
  const openLightbox = useCallback(() => setLightboxOpen(true), []);

  return (
    <>
      <h1 className="screen-header">Guide</h1>
      <p className="screen-lede">
        How Private Ballot is meant to be used, by role. Pick the path that matches what
        you are doing: voting in an election, or running one as the organizer.
      </p>

      <figure className="guide-flow" aria-label="Workflow overview">
        <button
          type="button"
          className="guide-flow-trigger"
          onClick={openLightbox}
          aria-label="Enlarge workflow diagram"
        >
          <img
            className="guide-flow-image"
            src={diagramSrc}
            alt={FLOW_DIAGRAM_ALT}
            draggable={false}
          />
        </button>
        <figcaption className="guide-flow-caption">
          Click the diagram to enlarge.
        </figcaption>
      </figure>
      {lightboxOpen && (
        <GuideDiagramLightbox src={diagramSrc} alt={FLOW_DIAGRAM_ALT} onClose={closeLightbox} />
      )}
      <Notice tone="info">
        <strong>Individual votes are never published to Tari Ootle.</strong> The
        independently verified offline archive is authoritative. Anchoring on Ootle is
        optional and non-binding — it publishes only a readable public aggregate summary,
        with detached evidence written beside the archive.
      </Notice>

      <Card title="Voter">
        <ol className="guide-steps">
          <li>
            <strong>Create or load your private voter credential.</strong> Your voter credential
            is your private voting identity, not a Tari wallet seed. Keep the encrypted
            credential file and its passphrase private.
          </li>
          <li>
            <strong>Give the organizer only your public enrollment key before freeze.</strong>{" "}
            That public key — never your credential — is what the ballot office enrolls on the
            eligible voter list.
          </li>
          <li>
            <strong>Receive the frozen election package.</strong> Load it (one folder, or the
            three files individually) on the Vote screen. The app verifies that its canonical
            files belong together and have not been altered.
          </li>
          <li>
            <strong>Receive the ballot-office connection file.</strong> The organizer exports a
            voter transport bundle for this election. Configure it on the Vote screen so the app
            knows which ballot office is authoritative here: every signed statement from that
            office is verified against this pinned connection. It contains no ballot-office
            private keys.
          </li>
          <li>
            <strong>Learn whether voting has opened.</strong> The frozen election package itself
            cannot tell you when voting opens or closes — only the ballot office can, and there
            are two equivalent ways to learn it:{" "}
            <em>check through your private connection</em> once the ballot-office connection is
            configured, or <em>import a signed election-status file</em> the office gives you.
            You do not need both. The app verifies either one against the pinned ballot-office
            authority and applies it only if it is authentic and not older than what you already
            know.
          </li>
          <li>
            <strong>Review the election.</strong> Confirm the election identity, ballot question,
            response choices, and voting rules before continuing. For newer election files, the
            question and response choices are cryptographically bound to the frozen election
            definition; legacy files honestly say when no canonical question exists.
          </li>
          <li>
            <strong>Verify anonymous eligibility.</strong> A Triptych-style linkable ring proof
            establishes that you control one credential in the frozen eligible set, without
            revealing which enrolled public key is yours.
          </li>
          <li>
            <strong>Choose your response.</strong> Choices become available only after a
            verified OPEN. Your choice stays local and can be changed any time before the
            release/export boundary.
          </li>
          <li>
            <strong>Create the anonymous eligibility proof.</strong> The proof and the ballot are
            bound to this frozen election.
          </li>
          <li>
            <strong>Connect privately and submit the encrypted ballot.</strong> Normal
            private-online submission sends the encrypted ballot package through Tor, reusing
            the ballot-office connection you configured earlier. A temporary network or
            onion-reachability failure reuses the <em>exact same</em> staged encrypted submission
            — it never creates a second ballot, a second proof, or another election nullifier.{" "}
            <strong>Offline fallback:</strong> save the encrypted ballot package and deliver it
            through the election's approved manual route.
          </li>
          <li>
            <strong>Receive an authenticated organizer receipt.</strong> Online success means the
            ballot was accepted by the organizer, who authenticated acceptance of the exact ballot
            you released. That receipt does not by itself claim final archive inclusion, final
            election verification, or Ootle anchoring.
          </li>
          <li>
            <strong>Check the final record later.</strong> The published archive and evidence can
            be independently replayed and checked once the election is finalized.{" "}
            {/* prettier-ignore */}
            Inclusion and Ootle anchoring are later checked from the published archive, not from the receipt.
            If the organizer chose to publish an Ootle anchor, the public aggregate result
            on Ootle is bound to the same archive by a domain-separated digest, so an
            observer can compare the on-chain result to the archive independently.
          </li>
        </ol>
      </Card>

      <Card title="Organizer / Ballot Office">
        <ol className="guide-steps">
          <li>
            <strong>Define the election.</strong> Set the election identity, the ballot question,
            and the governance source that defines what is being voted on.
          </li>
          <li>
            <strong>Enroll eligible voters.</strong> Collect and enroll eligible <em>public</em>{" "}
            enrollment keys. You never handle voters' private credentials.
          </li>
          <li>
            <strong>Define responses and rules.</strong> Add the responses voters can choose and
            the selection rules (minimum, maximum, abstention).
          </li>
          <li>
            <strong>Review and freeze the canonical election.</strong>{" "}
            <strong>Freezing is irreversible:</strong> it locks the election definition, the voter
            list, and the ballot responses.
          </li>
          <li>
            <strong>Start private intake.</strong> The app manages an election-scoped Tor
            hidden-service intake for you — no terminal, torrc, ports, or onion setup. Starting
            intake does not open voting.
          </li>
          <li>
            <strong>Export and distribute voter materials.</strong> Share the frozen election
            files together with the voter-safe transport bundle.
          </li>
          <li>
            <strong>Open voting.</strong> This is a separate, deliberate lifecycle action;
            starting Tor intake never opens the election on its own. Opening (and later closing)
            also fences the running intake immediately: ballots are accepted only while this
            election is authoritatively open.
          </li>
          <li>
            <strong>Voters learn the new lifecycle state one of two ways.</strong> Voters who
            configured their ballot-office connection can check the current state privately
            through your running intake — they need no extra file from you. For voters who
            cannot check privately, export a <em>signed election status statement</em> after
            each lifecycle change (open voting, close voting) and give them a copy: it is bound
            to this exact election and signed by this ballot office, so an independent computer
            learns FROZEN/OPEN/CLOSED without trusting any unsigned claim. Importing that file
            is the offline/manual alternative, not a requirement for every voter.
          </li>
          <li>
            <strong>Receive ballots.</strong> Private Tor submissions enter a durable
            election-scoped inbox and are reconciled through the authoritative organizer
            workspace — automatically while intake is running, and again on load after a restart.
            Manual encrypted ballot-file import remains an offline fallback.
          </li>
          <li>
            <strong>Keep participation sealed while voting is open</strong> when policy requires
            it; only permitted aggregate information is shown.
          </li>
          <li>
            <strong>Close voting.</strong> <strong>Closing is irreversible:</strong> no new
            ballots are accepted afterwards — the running intake is fenced immediately, and any
            voter still holding stale OPEN evidence cannot have a new ballot accepted.
          </li>
          <li>
            <strong>Tally and verify.</strong> Compute the deterministic tally and mark public
            verification complete before finalization.
          </li>
          <li>
            <strong>Finalize the election.</strong> <strong>Finalizing is irreversible.</strong>
          </li>
          <li>
            <strong>Write the final archive.</strong> The finalized archive binds the final
            election state and the saved record.
          </li>
          <li>
            <strong>Independently verify the final archive</strong> on the Archive screen — anyone
            with the archive folder can run the same check.
          </li>
          <li>
            <strong>Optionally anchor on Tari Ootle.</strong> Anchoring is organizer-side,
            optional, and non-binding — the final archive stays authoritative on its own.
            The anchor publishes a readable <em>public aggregate election result</em>
            derived only from the verified finalized archive: schema, network, election id,
            question, eligible/accepted/rejected counts, ordered response labels with their
            vote counts, manifest and archive hashes, and the voter-registry and
            ballot-option commitments. Individual ballots, voter identities, credentials,
            enrollment keys, nullifiers, proofs, and transport metadata are NEVER published.
            Individual voters never create an Ootle transaction. Detached evidence written
            beside the archive lets anyone re-verify the anchor independently.
          </li>
        </ol>
      </Card>

      <Card title="Voter transport bundle (ballot-office connection file)">
        <p className="card-body">
          The <strong>voter transport bundle</strong> — shown in the voter app as the{" "}
          <strong>ballot-office connection file</strong> — is a public, election-specific file
          from the ballot office that lets the voter app verify and reach that election's
          private Tor intake, and it pins the public key of the office that signs status
          statements and receipts for this election. It contains no ballot-office private keys,
          and configuring it never grants the voter any organizer ability.
        </p>
        <p className="card-body">It is different from each of these:</p>
        <ul className="guide-facts">
          <li>
            <strong>Your private voter credential</strong> — your secret voting identity, which
            never leaves your control.
          </li>
          <li>
            <strong>Your public enrollment key</strong> — the value the ballot office enrolls; safe
            to share, not enough to vote on its own.
          </li>
          <li>
            <strong>The frozen election package</strong> — the canonical election definition, voter
            list, and responses.
          </li>
          <li>
            <strong>The encrypted ballot file</strong> — your sealed ballot, produced when you
            submit or export.
          </li>
        </ul>
      </Card>

      <Card title="Privacy and safety">
        <ul className="guide-facts">
          <li>
            <strong>Never share your private voting credential</strong> — not with the
            organizer, and not with another voter.
          </li>
          <li>
            <strong>Your public enrollment key is safe to give the organizer.</strong> It is the
            value used for voter enrollment, and it is not enough to vote without the private
            credential.
          </li>
          <li>
            <strong>The organizer cannot recover your credential.</strong> To recover it on this
            or another computer, you need the encrypted credential file or backup plus the
            passphrase. Losing both the saved credential file and any usable backup means losing
            the ability to vote as that registered key.
          </li>
          <li>
            <strong>Copying the same credential to multiple computers does not allow two
            accepted votes in the same election.</strong> The election rejects a second ballot
            from the same registered key.
          </li>
          <li>
            <strong>The passphrase protects the credential file at rest.</strong> It does not
            protect a machine that is already compromised while the credential is unlocked.
          </li>
          <li>
            <strong>Anonymous eligibility, network privacy, and office authentication are
            three separate protections.</strong> The Triptych-style proof hides which eligible
            registry member proved membership; election-bound linkability (nullifier) semantics
            prevent a second accepted ballot from the same credential for that election; Tor
            mitigates network metadata during private delivery; and the pinned ballot-office
            authority from the connection file authenticates <em>who is speaking</em> — signed
            status statements and receipts verify against that office's key. No single layer
            provides all of these on its own: Tor does not authenticate eligibility or the
            ballot office, and the eligibility proof does not hide your network connection.
          </li>
          <li>
            <strong>Ballot content is not permanently secret.</strong> Your choice may appear in
            the final verifiable election record.
          </li>
          <li>
            <strong>Network anonymity depends on the submission route,</strong> not on the
            eligibility proof. The proof itself does not hide your network connection, and Tor
            alone does not provide voting anonymity.
          </li>
          <li>
            <strong>Ootle anchoring is aggregate and organizer-side.</strong> Voters never
            send an Ootle transaction. The anchor publishes a readable{" "}
            <em>public aggregate election result</em> — question, ordered response labels
            and counts, participation totals, and the archive commitments — but never
            individual ballots, voter identities, nullifiers, proofs, or transport metadata.
            The Ootle transaction itself is not a private/stealth ballot, and archive
            verification always happens before any anchor is prepared.
          </li>
        </ul>
        <Notice tone="info">
          Private online submission is optional. When Tor is available, the app can manage the
          private connection for both the voter and the ballot office. Offline encrypted
          ballot-file delivery remains available as a fallback. Tor protects the delivery path;
          the voting protocol provides anonymous eligibility and election-bound one-vote
          enforcement.
        </Notice>
      </Card>
    </>
  );
}

/**
 * Click-to-enlarge lightbox for the Guide diagram. Presentation-only: it
 * displays the same image the Guide already renders at full viewport size,
 * centered, with a visible Close button. Escape closes it, clicking the
 * backdrop closes it, and focus returns to the trigger on close.
 */
function GuideDiagramLightbox({
  src,
  alt,
  onClose,
}: {
  src: string;
  alt: string;
  onClose: () => void;
}) {
  const closeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    const previouslyFocused =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previouslyFocused?.focus();
    };
  }, [onClose]);

  return (
    <div
      className="guide-lightbox-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label="Workflow diagram"
      onClick={onClose}
    >
      <div
        className="guide-lightbox"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="guide-lightbox-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            ref={closeRef}
          >
            Close
          </button>
        </div>
        <img className="guide-lightbox-image" src={src} alt={alt} draggable={false} />
      </div>
    </div>
  );
}
