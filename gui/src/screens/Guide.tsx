import { Card, Notice } from "../components/ui";
import { useTheme } from "../theme/ThemeProvider";

import flowDiagramDark from "../assets/guide/private-ballot-flow-dark.png";
import flowDiagramLight from "../assets/guide/private-ballot-flow-light.png";

/** Alt text for the workflow overview diagram. It describes the current
 *  end-to-end workflow the diagram shows — ballot-office setup, the voter's
 *  anonymous private submission over Tor with an offline fallback, and the
 *  ballot office's reconcile/close/tally/finalize/anchor path. The same text
 *  serves both theme variants (the two PNGs are identical except for palette). */
const FLOW_DIAGRAM_ALT =
  "Private Ballot workflow overview. The ballot office creates and freezes the election, enrolls voters' public enrollment keys, starts private Tor intake, and exports a voter transport bundle. Each voter keeps their own private credential, shares only their public enrollment key, loads the frozen election and the transport bundle, proves anonymous eligibility, chooses a response, and submits the encrypted ballot privately over Tor — or saves an encrypted ballot file for offline delivery — then receives an authenticated organizer receipt. The ballot office reconciles accepted ballots, closes voting, tallies, verifies, writes the final archive, and optionally anchors the aggregate finalized commitment to Tari Ootle.";

/**
 * Guide — the built-in, role-based walkthrough for the Tari Private Ballot
 * product. It has two obvious paths (Voter and Organizer / Ballot Office)
 * written in plain language, a short explanation of the voter transport
 * bundle, and a privacy and safety section.
 *
 * This screen is presentation-only: it calls no backend commands, handles no
 * secret material, and never claims a capability that is not implemented.
 */
export function Guide() {
  const { resolved } = useTheme();
  const flowDiagram = resolved === "dark" ? flowDiagramDark : flowDiagramLight;
  return (
    <>
      <h1 className="screen-header">Guide</h1>
      <p className="screen-lede">
        How Tari Private Ballot is meant to be used, by role. Pick the path that matches what
        you are doing: voting in an election, or running one as the organizer.
      </p>

      <figure className="guide-flow">
        <img
          className="guide-flow-diagram"
          src={flowDiagram}
          alt={FLOW_DIAGRAM_ALT}
          draggable={false}
        />
      </figure>

      <Card title="Voter">
        <ol className="guide-steps">
          <li>
            <strong>Receive the election files.</strong> Load the frozen election package on the
            Vote screen. The app verifies that its canonical files belong together and have not
            been altered.
          </li>
          <li>
            <strong>Review the election.</strong> Confirm the election identity, ballot question,
            response choices, and voting rules before continuing. For newer election files, the
            question and response choices are cryptographically bound to the frozen election
            definition; legacy files honestly say when no canonical question exists.
          </li>
          <li>
            <strong>Use your voter credential.</strong> Your voter credential is your private
            voting identity, not a Tari wallet seed. Keep the encrypted credential file and its
            passphrase private. Give the organizer only your public enrollment key before the
            election is frozen.
          </li>
          <li>
            <strong>Verify anonymous eligibility.</strong> A Triptych-style linkable ring proof
            establishes that you control one credential in the frozen eligible set, without
            revealing which enrolled public key is yours.
          </li>
          <li>
            <strong>Choose your response.</strong> Your choice stays local and can be changed any
            time before the release/export boundary.
          </li>
          <li>
            <strong>Create the anonymous eligibility proof.</strong> The proof and the ballot are
            bound to this frozen election.
          </li>
          <li>
            <strong>Connect privately.</strong> Load and verify the organizer's voter-safe
            transport bundle and let the app manage the local Tor connection for you — no SOCKS
            port, torrc, onion hostname, or descriptor fingerprint to type.
          </li>
          <li>
            <strong>Submit the encrypted ballot.</strong> Normal private-online submission sends
            the encrypted ballot package through Tor. A temporary network or onion-reachability
            failure reuses the <em>exact same</em> staged encrypted submission — it never creates a
            second ballot, a second proof, or another election nullifier.{" "}
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
            starting Tor intake never opens the election on its own.
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
            ballots are accepted afterwards.
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
            <strong>Optionally anchor on Tari Ootle.</strong> The verified finalized{" "}
            <em>aggregate</em> archive commitment can be anchored on Ootle as an organizer-side
            operation. Individual voters never create an Ootle transaction.
          </li>
        </ol>
      </Card>

      <Card title="Voter transport bundle">
        <p className="card-body">
          The <strong>voter transport bundle</strong> is a public, election-specific file from the
          ballot office that lets the voter app verify and reach that election's private Tor
          intake. It contains no ballot-office private keys.
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
            <strong>Anonymous eligibility and network privacy are separate.</strong> The
            Triptych-style proof hides which eligible registry member proved membership;
            election-bound linkability (nullifier) semantics prevent a second accepted ballot from
            the same credential for that election; and Tor mitigates network metadata during
            private ballot delivery. No single layer provides all of these protections on its own.
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
            <strong>Ootle anchoring is aggregate and organizer-side.</strong> Voters never send
            an Ootle transaction; an anchor covers the whole archive commitment, not individual
            ballots, and the Ootle transaction itself is not a private/stealth ballot.
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
