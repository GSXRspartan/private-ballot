import { Card, Notice } from "../components/ui";
import { useTheme } from "../theme/ThemeProvider";

import flowDiagramDark from "../assets/guide/private-ballot-flow-dark.png";
import flowDiagramLight from "../assets/guide/private-ballot-flow-light.png";

/** Alt text for the workflow overview diagram. The diagram communicates the
 *  essential credential workflow, so the description states it fully; the
 *  same text serves both theme variants. */
const FLOW_DIAGRAM_ALT =
  "Private Ballot workflow: voters create and keep their own private credentials, share only public enrollment keys with the ballot office, create anonymous ballot packages, and the ballot office verifies, tallies, finalizes, and may anchor the final archive to Ootle.";

/**
 * Guide — the built-in, role-based walkthrough for the intended finished
 * Tari Private Ballot product. It has two obvious paths (Voter and
 * Organizer / Ballot Office) written in plain language, plus a short
 * privacy and safety section.
 *
 * This screen is presentation-only: it calls no backend commands, handles
 * no secret material, and never claims a capability that is not
 * implemented. Where final-product capability is not available today, the
 * wording says "intended" rather than pretending it works now.
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
            <strong>Receive the election files.</strong> The organizer shares the election
            package with you. Load it on the Vote screen; the app checks that the files belong
            together and have not been altered.
          </li>
          <li>
            <strong>Review the election.</strong> Check the election identity, ballot question,
            choices, and how many you may select before continuing. For newer election files,
            the question and response choices are cryptographically bound to the frozen election
            definition; legacy files honestly say when no canonical question exists.
          </li>
          <li>
            <strong>Use your voter credential.</strong> Your voter credential is your private
            voting identity, not a Tari wallet seed. Give the organizer only your public
            enrollment key before the election is frozen; keep the encrypted credential file,
            its passphrase, and any backup for yourself.
          </li>
          <li>
            <strong>Verify your eligibility.</strong> The app checks your public voting key
            against the election's eligible voter list.
          </li>
          <li>
            <strong>Choose your response.</strong> Selecting a response does not submit a vote;
            you can change it any time before creating the proof.
          </li>
          <li>
            <strong>Create the anonymous eligibility proof.</strong> This proves your credential
            belongs to the eligible voter set without revealing which eligible voter you are.
          </li>
          <li>
            <strong>Submit through the approved route.</strong> Use the election's approved
            private or offline submission route — typically saving a ballot file and delivering
            it through the election's approved intake method.
          </li>
          <li>
            <strong>Track your ballot's status.</strong> The voter workflow can show local
            preparation and transport receipt status: received, accepted by the organizer, or
            rejected. Inclusion and Ootle anchoring are later checked from the published archive
            and organizer evidence.
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
            <strong>Enroll eligible voters.</strong> Collect and enroll eligible{" "}
            <em>public</em> voting keys. You never handle voters' private credentials.
          </li>
          <li>
            <strong>Define responses and rules.</strong> Add the responses voters can choose and
            the selection rules (minimum, maximum, abstention).
          </li>
          <li>
            <strong>Review carefully, then freeze.</strong>{" "}
            <strong>Freezing is irreversible:</strong> it locks the election definition, the
            voter list, and the ballot responses.
          </li>
          <li>
            <strong>Distribute the election files</strong> to voters, then{" "}
            <strong>open voting</strong>.
          </li>
          <li>
            <strong>Receive ballots.</strong> Import ballot files through the approved intake
            path. Each ballot is verified, and a ballot from the same voter is never counted
            twice.
          </li>
          <li>
            <strong>Monitor only what is permitted.</strong> While voting is open, participation
            detail is hidden; only permitted aggregate information is shown.
          </li>
          <li>
            <strong>Close voting.</strong> <strong>Closing is irreversible:</strong> no new
            ballots are accepted afterwards.
          </li>
          <li>
            <strong>Compute the tally and mark it verified.</strong> This records completion of
            public verification before finalization.
          </li>
          <li>
            <strong>Finalize the election.</strong>{" "}
            <strong>Finalizing is irreversible.</strong>
          </li>
          <li>
            <strong>Write the final archive.</strong> The finalized archive binds the final
            election state and the saved record.
          </li>
          <li>
            <strong>Verify the final archive independently</strong> on the Archive screen — anyone
            with the archive folder can run the same check.
          </li>
          <li>
            <strong>Anchor when configured.</strong> The verified finalized aggregate archive can
            optionally be anchored on Ootle as an organizer-side, aggregate operation. Publish the
            archive and verification evidence for voters and auditors.
          </li>
        </ol>
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
            <strong>The eligibility proof hides which eligible registry member voted.</strong>{" "}
            It proves membership in the eligible voter set, nothing more.
          </li>
          <li>
            <strong>Ballot content is not permanently secret.</strong> Your choice may appear in
            the final verifiable election record.
          </li>
          <li>
            <strong>Network anonymity depends on the submission route,</strong> not on the
            eligibility proof. The proof itself does not hide your network connection.
          </li>
          <li>
            <strong>Ootle anchoring is aggregate and organizer-side.</strong> Voters never send
            an Ootle transaction; an anchor covers the whole archive commitment, not individual
            ballots.
          </li>
        </ul>
        <Notice tone="info">
          This guide describes the desktop workflow in this build. Private online transport is
          still shown only when the backend reports it is available; otherwise voters save a
          ballot file and deliver it through the election's approved intake method.
        </Notice>
      </Card>
    </>
  );
}
