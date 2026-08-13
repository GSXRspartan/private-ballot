import { Card, Notice } from "../components/ui";

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
  return (
    <>
      <h1 className="screen-header">Guide</h1>
      <p className="screen-lede">
        How Tari Private Ballot is meant to be used, by role. Pick the path that matches what
        you are doing: voting in an election, or running one as the organizer.
      </p>

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
            <strong>Use your voting credential.</strong> You need the private voting credential
            corresponding to a public voting key the organizer enrolled before the election was
            frozen. A credential created after the freeze cannot join the election.
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
          This guide describes the intended finished product. Where a capability is not
          available in this build — for example credential import or a production online
          transport — the screens say so rather than pretending it works.
        </Notice>
      </Card>
    </>
  );
}
