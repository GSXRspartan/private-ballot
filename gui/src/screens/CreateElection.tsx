import { useState } from "react";

import { BALLOT_PRESENTATIONS, BALLOT_TYPE_LABELS, BallotType } from "../ballot/ballotTypes";
import { Card, Notice, Placeholder } from "../components/ui";

/**
 * Create Election (organizer) — staged-state screen.
 *
 * Election creation (manifest, registry, option-set construction) is not wired
 * in this slice. This screen shows the intended structure and the
 * ballot-type-driven layout only; nothing is written to disk here and there
 * are no Save/Create actions. The creation workflow is being added in the next
 * organizer slice.
 */
export function CreateElection() {
  const [ballotType, setBallotType] = useState<BallotType>("ballot-measure");
  const presentation = BALLOT_PRESENTATIONS[ballotType];

  return (
    <>
      <h1 className="screen-header">Create Election</h1>
      <p className="screen-lede">
        Define a new election package: election manifest, voter registry, and the canonical
        option set. The three artifacts stay separate canonical files; there is no single-file
        container.
      </p>

      <Placeholder>
        Election creation workflow is being added in the next organizer slice. This screen shows
        the planned structure and ballot-type-driven vocabulary only; nothing is written to disk
        here and there are no Save or Create actions.
      </Placeholder>

      <Card title="Ballot type">
        <div className="radio-group" role="radiogroup" aria-label="Ballot type">
          {(Object.keys(BALLOT_TYPE_LABELS) as BallotType[]).map((type) => (
            <label key={type} className="radio-option">
              <input
                type="radio"
                name="ballot-type"
                value={type}
                checked={ballotType === type}
                onChange={() => setBallotType(type)}
              />
              {BALLOT_TYPE_LABELS[type]}
            </label>
          ))}
        </div>
        <p className="form-hint">
          The ballot type selects presentation vocabulary. The underlying canonical option set
          is identical in every case: ordered options with stable machine IDs and display
          names.
        </p>
      </Card>

      <div className="card-grid">
        <Card title="Election manifest">
          <div className="card-body">
            Versioned manifest binding the registry commitment, the option-set commitment, the
            proof suite, approval limits, and the governance source revision.
          </div>
        </Card>
        <Card title="Voter registry">
          <div className="card-body">
            Frozen snapshot of voter governance public keys. Voters own their keys; the
            authority never sees private keys.
          </div>
        </Card>
        <Card title={presentation.optionSetNoun}>
          <div className="card-body">
            {ballotType === "candidate" &&
              "The people standing for election, in canonical machine-ID order."}
            {ballotType === "governance-proposal" &&
              "The choices offered on the governance proposal, in canonical machine-ID order."}
            {ballotType === "ballot-measure" &&
              "The options offered by the ballot measure, in canonical machine-ID order."}
          </div>
          <ul className="option-list" aria-label={`Example ${presentation.optionSetNoun}`}>
            {[1, 2, 3].map((n) => (
              <li key={n} className="option-item">
                <span className="option-marker" aria-hidden="true" />
                <span>
                  Example {presentation.optionNoun} {n}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Notice tone="info">
        Approval limits (minimum/maximum selections, abstention) come from the manifest and are
        enforced by the backend during intake, not by this form.
      </Notice>
    </>
  );
}
