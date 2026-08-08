import { useState } from "react";

import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { useAppState } from "../state/AppState";
import { Card, Field, LifecyclePill, Notice, Placeholder } from "../components/ui";

const STEPS = [
  "Import credential",
  "Review ballot",
  "Cast vote",
  "Export ballot package",
] as const;

/**
 * Vote (voter) — staged-state screen (Slice 5A4).
 *
 * Steps: Import credential → Review ballot → Cast vote → Export ballot
 * package. When a real election is loaded, read-only election information and
 * the option list render from the real gui-core summary. Credential import and
 * proof construction are not yet enabled in 5A4; those steps are clearly marked
 * and never simulated. Voter key generation is a separately reviewed crypto
 * change (see the 5A2 design note).
 */
export function Vote() {
  const { election } = useAppState();
  const [step, setStep] = useState(0);
  const presentation = presentationFor(election);

  return (
    <>
      <h1 className="screen-header">Vote</h1>
      <p className="screen-lede">
        Cast a privacy-preserving approval ballot against a frozen election. Submission is
        file-based: you export a canonical ballot package and deliver it to the organizer out
        of band.
      </p>

      {election ? (
        <Card title="Loaded election (read-only)">
          <div className="field-list">
            <Field label="Election">
              {election.election_id_text ?? election.election_id_hex}
            </Field>
            <Field label="Lifecycle">
              <LifecyclePill state={election.lifecycle_state} />
            </Field>
            <Field label="Rules">{approvalRuleText(election)}</Field>
            <Field label="Proof suite">{election.proof_suite_id}</Field>
          </div>
        </Card>
      ) : (
        <Notice tone="info">
          No election is loaded. Load one from the Manage Election screen to review its ballot.
        </Notice>
      )}

      <ol className="steps" aria-label="Voting steps">
        {STEPS.map((label, index) => (
          <li
            key={label}
            className={`step${index === step ? " step-current" : ""}${index < step ? " step-done" : ""}`}
            aria-current={index === step ? "step" : undefined}
          >
            {index + 1} · {label}
          </li>
        ))}
      </ol>

      {step === 0 && (
        <Card title="Import credential">
          <Placeholder>
            Credential import is not yet enabled in Slice 5A4. It will be per session and never
            persisted. Voter key generation is a separately reviewed change to the crypto crate
            (deferred before Slice 5A6); this screen will import an existing governance
            credential. No credential material is shown, stored, or transmitted by this
            application.
          </Placeholder>
          <Notice tone="warn">
            A governance key is not a wallet key. Never import a wallet seed or derive one from
            wallet material.
          </Notice>
        </Card>
      )}

      {step === 1 && (
        <Card title="Review ballot">
          {election ? (
            <>
              <p className="card-body">{approvalRuleText(election)}</p>
              <h3>{presentation.selectionHeading}</h3>
              <ul className="option-list" aria-label={presentation.optionSetNoun}>
                {election.candidates.map((option) => (
                  <li key={option.machine_id_hex} className="option-item">
                    <span className="option-marker" aria-hidden="true" />
                    <span>{option.display_name}</span>
                  </li>
                ))}
              </ul>
              <p className="form-hint">{presentation.approvalMeaning}</p>
            </>
          ) : (
            <Placeholder>
              The review layout renders from the loaded option set and adapts its vocabulary to
              the ballot type (candidate election, governance proposal, or ballot measure).
              Nothing here assumes a candidate election. Load an election to see real options.
            </Placeholder>
          )}
        </Card>
      )}

      {step === 2 && (
        <Card title="Cast vote">
          <Placeholder>
            Proof construction is not yet enabled in Slice 5A4. It will happen entirely in the
            Rust crypto/verifier crates in a later slice. This application never implements
            cryptography in JavaScript and never simulates a successful vote.
          </Placeholder>
        </Card>
      )}

      {step === 3 && (
        <Card title="Export ballot package">
          <Placeholder>
            Exports one canonical ballot package file. Not yet enabled in Slice 5A4. Delivery to
            the organizer is out of band; there is no voter network submission protocol.
          </Placeholder>
        </Card>
      )}

      <div className="btn-row">
        <button
          type="button"
          className="btn btn-secondary"
          disabled={step === 0}
          onClick={() => setStep((s) => Math.max(0, s - 1))}
        >
          Back
        </button>
        <button
          type="button"
          className="btn btn-primary"
          disabled={step === STEPS.length - 1}
          onClick={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))}
        >
          Next
        </button>
      </div>
    </>
  );
}
