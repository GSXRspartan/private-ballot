import { useState } from "react";

import { approvalRuleText, presentationFor } from "../ballot/ballotTypes";
import { useAppState } from "../state/AppState";
import { Card, Notice, Pill, Placeholder } from "../components/ui";

const STEPS = [
  "Import credential",
  "Load election",
  "Review ballot",
  "Cast ballot",
  "Export ballot package",
  "Confirmation",
] as const;

/**
 * Vote (voter) — placeholder flow.
 *
 * Steps: Import credential → Load election → Review ballot → Cast ballot →
 * Export ballot package → Confirmation. Only the election review renders
 * real data (the loaded election summary). Proof construction and package
 * export are implemented in a later slice; voter key generation is a
 * separately reviewed crypto change (see the 5A2 design note).
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
            Credential import is per session and is never persisted. Voter key generation is a
            separately reviewed change to the crypto crate (deferred before Slice 5A6); this
            screen will import an existing governance credential. No credential material is
            shown, stored, or transmitted by this application.
          </Placeholder>
          <Notice tone="warn">
            A governance key is not a wallet key. Never import a wallet seed or derive one from
            wallet material.
          </Notice>
        </Card>
      )}

      {step === 1 && (
        <Card title="Load election">
          <Placeholder>
            The voter loads the election package (manifest, registry, option set) published by
            the organizer and independently verifies its bindings before voting. The backend
            loader enforces this; wiring lands with the voter slice.
          </Placeholder>
          {election ? (
            <p className="card-body">
              Currently loaded in this shell:{" "}
              <strong>{election.election_id_text ?? election.election_id_hex}</strong> (
              {election.candidates.length} {presentation.optionSetNoun.toLowerCase()}).
            </p>
          ) : (
            <p className="card-body">No election is loaded in this shell.</p>
          )}
        </Card>
      )}

      {step === 2 && (
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
              Nothing here assumes a candidate election.
            </Placeholder>
          )}
        </Card>
      )}

      {step === 3 && (
        <Card title="Cast ballot">
          <Placeholder>
            Proof construction happens entirely in the Rust crypto/verifier crates in a later
            slice. This application never implements cryptography in JavaScript.
          </Placeholder>
        </Card>
      )}

      {step === 4 && (
        <Card title="Export ballot package">
          <Placeholder>
            Exports one canonical ballot package file. Delivery to the organizer is out of
            band; there is no voter network submission protocol.
          </Placeholder>
        </Card>
      )}

      {step === 5 && (
        <Card title="Confirmation">
          <Placeholder>
            Shows the exported package digest and the delivery instructions. Acceptance is
            confirmed by the organizer&rsquo;s intake decision and is publicly verifiable in
            the final archive.
          </Placeholder>
          <Pill tone="info">File-based submission MVP</Pill>
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
