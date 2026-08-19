/**
 * Small presentation-only progression indicator shared by the Vote screen
 * (voter journey stages) and Manage Election (organizer lifecycle). It renders
 * the EXISTING `.steps`/`.step` visual language: completed steps carry a
 * checkmark, the current step is emphasized (`aria-current="step"`), and
 * future steps stay subdued. All derivation happens in the pure helpers
 * (`voterProgress.ts`, `lifecycle.ts`); this component only paints.
 */

import type { ProgressStep } from "../voterProgress";

export function ProgressSteps({
  label,
  steps,
}: {
  /** Accessible name for the progression list. */
  label: string;
  steps: ProgressStep[];
}) {
  return (
    <ol className="steps progress-steps" aria-label={label}>
      {steps.map((step, index) => (
        <li
          key={step.key}
          className={`step${
            step.state === "done"
              ? " step-done"
              : step.state === "current"
                ? " step-current"
                : ""
          }`}
          aria-current={step.state === "current" ? "step" : undefined}
        >
          {step.state === "done" && (
            <span className="step-check" aria-hidden="true">
              ✓
            </span>
          )}
          {step.label}
          {index < steps.length - 1 && (
            <span className="step-arrow" aria-hidden="true">
              →
            </span>
          )}
        </li>
      ))}
    </ol>
  );
}
