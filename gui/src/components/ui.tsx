import React, { useState } from "react";

import { describeError } from "../api/errorDisplay";
import type { GuiCommandError } from "../api/types";

/** Dashboard / content card. */
export function Card({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="card" aria-label={title}>
      <h3 className="card-title">{title}</h3>
      {children}
    </section>
  );
}

/** Status pill with a semantic tone. */
export function Pill({
  tone,
  children,
}: {
  tone: "neutral" | "ok" | "warn" | "error" | "info" | "brand";
  children: React.ReactNode;
}) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}

/** Lifecycle-state pill coloring shared by several screens. */
export function LifecyclePill({ state }: { state: string | null | undefined }) {
  if (!state) return <Pill tone="neutral">No election loaded</Pill>;
  switch (state) {
    case "DRAFT":
      return <Pill tone="neutral">{state}</Pill>;
    case "FROZEN":
      return <Pill tone="info">{state}</Pill>;
    case "OPEN":
      return <Pill tone="ok">{state}</Pill>;
    case "CLOSED":
    case "VERIFIED":
      return <Pill tone="warn">{state}</Pill>;
    case "FINALIZED":
      return <Pill tone="brand">{state}</Pill>;
    default:
      return <Pill tone="neutral">{state}</Pill>;
  }
}

/** Full-width bounded hash/digest rendering with the complete value in the
 *  accessible label and tooltip. */
export function HashValue({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="field-value">—</span>;
  return (
    <span className="hash" title={value} aria-label={value}>
      {value}
    </span>
  );
}

/** Label/value row used across detail cards. */
export function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <>
      <span className="field-label">{label}</span>
      <span className="field-value">{children}</span>
    </>
  );
}

/** Banner marking a screen or section as a non-final placeholder. */
export function Placeholder({ children }: { children: React.ReactNode }) {
  return (
    <div className="placeholder-banner" role="note">
      <strong>Placeholder.</strong> {children}
    </div>
  );
}

/** Notice callout. */
export function Notice({
  tone,
  children,
}: {
  tone: "info" | "warn" | "error" | "ok";
  children: React.ReactNode;
}) {
  return (
    <div className={`notice notice-${tone}`} role={tone === "error" ? "alert" : "note"}>
      {children}
    </div>
  );
}

/** Collapsible Advanced details section. Uses the native <details> element so
 *  it is keyboard accessible and announces expanded/collapsed state. */
export function DetailsSection({
  summary,
  children,
}: {
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <details className="details-section">
      <summary className="details-summary">{summary}</summary>
      <div className="details-body">{children}</div>
    </details>
  );
}

/** Copies a non-secret hash or ID to the clipboard. Only used for public,
 *  non-secret digests and identifiers. */
export function CopyButton({
  value,
  label = "Copy",
}: {
  value: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const onClick = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <button
      type="button"
      className="btn btn-secondary btn-copy"
      onClick={() => void onClick()}
      aria-label={`${label}: ${value}`}
    >
      {copied ? "Copied" : label}
    </button>
  );
}

/** Renders a structured backend error as an alert card with a concise title,
 *  the safe bounded message, and the stable machine code under an Advanced
 *  details disclosure. Keyboard-accessible dismissal when `onDismiss` is set. */
export function ErrorCard({
  error,
  onDismiss,
}: {
  error: GuiCommandError;
  onDismiss?: () => void;
}) {
  const display = describeError(error);
  return (
    <div className="error-card" role="alert" aria-live="assertive">
      <div className="error-card-main">
        <div className="error-card-title">{display.title}</div>
        <div className="error-card-message">{display.message}</div>
        <DetailsSection summary="Advanced details">
          <div className="field-list">
            <Field label="Machine code">
              <span className="hash">{display.code}</span>
            </Field>
            <Field label="Category">
              <span className="hash">{display.category}</span>
            </Field>
            {display.context && (
              <Field label="Context">
                <span className="hash">{display.context}</span>
              </Field>
            )}
          </div>
        </DetailsSection>
      </div>
      {onDismiss && (
        <button
          type="button"
          className="btn btn-secondary error-card-dismiss"
          onClick={onDismiss}
          aria-label="Dismiss error"
        >
          Dismiss
        </button>
      )}
    </div>
  );
}

/** Renders a backend boundary error, if present, as a structured ErrorCard. */
export function BackendErrorNotice({
  error,
  onDismiss,
}: {
  error: GuiCommandError | null;
  onDismiss?: () => void;
}) {
  if (!error) return null;
  return <ErrorCard error={error} onDismiss={onDismiss} />;
}
