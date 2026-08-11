import React, { useEffect, useRef, useState } from "react";

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
  ariaLabel,
}: {
  value: string;
  label?: string;
  /** Accessible name override. Defaults to `"${label}: ${value}"`. */
  ariaLabel?: string;
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
      aria-label={ariaLabel ?? `${label}: ${value}`}
    >
      {copied ? "Copied" : label}
    </button>
  );
}

/** Renders a structured backend error as an alert card in plain-language
 *  order: what happened, what the user can do next, then the diagnostic
 *  codes under a Technical details disclosure. Keyboard-accessible
 *  dismissal when `onDismiss` is set. */
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
        <div className="error-card-next">{display.nextStep}</div>
        <DetailsSection summary="Technical details">
          <div className="field-list">
            <Field label="Error code">
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

/**
 * Modal confirmation dialog for irreversible or destructive actions.
 *
 * Keyboard behavior: focus moves to the Cancel button when the dialog opens,
 * Escape cancels, and focus returns to the element that opened the dialog
 * when it closes. The caller decides whether the confirm action is styled as
 * destructive (`danger`).
 */
export function ConfirmDialog({
  title,
  body,
  confirmLabel,
  confirmTone = "primary",
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  confirmTone?: "primary" | "danger";
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const titleId = useRef(`confirm-title-${Math.random().toString(36).slice(2)}`);

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    cancelRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previouslyFocused?.focus();
    };
  }, [onCancel]);

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby={titleId.current}>
      <div className="modal">
        <h3 id={titleId.current} className="modal-title">
          {title}
        </h3>
        <div className="modal-body">{body}</div>
        <div className="modal-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onCancel}
            disabled={busy}
            ref={cancelRef}
          >
            Cancel
          </button>
          <button
            type="button"
            className={`btn ${confirmTone === "danger" ? "btn-danger" : "btn-primary"}`}
            onClick={onConfirm}
            disabled={busy}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
