import React from "react";

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

/** Renders a backend boundary error, if present. */
export function BackendErrorNotice({ message }: { message: string | null }) {
  if (!message) return null;
  return <Notice tone="error">Backend error — {message}</Notice>;
}
