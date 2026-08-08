/**
 * Lightweight inline SVG iconography for the analytics dashboard.
 *
 * No icon library is used (ADR-0007 keeps the frontend dependency surface
 * minimal and the offline package cache does not include one). These are
 * small, accessible, theme-aware through `currentColor`.
 */

/** A restrained lock icon used to indicate sealed results/participation.
 *  Information is never encoded by color alone: the icon always carries a
 *  textual label alongside it. */
export function LockIcon({
  label = "Sealed",
  size = 16,
}: {
  label?: string;
  size?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <title>{label}</title>
      <rect x="4" y="11" width="16" height="9" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}

/** A calm checkmark icon for disclosed/available states. */
export function CheckIcon({
  label = "Available",
  size = 16,
}: {
  label?: string;
  size?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <title>{label}</title>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
