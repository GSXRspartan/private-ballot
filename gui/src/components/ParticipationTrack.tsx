import { formatPercent, participationAccessibleText } from "../lifecycle";
import type { GuiParticipationSummaryV1 } from "../api/types";

/**
 * Professional linear participation progress track (Slice 5A5).
 *
 * A horizontal track is used instead of a line chart because the archive's
 * ingest sequence is ordering metadata only (not a wall-clock timestamp),
 * so no authoritative turnout-over-time series exists. Fabricating a trend
 * from current totals would be misleading; this track shows the current
 * disclosed participation only.
 *
 * The component is accessible: a screen reader reads the textual equivalent
 * from `participationAccessibleText`, never the SVG geometry. Color is never
 * the sole information channel (the numeric label is always rendered).
 *
 * When participation is sealed, the track renders a neutral empty state with
 * a restrained sealed-state label (the OPEN-lifecycle default "Hidden while
 * voting is open"; callers may pass a lifecycle-aware label) and lock
 * affordance; no numeric value is shown, so a withheld value never appears as
 * a misleading 0%.
 */
export function ParticipationTrack({
  summary,
  sealedLabel = "Hidden while voting is open",
}: {
  summary: GuiParticipationSummaryV1 | null;
  /** Truthful sealed-state label; callers may pass a lifecycle-aware label
   *  (e.g. "Voting has not opened yet" before voting opens). */
  sealedLabel?: string;
}) {
  const disclosed =
    summary !== null &&
    summary.participation_visibility !== "SEALED_UNTIL_CLOSE" &&
    summary.participation_basis_points !== null;
  const bps = disclosed ? (summary?.participation_basis_points ?? 0) : 0;
  const pctLabel = formatPercent(disclosed ? bps : null);
  const a11y = participationAccessibleText(summary);
  const fillWidth = Math.max(0, Math.min(100, bps / 100));

  return (
    <div
      className="participation-track"
      role="img"
      aria-label={a11y}
    >
      <div className="participation-track-head">
        <span className="participation-track-value" aria-hidden="true">
          {disclosed ? pctLabel : sealedLabel}
        </span>
        {summary?.accepted_ballots !== null && summary?.accepted_ballots !== undefined && (
          <span className="participation-track-sub" aria-hidden="true">
            {summary.accepted_ballots} of {summary.eligible_voters} eligible voters
          </span>
        )}
      </div>
      <div
        className="participation-track-bar"
        role="presentation"
        aria-hidden="true"
      >
        <div
          className="participation-track-fill"
          style={{ width: disclosed ? `${fillWidth}%` : "0%" }}
        />
      </div>
    </div>
  );
}
