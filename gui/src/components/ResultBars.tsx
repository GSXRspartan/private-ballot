import { approvalBps, approvalLabel, describeLeadingOutcome, formatPercent } from "../lifecycle";
import type { GuiTallySummaryV1 } from "../api/types";
import { presentationFor } from "../ballot/ballotTypes";
import type { GuiElectionSummaryV1 } from "../api/types";

/**
 * Horizontal result bars for the final disclosed tally (Slice 5A5, section J).
 *
 * Each bar independently represents the percentage of accepted ballots that
 * approved one option. For multi-approval ballots the bars do NOT sum to 100%
 * because voters may approve multiple options; pie charts are intentionally
 * not used. Abstentions are shown separately as a share of accepted ballots.
 *
 * The leading/tie state is rendered as text (never an invented winner).
 *
 * While results are sealed, this component renders a locked neutral state and
 * no per-option values.
 */
export function ResultBars({
  tally,
  election,
}: {
  tally: GuiTallySummaryV1 | null;
  election: GuiElectionSummaryV1 | null;
}) {
  if (!tally) {
    return (
      <div className="result-bars-sealed" role="img" aria-label="Results are sealed until voting closes.">
        <div className="result-bars-sealed-label">Locked</div>
        <p className="card-body">Results are sealed until voting closes.</p>
      </div>
    );
  }

  const accepted = tally.accepted_ballots;
  const presentation = presentationFor(election);
  const optionNoun = presentation.optionNoun;

  return (
    <div className="result-bars" role="list" aria-label="Final results by option">
      {tally.counts.map((count) => {
        const bps = approvalBps(count.approvals, accepted);
        const fillWidth = Math.max(0, Math.min(100, bps / 100));
        const label = approvalLabel(optionNoun, count.approvals, accepted);
        const name = count.display_name || count.candidate_id_hex;
        return (
          <div className="result-bar-row" role="listitem" key={count.candidate_id_hex}>
            <div className="result-bar-head">
              <span className="result-bar-name">{name}</span>
              <span className="result-bar-pct">{formatPercent(bps)}</span>
            </div>
            <div
              className="result-bar-track"
              role="img"
              aria-label={`${name}: ${label}`}
            >
              <div
                className="result-bar-fill"
                style={{ width: `${fillWidth}%` }}
              />
            </div>
            <span className="result-bar-sub">{count.approvals} approvals</span>
          </div>
        );
      })}

      <div className="result-bar-row result-bar-abstentions" role="listitem">
        <div className="result-bar-head">
          <span className="result-bar-name">Abstentions</span>
          <span className="result-bar-pct">
            {formatPercent(accepted > 0 ? Math.min(10000, Math.trunc((tally.abstentions * 10000) / accepted)) : 0)}
          </span>
        </div>
        <p className="result-bar-sub">{tally.abstentions} accepted ballots abstained</p>
      </div>

      <div className="result-bars-leading" aria-live="polite">
        {describeLeadingOutcome(tally)}
      </div>
    </div>
  );
}
