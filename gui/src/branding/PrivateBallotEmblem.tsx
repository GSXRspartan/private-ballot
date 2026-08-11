/**
 * Tari Private Ballot community emblem (React rendering).
 *
 * Renders the EXACT approved logo artwork. The source of truth is
 * gui/design/private-ballot-logo-reference.png; the files in gui/public are
 * derived directly from it (no redrawn, reinterpreted, or regenerated art).
 * Only the flat surrounding background was made transparent (artwork pixels
 * are byte-identical to the approved crops), so the emblem blends into the
 * header and About card surfaces instead of sitting on a visible rectangle:
 *
 *   /private-ballot-logo-dark.png    full emblem + equation, dark variant
 *   /private-ballot-logo-light.png   full emblem + equation, light variant
 *   /private-ballot-mark-dark.png    square mark tile, dark variant
 *   /private-ballot-mark-light.png   square mark tile, light variant
 *
 * The official Tari logo is NOT the application identity.
 *
 * Two variants:
 *   - "full":    ring + envelope + check + the equation underneath. For the
 *                About screen identity lockup.
 *   - "compact": square mark tile. For the titlebar-scale header brand and
 *                small icon usages.
 *
 * Theme support: the resolved theme selects the matching artwork variant
 * (dark-navy art on the dark theme, light art on the light theme).
 */

import React from "react";

import { useTheme } from "../theme/ThemeProvider";

interface EmblemProps {
  variant: "full" | "compact";
  /** Accessible label. When `decorative` is true the emblem is hidden from
   *  assistive technology instead. */
  title?: string;
  decorative?: boolean;
  className?: string;
}

const PrivateBallotEmblem: React.FC<EmblemProps> = ({
  variant,
  title = "Tari Private Ballot emblem",
  decorative = false,
  className,
}) => {
  const { resolved } = useTheme();
  const theme = resolved === "dark" ? "dark" : "light";
  const src =
    variant === "full"
      ? `/private-ballot-logo-${theme}.png`
      : `/private-ballot-mark-${theme}.png`;
  return (
    <img
      src={src}
      alt={decorative ? "" : title}
      aria-hidden={decorative || undefined}
      draggable={false}
      className={className}
    />
  );
};

export default PrivateBallotEmblem;
