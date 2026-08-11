import { useMemo } from "react";
import { encode } from "uqr";

/** Quiet zone (in modules) around the QR matrix, required for reliable
 *  scanner detection. */
const QUIET_ZONE = 4;

/**
 * Locally generated QR code rendered as inline SVG.
 *
 * The payload is encoded entirely in-process by the `uqr` library: there is
 * no network request, remote QR API, external image service, or analytics
 * involved, and no wallet/payment behavior of any kind. The matrix is
 * always rendered dark-on-white so it scans reliably in both dark and
 * light themes; module colors are never inverted.
 */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { path, size } = useMemo(() => {
    const { data, size } = encode(value, { ecc: "M", border: 0 });
    let path = "";
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (data[y][x]) path += `M${x} ${y}h1v1h-1z`;
      }
    }
    return { path, size };
  }, [value]);

  const total = size + QUIET_ZONE * 2;
  return (
    <svg
      className="qr-code"
      role="img"
      aria-label={label}
      viewBox={`${-QUIET_ZONE} ${-QUIET_ZONE} ${total} ${total}`}
      shapeRendering="crispEdges"
    >
      <rect
        x={-QUIET_ZONE}
        y={-QUIET_ZONE}
        width={total}
        height={total}
        fill="#ffffff"
      />
      <path d={path} fill="#000000" />
    </svg>
  );
}
