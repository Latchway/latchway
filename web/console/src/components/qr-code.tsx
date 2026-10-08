import { encode } from "uqr";

/** A QR code drawn as one SVG path from the encoder's module grid; nothing is fetched or injected as HTML. */
export function QrCode({ label, size = 176, value }: { label: string; size?: number; value: string }) {
  const { data } = encode(value, { ecc: "M", border: 2 });
  const count = data.length;
  let path = "";
  data.forEach((row, y) => row.forEach((dark, x) => { if (dark) path += `M${x} ${y}h1v1h-1z`; }));
  return (
    <svg aria-label={label} className="lw-qr" height={size} role="img" shapeRendering="crispEdges" viewBox={`0 0 ${count} ${count}`} width={size}>
      <rect fill="#ffffff" height={count} width={count} />
      <path d={path} fill="#000000" />
    </svg>
  );
}
