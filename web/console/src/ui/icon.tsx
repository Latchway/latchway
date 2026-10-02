import type { CSSProperties } from "react";

import { ICONS, type IconName, type IconNode } from "./icon-data";
import { cx } from "./cx";

export type { IconName } from "./icon-data";

interface IconProps {
  className?: string;
  /** Accessible name. Without it the icon is decorative and hidden from assistive technology. */
  label?: string;
  name: IconName;
  size?: number;
  spin?: boolean;
  style?: CSSProperties;
}

/** Galva icon in currentColor (brand marks keep their own colors). */
export function Icon({ className, label, name, size, spin, style }: IconProps) {
  const icon = ICONS[name];
  const sized = size ? { height: size, width: size, ...style } : style;
  const a11y = label ? { "aria-label": label, role: "img" } : { "aria-hidden": true };
  return (
    <span className={cx("lw-icon", spin && "lw-spin", className)} style={sized} {...a11y}>
      {icon.kind === "filled" ? (
        <svg fill="none" focusable="false" height="1em" viewBox={icon.viewBox} width="1em" xmlns="http://www.w3.org/2000/svg">
          {(icon.nodes as readonly IconNode[]).map(([tag, attributes], index) =>
            tag === "rect" ? <rect key={index} {...attributes} /> : <path key={index} {...attributes} />
          )}
        </svg>
      ) : (
        <svg
          fill="none"
          focusable="false"
          height="1em"
          stroke="currentColor"
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.8}
          viewBox="0 0 24 24"
          width="1em"
        >
          {icon.paths.map((d) => <path d={d} key={d} />)}
        </svg>
      )}
    </span>
  );
}

/** The Latchway mark: an accent tile with an "L" and a latch bolt. */
export function Logo({ className }: { className?: string }) {
  return (
    <span aria-label="Latchway" className={cx("lw-logo", className)} role="img">
      <svg height={24} viewBox="0 0 24 24" width={24}>
        <rect fill="var(--accent-primary)" height={22} rx={6.5} width={22} x={1} y={1} />
        <path d="M8.5 6.5v10.5h7.5" fill="none" stroke="#ffffff" strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.4} />
        <path d="M12.5 11.75h5" fill="none" stroke="#ffffff" strokeLinecap="round" strokeOpacity={0.7} strokeWidth={2.4} />
      </svg>
    </span>
  );
}
