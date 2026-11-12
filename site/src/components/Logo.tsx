// The sinkd mark: depression contours, three rings stacked on one low
// point in clay, the brand's one hue. The same geometry and colors as
// extension/scripts/logo.mjs, on a 128 grid.

/** The rings from the outside in, each floor `STEP` above the last. */
export const RADII = [43, 31, 19];
export const STEP = 7;
export const STROKE = 3.6;
export const DOT = 5.5;
export const BOTTOM = 105;
/** Where ring `i` is centred. */
export const ringY = (i: number) => BOTTOM - i * STEP - (RADII[i] ?? 0);
/** The low point: a step above the innermost ring's floor. */
export const LOW_Y = BOTTOM - (RADII.length - 1) * STEP - STEP - DOT + 1;
/** The low point's color. */
export const CLAY = "#B87A5E";

const VARIANTS = {
  /** Ink lines on snow: the bare mark on light grounds, the tile on dark ones. */
  paper: { tile: "#F4F4F4", line: "#161616" },
  /** White lines on ink: the bare mark on dark grounds, the tile on light ones. */
  graphite: { tile: "#161616", line: "#FFFFFF" },
} as const;

interface Props {
  size: number;
  variant?: keyof typeof VARIANTS;
  /** Leave out the tile, for the mark on a background of its own color. */
  bare?: boolean;
  className?: string;
}

export function Logo({ size, variant = "paper", bare = false, className }: Props) {
  const { tile, line } = VARIANTS[variant];
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 128 128"
      className={className}
      role="img"
      aria-label="sinkd"
    >
      {!bare && <rect width="128" height="128" rx="28" fill={tile} />}
      {RADII.map((r, i) => (
        <circle
          key={r}
          cx="64"
          cy={ringY(i)}
          r={r}
          fill="none"
          stroke={line}
          strokeWidth={STROKE}
        />
      ))}
      <circle cx="64" cy={LOW_Y} r={DOT} fill={CLAY} />
    </svg>
  );
}
