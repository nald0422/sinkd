// The sinkd mark: depression contours, three rings stacked on one low
// point. The same geometry as extension/scripts/logo.mjs, on a 128 grid.

const RADII = [43, 31, 19];
const STEP = 7;
const STROKE = 3.6;
const DOT = 5.5;
const BOTTOM = 105;

const VARIANTS = {
  stone: { tile: "#ECE7DD", line: "#2C302C" },
  basalt: { tile: "#2C302C", line: "#D9CDB4" },
} as const;

interface Props {
  size: number;
  variant?: keyof typeof VARIANTS;
  /** Leave out the tile, for the mark on a background of its own color. */
  bare?: boolean;
  className?: string;
}

export function Logo({ size, variant = "stone", bare = false, className }: Props) {
  const { tile, line } = VARIANTS[variant];
  const floor = BOTTOM - (RADII.length - 1) * STEP;
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
          cy={BOTTOM - i * STEP - r}
          r={r}
          fill="none"
          stroke={line}
          strokeWidth={STROKE}
        />
      ))}
      <circle cx="64" cy={floor - STEP - DOT + 1} r={DOT} fill="#B87A5E" />
    </svg>
  );
}
