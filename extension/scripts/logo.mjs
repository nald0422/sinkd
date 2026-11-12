// The sinkd logo: depression contours. Maps draw a sinkhole as closed
// contour lines that crowd together on the steep side and close around a
// low point; here three rings stack on one low point (clay, the brand's
// one hue) and fan out toward the top. Otherwise in the brand's grays,
// white to ink; two variants of the same mark:
//
//   paper     ink lines on snow (for dark surroundings, where it stands out)
//   graphite  white lines on ink (for light surroundings; also the
//             extension's icon, which must hold on light and dark toolbars)
//
// Writes the brand kit into docs/brand/<variant>/:
//
//   logo.svg, logo-small.svg    vector masters (the small one for 32 px; 16 px
//                               is drawn pixel by pixel)
//   store-icon-128.png          Chrome Web Store icon: 96 px of artwork in
//                               a transparent 128 px square, as the store asks
//   icon16/32/48/128.png        toolbar and extension-page icons
//   wordmark.png                mark and name, on a transparent background
//
// and the graphite icons into static/icons/, which the extension ships,
// plus the paper icon32 the popup's header shows in dark mode.
//
//   node scripts/logo.mjs

import { cpSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { chromium } from "playwright-core";

/** The brand's grays, white to ink. */
export const INK = "#161616";
export const GRAPHITE = "#3A3A3A";
export const SMOKE = "#6B6B6B";
export const PEWTER = "#8A8A8A";
export const SILVER = "#BDBDBD";
export const MIST = "#E2E2E2";
export const SNOW = "#F4F4F4";
export const WHITE = "#FFFFFF";
/** The low point: the one hue in the brand. */
export const CLAY = "#B87A5E";

export const VARIANTS = {
  paper: { tile: SNOW, line: INK, dot: CLAY, text: INK },
  graphite: { tile: INK, line: WHITE, dot: CLAY, text: WHITE },
};

/** Rings from the outside in, each bottom one `step` above the last. */
const LARGE = { radii: [43, 31, 19], step: 7, w: 3.6, dot: 5.5, bottom: 105 };
/** Fewer, heavier rings, so the shape survives at 16 and 32 px. */
const SMALL = { radii: [45, 25], step: 12, w: 9, dot: 9, bottom: 108 };

/** The mark on a 128 grid. */
export function mark({ tile, line, dot: low }, { radii, step, w, dot, bottom } = LARGE) {
  let s = `<rect width="128" height="128" rx="28" fill="${tile}"/>`;
  radii.forEach((r, i) => {
    const b = bottom - i * step;
    s += `<circle cx="64" cy="${b - r}" r="${r}" fill="none" stroke="${line}" stroke-width="${w}"/>`;
  });
  // The low point sits a step above the innermost ring's floor.
  const floor = bottom - (radii.length - 1) * step;
  return `${s}<circle cx="64" cy="${floor - step - dot + 1}" r="${dot}" fill="${low}"/>`;
}

/**
 * 16 px, pixel by pixel, so the rings stay crisp lines instead of a blur:
 * Z is a ring, P the low point, + the tile.
 */
const PIXELS16 = [
  "................",
  ".++++++++++++++.",
  ".++++ZZZZZZ++++.",
  ".+++Z++++++Z+++.",
  ".++Z++++++++Z++.",
  ".+Z++++++++++Z+.",
  ".+Z+++ZZZZ+++Z+.",
  ".+Z++Z++++Z++Z+.",
  ".+Z++Z+PP+Z++Z+.",
  ".+Z++Z+PP+Z++Z+.",
  ".+Z++Z++++Z++Z+.",
  ".++Z++ZZZZ++Z++.",
  ".+++Z++++++Z+++.",
  ".++++ZZZZZZ++++.",
  ".++++++++++++++.",
  "................",
];

function mark16({ tile, line, dot }) {
  const cells = { Z: [], P: [] };
  PIXELS16.forEach((row, y) => {
    [...row].forEach((c, x) => {
      cells[c]?.push(`<rect x="${x}" y="${y}" width="1" height="1"/>`);
    });
  });
  return (
    `<rect width="16" height="16" rx="3.5" fill="${tile}"/>` +
    `<g shape-rendering="crispEdges"><g fill="${line}">${cells.Z.join("")}</g>` +
    `<g fill="${dot}">${cells.P.join("")}</g></g>`
  );
}

const svg = (body, size, viewBox = "0 0 128 128") =>
  `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="${viewBox}">${body}</svg>`;

const root = resolve(import.meta.dirname, "..");
const brand = resolve(root, "..", "docs", "brand");

if (import.meta.url === `file://${process.argv[1]}`) {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  for (const [name, colors] of Object.entries(VARIANTS)) {
    const out = join(brand, name);
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "logo.svg"), `${svg(mark(colors), 512)}\n`);
    writeFileSync(join(out, "logo-small.svg"), `${svg(mark(colors, SMALL), 512)}\n`);
    const shoot = async (html, width, height, file) => {
      await page.setViewportSize({ width, height });
      await page.setContent(
        `<!doctype html><html><body style="margin:0;background:transparent">${html}</body></html>`,
      );
      await page.screenshot({ path: join(out, file), omitBackground: true });
    };
    await shoot(svg(mark16(colors), 16, "0 0 16 16"), 16, 16, "icon16.png");
    await shoot(svg(mark(colors, SMALL), 32), 32, 32, "icon32.png");
    for (const size of [48, 128]) {
      await shoot(svg(mark(colors), size), size, size, `icon${size}.png`);
    }
    await shoot(svg(mark(colors), 128, "-16 -16 160 160"), 128, 128, "store-icon-128.png");
    await shoot(
      `<div style="display:flex;align-items:center;gap:30px;padding:24px 44px 24px 24px;width:max-content">
        ${svg(mark(colors), 128)}
        <span style="font:500 100px/1 -apple-system,'SF Pro Display','Inter','Helvetica Neue',sans-serif;
          letter-spacing:-0.015em;color:${colors.text};padding-bottom:8px">sinkd</span>
      </div>`,
      560,
      176,
      "wordmark.png",
    );
  }
  await browser.close();
  for (const size of [16, 32, 48, 128]) {
    cpSync(
      join(brand, "graphite", `icon${size}.png`),
      join(root, "static", "icons", `icon${size}.png`),
    );
  }
  cpSync(join(brand, "paper", "icon32.png"), join(root, "static", "icons", "paper32.png"));
  console.log(`wrote ${brand} and the extension's icons`);
}
