// Store images, into ../release/, in the brand's colors (scripts/logo.mjs).
// The store's are dark, as stores show them best: the mark's contour lines
// spread out behind the product from a clay low point, a headline at the
// top, the name at the bottom left.
//
//   screenshot-1-overview.png      the popup over the page, and what sinkd does
//   screenshot-2-before-after.png  a page without and with the extension
//   screenshot-3-live-log.png      the popup's live log, on that page
//   screenshot-4-privacy.png       links, cookies, fingerprints, GPC, WebRTC
//   screenshot-5-every-app.png     the sinkd command, for every app
//   promo-440x280.png              the small promo tile
//   marquee-1400x560.png           the marquee promo tile
//   og-1200x630.png                the link preview image, for the website
//   page-before.png, page-after.png  the before/after captures (the website builds
//                                    the page itself: site/src/components/PageSweep.tsx)
//
//   node scripts/store-images.mjs [--extension dist]
//
// Everything runs in Playwright's Chromium with throwaway profiles. The
// before/after is a real render: a made-up news site served from a local
// server, its ads from a host EasyList blocks, in boxes with class names
// EasyList hides (not ones the compiler leaves out as detector bait), once
// in a browser without
// the extension and once with the build in --extension. The popup's tab
// lookup is stubbed to report that site. For the log, a copy of the build
// gets declarativeNetRequestFeedback, so the popup can read a tab it
// wasn't opened from; the store build doesn't have it and doesn't need it.

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { chromium } from "playwright-core";

import { CLAY, INK, MIST, mark, SILVER, SMOKE, SNOW, VARIANTS, WHITE } from "./logo.mjs";

/** VS Code's Dark+ terminal, as the popup's log console has it. */
const TERM = { bg: "#1E1E1E", bar: "#323233", dot: "#5A5A5A", text: "#D4D4D4", red: "#F14C4C" };

const root = resolve(import.meta.dirname, "..");
const { values } = parseArgs({ options: { extension: { type: "string" } } });
const extension = resolve(root, values.extension ?? "dist");
const release = resolve(root, "..", "release");
mkdirSync(release, { recursive: true });

const MUTED = SMOKE;
const SITE = "theledger.example";

// `sinkd check` output, captured from the real command (resolver installed
// with its default lists; 2026-11-09).
const TERMINAL = `$ sinkd check ad.doubleclick.net

Resolver (every app; DNS name ad.doubleclick.net):
  BLOCKED by \`ad.doubleclick.net\` in a blocklist: answered 0.0.0.0 / ::
  unblock it with \`sinkd allow add ad.doubleclick.net\`

Extension, network (browser only):
  BLOCKED by \`||ad.doubleclick.net^\`
    easylist, line 58629 (ruleset "ads"); the extension applies it

$ sinkd check googletagmanager.com

Resolver (every app; DNS name googletagmanager.com):
  BLOCKED by \`googletagmanager.com\` in a blocklist: answered 0.0.0.0 / ::
  unblock it with \`sinkd allow add googletagmanager.com\`

Extension, network (browser only):
  BLOCKED by \`||googletagmanager.com^\`
    easyprivacy, line 3721 (ruleset "privacy"); the extension applies it`;

// ---------------------------------------------------------------- the site

/** Ad creatives, deliberately loud, served from ad.doubleclick.net. */
const ADS = {
  "/leaderboard.svg": `<svg xmlns="http://www.w3.org/2000/svg" width="970" height="120" viewBox="0 0 970 120">
    <rect width="970" height="120" fill="#1f5eff"/><rect x="0" y="0" width="260" height="120" fill="#ffd400"/>
    <text x="130" y="72" font-family="Arial Black,Arial" font-size="40" font-weight="900" text-anchor="middle" fill="#1f2a6b">40% OFF</text>
    <text x="300" y="56" font-family="Arial" font-size="34" font-weight="700" fill="#fff">MEGA MATTRESS SALE</text>
    <text x="300" y="92" font-family="Arial" font-size="20" fill="#dfe6ff">Ends tonight! Free delivery on every order</text>
    <rect x="770" y="34" width="170" height="52" rx="26" fill="#ff3b6b"/>
    <text x="855" y="68" font-family="Arial" font-size="22" font-weight="700" text-anchor="middle" fill="#fff">SHOP NOW ›</text></svg>`,
  "/sidebar.svg": `<svg xmlns="http://www.w3.org/2000/svg" width="300" height="250" viewBox="0 0 300 250">
    <rect width="300" height="250" fill="#ff5a1f"/><circle cx="240" cy="60" r="70" fill="#ffd400"/>
    <text x="24" y="70" font-family="Arial Black,Arial" font-size="30" font-weight="900" fill="#fff">YOU WON!</text>
    <text x="24" y="108" font-family="Arial" font-size="19" fill="#fff">Claim your free cruise</text>
    <text x="24" y="134" font-family="Arial" font-size="19" fill="#fff">before the timer runs out</text>
    <rect x="24" y="170" width="160" height="48" rx="8" fill="#1d1d1d"/>
    <text x="104" y="201" font-family="Arial" font-size="19" font-weight="700" text-anchor="middle" fill="#ffd400">CLAIM NOW</text></svg>`,
  "/native.svg": `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="120" viewBox="0 0 200 120">
    <rect width="200" height="120" fill="#9b5cff"/><circle cx="100" cy="60" r="34" fill="#ff4fd8"/>
    <text x="100" y="70" font-family="Arial Black,Arial" font-size="30" text-anchor="middle" fill="#fff">!!</text></svg>`,
};

const HERO = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="560" viewBox="0 0 1200 560">
  <defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#cfd8d4"/><stop offset="1" stop-color="#eef0ea"/></linearGradient></defs>
  <rect width="1200" height="560" fill="url(#sky)"/>
  <circle cx="900" cy="150" r="56" fill="#f4ead6"/>
  <path d="M0 330 C200 250 380 300 560 260 C760 215 920 280 1200 230 V560 H0Z" fill="#a9b5a3"/>
  <path d="M0 390 C240 340 470 380 700 345 C900 315 1040 350 1200 330 V560 H0Z" fill="#8a9886"/>
  <path d="M0 450 C300 425 600 455 900 430 C1020 420 1120 430 1200 425 V560 H0Z" fill="#6f8a93"/>
  <path d="M0 490 C300 475 600 500 900 482 C1030 475 1130 480 1200 478 V560 H0Z" fill="#5e7983"/></svg>`;

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>The Ledger</title><style>
  body { margin: 0; font-family: Georgia, "Times New Roman", serif; color: #1d1d1b; background: #fff; }
  header { border-bottom: 1px solid #ddd; padding: 22px 48px 14px; display: flex; align-items: baseline; justify-content: space-between; }
  .masthead { font-size: 44px; font-weight: 700; letter-spacing: -0.02em; }
  nav { font: 600 15px -apple-system, system-ui, sans-serif; color: #555; display: flex; gap: 22px; }
  main { display: grid; grid-template-columns: 1fr 300px; gap: 40px; padding: 30px 48px; }
  .kicker { font: 700 14px -apple-system, system-ui, sans-serif; color: #8a4b2f; letter-spacing: 0.08em; text-transform: uppercase; }
  h1 { font-size: 46px; line-height: 1.08; margin: 10px 0 14px; letter-spacing: -0.015em; }
  .byline { font: 15px -apple-system, system-ui, sans-serif; color: #666; margin-bottom: 18px; }
  .hero { width: 100%; height: auto; display: block; border-radius: 4px; }
  p { font-size: 20px; line-height: 1.6; margin: 18px 0; }
  .sponsored-container { display: flex; gap: 16px; align-items: center; border: 1px solid #eee; padding: 14px; margin: 22px 0; font: 17px -apple-system, system-ui, sans-serif; }
  .sponsored-container img { width: 140px; height: auto; }
  .sponsored-container small { display: block; color: #999; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
  aside h3 { font: 700 15px -apple-system, system-ui, sans-serif; text-transform: uppercase; letter-spacing: 0.08em; color: #777; margin: 0 0 12px; }
  aside li { font-size: 18px; line-height: 1.4; margin: 0 0 14px; }
  aside ol { padding-left: 20px; margin: 0; }
  .ad-wrapper { margin: 0 0 24px; }
  .ad-wrapper img { width: 300px; height: auto; display: block; }
  .ad-leaderboard { display: flex; justify-content: center; padding: 18px 0; background: #f6f6f6; border-bottom: 1px solid #eee; }
  .ad-leaderboard img { width: 860px; height: auto; display: block; }
</style></head><body>
  <header><span class="masthead">The Ledger</span><nav><span>World</span><span>Climate</span><span>Business</span><span>Culture</span></nav></header>
  <div class="ad-leaderboard"><img src="http://ad.doubleclick.net/leaderboard.svg" alt=""></div>
  <main>
    <article>
      <div class="kicker">Climate</div>
      <h1>Coastal towns redraw their maps as the tides creep higher</h1>
      <div class="byline">By Mara Holt · 6 min read</div>
      <img class="hero" src="/hero.svg" alt="">
      <p>Along the northern shore, harbor towns are quietly moving roads, pumps and power lines a few hundred meters inland, betting that slow, early changes cost less than emergency repairs.</p>
      <div class="sponsored-container"><img src="http://ad.doubleclick.net/native.svg" alt=""><div><small>Sponsored</small>Doctors hate this one weird trick for sleeping better</div></div>
      <p>“We used to plan for the storm of the century,” said one town engineer. “Now we plan for the Tuesday high tide.”</p>
    </article>
    <aside>
      <div class="ad-wrapper"><img src="http://ad.doubleclick.net/sidebar.svg" alt=""></div>
      <h3>Most read</h3>
      <ol><li>The quiet return of the night train</li><li>What a warmer winter means for maple syrup</li><li>Inside the library that lends out tools</li></ol>
    </aside>
  </main>
  <script src="http://www.googletagmanager.com/gtm.js?id=GTM-LEDGER"></script>
  <script src="http://www.google-analytics.com/analytics.js"></script>
  <script src="http://securepubads.g.doubleclick.net/tag/js/gpt.js"></script>
  <script src="http://cdn.segment.com/analytics.js/v1/ledger/analytics.min.js"></script>
  <img src="http://www.facebook.com/tr?id=1&amp;ev=PageView" alt="" width="1" height="1" style="position:absolute;left:-9px">
  <img src="http://bat.bing.com/action/0?ti=1" alt="" width="1" height="1" style="position:absolute;left:-9px">
  <iframe src="/newsletter?utm_source=newsletter&amp;utm_campaign=fall&amp;fbclid=IwAR2x9" title="" style="display:none"></iframe>
</body></html>`;

function serve() {
  const server = createServer((req, res) => {
    const host = (req.headers.host ?? "").replace(/:\d+$/, "");
    const path = (req.url ?? "/").split("?")[0];
    const send = (type, body) => {
      res.writeHead(200, { "content-type": type, "cache-control": "no-store" });
      res.end(body);
    };
    if (host === "ad.doubleclick.net" && ADS[path]) return send("image/svg+xml", ADS[path]);
    if (host === SITE && path === "/hero.svg") return send("image/svg+xml", HERO);
    if (host === SITE && path === "/newsletter")
      return send("text/html; charset=utf-8", "<!doctype html><title>Newsletter</title>");
    if (host === SITE) return send("text/html; charset=utf-8", PAGE);
    res.writeHead(204);
    res.end();
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

// --------------------------------------------------------------- rendering

const logo = (variant, size) =>
  `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">${mark(VARIANTS[variant])}</svg>`;

const png = (buffer) => `data:image/png;base64,${buffer.toString("base64")}`;

/** A browser window around a page screenshot; `height` shows only the top of the page. */
const browserWindow = (src, width, address, height) => `
  <div style="width:${width}px;border-radius:12px;overflow:hidden;background:#fff;box-shadow:0 0 0 1px rgba(255,255,255,.08),0 30px 80px rgba(0,0,0,.55)">
    <div style="height:38px;background:${MIST};display:flex;align-items:center;gap:8px;padding:0 14px">
      ${[1, 2, 3].map(() => `<span style="width:11px;height:11px;border-radius:50%;background:${SILVER}"></span>`).join("")}
      <span style="margin-left:14px;flex:1;height:24px;border-radius:7px;background:${SNOW};font:13px -apple-system,system-ui;color:${SMOKE};display:flex;align-items:center;padding:0 12px">${address}</span>
    </div>
    <div style="${height ? `height:${height}px;overflow:hidden` : ""}"><img src="${src}" style="display:block;width:${width}px"></div>
  </div>`;

const STYLE = (bg, ink, accent) => `
  * { box-sizing: border-box; }
  body { margin: 0; overflow: hidden; background: ${bg}; color: ${ink};
    font-family: -apple-system, system-ui, "Segoe UI", sans-serif; }
  h1 { margin: 0; font-weight: 500; letter-spacing: -0.015em; }
  .muted { color: ${MUTED}; }
  .accent { color: ${accent}; }
  ul { list-style: none; padding: 0; margin: 0; }
  li { padding-left: 28px; position: relative; }
  li::before { content: ""; position: absolute; left: 0; top: 0.5em; width: 10px; height: 10px; border-radius: 50%; background: ${ink}; }
  .mono { font-family: "SF Mono", Menlo, ui-monospace, monospace; }
  .label { font: 600 14px -apple-system, system-ui; letter-spacing: .06em; text-transform: uppercase; color: ${MUTED}; }
  .card { background: #fff; border-radius: 14px; padding: 26px 28px; box-shadow: 0 10px 30px rgba(22,22,22,.08); }`;

// ------------------------------------------------------------ the store look

/** The darks of the store images. */
const NIGHT = {
  rest: "#8F8F8F",
  text: "#E6E6E6",
  card: "rgba(28,28,28,0.88)",
  edge: "rgba(255,255,255,0.10)",
};
/** Single-quoted names: it goes inside style attributes. */
const FONT = "-apple-system, 'SF Pro Display', system-ui, 'Segoe UI', sans-serif";

/** The mark without its tile: white contours and the clay low point. */
const bare = (size) =>
  `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 128 128">${mark({ tile: "none", line: WHITE, dot: CLAY })}</svg>`;

/**
 * Contour lines spreading out from a low point at (x, y), as the mark
 * draws them (each ring's floor a little below the last, so they crowd on
 * one side), fading with distance, and the clay glow of the low point.
 */
function contours(width, height, x, y, { rings = 12, opacity = 0.12, glow = 230 } = {}) {
  let lines = "";
  for (let k = 0; k < rings; k++) {
    const r = 54 + k * 58 + k * k * 4;
    const floor = y + 16 + k * 10;
    const o = (opacity * (1 - k / (rings + 3))).toFixed(3);
    lines += `<circle cx="${x}" cy="${floor - r}" r="${r}" fill="none" stroke="#fff" stroke-opacity="${o}" stroke-width="1.4"/>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" style="position:absolute;inset:0">
    <defs><radialGradient id="glow"><stop offset="0" stop-color="${CLAY}" stop-opacity="0.45"/><stop offset="1" stop-color="${CLAY}" stop-opacity="0"/></radialGradient></defs>
    <circle cx="${x}" cy="${y}" r="${glow}" fill="url(#glow)"/>${lines}
    <circle cx="${x}" cy="${y}" r="7" fill="${CLAY}"/></svg>`;
}

/** A store image: the backdrop around the low point, the content, and the name at the bottom left. */
const stage = (width, height, [x, y], body, { brand = true, ...backdrop } = {}) => `
  <div style="position:relative;width:${width}px;height:${height}px;overflow:hidden;
    background:radial-gradient(circle at ${x}px ${y}px, #2B2B2B 0, #181818 40%, #0D0D0D 100%)">
    ${contours(width, height, x, y, backdrop)}
    <div style="position:absolute;inset:0">${body}</div>
    ${
      brand
        ? `<div style="position:absolute;left:72px;bottom:52px;display:flex;align-items:center;gap:12px">${bare(42)}
      <span style="font:600 28px/1 ${FONT};letter-spacing:-.015em">sinkd</span></div>`
        : ""
    }
  </div>`;

/** A headline, its second part in gray, as the website sets them. */
const headline = (lead, rest, size = 56) =>
  `<h1 style="font:600 ${size}px/1.08 ${FONT};letter-spacing:-.028em;margin:0;text-wrap:balance">${lead}${rest ? ` <span style="color:${NIGHT.rest}">${rest}</span>` : ""}</h1>`;
const lede = (text, width = 480) =>
  `<p style="font:21px/1.5 ${FONT};color:${NIGHT.rest};margin:22px 0 0;max-width:${width}px">${text}</p>`;

/** A card floating over the product. */
const chip = (title, text) => `
  <div style="display:flex;gap:12px;align-items:flex-start;padding:14px 20px 15px 16px;border-radius:16px;
    background:${NIGHT.card};box-shadow:0 0 0 1px ${NIGHT.edge},0 18px 44px rgba(0,0,0,.5);backdrop-filter:blur(12px)">
    <span style="flex:none;width:10px;height:10px;border-radius:50%;background:${CLAY};margin-top:7px"></span>
    <span><b style="display:block;font:600 18px/1.3 ${FONT}">${title}</b>
      <span style="font:15px/1.35 ${FONT};color:${NIGHT.rest}">${text}</span></span>
  </div>`;

/** A small label over a window. */
const tag = (text, on) =>
  `<span style="display:inline-block;margin:0 0 14px 2px;padding:7px 13px;border-radius:999px;font:600 13px/1 ${FONT};letter-spacing:.08em;text-transform:uppercase;${on ? `background:${WHITE};color:${INK}` : `background:${NIGHT.card};color:${NIGHT.text};box-shadow:0 0 0 1px ${NIGHT.edge}`}">${text}</span>`;

/** Product shots: lifted off the backdrop, and turned a little toward the headline. */
const LIFT = "box-shadow:0 0 0 1px rgba(255,255,255,.08),0 34px 90px rgba(0,0,0,.6)";
const TURN = "transform:perspective(1800px) rotateY(-13deg) rotateX(4deg)";

const DARK_STYLE = `
  * { box-sizing: border-box; }
  body { margin: 0; overflow: hidden; background: #0D0D0D; color: ${WHITE};
    font-family: ${FONT}; -webkit-font-smoothing: antialiased; }
  .mono { font-family: "SF Mono", Menlo, ui-monospace, monospace; }`;

const server = await serve();
const { port } = server.address();
const resolverRule = `--host-resolver-rules=MAP *:80 127.0.0.1:${port}`;
const profile = mkdtempSync(join(tmpdir(), "sinkd-images-"));
const loaded = mkdtempSync(join(tmpdir(), "sinkd-images-extension-"));
cpSync(extension, loaded, { recursive: true });
const manifestFile = join(loaded, "manifest.json");
const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
manifest.permissions = [...new Set([...manifest.permissions, "declarativeNetRequestFeedback"])];
writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
const withExtension = await chromium.launchPersistentContext(profile, {
  channel: "chromium",
  headless: true,
  deviceScaleFactor: 2,
  // The popup as it is once open, without its splash.
  reducedMotion: "reduce",
  args: [`--disable-extensions-except=${loaded}`, `--load-extension=${loaded}`, resolverRule],
});
const plain = await chromium.launch({ channel: "chromium", headless: true, args: [resolverRule] });
try {
  const ours = (w) =>
    w.url().startsWith("chrome-extension://") && w.url().endsWith("/background.js");
  const worker =
    withExtension.serviceWorkers().find(ours) ??
    (await withExtension.waitForEvent("serviceworker", { predicate: ours }));
  const id = new URL(worker.url()).host;
  // Give the extension a moment to switch its rulesets on after install.
  await new Promise((r) => setTimeout(r, 1500));

  // The popup, as it looks on the site.
  const popup = await withExtension.newPage();
  await popup.addInitScript((site) => {
    chrome.tabs.query = async () => [{ id: 1, url: `http://${site}/climate/tides` }];
  }, SITE);
  await popup.setViewportSize({ width: 340, height: 900 });
  await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.waitForSelector("#site-features li");
  const popupHeight = await popup.evaluate(() => document.body.scrollHeight);
  await popup.setViewportSize({ width: 340, height: popupHeight });
  const popupFull = await popup.screenshot();
  const popupTop = await popup.screenshot({ clip: { x: 0, y: 0, width: 340, height: 600 } });

  // The page, without and with the extension.
  const shootPage = async (context) => {
    const page = await context.newPage();
    await page.setViewportSize({ width: 1000, height: 1010 });
    await page.goto(`http://${SITE}/climate/tides`);
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1500);
    const shot = await page.screenshot();
    await page.close();
    return shot;
  };
  const before = await shootPage(await plain.newContext({ deviceScaleFactor: 2 }));
  const after = await shootPage(withExtension);
  writeFileSync(join(release, "page-before.png"), before);
  writeFileSync(join(release, "page-after.png"), after);

  // The popup's log, on that page: opened on it, then the page reloaded,
  // so each request shows as it happens, with its address.
  const reader = await withExtension.newPage();
  await reader.setViewportSize({ width: 1000, height: 1010 });
  await reader.goto(`http://${SITE}/climate/tides`);
  await reader.waitForLoadState("networkidle");
  const tabId = await worker.evaluate(
    async (site) => (await chrome.tabs.query({ url: `http://${site}/*` }))[0]?.id,
    SITE,
  );
  const logView = await withExtension.newPage();
  await logView.addInitScript(
    ([tab, site]) => {
      chrome.tabs.query = async () => [{ id: tab, url: `http://${site}/climate/tides` }];
    },
    [tabId, SITE],
  );
  await logView.setViewportSize({ width: 340, height: 600 });
  await logView.goto(`chrome-extension://${id}/popup.html`);
  await logView.click("#tab-log");
  await logView.waitForTimeout(800);
  await reader.reload();
  await reader.waitForLoadState("networkidle");
  await logView.waitForTimeout(1500);
  const popupLog = await logView.screenshot();

  const page = await withExtension.newPage();
  const render = async (body, file, { width = 1280, height = 800, style = DARK_STYLE } = {}) => {
    await page.setViewportSize({ width, height });
    await page.setContent(
      `<!doctype html><html><head><style>${style} body { width:${width}px; height:${height}px; }</style></head><body>${body}</body></html>`,
    );
    // At CSS size: the stores want exactly these dimensions. Captures
    // inside were taken at 2x, so they stay sharp.
    await page.screenshot({ path: join(release, file), scale: "css" });
  };

  await render(
    stage(
      1280,
      800,
      [930, 560],
      `<div style="position:absolute;left:72px;top:150px;width:400px">
        ${headline("Blocks ads<br>and trackers.", "<br>Blends in.", 64)}
        ${lede("Strips tracking from links and cookies, and gives every site a different fingerprint. No account, nothing collected.", 380)}
      </div>
      <img src="${png(popupFull)}" style="position:absolute;right:112px;top:58px;width:380px;border-radius:14px;${LIFT};${TURN}">
      <div style="position:absolute;left:478px;top:190px;width:300px">${chip("Ads and trackers", "Blocked before they load")}</div>
      <div style="position:absolute;left:512px;top:404px;width:300px">${chip("Tracking in links", "Stripped from every address")}</div>
      <div style="position:absolute;left:482px;top:616px;width:300px">${chip("Your fingerprint", "Different on every site")}</div>`,
    ),
    "screenshot-1-overview.png",
  );

  await render(
    stage(
      1280,
      800,
      [660, 780],
      `<div style="position:absolute;left:72px;top:64px">
        ${headline("Ads gone.", "The page stays whole.")}
        ${lede("Ad slots disappear and the layout closes up, instead of leaving holes.", 900)}
      </div>
      <div style="position:absolute;left:72px;top:262px;opacity:.62;transform:rotate(-1.5deg);transform-origin:top left">
        ${tag("Without sinkd")}${browserWindow(png(before), 500, SITE, 330)}</div>
      <div style="position:absolute;left:600px;top:226px">
        ${tag("With sinkd", true)}${browserWindow(png(after), 608, SITE, 410)}</div>`,
    ),
    "screenshot-2-before-after.png",
  );

  await render(
    stage(
      1280,
      800,
      [900, 470],
      `<div style="position:absolute;left:72px;top:170px;width:500px">
        ${headline("See what it blocks,", "<br>as it happens.")}
        ${lede("The Log tab lists every block, stand-in, cleaned link and header change on the page, live. It adds up to the count on the toolbar.")}
      </div>
      <img src="${png(popupLog)}" style="position:absolute;right:150px;top:70px;width:392px;border-radius:14px;${LIFT};${TURN}">`,
    ),
    "screenshot-3-live-log.png",
  );

  const strike = (text) =>
    `<span style="text-decoration:line-through;text-decoration-color:${CLAY};text-decoration-thickness:2px;color:${NIGHT.rest}">${text}</span>`;
  const card = (label, body, extra = "") => `
    <div style="padding:22px 26px;border-radius:18px;background:${NIGHT.card};box-shadow:0 0 0 1px ${NIGHT.edge};${extra}">
      <div style="font:600 13px/1 ${FONT};letter-spacing:.08em;text-transform:uppercase;color:${NIGHT.rest}">${label}</div>
      ${body}
    </div>`;
  const text = (s) =>
    `<p style="font:18px/1.5 ${FONT};color:${NIGHT.text};margin:12px 0 0">${s}</p>`;
  const code = (s) =>
    `<div class="mono" style="font-size:15px;color:${SILVER};margin-top:10px">${s}</div>`;
  await render(
    stage(
      1280,
      800,
      [1120, 760],
      `<div style="position:absolute;left:72px;top:64px">
        ${headline("Less to track you with.", "Beyond blocking.")}
        ${lede("What still loads carries less about you.", 900)}
      </div>
      <div style="position:absolute;left:72px;right:72px;top:236px;display:grid;grid-template-columns:repeat(3,1fr);gap:16px">
        ${card(
          "Tracking parameters, removed from links",
          `<div class="mono" style="font-size:17px;line-height:1.7;margin-top:12px;color:${NIGHT.text};white-space:nowrap">shop.example/boots?id=42${strike("&amp;utm_source=news&amp;fbclid=IwAR2x9")}</div>
          <div class="mono" style="font-size:17px;line-height:1.7;color:${WHITE};white-space:nowrap">→ shop.example/boots?id=42</div>`,
          "grid-column:span 2",
        )}
        ${card("Your local address, kept local", text("WebRTC uses only the public network interface, so pages can't read your local IP address."))}
        ${card("Cookies and referrer", text("Requests to trackers go out without your cookies or the page you came from. Analytics cookies expire within a week."))}
        ${card("A fingerprint per site", text("Each site sees its own canvas, WebGL and audio fingerprint, stable for the session.") + code("news.example → 9f3a…c1"))}
        ${card("Global Privacy Control", text("Every site is told not to sell or share your data, a legal opt-out in several US states.") + code("Sec-GPC: 1"))}
      </div>`,
    ),
    "screenshot-4-privacy.png",
  );

  const escapeHtml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const terminal = escapeHtml(TERMINAL)
    .replace(/^(\$ .*)$/gm, `<span style="color:${WHITE}">$1</span>`)
    .replace(/BLOCKED/g, `<span style="color:${TERM.red}">BLOCKED</span>`);
  await render(
    stage(
      1280,
      800,
      [960, 640],
      `<div style="position:absolute;left:72px;top:170px;width:400px">
        ${headline("Every app,", "<br>not just<br>the browser.")}
        ${lede("The free sinkd program for macOS and Linux blocks the same trackers for your whole computer, as its DNS resolver.", 400)}
      </div>
      <div style="position:absolute;left:510px;top:118px;width:700px;border-radius:12px;overflow:hidden;${LIFT}">
        <div style="height:34px;background:${TERM.bar};display:flex;align-items:center;gap:8px;padding:0 14px">
          ${[1, 2, 3].map(() => `<span style="width:11px;height:11px;border-radius:50%;background:${TERM.dot}"></span>`).join("")}
        </div>
        <pre class="mono" style="margin:0;background:${TERM.bg};color:${TERM.text};font-size:13.6px;line-height:1.55;padding:22px 24px;white-space:pre">${terminal}</pre>
      </div>`,
    ),
    "screenshot-5-every-app.png",
  );

  await render(
    stage(
      440,
      280,
      [372, 236],
      `<div style="position:absolute;left:34px;top:0;bottom:0;display:flex;flex-direction:column;justify-content:center">
        <div style="display:flex;align-items:center;gap:14px">${bare(62)}
          <span style="font:600 54px/1 ${FONT};letter-spacing:-.025em">sinkd</span></div>
        <p style="font:19px/1.35 ${FONT};color:${SILVER};margin:18px 0 0">Ad and tracker blocking<br>that blends in.</p>
      </div>`,
      { brand: false, rings: 8, glow: 140 },
    ),
    "promo-440x280.png",
    { width: 440, height: 280 },
  );

  await render(
    stage(
      1400,
      560,
      [1010, 470],
      `<div style="position:absolute;left:84px;top:0;bottom:0;width:600px;display:flex;flex-direction:column;justify-content:center">
        <div style="display:flex;align-items:center;gap:14px;margin-bottom:34px">${bare(50)}
          <span style="font:600 36px/1 ${FONT};letter-spacing:-.02em">sinkd</span></div>
        ${headline("Ad and tracker blocking", "that blends in.", 60)}
        ${lede("Blocks ads, trackers and malware sites, strips tracking, and blurs your fingerprint. In Chrome, and for every app on your computer.", 560)}
      </div>
      <div style="position:absolute;left:760px;top:84px">${browserWindow(png(after), 520, SITE, 440)}</div>
      <img src="${png(popupTop)}" style="position:absolute;right:76px;top:42px;width:290px;border-radius:12px;${LIFT};${TURN}">`,
      { brand: false },
    ),
    "marquee-1400x560.png",
    { width: 1400, height: 560 },
  );

  await render(
    `<div style="display:flex;flex-direction:column;justify-content:center;height:100%;padding:0 96px">
      <h1 style="font-size:84px;display:flex;align-items:center;gap:28px">${logo("graphite", 104)}sinkd</h1>
      <p class="muted" style="font-size:34px;margin:26px 0 0">Ad and tracker blocking that <span class="accent">blends in</span>.</p>
    </div>`,
    "og-1200x630.png",
    { width: 1200, height: 630, style: STYLE(SNOW, INK, SMOKE) },
  );
  console.log(`wrote the store images and the website's images to ${release}`);
} finally {
  await withExtension.close();
  await plain.close();
  server.close();
  rmSync(profile, { recursive: true, force: true });
  rmSync(loaded, { recursive: true, force: true });
}
