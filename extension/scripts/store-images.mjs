// Store images, into ../release/, in the brand's colors (scripts/logo.mjs):
//
//   screenshot-1-overview.png      the popup, and what sinkd does
//   screenshot-2-before-after.png  a page without and with the extension
//   screenshot-3-controls.png      the popup's per-site switches, close up
//   screenshot-4-privacy.png       links, cookies, referrer, fingerprints
//   screenshot-5-every-app.png     the sinkd command, for every app
//   promo-440x280.png              the small promo tile
//
//   node scripts/store-images.mjs [--extension dist]
//
// Everything runs in Playwright's Chromium with throwaway profiles. The
// before/after is a real render: a made-up news site served from a local
// server, its ads from a host EasyList blocks, in boxes with class names
// EasyList hides (not ones the compiler leaves out as detector bait), once
// in a browser without
// the extension and once with the build in --extension. The popup's tab
// lookup is stubbed to report that site.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { chromium } from "playwright-core";

import { BASALT, CLAY, mark, SAND, STONE, VARIANTS } from "./logo.mjs";

const root = resolve(import.meta.dirname, "..");
const { values } = parseArgs({ options: { extension: { type: "string" } } });
const extension = resolve(root, values.extension ?? "dist");
const release = resolve(root, "..", "release");
mkdirSync(release, { recursive: true });

const MUTED = "#5B5F57";
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

/** A browser window around a page screenshot. */
const browserWindow = (src, width, address) => `
  <div style="width:${width}px;border-radius:12px;overflow:hidden;background:#fff;box-shadow:0 22px 60px rgba(44,48,44,.20)">
    <div style="height:38px;background:#e4dfd4;display:flex;align-items:center;gap:8px;padding:0 14px">
      ${[1, 2, 3].map(() => `<span style="width:11px;height:11px;border-radius:50%;background:#cfc8ba"></span>`).join("")}
      <span style="margin-left:14px;flex:1;height:24px;border-radius:7px;background:#f4f1ea;font:13px -apple-system,system-ui;color:#6b6a63;display:flex;align-items:center;padding:0 12px">${address}</span>
    </div>
    <img src="${src}" style="display:block;width:${width}px">
  </div>`;

const STYLE = (bg, ink) => `
  * { box-sizing: border-box; }
  body { margin: 0; overflow: hidden; background: ${bg}; color: ${ink};
    font-family: -apple-system, system-ui, "Segoe UI", sans-serif; }
  h1 { margin: 0; font-weight: 500; letter-spacing: -0.015em; }
  .muted { color: ${MUTED}; }
  .accent { color: ${CLAY}; }
  ul { list-style: none; padding: 0; margin: 0; }
  li { padding-left: 28px; position: relative; }
  li::before { content: ""; position: absolute; left: 0; top: 0.5em; width: 10px; height: 10px; border-radius: 50%; background: ${CLAY}; }
  .mono { font-family: "SF Mono", Menlo, ui-monospace, monospace; }
  .label { font: 600 14px -apple-system, system-ui; letter-spacing: .06em; text-transform: uppercase; color: ${MUTED}; }
  .card { background: #fff; border-radius: 14px; padding: 26px 28px; box-shadow: 0 10px 30px rgba(44,48,44,.08); }`;

/** The title block shared by the feature screenshots. */
const title = (heading, text) => `
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:22px">${logo("stone", 40)}
    <span style="font:500 22px -apple-system,system-ui;letter-spacing:-.01em">sinkd</span></div>
  <h1 style="font-size:44px;line-height:1.12">${heading}</h1>
  <p class="muted" style="font-size:21px;line-height:1.5;margin:18px 0 0">${text}</p>`;

const server = await serve();
const { port } = server.address();
const resolverRule = `--host-resolver-rules=MAP *:80 127.0.0.1:${port}`;
const profile = mkdtempSync(join(tmpdir(), "sinkd-images-"));
const withExtension = await chromium.launchPersistentContext(profile, {
  channel: "chromium",
  headless: true,
  deviceScaleFactor: 2,
  args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, resolverRule],
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
  await popup.setViewportSize({ width: 332, height: 900 });
  await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.waitForSelector("#site-features li");
  const popupHeight = await popup.evaluate(() => document.body.scrollHeight);
  await popup.setViewportSize({ width: 332, height: popupHeight });
  const popupFull = await popup.screenshot();
  const popupTop = await popup.screenshot({ clip: { x: 0, y: 0, width: 332, height: 470 } });

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

  const page = await withExtension.newPage();
  const render = async (
    body,
    file,
    { bg = STONE, ink = BASALT, width = 1280, height = 800 } = {},
  ) => {
    await page.setViewportSize({ width, height });
    await page.setContent(
      `<!doctype html><html><head><style>${STYLE(bg, ink)} body { width:${width}px; height:${height}px; }</style></head><body>${body}</body></html>`,
    );
    // At CSS size: the stores want exactly these dimensions. Captures
    // inside were taken at 2x, so they stay sharp.
    await page.screenshot({ path: join(release, file), scale: "css" });
  };

  await render(
    `<div style="display:flex;align-items:center;gap:72px;padding:0 96px;height:100%">
      <div style="flex:1">
        <h1 style="font-size:64px;display:flex;align-items:center;gap:22px">${logo("stone", 76)}sinkd</h1>
        <p class="muted" style="font-size:26px;margin:22px 0 40px">Ad and tracker blocking that <span class="accent">blends in</span>.</p>
        <ul style="font-size:22px;line-height:1.5;display:grid;gap:14px">
          <li>Blocks ads, trackers and malware sites</li>
          <li>Strips tracking parameters, tracker cookies and referrers</li>
          <li>Fingerprinting noise that stays stable per site</li>
          <li>Global Privacy Control, WebRTC IP protection</li>
          <li>Each protection off per site, in one click</li>
        </ul>
        <p class="muted" style="font-size:18px;margin-top:40px">No remote code. No data collected.</p>
      </div>
      <img src="${png(popupFull)}" style="height:700px;border-radius:12px;box-shadow:0 18px 50px rgba(44,48,44,.18)">
    </div>`,
    "screenshot-1-overview.png",
  );

  await render(
    `<div style="padding:44px 72px 0">
      <h1 style="font-size:40px">Ads gone. <span class="accent">The page stays whole.</span></h1>
      <p class="muted" style="font-size:19px;margin:10px 0 0">Ad slots disappear and the layout closes up, instead of leaving holes.</p>
    </div>
    <div style="display:flex;gap:40px;padding:26px 72px 0">
      ${[
        ["Without sinkd", before],
        ["With sinkd", after],
      ]
        .map(
          ([label, shot]) => `<div>
            <div class="label" style="margin:0 0 12px 4px">${label}</div>
            ${browserWindow(png(shot), 548, SITE)}</div>`,
        )
        .join("")}
    </div>`,
    "screenshot-2-before-after.png",
  );

  await render(
    `<div style="display:flex;align-items:center;gap:80px;padding:0 96px;height:100%">
      <div style="flex:1">${title(
        "In control, <span class='accent'>site by site</span>",
        "Switch sinkd off for one site, or just one protection there. Your choice is remembered, and nothing else changes.",
      )}
        <ul style="font-size:20px;line-height:1.5;display:grid;gap:12px;margin-top:34px">
          <li>One switch for the whole site</li>
          <li>Or fingerprinting, cookies, referrer, GPC on their own</li>
          <li>Kinds of blocking on or off everywhere</li>
        </ul>
      </div>
      <img src="${png(popupTop)}" style="width:498px;border-radius:14px;box-shadow:0 22px 60px rgba(44,48,44,.20)">
    </div>`,
    "screenshot-3-controls.png",
  );

  const strike = (s) =>
    `<span style="text-decoration:line-through;text-decoration-color:${CLAY};text-decoration-thickness:2px;color:#9a8f7f">${s}</span>`;
  await render(
    `<div style="padding:40px 72px 0">${title(
      "Less to track you with",
      "Beyond blocking: what still loads carries less about you.",
    )}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:26px 72px 0">
      <div class="card" style="grid-column:1 / span 2;padding:22px 28px">
        <div class="label">Tracking parameters, removed from links</div>
        <div class="mono" style="font-size:18px;margin-top:12px;line-height:1.7">shop.example/boots?id=42${strike("&amp;utm_source=newsletter&amp;utm_campaign=fall&amp;fbclid=IwAR2x9")}</div>
        <div class="mono" style="font-size:18px;line-height:1.7">→ shop.example/boots?id=42</div>
      </div>
      <div class="card" style="padding:22px 28px">
        <div class="label">Cookies and referrer</div>
        <p style="font-size:18px;line-height:1.5;margin:10px 0 0">Requests to trackers go out without your cookies or the page you came from. Analytics cookies expire within a week.</p>
      </div>
      <div class="card" style="padding:22px 28px">
        <div class="label">A fingerprint per site</div>
        <p style="font-size:18px;line-height:1.5;margin:10px 0 8px">Each site sees its own canvas, WebGL and audio fingerprint, stable for the session, so visits can't be linked.</p>
        <div class="mono" style="font-size:15px;color:${MUTED}">news.example → 9f3a…c1 &nbsp;·&nbsp; shop.example → 47d0…8e</div>
      </div>
      <div class="card" style="padding:22px 28px">
        <div class="label">Global Privacy Control</div>
        <p style="font-size:18px;line-height:1.5;margin:10px 0 8px">Every site is told not to sell or share your data, a legally recognized opt-out in several US states.</p>
        <div class="mono" style="font-size:15px;color:${MUTED}">Sec-GPC: 1</div>
      </div>
      <div class="card" style="padding:22px 28px">
        <div class="label">Your local address, kept local</div>
        <p style="font-size:18px;line-height:1.5;margin:10px 0 0">WebRTC uses only the public network interface, so pages can't read your device's local IP address.</p>
      </div>
    </div>`,
    "screenshot-4-privacy.png",
  );

  const escapeHtml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const terminal = escapeHtml(TERMINAL)
    .replace(/^(\$ .*)$/gm, `<span style="color:#f1ece2">$1</span>`)
    .replace(/BLOCKED/g, `<span style="color:${CLAY}">BLOCKED</span>`);
  await render(
    `<div style="display:flex;align-items:center;gap:48px;padding:0 64px;height:100%">
      <div style="width:380px">${title(
        "Every app, <span class='accent'>not just the browser</span>",
        "The free sinkd program for macOS and Linux blocks the same trackers for your whole computer, as its DNS resolver. Its allowlist and pause reach the extension too.",
      )}</div>
      <div style="flex:1;border-radius:12px;overflow:hidden;box-shadow:0 22px 60px rgba(44,48,44,.25)">
        <div style="height:34px;background:#3a3f39;display:flex;align-items:center;gap:8px;padding:0 14px">
          ${[1, 2, 3].map(() => `<span style="width:11px;height:11px;border-radius:50%;background:#5c6259"></span>`).join("")}
        </div>
        <pre class="mono" style="margin:0;background:${BASALT};color:${SAND};font-size:13.8px;line-height:1.55;padding:22px 24px;white-space:pre">${terminal}</pre>
      </div>
    </div>`,
    "screenshot-5-every-app.png",
  );

  await render(
    `<div style="display:flex;flex-direction:column;justify-content:center;height:100%;padding:0 36px">
      <h1 style="font-size:54px;display:flex;align-items:center;gap:16px">${logo("basalt", 64)}sinkd</h1>
      <p style="font-size:21px;margin:16px 0 0;line-height:1.35;color:#A9A08C">Blocks ads and trackers.<br>
        <span class="accent">Blends in.</span></p>
    </div>`,
    "promo-440x280.png",
    { bg: BASALT, ink: SAND, width: 440, height: 280 },
  );
  console.log(`wrote 5 screenshots and the promo tile to ${release}`);
} finally {
  await withExtension.close();
  await plain.close();
  server.close();
  rmSync(profile, { recursive: true, force: true });
}
