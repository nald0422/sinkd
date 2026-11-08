// Store images, into ../release/: a 1280x800 screenshot and a 440x280
// promo tile, showing the popup as it looks on a news site.
//
//   node scripts/store-images.mjs [--extension dist]
//
// The popup runs in Playwright's Chromium with a throwaway profile. Its
// tab lookup is stubbed to report a news site, which the background script
// answers for; no site is loaded.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { chromium } from "playwright-core";

const root = resolve(import.meta.dirname, "..");
const { values } = parseArgs({ options: { extension: { type: "string" } } });
const extension = resolve(root, values.extension ?? "dist");
const release = resolve(root, "..", "release");
mkdirSync(release, { recursive: true });

const profile = mkdtempSync(join(tmpdir(), "sinkd-images-"));
const context = await chromium.launchPersistentContext(profile, {
  channel: "chromium",
  headless: true,
  deviceScaleFactor: 2,
  args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
});
try {
  const ours = (w) =>
    w.url().startsWith("chrome-extension://") && w.url().endsWith("/background.js");
  const worker =
    context.serviceWorkers().find(ours) ??
    (await context.waitForEvent("serviceworker", { predicate: ours }));
  const id = new URL(worker.url()).host;

  const popup = await context.newPage();
  await popup.addInitScript(() => {
    chrome.tabs.query = async () => [{ id: 1, url: "https://www.example-news.com/world" }];
  });
  await popup.setViewportSize({ width: 300 + 32, height: 900 });
  await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.waitForSelector("#site-features li");
  const height = await popup.evaluate(() => document.body.scrollHeight);
  await popup.setViewportSize({ width: 332, height });
  const shot = (await popup.screenshot()).toString("base64");

  const page = await context.newPage();
  const render = async (width, height, body, file) => {
    await page.setViewportSize({ width, height });
    await page.setContent(`<!doctype html><html><head><style>
      * { box-sizing: border-box; }
      body { margin: 0; width: ${width}px; height: ${height}px; overflow: hidden;
        font-family: -apple-system, system-ui, "Segoe UI", sans-serif; color: #1b2033;
        background: linear-gradient(135deg, #eef3ff 0%, #dbe6ff 100%); }
      .popup { border-radius: 12px; box-shadow: 0 18px 50px rgba(27, 37, 89, 0.25); background: #fff; }
      h1 { margin: 0; color: #1b2559; letter-spacing: -0.02em; }
      .accent { color: #2563eb; }
      ul { list-style: none; padding: 0; margin: 0; }
      li { padding-left: 30px; position: relative; }
      li::before { content: ""; position: absolute; left: 0; top: 0.45em; width: 14px; height: 14px;
        border-radius: 50%; background: #2563eb; }
    </style></head><body>${body}</body></html>`);
    // At CSS size: the stores want exactly these dimensions. The popup
    // inside was captured at 2x, so it stays sharp.
    await page.screenshot({ path: join(release, file), scale: "css" });
  };

  await render(
    1280,
    800,
    `<div style="display:flex;align-items:center;gap:72px;padding:0 96px;height:100%">
      <div style="flex:1">
        <h1 style="font-size:64px">sinkd</h1>
        <p style="font-size:26px;margin:14px 0 40px;color:#3b4366">Ad and tracker blocking that
          <span class="accent">blends in</span>.</p>
        <ul style="font-size:22px;line-height:1.5;display:grid;gap:14px">
          <li>Blocks ads, trackers and malware sites</li>
          <li>Strips tracking parameters, tracker cookies and referrers</li>
          <li>Fingerprinting noise that stays stable per site</li>
          <li>Global Privacy Control, WebRTC IP protection</li>
          <li>Each protection off per site, in one click</li>
        </ul>
        <p style="font-size:18px;margin-top:40px;color:#5d6478">No remote code. No data collected.</p>
      </div>
      <img class="popup" src="data:image/png;base64,${shot}" style="height:700px">
    </div>`,
    "screenshot-1280x800.png",
  );
  await render(
    440,
    280,
    `<div style="display:flex;flex-direction:column;justify-content:center;height:100%;padding:0 36px">
      <h1 style="font-size:52px">sinkd</h1>
      <p style="font-size:22px;margin:10px 0 0;color:#3b4366;line-height:1.3">Blocks ads and trackers.<br>
        <span class="accent">Blends in.</span></p>
    </div>`,
    "promo-440x280.png",
  );
  console.log(`wrote ${join(release, "screenshot-1280x800.png")} and promo-440x280.png`);
} finally {
  await context.close();
  rmSync(profile, { recursive: true, force: true });
}
