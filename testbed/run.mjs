// The testbed harness: local pages that reproduce how sites detect ad
// blockers (Part C) and how they track (Part B), loaded in Playwright's
// Chromium, or its Firefox, with and without the extension.
//
//   node testbed/run.mjs [--browser chromium|firefox] [--real] [--bench]
//
// Every page is opened in up to three browsers:
//
// - plain: no extension, nothing blocked. Detectors must stay quiet here,
//   or the page itself is wrong.
// - naive: no extension, but ad and tracker hosts are aborted and bait
//   classes hidden, as a blocker without surrogates or scriptlets would.
//   Detectors must fire here, or they don't test anything.
// - sinkhole: the extension, built from rulesets.toml (lists/testbed.txt
//   plus the real surrogate and parameter lists). Detectors must stay
//   quiet, and no ad or tracker request may reach the server.
//
// --real also runs the pages that matter against extension/dist (the
// build from the public lists; dist-firefox for Firefox): generic hiding
// must spare bait, trackers from the public lists must not get out, and
// the page must look the same. --bench measures the budgets on that
// build: first contentful paint, page-engine init and lookup times,
// scriptlet cost, background memory.
//
// The browsers run headless with throwaway profiles. Every hostname leads
// to the local server, so nothing leaves the machine and no real site is
// contacted: Chromium resolves them all to it (--host-resolver-rules);
// Firefox uses it as its proxy, except for the names the CNAME checks
// need it to look up, which Firefox's DNS override service answers.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { gzipSync } from "node:zlib";

import { benchPage } from "./bench-page.mjs";
import { startServer } from "./server.mjs";

const here = import.meta.dirname;
const extensionRoot = resolve(here, "..", "extension");
// playwright-core is the extension's dev dependency; the testbed has none.
const { chromium, firefox } = createRequire(join(extensionRoot, "package.json"))("playwright-core");
const { build } = await import(pathToFileURL(join(extensionRoot, "scripts", "build.mjs")).href);
const { launchFirefox, overrideDns } = await import(
  pathToFileURL(join(extensionRoot, "scripts", "firefox.mjs")).href
);

const { values: args } = parseArgs({
  options: {
    real: { type: "boolean" },
    bench: { type: "boolean" },
    browser: { type: "string", default: "chromium" },
  },
});
const FIREFOX = args.browser === "firefox";
const BROWSER = FIREFOX ? "Firefox" : "Chrome";

// ------------------------------------------------------------------ browsers

/** Hosts a naive blocker aborts, and the bait it hides. */
const NAIVE_HOSTS = [
  "ads.detect-cdn.test",
  "pagead2.googlesyndication.com",
  "www.googletagservices.com",
  "www.google-analytics.com",
  "tracker.track-cdn.test",
];
const NAIVE_CSS =
  ".adsbox,.ad-banner,.pub_300x250,.textAd,.text-ad-links,#ad-slot,ins.adsbygoogle" +
  "{display:none!important}";

const hostRules = (server) =>
  `--host-resolver-rules=MAP *:80 127.0.0.1:${server.port}` +
  (server.httpsPort ? `,MAP *:443 127.0.0.1:${server.httpsPort}` : "");
// The HTTPS pages use a certificate made for the run; only these test
// browsers are told to accept it.
const contextOptions = { ignoreHTTPSErrors: true };
const profiles = [];

/**
 * CNAME uncloaking (Firefox): first-party names and their DNS aliases. The
 * pages ask for these at the server's own port, so they skip the proxy and
 * Firefox looks them up: sinkhole never looks up proxied requests (the
 * local resolver would learn of them). The extension's Firefox gets the
 * aliases from the DNS override service; the plain one resolves the names
 * to the server without them.
 */
const ALIASES = {
  // A listed tracker: blocked.
  "metrics.cloak.test": "collect.cname-tracker.test",
  // Listed, but the alias is on the same site: not cloaking.
  "cdn.cloak.test": "edge.cloak.test",
  // Not listed.
  "img.cloak.test": "img.cdn-provider.test",
  // Listed, but excepted (@@).
  "api.cloak.test": "api.cname-tracker.test",
  // The real lists' trackers (--real).
  "smetrics.realnews.test": "realnews.test.sc.omtrdc.net",
  "ea.realnews.test": "realnews.eulerian.net",
};
/** A name with a tracker alias that is only ever asked for through the proxy. */
const PROXIED_ALIAS = ["stats.cloak.test", "collect.cname-tracker.test"];

/** Firefox's proxy settings: everything through the server but `ALIASES`. */
const proxyFor = (server) => ({
  server: `http://127.0.0.1:${server.port}`,
  bypass: Object.keys(ALIASES).join(","),
});

async function plainBrowser(server, { naive = false } = {}) {
  const browser = FIREFOX
    ? await firefox.launch({
        headless: true,
        proxy: proxyFor(server),
        firefoxUserPrefs: { "network.dns.localDomains": Object.keys(ALIASES).join(",") },
      })
    : await chromium.launch({ channel: "chromium", headless: true, args: [hostRules(server)] });
  const context = await browser.newContext(contextOptions);
  if (naive) {
    await context.route(
      (url) => NAIVE_HOSTS.includes(url.hostname),
      (route) => route.abort("blockedbyclient"),
    );
    await context.addInitScript((css) => {
      document.addEventListener("DOMContentLoaded", () => {
        const style = document.createElement("style");
        style.textContent = css;
        document.head.appendChild(style);
      });
    }, NAIVE_CSS);
  }
  return { context, close: () => browser.close() };
}

/** A persistent profile without the extension: the bench's baseline. */
async function bareBrowser(server) {
  const profile = mkdtempSync(join(tmpdir(), "sinkhole-testbed-"));
  profiles.push(profile);
  const context = FIREFOX
    ? await firefox.launchPersistentContext(profile, {
        ...contextOptions,
        headless: true,
        proxy: proxyFor(server),
      })
    : await chromium.launchPersistentContext(profile, {
        ...contextOptions,
        channel: "chromium",
        headless: true,
        args: [hostRules(server)],
      });
  return { context, close: () => context.close() };
}

/** Waits until the background script has registered every page script. */
async function registered(evaluate, path) {
  // Settings are applied on install: rulesets enabled, scriptlets and the
  // GPC and fingerprint scripts registered.
  const scriptlets = JSON.parse(readFileSync(join(path, "scriptlets.json"), "utf8")).length + 2;
  const started = Date.now();
  for (;;) {
    const count = await evaluate(async () =>
      globalThis.chrome?.scripting
        ? (await chrome.scripting.getRegisteredContentScripts()).length
        : -1,
    );
    if (count >= scriptlets) return Date.now() - started;
    assert.ok(Date.now() - started < 10_000, `scriptlets never registered (${count})`);
    await new Promise((ok) => setTimeout(ok, 50));
  }
}

/**
 * The extension in a fresh profile, or in `profile` again: a new browser
 * session with everything the last one stored on disk. (Firefox installs
 * the extension anew in each session: it is a temporary add-on.)
 *
 * The result has the context; `worker.evaluate(fn, arg)` in the
 * background script; `send(request)` from the popup; `popup(fn, arg)`,
 * which runs `fn(document, window, arg)` in the popup page; and `origin`,
 * the extension's own.
 */
async function extensionBrowser(path, server, profile = null) {
  if (profile === null) {
    profile = mkdtempSync(join(tmpdir(), "sinkhole-testbed-"));
    profiles.push(profile);
  }
  if (FIREFOX) {
    const ff = await launchFirefox(path, profile, {
      ...contextOptions,
      proxy: proxyFor(server),
    });
    for (const [name, alias] of Object.entries(ALIASES)) await overrideDns(ff, name, alias);
    await overrideDns(ff, ...PROXIED_ALIAS);
    const setupMs = await registered(ff.evaluate, path);
    return {
      ...ff,
      worker: { evaluate: ff.evaluate },
      path,
      profile,
      setupMs,
    };
  }
  const context = await chromium.launchPersistentContext(profile, {
    ...contextOptions,
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${path}`, `--load-extension=${path}`, hostRules(server)],
  });
  const ours = (w) =>
    w.url().startsWith("chrome-extension://") && w.url().endsWith("/background.js");
  let worker = context.serviceWorkers().find(ours);
  worker ??= await context.waitForEvent("serviceworker", { predicate: ours });
  const id = new URL(worker.url()).host;
  const setupMs = await registered((fn, arg) => worker.evaluate(fn, arg), path);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);
  return {
    context,
    worker,
    id,
    origin: `chrome-extension://${id}`,
    path,
    profile,
    setupMs,
    send: (request) => popup.evaluate((r) => chrome.runtime.sendMessage(r), request),
    popup: async (fn, arg, { reload = false } = {}) => {
      if (reload) await popup.reload();
      return popup.evaluate(`(${fn})(document, window, ${JSON.stringify(arg ?? null)})`);
    },
    close: () => context.close(),
  };
}

/** Opens a page, waits for its results, and returns them. */
async function visit(context, url, { settle = 0 } = {}) {
  const page = await context.newPage();
  try {
    await page.goto(url);
    await page.waitForFunction(() => window.results?.done === true || !window.results, null, {
      timeout: 5000,
    });
    if (settle) await page.waitForTimeout(settle);
    return await page.evaluate(() => window.results ?? null);
  } finally {
    await page.close();
  }
}

// --------------------------------------------------------------------- checks

const results = [];
async function check(name, fn) {
  try {
    const note = await fn();
    results.push({ name, ok: true });
    console.log(`  ok    ${name}${note ? `  [${note}]` : ""}`);
  } catch (error) {
    results.push({ name, ok: false });
    console.log(`  FAIL  ${name}\n        ${String(error.message).split("\n").join("\n        ")}`);
  }
}

const leaks = (text) => typeof text === "string" && text.includes("-extension://");

/** Requests the server saw while `fn` ran, to any of `hosts`. */
async function requestsDuring(server, hosts, fn) {
  const before = server.log.length;
  const value = await fn();
  const entries = server.log
    .slice(before)
    .filter((r) => hosts.some((h) => r.host === h || r.host.endsWith(`.${h}`)));
  return { value, seen: entries.map((r) => `${r.host}${r.url}`), entries };
}

const DETECT = "http://detect.test";
const AD_HOSTS = [
  "detect-cdn.test",
  "googlesyndication.com",
  "googletagservices.com",
  "google-analytics.com",
];

/**
 * `expected`: detections that are right for this build, reported rather
 * than failed (the real lists know nothing about the testbed's own site).
 * `known`: detections from a known gap of this browser (DESIGN.md).
 */
async function detectionChecks(
  server,
  plain,
  naive,
  ext,
  pages,
  { expected = [], known: gaps = [] } = {},
) {
  for (const page of pages) {
    const url = `${DETECT}/${page}.html`;
    await check(`${page}: the page is quiet without a blocker`, async () => {
      const r = await visit(plain.context, url);
      assert.deepEqual(r.detections, []);
    });
    if (naive) {
      await check(`${page}: the page catches a naive blocker`, async () => {
        const r = await visit(naive.context, url);
        assert.ok(r.detections.length > 0, "a plain block went unnoticed");
        return `${r.detections.length} caught`;
      });
    }
    await check(`${page}: no detection fires with sinkhole`, async () => {
      const { value: r, seen } = await requestsDuring(server, AD_HOSTS, () =>
        visit(ext.context, url),
      );
      const known = r.detections.filter((d) => expected.some((re) => re.test(d)));
      const gap = r.detections.filter((d) => gaps.some((re) => re.test(d)));
      assert.deepEqual(
        r.detections.filter((d) => !known.includes(d) && !gap.includes(d)),
        [],
      );
      assert.deepEqual(r.errors.filter(leaks), [], "an error names the extension");
      assert.deepEqual(seen, [], "ad requests reached the network");
      if (page === "globals" && naive) {
        assert.equal(
          r.early.canRunAds,
          true,
          "scriptlets did not run before the first page script",
        );
      }
      return [
        known.length ? `expected without a site rule: ${known.join("; ")}` : "",
        gap.length ? `known ${BROWSER} gap: ${gap.join("; ")}` : "",
      ]
        .filter(Boolean)
        .join("; ");
    });
  }
}

/** The stealth page with and without the extension: they must match. */
async function stealthChecks(plain, ext, { allowedNames }) {
  const [base, mine] = [
    await visit(plain.context, `${DETECT}/stealth.html`),
    await visit(ext.context, `${DETECT}/stealth.html`),
  ];
  await check("stealth: patched functions look native (source, name, length, keys)", () => {
    for (const [name, fn] of Object.entries(base.functions)) {
      assert.deepEqual(mine.functions[name], fn, name);
    }
  });
  await check("stealth: no globals beyond what the rules define", () => {
    const extra = mine.names.filter((n) => !base.names.includes(n));
    const missing = base.names.filter((n) => !mine.names.includes(n));
    assert.deepEqual(missing, []);
    assert.deepEqual(
      extra.filter((n) => !allowedNames.includes(n)),
      [],
    );
    return extra.length ? `rule-defined: ${extra.join(", ")}` : "";
  });
  await check("stealth: no stack frame names the extension", () => {
    const named = Object.entries(mine.stacks).filter(([k, s]) => k !== "inReviver" && leaks(s));
    assert.deepEqual(
      named.map(([k]) => k),
      [],
    );
    assert.equal(Object.keys(mine.stacks).length, Object.keys(base.stacks).length);
    return leaks(mine.stacks.inReviver) ? "known: a JSON.parse reviver sees the wrapper frame" : "";
  });
  await check("stealth: no DOM nodes, attributes, style sheets or mutations added", () => {
    assert.deepEqual(mine.dom, base.dom);
    assert.equal(mine.styleSheets, base.styleSheets);
    assert.equal(mine.adoptedStyleSheets, base.adoptedStyleSheets);
    assert.equal(mine.scripts, base.scripts);
    assert.deepEqual(mine.mutations, base.mutations);
  });
  await check("stealth: resource timing shows no extension URLs", () => {
    assert.deepEqual(
      mine.resources.filter((u) => /^[a-z]+-extension:/.test(u)),
      [],
    );
  });
  // Chrome extension IDs are the same in every install, so a page could
  // probe for known ones; sinkhole's resources answer only at a URL that
  // changes (use_dynamic_url). Firefox addresses an install by a random
  // UUID instead, never by the add-on ID; its web-accessible resources
  // (the surrogates) answer there, so the UUID must not leak (the checks
  // above), and nothing else may answer.
  await check("stealth: the page can't fetch any extension file by its ID", async () => {
    const files = [
      "manifest.json",
      "content.js",
      "background.js",
      "engine.wasm",
      ...readdirSync(join(ext.path, "war")).map((f) => `war/${f}`),
      ...readdirSync(join(ext.path, "scriptlets")).map((f) => `scriptlets/${f}`),
    ];
    const page = await ext.context.newPage();
    await page.goto(`${DETECT}/stealth.html`);
    const probe = (origin) =>
      page.evaluate(
        async ([base, list]) => {
          const out = [];
          for (const file of list) {
            try {
              await fetch(`${base}/${file}`);
              out.push(file);
            } catch {
              // Not web-accessible at this URL: what we want.
            }
          }
          return out;
        },
        [origin, files],
      );
    const byId = await probe(FIREFOX ? `moz-extension://${ext.id}` : ext.origin);
    const byOrigin = FIREFOX ? await probe(ext.origin) : [];
    await page.close();
    assert.deepEqual(byId, []);
    assert.deepEqual(
      byOrigin.filter((f) => !f.startsWith("war/")),
      [],
      "only surrogates at the install's own origin",
    );
    return `${files.length} files probed`;
  });
}

const display = (page, id) =>
  page.evaluate((id) => {
    const el = document.getElementById(id);
    if (!el) return "absent";
    const style = getComputedStyle(el);
    return style.display === "none" ? "hidden" : "shown";
  }, id);

async function cosmetic(context, host) {
  const page = await context.newPage();
  await page.goto(`http://${host}/`);
  await page.waitForLoadState("load");
  await page.waitForTimeout(600);
  const ids = [
    "specific",
    "generic",
    "has-text",
    "plain-card",
    "remove",
    "upward",
    "untouched",
    "late-generic",
    "late-has-text",
  ];
  const state = {};
  for (const id of ids) state[id] = await display(page, id);
  state.position = await page.evaluate(
    () =>
      document.getElementById("style") &&
      getComputedStyle(document.getElementById("style")).position,
  );
  state.blur = await page.evaluate(
    () => document.getElementById("remove-class")?.classList.contains("blur") ?? null,
  );
  state.styleSheets = await page.evaluate(() => document.styleSheets.length);
  await page.close();
  return state;
}

async function cosmeticChecks(ext) {
  await check(
    "cosmetic: specific, generic, style, procedural and scriptlet rules apply",
    async () => {
      const s = await cosmetic(ext.context, "cosmetic.test");
      assert.deepEqual(s, {
        specific: "hidden",
        generic: "hidden",
        "has-text": "hidden",
        "plain-card": "shown",
        remove: "absent",
        upward: "hidden",
        untouched: "shown",
        "late-generic": "hidden",
        "late-has-text": "hidden",
        position: "static",
        blur: false,
        // The page's own <style>, nothing more: rules go in at the user origin.
        styleSheets: 1,
      });
    },
  );
  await check("cosmetic: #@# cancels a generic rule on its site", async () => {
    const s = await cosmetic(ext.context, "exempt.test");
    assert.deepEqual([s.specific, s.generic, s["late-generic"]], ["shown", "shown", "shown"]);
  });
  await check("cosmetic: $generichide keeps specific rules, drops generic ones", async () => {
    const s = await cosmetic(ext.context, "generichide.test");
    assert.deepEqual([s.specific, s.generic, s["late-generic"]], ["hidden", "shown", "shown"]);
  });
  await check("cosmetic: $elemhide drops all hiding", async () => {
    const s = await cosmetic(ext.context, "elemhide.test");
    assert.deepEqual([s.specific, s.generic, s["late-generic"]], ["shown", "shown", "shown"]);
  });
  await check("cosmetic: pausing a site turns cosmetic rules and scriptlets off", async () => {
    await ext.send({ type: "setSite", site: "cosmetic.test", paused: true });
    try {
      const s = await cosmetic(ext.context, "cosmetic.test");
      assert.deepEqual([s.specific, s.generic, s.blur], ["shown", "shown", true]);
    } finally {
      await ext.send({ type: "setSite", site: "cosmetic.test", paused: false });
    }
    const s = await cosmetic(ext.context, "cosmetic.test");
    assert.deepEqual([s.specific, s.blur], ["hidden", false]);
  });
  await check(
    "cosmetic: switching a ruleset off drops its cosmetic rules and scriptlets",
    async () => {
      await ext.send({ type: "setRuleset", id: "ads", enabled: false });
      try {
        const s = await cosmetic(ext.context, "cosmetic.test");
        assert.deepEqual(
          [s.specific, s.generic, s["has-text"], s.blur],
          ["shown", "shown", "shown", true],
        );
      } finally {
        await ext.send({ type: "setRuleset", id: "ads", enabled: true });
      }
    },
  );
}

const TRACKERS = ["track-cdn.test"];

async function trackerPage(server, context, hosts) {
  return requestsDuring(server, hosts, async () => {
    const page = await context.newPage();
    await page.goto("http://track.test/trackers.html");
    await page.waitForFunction(() => window.results?.done === true);
    const real = await page.evaluate(() => results.real);
    const ownImage = await page.evaluate(() => results.ownImage === true);
    await Promise.all([page.waitForURL("**/landing"), page.click("#ping")]);
    // Pings are sent after the navigation starts.
    await page.waitForTimeout(300);
    await page.close();
    return { real, ownImage };
  });
}

async function trackingChecks(server, plain, ext) {
  await check("trackers: the page makes every kind of tracker request", async () => {
    const { seen } = await trackerPage(server, plain.context, TRACKERS);
    // Firefox sends no hyperlink pings unless the user turns them on.
    const kinds = ["/pixel.gif", "/tag.js", "/beacon", "/collect", ...(FIREFOX ? [] : ["/ping"])];
    for (const kind of kinds) {
      assert.ok(
        seen.some((s) => s.includes(kind)),
        `${kind} never sent: ${seen}`,
      );
    }
  });
  await check(
    "trackers: no tracker request leaves the browser (img, script, beacon, fetch, ping)",
    async () => {
      const { value, seen } = await trackerPage(server, ext.context, TRACKERS);
      assert.deepEqual(seen, []);
      assert.equal(value.ownImage, true, "the first-party image was blocked");
    },
  );
  await check("parameters: tracking parameters are stripped from links", async () => {
    const page = await ext.context.newPage();
    await page.goto("http://track.test/links.html");
    const { seen } = await requestsDuring(server, ["shop.test"], async () => {
      await Promise.all([page.waitForURL("http://shop.test/**"), page.click("#tracked")]);
    });
    await page.close();
    assert.deepEqual(seen, ["shop.test/landing?id=42"]);
  });
}

// ------------------------------------------------------------- privacy (M7)

/** Opens a page and waits for its results, like visit(), returning the
 * requests it made to `hosts` too. */
const visitLogged = async (server, context, url, hosts) => {
  const logged = await requestsDuring(server, hosts, () => visit(context, url));
  // Chromium asks for a favicon on its own; it isn't the page's request.
  logged.entries = logged.entries.filter((e) => e.url !== "/favicon.ico");
  return logged;
};

async function gpcChecks(server, plain, ext) {
  const hosts = ["gpc.test", "gpc-cdn.test", "gpc-frame.test"];
  const url = "http://gpc.test/";
  // Firefox has navigator.globalPrivacyControl, false unless the user
  // turned GPC on; Chrome has none.
  const off = FIREFOX ? false : null;
  await check("gpc: without the extension, no signal", async () => {
    const { value, entries } = await visitLogged(server, plain.context, url, hosts);
    assert.equal(value.gpc, off);
    assert.deepEqual(
      entries.map((e) => e.gpc),
      [null, null, null],
    );
  });
  await check(
    "gpc: Sec-GPC on the page, its subresources and frames; navigator.globalPrivacyControl",
    async () => {
      const { value, entries } = await visitLogged(server, ext.context, url, hosts);
      assert.equal(value.gpc, true);
      assert.deepEqual(entries.map((e) => `${e.host}:${e.gpc}`).sort(), [
        "gpc-cdn.test:1",
        "gpc-frame.test:1",
        "gpc.test:1",
      ]);
    },
  );
  await check("gpc: a site exception drops both signals there", async () => {
    await ext.send({ type: "setSiteException", feature: "gpc", site: "gpc.test", off: true });
    try {
      const { value, entries } = await visitLogged(server, ext.context, url, hosts);
      assert.equal(value.gpc, off);
      assert.deepEqual(
        entries.map((e) => e.gpc),
        [null, null, null],
      );
    } finally {
      await ext.send({ type: "setSiteException", feature: "gpc", site: "gpc.test", off: false });
    }
  });
}

async function referrerChecks(server, plain, ext) {
  const hosts = ["ref.test", "ref-cdn.test", "cookie-tracker.test"];
  const url = "http://ref.test/page.html?secret=1";
  const referers = (entries) =>
    Object.fromEntries(
      entries
        .filter((e) => e.url !== "/page.html?secret=1")
        .map((e) => [`${e.host}${e.url.split("?")[0]}`, e.referer]),
    );
  // Firefox ignores a policy looser than its default for requests to
  // other sites (network.http.referer.disallowCrossSiteRelaxingDefault),
  // and sends them the origin; not for its other origins of the same site.
  const crossSite = FIREFOX ? "http://ref.test/" : url;
  await check(
    "referrer: the page asks for full referrers (unsafe-url), and gets them without the extension",
    async () => {
      const { entries } = await visitLogged(server, plain.context, url, hosts);
      assert.deepEqual(referers(entries), {
        "ref-cdn.test/pixel.gif": crossSite,
        "ref.test/own.gif": url,
        "static.ref.test/pixel.gif": url,
        "cookie-tracker.test/allowed.gif": crossSite,
      });
      return FIREFOX ? "Firefox sends other sites the origin anyway" : "";
    },
  );
  await check(
    "referrer: other origins and sites get the origin, trackers nothing, the page itself all",
    async () => {
      const { entries } = await visitLogged(server, ext.context, url, hosts);
      assert.deepEqual(referers(entries), {
        "ref-cdn.test/pixel.gif": "http://ref.test/",
        "ref.test/own.gif": url,
        "static.ref.test/pixel.gif": "http://ref.test/",
        "cookie-tracker.test/allowed.gif": null,
      });
    },
  );
  await check("referrer: a site exception restores the page's own policy", async () => {
    await ext.send({ type: "setSiteException", feature: "referrer", site: "ref.test", off: true });
    try {
      const { entries } = await visitLogged(server, ext.context, url, hosts);
      assert.equal(referers(entries)["static.ref.test/pixel.gif"], url);
      assert.equal(referers(entries)["ref-cdn.test/pixel.gif"], crossSite);
      assert.equal(referers(entries)["cookie-tracker.test/allowed.gif"], crossSite);
    } finally {
      await ext.send({
        type: "setSiteException",
        feature: "referrer",
        site: "ref.test",
        off: false,
      });
    }
  });
}

/** Days until each cookie of `url` expires (null for session cookies). */
async function cookieDays(context, url) {
  const now = Date.now() / 1000;
  const cookies = await context.cookies(url);
  return Object.fromEntries(
    cookies.map((c) => [c.name, c.expires > 0 ? Math.round((c.expires - now) / 86400) : null]),
  );
}

async function cookieChecks(server, plain, ext) {
  const page = "http://cookie.test/";
  const capped = async (context) => {
    await context.clearCookies({ domain: "cookie.test" });
    await visit(context, page);
    // The cap is applied when Chrome reports the cookie change.
    await new Promise((done) => setTimeout(done, 500));
    return cookieDays(context, page);
  };
  // The page asks for two years; Chrome allows at most 400 days.
  await check("cookies: tracking cookies live 400 days without the extension", async () => {
    const days = await capped(plain.context);
    for (const name of ["_ga", "_ga_TEST123", "_fbp", "prefs", "sid"]) {
      assert.ok(days[name] > 300, `${name}: ${days[name]} days`);
    }
  });
  await check(
    "cookies: first-party tracking cookies expire within a week, others untouched",
    async () => {
      const days = await capped(ext.context);
      for (const name of ["_ga", "_ga_TEST123", "_fbp"]) {
        assert.ok(days[name] <= 7, `${name}: ${days[name]} days`);
      }
      for (const name of ["prefs", "sid"]) {
        assert.ok(days[name] > 300, `${name}: ${days[name]} days`);
      }
    },
  );
  await check("cookies: a site exception leaves its tracking cookies alone", async () => {
    await ext.send({
      type: "setSiteException",
      feature: "cookies",
      site: "cookie.test",
      off: true,
    });
    try {
      const days = await capped(ext.context);
      assert.ok(days._ga > 300, `_ga: ${days._ga} days`);
    } finally {
      await ext.send({
        type: "setSiteException",
        feature: "cookies",
        site: "cookie.test",
        off: false,
      });
    }
  });

  if (!server.httpsPort) return;
  // A tracker's own cookie, set when it was visited directly, would come
  // back on every site that embeds it, and it could set more.
  const thirdParty = async (context) => {
    await context.clearCookies({ domain: "cookie-tracker.test" });
    await visit(context, "https://cookie-tracker.test/set");
    const { entries } = await visitLogged(server, context, "https://news.test/embed.html", [
      "cookie-tracker.test",
    ]);
    const names = (await context.cookies("https://cookie-tracker.test")).map((c) => c.name);
    return { sent: entries[0]?.cookie ?? null, stored: names.sort() };
  };
  let baseline = null;
  await check(
    "cookies: without the extension, a tracker's cookies flow both ways as a third party",
    async () => {
      baseline = await thirdParty(plain.context);
      assert.equal(baseline.sent, "tid=first");
      assert.deepEqual(baseline.stored, ["tid", "tid2"]);
    },
  );
  await check(
    "cookies: a tracker let through by a list exception gets no cookies and sets none",
    async () => {
      const r = await thirdParty(ext.context);
      assert.equal(r.sent, null);
      assert.deepEqual(r.stored, ["tid"], "only its first-party cookie");
    },
  );
}

async function webrtcChecks(ext) {
  const policy = () =>
    ext.worker.evaluate(() => chrome.privacy.network.webRTCIPHandlingPolicy.get({}));
  await check("webrtc: the IP handling policy is default_public_interface_only", async () => {
    const p = await policy();
    assert.deepEqual(p, {
      levelOfControl: "controlled_by_this_extension",
      value: "default_public_interface_only",
    });
  });
  await check("webrtc: switching the feature off gives the setting back", async () => {
    await ext.send({ type: "setFeature", id: "webrtc", enabled: false });
    try {
      const p = await policy();
      assert.equal(p.levelOfControl, "controllable_by_this_extension");
      assert.equal(p.value, "default");
    } finally {
      await ext.send({ type: "setFeature", id: "webrtc", enabled: true });
    }
    assert.equal((await policy()).value, "default_public_interface_only");
  });
}

/** The popup, freshly rendered: feature switches, per-site ones, and
 * whether the site access notice shows. */
const popupState = (ext) =>
  ext.popup(
    async (doc) => {
      for (let i = 0; i < 100 && !doc.querySelector("#features li"); i++) {
        await new Promise((ok) => setTimeout(ok, 50));
      }
      return {
        features: doc.querySelectorAll("#features li").length,
        siteFeatures: doc.querySelectorAll("#site-features li").length,
        accessNotice: !doc.getElementById("access").hidden,
      };
    },
    null,
    { reload: true },
  );

async function popupChecks(ext) {
  await check("popup: lists the privacy features, with per-site switches on a site", async () => {
    // Firefox adds CNAME uncloaking. Not on a web page: no per-site switches.
    assert.deepEqual(await popupState(ext), {
      features: FIREFOX ? 6 : 5,
      siteFeatures: 0,
      accessNotice: false,
    });
  });
  if (!FIREFOX) return;
  // Firefox lets the user take an extension's site access away in its
  // add-on settings (Chrome doesn't let an extension drop a required one).
  await check("popup: asks for site access back when the user took it away", async () => {
    const all = { origins: ["<all_urls>"] };
    await ext.worker.evaluate((p) => chrome.permissions.remove(p), all);
    try {
      assert.equal((await popupState(ext)).accessNotice, true);
    } finally {
      // As the user would grant it again, from Firefox's side.
      await ext.parent(async (id) => {
        const { ExtensionPermissions } = ChromeUtils.importESModule(
          "resource://gre/modules/ExtensionPermissions.sys.mjs",
        );
        const { extension } = WebExtensionPolicy.getByID(id);
        await ExtensionPermissions.add(id, { permissions: [], origins: ["<all_urls>"] }, extension);
        return true;
      }, ext.id);
    }
    assert.equal(await ext.worker.evaluate((p) => chrome.permissions.contains(p), all), true);
    assert.equal((await popupState(ext)).accessNotice, false);
  });
}

// ---------------------------------------------------- CNAME uncloaking (M8)

/** The page of first-party names with aliases, on `site` (see ALIASES). */
const cloakPage = (server, site) => {
  const images = Object.keys(ALIASES)
    .filter((name) => name.endsWith(`.${site}`))
    .map((name) => [name, `http://${name}:${server.port}/pixel.gif`]);
  if (site === "cloak.test")
    images.push([PROXIED_ALIAS[0], `http://${PROXIED_ALIAS[0]}/pixel.gif`]);
  return `<!doctype html><meta charset="utf-8"><title>CNAME cloaking</title>
<script>window.results = { loaded: {} };</script>
${images
  .map(
    ([name, src]) =>
      `<img src="${src}" alt="" onload="results.loaded['${name}'] = true" onerror="results.loaded['${name}'] = false">`,
  )
  .join("\n")}
<script>addEventListener("load", () => { results.done = true; });</script>`;
};

async function cnameChecks(server, plain, ext) {
  const url = "http://cloak.test/";
  const hosts = ["cloak.test"];
  const loaded = async (context) => {
    const { value, seen } = await requestsDuring(server, hosts, () => visit(context, url));
    const page = ["cloak.test/", "cloak.test/favicon.ico"];
    return { loaded: value.loaded, seen: seen.filter((s) => !page.includes(s)).sort() };
  };
  const all = {
    "metrics.cloak.test": true,
    "cdn.cloak.test": true,
    "img.cloak.test": true,
    "api.cloak.test": true,
    "stats.cloak.test": true,
  };
  await check("cname: without the extension, every aliased name loads", async () => {
    const r = await loaded(plain.context);
    assert.deepEqual(r.loaded, all);
    assert.equal(r.seen.length, 5);
  });
  await check(
    "cname: a site's name aliased to a blocked tracker is blocked, and never reaches the network",
    async () => {
      const r = await loaded(ext.context);
      assert.deepEqual(r.loaded, { ...all, "metrics.cloak.test": false });
      assert.ok(!r.seen.some((s) => s.startsWith("metrics.")), r.seen.join(", "));
      return "an alias on the same site, an unlisted one, an excepted one and a proxied one load";
    },
  );
  await check("cname: a site exception turns uncloaking off there", async () => {
    await ext.send({ type: "setSiteException", feature: "cname", site: "cloak.test", off: true });
    try {
      assert.deepEqual((await loaded(ext.context)).loaded, all);
    } finally {
      await ext.send({
        type: "setSiteException",
        feature: "cname",
        site: "cloak.test",
        off: false,
      });
    }
  });
  await check("cname: switching the feature off, or the ruleset naming the tracker", async () => {
    for (const [on, off] of [
      [
        { type: "setFeature", id: "cname", enabled: true },
        { type: "setFeature", id: "cname", enabled: false },
      ],
      [
        { type: "setRuleset", id: "privacy", enabled: true },
        { type: "setRuleset", id: "privacy", enabled: false },
      ],
    ]) {
      await ext.send(off);
      try {
        assert.deepEqual((await loaded(ext.context)).loaded, all, off.type);
      } finally {
        await ext.send(on);
      }
    }
    assert.equal((await loaded(ext.context)).loaded["metrics.cloak.test"], false, "back on");
  });
  await check("cname: still blocked after the event page was suspended", async () => {
    await ext.suspend();
    const r = await loaded(ext.context);
    assert.equal(r.loaded["metrics.cloak.test"], false);
    assert.ok(!r.seen.some((s) => s.startsWith("metrics.")));
  });
}

const FP = (host) => `http://${host}/fingerprint.html`;

/** The fingerprint checks; returns the browser to use afterwards (the last
 * check starts a new session). */
async function fingerprintChecks(server, plain, ext) {
  const base = [
    await visit(plain.context, FP("fp.test")),
    await visit(plain.context, FP("fp-b.test")),
  ];
  const hashes = (r) => ({
    dataURL: r.dataURL,
    imageData: r.imageData,
    audio: r.audio.sum,
    frame: r.frame,
    webgl: r.webgl?.pixels ?? null,
    webglURL: r.webgl?.dataURL ?? null,
  });
  await check("fingerprint: without protection, two sites see the same hashes", () => {
    assert.deepEqual(hashes(base[1]), hashes(base[0]));
    return base[0].webgl ? "" : "no WebGL in this browser";
  });
  const a1 = await visit(ext.context, FP("fp.test"));
  const a2 = await visit(ext.context, FP("fp.test"));
  const b = await visit(ext.context, FP("fp-b.test"));
  await check("fingerprint: hashes are stable within a site and session", () => {
    assert.deepEqual(hashes(a2), hashes(a1));
  });
  await check("fingerprint: another site sees different hashes, a third-party frame too", () => {
    const [x, y] = [hashes(a1), hashes(b)];
    for (const key of Object.keys(x)) {
      if (x[key] !== null) assert.notEqual(y[key], x[key], key);
    }
  });
  await check("fingerprint: never the true values, not even before the seed arrives", () => {
    const [x, t] = [hashes(a1), hashes(base[0])];
    for (const key of Object.keys(x)) {
      if (x[key] !== null) assert.notEqual(x[key], t[key], key);
    }
    assert.notEqual(a1.early, base[0].early);
    return a1.early === a2.early
      ? ""
      : "early reads (before the seed) differ per load, as designed";
  });
  await check("fingerprint: reads agree with each other; blank canvases stay blank", () => {
    assert.equal(a1.partAgrees, true, "a part of the canvas read alone matches the whole");
    assert.equal(a1.audio.stable, true, "audio read twice is the same");
    assert.equal(a1.blank, base[0].blank);
  });
  await check("fingerprint: CPU count bucketed to 2, 4 or 8; no user agent change", async () => {
    assert.ok([2, 4, 8].includes(a1.cores), String(a1.cores));
    const ua = async (context) => {
      const page = await context.newPage();
      await page.goto(FP("fp.test"));
      const value = await page.evaluate(() => [navigator.userAgent, navigator.platform]);
      await page.close();
      return value;
    };
    assert.deepEqual(await ua(ext.context), await ua(plain.context));
    return `${base[0].cores} → ${a1.cores}`;
  });
  await check("fingerprint: the WebGL renderer is bucketed", () => {
    const renderer = base[0].webgl?.renderer;
    if (!renderer) return "no WebGL renderer string in this browser";
    if (/SwiftShader|llvmpipe/.test(renderer)) {
      assert.equal(a1.webgl.renderer, renderer);
      return "software renderer here, passed through";
    }
    if (renderer.endsWith(", or similar")) {
      assert.equal(a1.webgl.renderer, renderer);
      return `Firefox's own coarse name, passed through: ${renderer}`;
    }
    assert.notEqual(a1.webgl.renderer, renderer);
    return a1.webgl.renderer;
  });
  await check("fingerprint: a site exception gives that site its true values", async () => {
    await ext.send({
      type: "setSiteException",
      feature: "fingerprinting",
      site: "fp-b.test",
      off: true,
    });
    try {
      const r = await visit(ext.context, FP("fp-b.test"));
      assert.deepEqual(hashes(r), hashes(base[1]));
    } finally {
      await ext.send({
        type: "setSiteException",
        feature: "fingerprinting",
        site: "fp-b.test",
        off: false,
      });
    }
  });
  let next = ext;
  await check("fingerprint: a new browser session sees different hashes", async () => {
    await ext.close();
    next = await extensionBrowser(ext.path, server, ext.profile);
    const c1 = await visit(next.context, FP("fp.test"));
    const c2 = await visit(next.context, FP("fp.test"));
    assert.deepEqual(hashes(c2), hashes(c1), "stable within the new session");
    assert.notEqual(c1.dataURL, a1.dataURL);
    assert.notEqual(c1.audio.sum, a1.audio.sum);
  });
  return next;
}

// ---------------------------------------------------------------- real build

async function realChecks(server, plain, real) {
  console.log(`real build: ${real.path}`);
  // The public lists block the testbed site's own ads.js (a generic rule)
  // and have no scriptlet for this made-up site: that takes a site rule,
  // which the testbed build has. The ad-network scripts must still pass.
  await detectionChecks(server, plain, null, real, ["globals", "bait"], {
    expected: [/^ads\.js: onerror$/, /^canRunAds is not set$/],
  });
  await check("real: no tracker from the public lists reaches the network", async () => {
    const { value, seen } = await trackerPage(server, real.context, [
      "track-cdn.test",
      ...[
        "google-analytics.com",
        "googletagmanager.com",
        "facebook.net",
        "facebook.com",
        "bing.com",
        "hotjar.com",
        "quantserve.com",
        "scorecardresearch.com",
        "doubleclick.net",
        "pinterest.com",
        "tiktok.com",
        "licdn.com",
      ],
    ]);
    // track-cdn.test is the testbed's own; the public lists don't know it.
    const leaked = seen.filter((s) => !s.startsWith("tracker.track-cdn.test"));
    assert.deepEqual(leaked, []);
    return `${value.real.length} endpoints`;
  });
  if (FIREFOX) {
    await check("real: names aliased to the public lists' CNAME trackers are blocked", async () => {
      const { value, seen } = await requestsDuring(server, ["realnews.test"], () =>
        visit(real.context, "http://realnews.test/"),
      );
      assert.deepEqual(value.loaded, {
        "smetrics.realnews.test": false,
        "ea.realnews.test": false,
      });
      assert.deepEqual(
        seen.filter((s) => s.startsWith("smetrics.") || s.startsWith("ea.")),
        [],
      );
      return "Adobe (omtrdc.net), Eulerian";
    });
  }
  await check(
    `real: ${BROWSER} took the cookie and Referer rules with every tracker host`,
    async () => {
      const trackers = JSON.parse(readFileSync(join(real.path, "trackers.json"), "utf8"));
      const rules = await real.worker.evaluate(() =>
        chrome.declarativeNetRequest.getDynamicRules(),
      );
      const sizes = Object.fromEntries(
        rules.map((r) => [r.id, r.condition.requestDomains?.length ?? 0]),
      );
      assert.equal(sizes[4], trackers.length, "cookies");
      assert.equal(sizes[5], trackers.length, "Referer");
      return `${trackers.length} hosts, ${rules.length} dynamic rules`;
    },
  );
  const bare = await visit(plain.context, `${DETECT}/stealth.html`);
  const mine = await visit(real.context, `${DETECT}/stealth.html`);
  await check("real: a page without site rules looks exactly the same", () => {
    assert.deepEqual(mine.names, bare.names);
    assert.deepEqual(mine.dom, bare.dom);
    assert.deepEqual(mine.functions, bare.functions);
    assert.deepEqual(mine.mutations, bare.mutations);
  });
}

// --------------------------------------------------------------------- bench

const percentile = (values, p) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
};
const ms = (v) => `${v.toFixed(3)} ms`;

/** First contentful paint and DOMContentLoaded end of one load. FCP is
 * coarsened to 4 ms by Chromium, hence many runs and means. `null` when the
 * load reports no paint in time: Firefox now and then reports none for a
 * page in a tab Playwright just opened. */
async function paint(context, url) {
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: "load", timeout: 10_000 });
    return await page.evaluate(
      () =>
        new Promise((done) => {
          setTimeout(() => done(null), 3000);
          new PerformanceObserver((list) => {
            const entry = list.getEntriesByName("first-contentful-paint")[0];
            const nav = performance.getEntriesByType("navigation")[0];
            if (entry) done({ fcp: entry.startTime, dcl: nav.domContentLoadedEventEnd });
          }).observe({ type: "paint", buffered: true });
        }),
    );
  } catch {
    return null;
  } finally {
    await page.close();
  }
}

const mean = (values) => values.reduce((a, b) => a + b, 0) / values.length;
/** Standard error of the mean. */
const stderr = (values) => {
  const m = mean(values);
  return Math.sqrt(
    values.reduce((a, v) => a + (v - m) ** 2, 0) / (values.length - 1) / values.length,
  );
};

async function bench(server, plain, real, dist) {
  console.log(`bench (extension/${FIREFOX ? "dist-firefox" : "dist"}, ${BROWSER}):`);
  const url = "http://bench.test/";
  // Firefox times paints by its refresh ticks, so its values are coarser.
  const runs = FIREFOX ? 100 : 40;
  // Both sides in the same kind of browser: a persistent profile, one
  // without the extension. Rounds alternate so drift hits both alike.
  const bare = await bareBrowser(server);
  try {
    for (const latency of [0, 40]) {
      server.setLatency(latency);
      const without = [];
      const withExt = [];
      await paint(bare.context, url);
      await paint(real.context, url);
      // Rounds where either side reported no paint are left out, whole.
      let dropped = 0;
      for (let i = 0; i < runs; i++) {
        const a = await paint(bare.context, url);
        const b = await paint(real.context, url);
        if (a && b) {
          without.push(a);
          withExt.push(b);
        } else {
          dropped += 1;
        }
      }
      for (const metric of ["fcp", "dcl"]) {
        const a = without.map((r) => r[metric]);
        const b = withExt.map((r) => r[metric]);
        const change = ((mean(b) - mean(a)) / mean(a)) * 100;
        const se = (Math.sqrt(stderr(a) ** 2 + stderr(b) ** 2) / mean(a)) * 100;
        console.log(
          `  ${metric === "fcp" ? "first contentful paint" : "DOMContentLoaded end  "}, ` +
            `${latency} ms latency, mean of ${a.length}: ${mean(a).toFixed(1)} ms without, ` +
            `${mean(b).toFixed(1)} ms with (${change >= 0 ? "+" : ""}${change.toFixed(1)}% ± ${se.toFixed(1)}%)` +
            (metric === "fcp" ? "; budget < 5%" : "") +
            (dropped ? `; ${dropped} rounds without a paint left out` : ""),
        );
      }
    }
  } finally {
    server.setLatency(0);
    await bare.close();
  }

  // The page engine in Node's V8: init, and the per-navigation lookups.
  const { Engine } = await import(
    pathToFileURL(join(extensionRoot, "build", "js", "engine.js")).href
  );
  const wasm = readFileSync(join(dist, "engine.wasm"));
  const index = readFileSync(join(dist, "page", "index.bin"));
  const inits = [];
  let engine;
  for (let i = 0; i < 20; i++) {
    const t = performance.now();
    engine = await Engine.load(wasm, index);
    inits.push(performance.now() - t);
  }
  console.log(
    `  page engine: ${(wasm.length / 1024).toFixed(0)} KiB wasm (${(gzipSync(wasm).length / 1024).toFixed(0)} KiB gzipped), ` +
      `index ${(index.length / 1024).toFixed(0)} KiB (${(gzipSync(index).length / 1024).toFixed(0)} KiB gzipped); ` +
      `init median ${ms(percentile(inits, 50))}, max ${ms(Math.max(...inits))} (budget < 100 ms)`,
  );
  const entries = JSON.parse(readFileSync(join(dist, "scriptlets.json"), "utf8"));
  const listed = entries
    .flatMap((e) => e.matches)
    .map((m) => m.replace(/^\*:\/\/(\*\.)?/, "").replace(/\/\*$/, ""))
    .filter((h) => !h.includes("*"));
  const hosts = [];
  for (let i = 0; i < 5000; i++) {
    hosts.push(
      i % 2 ? `www.${listed[(i * 7919) % listed.length]}` : `site${i}.example${i % 13}.com`,
    );
  }
  const mask = JSON.parse(readFileSync(join(dist, "rulesets.json"), "utf8")).reduce(
    (m, r) => m | r.mask,
    0,
  );
  const lookups = hosts.map((host) => {
    const t = performance.now();
    engine.page(host, mask);
    return performance.now() - t;
  });
  const tokens = [...new Set(benchPage().match(/class="[^"]+"|id="[^"]+"/g))].flatMap((attr) => {
    const [kind, value] = attr.split("=");
    return value
      .slice(1, -1)
      .split(" ")
      .map((v) => (kind === "id" ? `#${v}` : `.${v}`));
  });
  const generic = hosts.slice(0, 2000).map((host) => {
    const t = performance.now();
    engine.generic(host, mask, tokens, true);
    return performance.now() - t;
  });
  console.log(
    `  cosmetic lookup per navigation (${hosts.length} hostnames): p50 ${ms(percentile(lookups, 50))}, ` +
      `p99 ${ms(percentile(lookups, 99))} (budget p99 < 1 ms)`,
  );
  console.log(
    `  generic lookup for the bench page's ${tokens.length} tokens: p50 ${ms(percentile(generic, 50))}, ` +
      `p99 ${ms(percentile(generic, 99))}`,
  );

  // Scriptlets, measured by evaluating the files in a page: what the
  // every-page entity file costs a page it has nothing for, and what the
  // largest site file costs a page it does have calls for (lookup plus
  // running them). Chrome may cache compiled content scripts, so these
  // are upper bounds. Not included: Chrome matching each URL against the
  // registered patterns, which shows up in the paint numbers above.
  const files = entries.map((e) => join(dist, e.file));
  const cost = async (file, host) => {
    const source = readFileSync(file, "utf8");
    const times = [];
    for (let i = 0; i < 30; i++) {
      const page = await plain.context.newPage();
      await page.goto(`http://${host}/blank`);
      times.push(
        await page.evaluate((code) => {
          const t = performance.now();
          // Global (indirect) eval, as a content script runs: in a
          // throwaway page, to time the file itself.
          // biome-ignore lint/security/noGlobalEval: timing evaluation is the point
          globalThis.eval(code);
          return performance.now() - t;
        }, source),
      );
      await page.close();
    }
    return `${(source.length / 1024).toFixed(0)} KiB: p50 ${ms(percentile(times, 50))}, p99 ${ms(percentile(times, 99))}`;
  };
  const patterns = entries.reduce((n, e) => n + e.matches.length, 0);
  console.log(
    `  scriptlets: ${files.length} files, ${(files.reduce((n, f) => n + statSync(f).size, 0) / 1024).toFixed(0)} KiB, ` +
      `${patterns} match patterns`,
  );
  for (const entry of entries.filter((e) => e.matches.includes("*://*/*"))) {
    console.log(
      `    ${entry.file} (every page), on a page it has nothing for, ${await cost(join(dist, entry.file), "bench.test")}`,
    );
  }
  const sites = entries.filter((e) => !e.matches.includes("*://*/*"));
  const largest = sites.reduce((a, b) =>
    statSync(join(dist, a.file)).size >= statSync(join(dist, b.file)).size ? a : b,
  );
  const host = largest.matches[0].replace(/^\*:\/\/(\*\.)?/, "").replace(/\/\*$/, "");
  console.log(
    `    ${largest.file} (largest), on ${host}, which it has calls for, ${await cost(join(dist, largest.file), host)}`,
  );

  const state = await real.send({ type: "state", url });
  const mib = (n) => (n / 1048576).toFixed(1);
  if (FIREFOX) {
    await uncloakBench(real, dist);
    const memory = await real.parent(async () => {
      const info = await ChromeUtils.requestProcInfo();
      return info.children.filter((c) => c.type === "extension").map((c) => c.memory);
    });
    console.log(
      `  event page: engine init ${state.page?.initMs ?? "?"} ms in Firefox; extension process ` +
        `${memory.map(mib).join(", ")} MiB resident (Firefox's one process for all extensions, ` +
        "its own overhead included)",
    );
    return;
  }
  const heap = await workerHeap(real.context);
  console.log(
    `  service worker: engine init ${state.page?.initMs ?? "?"} ms in Chromium; ` +
      `JS heap ${mib(heap.usedSize)} MiB used of ${mib(heap.totalSize)} MiB, ` +
      `plus ${mib(heap.backingStorageSize)} MiB of buffers (the wasm memory holding the index)`,
  );
}

/**
 * CNAME uncloaking's costs (Firefox): loading the host lists in the event
 * page, and the decision every request waits for when its host's alias is
 * already known, timed in Node from the same code.
 */
async function uncloakBench(real, dist) {
  const load = await real.worker.evaluate(async () => {
    const t = performance.now();
    const entries = await (await fetch("uncloak.json")).json();
    const kinds = ["block", "exempt", "documents"];
    const maps = kinds.map(() => new Map());
    for (const [i, entry] of entries.entries()) {
      kinds.forEach((kind, k) => {
        for (const host of entry[kind]) maps[k].set(host, (maps[k].get(host) ?? 0) | (1 << i));
      });
    }
    return { ms: performance.now() - t, hosts: maps.reduce((n, m) => n + m.size, 0) };
  });
  const core = await import(pathToFileURL(join(extensionRoot, "build", "js", "core.js")).href);
  const entries = JSON.parse(readFileSync(join(dist, "uncloak.json"), "utf8"));
  const suffixes = JSON.parse(readFileSync(join(dist, "suffixes.json"), "utf8"));
  const sets = new core.HostSets(entries);
  const settings = core.normalizeSettings({});
  const blocked = entries.flatMap((e) => e.block);
  const times = [];
  for (let i = 0; i < 20000; i++) {
    const t = performance.now();
    const mask = sets.mask(settings);
    const host = core.uncloakCandidate(
      {
        url: `https://cdn${i}.site${i % 97}.example/a.js`,
        type: "script",
        documentUrl: `https://www.site${i % 97}.example/`,
        proxied: false,
      },
      settings,
      sets,
      mask,
    );
    if (host) core.aliasBlocked(host, `x.${blocked[i % blocked.length]}`, sets, mask, suffixes);
    times.push(performance.now() - t);
  }
  const bytes = statSync(join(dist, "uncloak.json")).size;
  console.log(
    `  uncloak: ${load.hosts} hosts (${(bytes / 1024).toFixed(0)} KiB) loaded in ${load.ms.toFixed(1)} ms ` +
      `in the event page; per request with a known alias: p50 ${ms(percentile(times, 50))}, ` +
      `p99 ${ms(percentile(times, 99))} (Node)`,
  );
}

/** The worker's heap, through the DevTools protocol (workers have no
 * performance.memory). */
async function workerHeap(context) {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  try {
    const { targetInfos } = await cdp.send("Target.getTargets");
    const worker = targetInfos.find(
      (t) => t.type === "service_worker" && t.url.endsWith("/background.js"),
    );
    const { sessionId } = await cdp.send("Target.attachToTarget", {
      targetId: worker.targetId,
      flatten: false,
    });
    const reply = new Promise((done) =>
      cdp.on("Target.receivedMessageFromTarget", (e) => {
        const message = JSON.parse(e.message);
        if (message.id === 1) done(message.result);
      }),
    );
    await cdp.send("Target.sendMessageToTarget", {
      sessionId,
      message: JSON.stringify({ id: 1, method: "Runtime.getHeapUsage" }),
    });
    return await reply;
  } finally {
    await cdp.detach();
    await page.close();
  }
}

// ---------------------------------------------------------------------- main

async function main() {
  const server = await startServer({
    generated: {
      "bench.test/": () => benchPage(),
      "cloak.test/": () => cloakPage(server, "cloak.test"),
      "realnews.test/": () => cloakPage(server, "realnews.test"),
    },
    https: true,
  });
  const testbed = build({
    browser: FIREFOX ? "firefox" : "chrome",
    rulesets: resolve(here, "rulesets.toml"),
    out: FIREFOX ? "build/testbed-extension-firefox" : "build/testbed-extension",
    compiled: "build/testbed-compiled",
    offline: true,
    quiet: true,
  });
  const plain = await plainBrowser(server);
  const naive = await plainBrowser(server, { naive: true });
  let ext = await extensionBrowser(testbed.out, server);
  console.log(
    `${BROWSER}, testbed build: ${testbed.rules} rules; set up ${ext.setupMs} ms after install`,
  );
  const opened = [plain, naive, ext];
  try {
    await detectionChecks(server, plain, naive, ext, ["globals", "bait", "probes", "detectors"], {
      // Firefox runs content scripts in a new about:blank frame a task
      // late, so a fetch taken from it at once is the browser's own.
      known: FIREFOX ? [/^fetch probe from a fresh iframe failed$/] : [],
    });
    await stealthChecks(plain, ext, {
      allowedNames: ["canRunAds", "adblockDetector", "blockAdBlock", "adHelpers"],
    });
    await cosmeticChecks(ext);
    await trackingChecks(server, plain, ext);
    await gpcChecks(server, plain, ext);
    await referrerChecks(server, plain, ext);
    await cookieChecks(server, plain, ext);
    await webrtcChecks(ext);
    await popupChecks(ext);
    if (FIREFOX) await cnameChecks(server, plain, ext);
    // Last: it restarts the browser for a new session.
    ext = await fingerprintChecks(server, plain, ext);
    opened.push(ext);

    const dist = join(extensionRoot, FIREFOX ? "dist-firefox" : "dist");
    if (args.real || args.bench) {
      assert.ok(
        existsSync(join(dist, "page")),
        `${dist} is missing; run \`npm run build${FIREFOX ? ":firefox" : ""}\` first`,
      );
      const real = await extensionBrowser(dist, server);
      opened.push(real);
      if (args.real) await realChecks(server, plain, real);
      if (args.bench) await bench(server, plain, real, dist);
    }
  } finally {
    await Promise.all([...new Set(opened)].map((b) => b.close().catch(() => {})));
    await server.close();
    for (const profile of profiles) rmSync(profile, { recursive: true, force: true });
  }
  const failed = results.filter((r) => !r.ok);
  console.log(`${results.length - failed.length} passed, ${failed.length} failed`);
  process.exitCode = failed.length ? 1 : 0;
}

await main();
