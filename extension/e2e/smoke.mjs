// End-to-end smoke test: the unpacked extension in Playwright's Chromium,
// or its Firefox.
//
//   npm run e2e [-- --browser firefox] [-- --skip-real]
//
// The browser runs headless with a throwaway profile that is deleted
// afterwards; the user's own browsers are never touched. Every hostname
// leads to a local test server, so nothing leaves the machine: Chromium
// resolves them all to it (--host-resolver-rules), Firefox uses it as its
// proxy.
//
// Part 1 builds the extension from e2e/fixtures/rulesets.toml (the real
// surrogate and parameter lists plus a small fixture list) and checks
// behavior in real pages: blocking, exceptions, third-party rules,
// surrogates, parameter stripping, signed URLs, pausing a site and
// switching a ruleset off.
//
// Part 2 loads the real build (dist/ or dist-firefox/, as `npm run build --
// --dev` makes it) and asks the browser, through declarativeNetRequest
// .testMatchOutcome, whether the compiled rules from the real lists loaded
// and match what they should.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { chromium } from "playwright-core";

import { build } from "../scripts/build.mjs";
import { launchFirefox } from "../scripts/firefox.mjs";

const root = resolve(import.meta.dirname, "..");
const { values: args } = parseArgs({
  options: { "skip-real": { type: "boolean" }, browser: { type: "string", default: "chromium" } },
});
const firefox = args.browser === "firefox";
const browserName = firefox ? "Firefox" : "Chrome";

/** A local server for every hostname; it logs host + path of each request. */
async function startServer() {
  const log = [];
  const server = createServer((req, res) => {
    // As Firefox's proxy, the server gets absolute URLs.
    if (/^https?:\/\//.test(req.url)) {
      const url = new URL(req.url);
      req.url = url.pathname + url.search;
    }
    const host = (req.headers.host ?? "").replace(/:\d+$/, "");
    log.push(`${host}${req.url}`);
    const path = req.url.split("?")[0];
    const send = (type, body) => {
      res.writeHead(200, { "content-type": type, "cache-control": "no-store" });
      res.end(body);
    };
    if (path === "/page.html") return send("text/html", page());
    if (path === "/landing") return send("text/html", "<title>landing</title>");
    if (path === "/ad.js") return send("text/javascript", "window.results.adLoaded = true;");
    if (path === "/allowed.js") {
      return send("text/javascript", "window.results.allowedLoaded = true;");
    }
    if (path.endsWith(".gif")) {
      const gif = Buffer.from(
        "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==",
        "base64",
      );
      return send("image/gif", gif);
    }
    // The real ad and analytics scripts: if one of these runs, the
    // surrogate redirect did not happen.
    if (path.endsWith(".js")) return send("text/javascript", "window.results.realScript = true;");
    res.writeHead(404);
    res.end();
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  return { server, log, port: server.address().port };
}

// URLs carry no port: Chromium maps port 80 of every host to the server
// (Firefox sends everything there), so filters like `||host/path` see the
// URLs real pages have.
function page() {
  const url = (host, path) => `http://${host}${path}`;
  return `<!doctype html><title>test</title>
<script>window.results = {};</script>
<script src="${url("ads.sinkhole.test", "/ad.js")}" onerror="results.adBlocked = true"></script>
<script src="${url("ads.sinkhole.test", "/allowed.js")}"></script>
<script src="${url("pagead2.googlesyndication.com", "/pagead/js/adsbygoogle.js")}"></script>
<script src="${url("www.googletagservices.com", "/tag/js/gpt.js")}"></script>
<script src="${url("www.google-analytics.com", "/analytics.js")}"></script>
<img src="${url("tracker.sinkhole.test", "/t.gif")}"
     onload="results.trackerLoaded = true" onerror="results.trackerBlocked = true">
<script>
  results.adsbygoogle = !!(window.adsbygoogle && window.adsbygoogle.loaded);
  if (window.googletag) googletag.cmd.push(function () { results.gptQueue = true; });
  if (window.ga) ga("send", "pageview", { hitCallback: function () { results.gaCallback = true; } });
</script>`;
}

/**
 * The browser with the extension: its context, `evaluate(fn, arg)` in the
 * background script, and `send(request)` from the popup.
 */
async function launch(extension, port) {
  const profile = mkdtempSync(join(tmpdir(), "sinkhole-e2e-"));
  if (firefox) {
    const ff = await launchFirefox(extension, profile, {
      proxy: { server: `http://127.0.0.1:${port}` },
      // testMatchOutcome needs it, besides the feedback permission.
      prefs: { "extensions.dnr.feedback": true },
    });
    return { ...ff, profile };
  }
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${extension}`,
      `--load-extension=${extension}`,
      `--host-resolver-rules=MAP *:80 127.0.0.1:${port}`,
    ],
  });
  // Chromium's own component extensions have workers too; ours is the
  // one running background.js.
  const ours = (w) =>
    w.url().startsWith("chrome-extension://") && w.url().endsWith("/background.js");
  let worker = context.serviceWorkers().find(ours);
  worker ??= await context.waitForEvent("serviceworker", { predicate: ours });
  const id = new URL(worker.url()).host;
  // The popup page is an extension page, so it may message the worker.
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);
  return {
    context,
    profile,
    evaluate: (fn, arg) => worker.evaluate(fn, arg),
    send: (request) => popup.evaluate((r) => chrome.runtime.sendMessage(r), request),
    popup: async (fn, arg, { reload = false } = {}) => {
      if (reload) await popup.reload();
      return popup.evaluate(`(${fn})(document, window, ${JSON.stringify(arg ?? null)})`);
    },
    close: () => context.close(),
  };
}

/** Waits until the background script has applied its settings on install. */
async function ready(ext, expected) {
  const started = Date.now();
  for (;;) {
    // The worker can be reported before Chrome has bound its APIs.
    const enabled = await ext.evaluate(() =>
      globalThis.chrome?.declarativeNetRequest
        ? chrome.declarativeNetRequest.getEnabledRulesets()
        : [],
    );
    if (expected.every((id) => enabled.includes(id))) return Date.now() - started;
    assert.ok(Date.now() - started < 10_000, `rulesets never enabled: ${enabled}`);
    await new Promise((ok) => setTimeout(ok, 50));
  }
}

async function results(page) {
  await page.waitForFunction(
    () => window.results?.gaCallback !== undefined || document.readyState === "complete",
  );
  await page.waitForTimeout(150);
  return page.evaluate(() => window.results);
}

const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}

async function run() {
  const { server, log, port } = await startServer();
  const fixture = build({
    browser: firefox ? "firefox" : "chrome",
    rulesets: "e2e/fixtures/rulesets.toml",
    out: firefox ? "build/e2e-extension-firefox" : "build/e2e-extension",
    compiled: "build/e2e-compiled",
    offline: true,
    dev: true,
    quiet: true,
  });
  const site = "http://site.test";
  const ext = await launch(fixture.out, port);
  const setupMs = await ready(ext, ["ads", "privacy", "params"]);
  const tab = await ext.context.newPage();
  const send = ext.send;

  check("blocks listed requests", async () => {
    await tab.goto(`${site}/page.html`);
    const r = await results(tab);
    assert.equal(r.adBlocked, true, JSON.stringify(r));
    assert.equal(r.adLoaded, undefined);
  });
  check("honors @@ exceptions", async () => {
    const r = await results(tab);
    assert.equal(r.allowedLoaded, true);
  });
  check("blocks third-party trackers only", async () => {
    const r = await results(tab);
    assert.equal(r.trackerBlocked, true);
    log.length = 0;
    await tab.goto("http://tracker.sinkhole.test/landing");
    assert.ok(log.includes("tracker.sinkhole.test/landing"), "first-party visit allowed");
  });
  check("serves surrogates, which never reach the network", async () => {
    log.length = 0;
    await tab.goto(`${site}/page.html`);
    const r = await results(tab);
    assert.equal(r.adsbygoogle, true, "adsbygoogle surrogate");
    assert.equal(r.gptQueue, true, "googletag.cmd ran the callback");
    await tab.waitForFunction(() => window.results.gaCallback === true);
    assert.equal(r.realScript, undefined, "no real ad script ran");
    for (const host of [
      "pagead2.googlesyndication.com",
      "www.googletagservices.com",
      "www.google-analytics.com",
    ]) {
      assert.ok(!log.some((l) => l.startsWith(host)), `${host} was contacted: ${log}`);
    }
  });
  check("strips tracking parameters from navigations", async () => {
    log.length = 0;
    await tab.goto(`${site}/landing?utm_source=news&fbclid=abc&s_cid=1&ref_id=2&keep=1`);
    assert.deepEqual(log, ["site.test/landing?keep=1"]);
    assert.equal(new URL(tab.url()).search, "?keep=1");
  });
  check("leaves signed URLs alone", async () => {
    log.length = 0;
    await tab.goto(`${site}/landing?X-Amz-Signature=sig&utm_source=news`);
    assert.deepEqual(log, ["site.test/landing?X-Amz-Signature=sig&utm_source=news"]);
  });
  check("switching a site off stops everything there", async () => {
    await send({ type: "setSite", site: "site.test", paused: true });
    await tab.goto(`${site}/page.html`);
    const r = await results(tab);
    assert.equal(r.adLoaded, true, JSON.stringify(r));
    assert.equal(r.realScript, true, "no surrogates either");
    log.length = 0;
    await tab.goto(`${site}/landing?utm_source=news`);
    assert.deepEqual(log, ["site.test/landing?utm_source=news"]);
    await send({ type: "setSite", site: "site.test", paused: false });
    await tab.goto(`${site}/page.html`);
    assert.equal((await results(tab)).adBlocked, true, "back on");
  });
  check("each ruleset switches off on its own", async () => {
    await send({ type: "setRuleset", id: "params", enabled: false });
    log.length = 0;
    await tab.goto(`${site}/landing?utm_source=news`);
    assert.deepEqual(log, ["site.test/landing?utm_source=news"]);
    await tab.goto(`${site}/page.html`);
    assert.equal((await results(tab)).adBlocked, true, "ads still blocked");
    await send({ type: "setRuleset", id: "params", enabled: true });
    log.length = 0;
    await tab.goto(`${site}/landing?utm_source=news`);
    assert.deepEqual(log, ["site.test/landing"]);
  });
  check("the popup lists the rulesets", async () => {
    const count = await ext.popup(
      async (doc) => {
        for (let i = 0; i < 100 && !doc.querySelector("#rulesets li"); i++) {
          await new Promise((ok) => setTimeout(ok, 50));
        }
        return doc.querySelectorAll("#rulesets li").length;
      },
      null,
      { reload: true },
    );
    assert.equal(count, 3);
  });

  let failed = 0;
  console.log(
    `${browserName}, fixture build: ${fixture.rules} rules; rulesets enabled ${setupMs} ms after install`,
  );
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log(`  ok    ${name}`);
    } catch (e) {
      failed += 1;
      console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
    }
  }
  await ext.close();
  rmSync(ext.profile, { recursive: true, force: true });

  if (!args["skip-real"]) {
    failed += await realRules(port);
  }
  server.close();
  if (failed > 0) {
    console.log(`${failed} check(s) failed`);
    process.exit(1);
  }
}

/** Whether `action` is a redirect that only removes parameters `url` doesn't have. */
function noop(url, action) {
  const transform = action?.redirect?.transform;
  const remove = transform?.queryTransform?.removeParams;
  if (action?.type !== "redirect" || !remove || Object.keys(transform).length !== 1) {
    return false;
  }
  const params = [...new URL(url).searchParams.keys()];
  return (
    Object.keys(transform.queryTransform).length === 1 && !params.some((p) => remove.includes(p))
  );
}

/** The real build: did the browser load every ruleset, and do the rules match? */
async function realRules(port) {
  const dist = join(root, firefox ? "dist-firefox" : "dist");
  const manifest = join(dist, "manifest.json");
  if (
    !existsSync(manifest) ||
    !readFileSync(manifest, "utf8").includes("declarativeNetRequestFeedback")
  ) {
    const command = firefox ? "npm run build:firefox -- --dev" : "npm run build -- --dev";
    console.log(`real build: skipped (build it first with \`${command}\`)`);
    return 0;
  }
  const ext = await launch(dist, port);
  let failed = 0;
  const report = (ok, line) => {
    if (!ok) failed += 1;
    console.log(`  ${ok ? "ok  " : "FAIL"}  ${line}`);
  };
  try {
    const expected = ["ads", "privacy", "badware", "unbreak", "params"];
    const setupMs = await ready(ext, expected);
    const status = await ext.evaluate(async () => ({
      available: await chrome.declarativeNetRequest.getAvailableStaticRuleCount(),
      guaranteed: chrome.declarativeNetRequest.GUARANTEED_MINIMUM_STATIC_RULES,
      enabled: await chrome.declarativeNetRequest.getEnabledRulesets(),
    }));
    console.log(
      `real build: rulesets ${status.enabled.join(", ")} enabled ${setupMs} ms after install; ` +
        `${status.available} static rules still available`,
    );
    if (firefox) {
      // Firefox drops a rule it can't parse and loads the rest, so the
      // count of rules it holds must be the count the build has.
      const index = JSON.parse(readFileSync(join(dist, "rulesets.json"), "utf8"));
      const total = index.reduce((n, r) => n + r.rules, 0);
      const loaded = status.guaranteed - status.available;
      report(loaded === total, `Firefox loaded all ${total} static rules (${loaded})`);
    }
    // Chrome refuses an extension with an oversized regex outright, so
    // every one in the build is re-checked with Chrome itself.
    const regex = await ext.evaluate(async (ids) => {
      let total = 0;
      const refused = [];
      for (const id of ids) {
        const response = await fetch(chrome.runtime.getURL(`rulesets/${id}.json`));
        for (const rule of await response.json()) {
          const source = rule.condition.regexFilter;
          if (!source) continue;
          total += 1;
          const verdict = await chrome.declarativeNetRequest.isRegexSupported({
            regex: source,
            isCaseSensitive: rule.condition.isUrlFilterCaseSensitive ?? false,
          });
          if (!verdict.isSupported) refused.push(`${id}#${rule.id} ${verdict.reason}: ${source}`);
        }
      }
      return { total, refused };
    }, expected);
    const regexOk = regex.refused.length === 0;
    report(
      regexOk,
      `${browserName} supports all ${regex.total} regex rules` +
        (regexOk ? "" : `\n        ${regex.refused.slice(0, 5).join("\n        ")}`),
    );
    const cases = [
      [
        "adsbygoogle.js gets the surrogate",
        "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
        "script",
        "redirect",
      ],
      [
        "analytics.js gets the surrogate",
        "https://www.google-analytics.com/analytics.js",
        "script",
        "redirect",
      ],
      ["doubleclick is blocked", "https://ad.doubleclick.net/ddm/adj/x", "image", "block"],
      [
        "a tracker pixel is blocked",
        "https://www.facebook.com/tr?id=1&ev=PageView",
        "image",
        "block",
      ],
      [
        "utm_source is stripped",
        "https://example.org/article?utm_source=x",
        "main_frame",
        "redirect",
      ],
      ["an ordinary page is untouched", "https://example.org/article", "main_frame", null],
      ["an ordinary image is untouched", "https://upload.wikimedia.org/a.png", "image", null],
    ];
    for (const [name, url, type, want] of cases) {
      const outcome = await ext.evaluate(
        async ([u, t]) => {
          const result = await chrome.declarativeNetRequest.testMatchOutcome({
            url: u,
            type: t,
            initiator: "https://news.example",
          });
          return result.matchedRules;
        },
        [url, type],
      );
      const actions = await Promise.all(
        outcome.map(({ ruleId, rulesetId }) =>
          ext.evaluate(
            async ([id, set]) => {
              // The dynamic rules are the per-site switch and the privacy
              // header features (M7), not compiled rulesets.
              const rules =
                set === "_dynamic"
                  ? await chrome.declarativeNetRequest.getDynamicRules()
                  : await (await fetch(chrome.runtime.getURL(`rulesets/${set}.json`))).json();
              return rules.find((r) => r.id === id)?.action;
            },
            [ruleId, rulesetId],
          ),
        ),
      ).then((found) => found.map((action) => (noop(url, action) ? "noop" : action?.type)));
      // "Untouched": no compiled rule acts. GPC's header rule (dynamic,
      // modifyHeaders) applies to every request by design. Firefox also
      // reports a parameter-stripping redirect with nothing to strip,
      // which Chrome leaves out; it doesn't act either.
      const compiled = outcome.filter(
        (m, i) => m.rulesetId !== "_dynamic" && actions[i] !== "noop",
      );
      const ok = want === null ? compiled.length === 0 : actions.includes(want);
      const detail = outcome.map((m, i) => `${m.rulesetId}#${m.ruleId}:${actions[i]}`).join(" ");
      report(ok, `${name}  [${detail || "no match"}]`);
    }
  } finally {
    await ext.close();
    rmSync(ext.profile, { recursive: true, force: true });
  }
  return failed;
}

await run();
