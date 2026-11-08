// End-to-end test of the browser bridge: the command line, the native
// host, the extension and the browser's rules, in one chain.
//
//   npm run e2e:bridge [-- --browser firefox]
//
// Everything is scratch: a resolver config in a temporary directory, a
// resolver on a free high port, a throwaway browser profile, and the host
// registered in that profile only (Chromium looks for hosts in its
// user-data directory; Firefox in $HOME, which is pointed at a temporary
// directory for it). `sinkhole bridge install` also runs with a temporary
// HOME, so nothing is written to the user's own home or browsers.
//
// The permission: the real build asks for it from the popup, and
// automation can't click a browser's permission prompt. In Firefox the
// test grants it from the parent process, as the prompt would, so the real
// connect-on-grant path runs. In Chromium the build under test declares
// it as required instead.

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { chromium } from "playwright-core";

import { build, FIREFOX_ID } from "../scripts/build.mjs";
import { launchFirefox } from "../scripts/firefox.mjs";

const root = resolve(import.meta.dirname, "..");
const repo = resolve(root, "..");
const { values: args } = parseArgs({
  options: { browser: { type: "string", default: "chromium" } },
});
const firefox = args.browser === "firefox";
const binary = join(repo, "target", "release", "sinkhole");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function freePort() {
  const server = createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  await new Promise((r) => server.close(r));
  return port;
}

/** Polls `fn` until it returns something truthy, or fails after `ms`. */
async function until(what, fn, ms = 10_000) {
  const started = Date.now();
  for (;;) {
    const value = await fn();
    if (value) return value;
    if (Date.now() - started > ms) throw new Error(`timed out waiting for ${what}`);
    await sleep(200);
  }
}

function cli(dir, ...argv) {
  return execFileSync(binary, ["--config", join(dir, "sinkhole.toml"), ...argv], {
    encoding: "utf8",
    env: { ...process.env, HOME: join(dir, "home") },
  });
}

async function startResolver(dir) {
  const port = await freePort();
  writeFileSync(
    join(dir, "sinkhole.toml"),
    `allow = ["ads.sinkhole.test"]
block = ["blocked.test", "*.wild.test"]

[listen]
addrs = ["127.0.0.1:${port}"]

[updates]
cache_dir = "cache"

[control]
socket = "c.sock"

# Never asked: the test sends no query.
[[upstream]]
protocol = "udp"
addr = "127.0.0.1:9"
`,
  );
  const daemon = spawn(binary, ["run", "--config", join(dir, "sinkhole.toml")], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  let log = "";
  daemon.stderr.on("data", (d) => {
    log += d;
  });
  await until("the resolver's control socket", () => existsSync(join(dir, "c.sock")));
  return { daemon, log: () => log };
}

/** The extension; in Chromium with nativeMessaging granted up front. */
function extension() {
  const built = build({
    browser: firefox ? "firefox" : "chrome",
    rulesets: "e2e/fixtures/rulesets.toml",
    out: firefox ? "build/bridge-extension-firefox" : "build/bridge-extension",
    compiled: "build/e2e-compiled",
    offline: true,
    dev: true,
    quiet: true,
  });
  if (!firefox) {
    const path = join(built.out, "manifest.json");
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    manifest.permissions.push("nativeMessaging");
    delete manifest.optional_permissions;
    writeFileSync(path, JSON.stringify(manifest, null, 2));
  }
  return built.out;
}

async function launch(dir, out) {
  const profile = join(dir, "profile");
  mkdirSync(profile);
  if (firefox) {
    // Firefox reads host manifests from one per-user directory, found once
    // (~/Library/Application Support/Mozilla on macOS, whatever $HOME
    // says). In this throwaway Firefox only, the lookup is pointed at the
    // scratch directory instead, from the parent process.
    const mozilla = join(dir, "mozilla");
    cli(dir, "bridge", "install", "--dir", join(mozilla, "NativeMessagingHosts"), "--firefox");
    // testMatchOutcome needs the feedback pref in Firefox.
    const ff = await launchFirefox(out, profile, { prefs: { "extensions.dnr.feedback": true } });
    await ff.parent(
      async (dirs) => {
        const { NativeManifests } = ChromeUtils.importESModule(
          "resource://gre/modules/NativeManifests.sys.mjs",
        );
        await NativeManifests.init();
        NativeManifests._lookup = (type, name, context) =>
          NativeManifests._tryPaths(type, name, dirs, context);
        return true;
      },
      [mozilla],
    );
    // The user's "Allow" in the permission prompt.
    await ff.parent(async (id) => {
      const { ExtensionPermissions } = ChromeUtils.importESModule(
        "resource://gre/modules/ExtensionPermissions.sys.mjs",
      );
      const { extension } = WebExtensionPolicy.getByID(id);
      await ExtensionPermissions.add(
        id,
        { permissions: ["nativeMessaging"], origins: [] },
        extension,
      );
      return true;
    }, FIREFOX_ID);
    return { ...ff, id: FIREFOX_ID };
  }
  const context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${out}`, `--load-extension=${out}`],
  });
  const ours = (w) =>
    w.url().startsWith("chrome-extension://") && w.url().endsWith("/background.js");
  let worker = context.serviceWorkers().find(ours);
  worker ??= await context.waitForEvent("serviceworker", { predicate: ours });
  const id = new URL(worker.url()).host;
  // Chromium reads hosts from the profile's NativeMessagingHosts.
  cli(dir, "bridge", "install", "--dir", join(profile, "NativeMessagingHosts"), "--chrome-id", id);
  const popup = await context.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);
  return {
    context,
    id,
    evaluate: (fn, arg) => worker.evaluate(fn, arg),
    send: (request) => popup.evaluate((r) => chrome.runtime.sendMessage(r), request),
    close: () => context.close(),
  };
}

const dynamicRules = (ext) => ext.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
const ruleById = (rules, id) => rules.find((r) => r.id === id);

const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}

async function run() {
  const dir = mkdtempSync(join(tmpdir(), "sinkhole-bridge-"));
  const { daemon, log } = await startResolver(dir);
  const out = extension();
  const ext = await launch(dir, out);
  const state = () => ext.send({ type: "state", url: "https://site.test/" });

  check("connects and turns the resolver's lists into rules", async () => {
    // Firefox connects by itself once the permission is granted.
    if (!firefox) await ext.send({ type: "bridgeConnect" });
    const rules = await until("the bridge's rules", async () => {
      const r = await dynamicRules(ext);
      return ruleById(r, 10) && ruleById(r, 11) ? r : null;
    }).catch(async (e) => {
      throw new Error(`${e.message}; bridge: ${JSON.stringify((await state()).bridge)}`);
    });
    assert.deepEqual(ruleById(rules, 10).condition.requestDomains, ["ads.sinkhole.test"]);
    assert.equal(ruleById(rules, 10).action.type, "allow");
    assert.deepEqual(ruleById(rules, 11).condition.requestDomains, ["blocked.test"]);
    assert.ok(ruleById(rules, 100).condition.regexFilter.includes("wild\\.test"));
    const s = await state();
    assert.equal(s.bridge.connected, true);
    assert.equal(s.bridge.running, true);
    return "allow 1, block 1, regex 1";
  });
  check("the resolver's allowlist beats a list's block; its blocklist blocks", async () => {
    const outcome = (url) =>
      ext.evaluate(
        (u) =>
          chrome.declarativeNetRequest.testMatchOutcome({
            url: u,
            type: "script",
            initiator: "https://site.test",
          }),
        url,
      );
    const ids = (o) => o.matchedRules.map((r) => r.ruleId);
    const allowed = await outcome("https://ads.sinkhole.test/ad.js");
    assert.deepEqual(ids(allowed), [10], JSON.stringify(allowed));
    assert.deepEqual(ids(await outcome("https://blocked.test/x.js")), [11]);
    assert.deepEqual(ids(await outcome("https://cdn.wild.test/x.js")), [100]);
    // Only the privacy header rules (ids 2-5) match a name the bridge
    // doesn't cover.
    const notWild = await outcome("https://wild.test/x.js");
    assert.deepEqual(
      notWild.matchedRules.filter((r) => r.ruleId >= 10),
      [],
    );
  });
  check("`sinkhole block add` reaches the browser within seconds", async () => {
    const started = Date.now();
    cli(dir, "block", "add", "late.test");
    await until("the new entry", async () =>
      ruleById(await dynamicRules(ext), 11)?.condition.requestDomains?.includes("late.test"),
    );
    return `${Date.now() - started} ms`;
  });
  check("`sinkhole pause` pauses the browser too, and `resume` ends it", async () => {
    cli(dir, "pause", "--for", "5m");
    await until("the pause", async () => {
      const pause = ruleById(await dynamicRules(ext), 1);
      // Firefox reports an unset condition as null, Chrome leaves it out.
      return pause && pause.condition.requestDomains == null;
    });
    const s = await state();
    assert.equal(s.paused, true);
    assert.ok(s.bridge.paused?.until > Date.now());
    const scripts = await ext.evaluate(() => chrome.scripting.getRegisteredContentScripts());
    assert.deepEqual(scripts, [], "page scripts unregistered while paused");
    cli(dir, "resume");
    await until("the end of the pause", async () => !ruleById(await dynamicRules(ext), 1));
    const after = await ext.evaluate(() => chrome.scripting.getRegisteredContentScripts());
    assert.ok(after.length > 0, "page scripts back");
  });
  check("a resolver that stops ends its pause in the browser", async () => {
    cli(dir, "pause");
    await until("the pause", async () => ruleById(await dynamicRules(ext), 1));
    daemon.kill("SIGTERM");
    await until("the resolver to stop", async () => {
      const s = await state();
      return s.bridge.running === false && s.bridge.paused === null;
    });
    assert.equal(ruleById(await dynamicRules(ext), 1), undefined);
    // The lists still apply: they come from the config file.
    assert.ok(ruleById(await dynamicRules(ext), 11));
  });
  check("disconnecting removes every rule the bridge added", async () => {
    await ext.send({ type: "bridgeDisconnect" });
    const rules = await dynamicRules(ext);
    assert.deepEqual(
      rules.filter((r) => r.id >= 10).map((r) => r.id),
      [],
    );
    const s = await state();
    assert.equal(s.bridge.connected, false);
  });

  let failed = 0;
  try {
    for (const [name, fn] of checks) {
      try {
        const note = await fn();
        console.log(`  ok    ${name}${note ? `  [${note}]` : ""}`);
      } catch (e) {
        failed++;
        console.log(`  FAIL  ${name}\n        ${e.message.split("\n").join("\n        ")}`);
      }
    }
  } finally {
    await ext.close();
    daemon.kill("SIGTERM");
    if (failed) console.log(log());
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(`${checks.length - failed} passed, ${failed} failed`);
  process.exitCode = failed ? 1 : 0;
}

await run();
