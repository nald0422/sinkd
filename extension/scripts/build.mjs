// Builds the unpacked extension.
//
//   node scripts/build.mjs [--browser chrome|firefox] [--out DIR]
//                          [--rulesets rulesets.toml]
//                          [--cache DIR] [--offline] [--dev]
//
// 1. `sinkhole compile` turns the lists named in rulesets.toml into DNR
//    rulesets, surrogates, the page index, scriptlet files and a report
//    (build/compiled/).
// 2. cargo builds the page engine for wasm32 (crates/engine-wasm).
// 3. tsc compiles src/ (build/js/).
// 4. Everything is assembled in --out (dist/ for Chrome, dist-firefox/
//    for Firefox), and the manifest's rule_resources are filled in from
//    the compiled rulesets. Firefox gets the same code with its own
//    manifest (see firefoxManifest) and the host lists for uncloaking.
//
// --dev adds the declarativeNetRequestFeedback permission, which the
// end-to-end test needs for testMatchOutcome. Release builds omit it.

import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const repo = resolve(root, "..");

/** The add-on ID Firefox knows the extension by: permanent once published. */
export const FIREFOX_ID = "sinkhole@sinkhole.invalid";

/**
 * The Chrome manifest, made Firefox's: an event page instead of a service
 * worker (Firefox has no extension service workers), the `dns` and
 * blocking webRequest permissions for CNAME uncloaking, and Gecko's
 * settings. Firefox 140 (the current ESR) has everything else it uses:
 * DNR, main-world scripts, storage.session, data_collection_permissions.
 */
export function firefoxManifest(chromeManifest) {
  const manifest = structuredClone(chromeManifest);
  delete manifest.minimum_chrome_version;
  manifest.background = { scripts: ["background.js"], type: "module" };
  manifest.permissions = [...manifest.permissions, "dns", "webRequest", "webRequestBlocking"];
  // Chrome's guard against probing for an extension's resources; Firefox
  // gives each install its own random moz-extension:// host instead.
  for (const resources of manifest.web_accessible_resources) {
    delete resources.use_dynamic_url;
  }
  manifest.browser_specific_settings = {
    gecko: {
      id: FIREFOX_ID,
      strict_min_version: "140.0",
      data_collection_permissions: { required: ["none"] },
    },
  };
  return manifest;
}

/** Resource types Chrome's DNR has and Firefox's lacks. */
const CHROME_ONLY_TYPES = ["webtransport", "webbundle"];

/**
 * A compiled rule for Firefox, which drops a rule naming a resource type it
 * doesn't know (the compiler spells out every type for `$all` and negated
 * types). Those types can't occur in Firefox, so leaving them out changes
 * nothing else.
 */
export function firefoxRule(rule) {
  const condition = { ...rule.condition };
  for (const key of ["resourceTypes", "excludedResourceTypes"]) {
    if (condition[key]) {
      condition[key] = condition[key].filter((t) => !CHROME_ONLY_TYPES.includes(t));
      if (condition[key].length === 0) delete condition[key];
    }
  }
  return { ...rule, condition };
}

/** Rewrites the rulesets in `dir` with firefoxRule; returns how many rules changed. */
function firefoxRulesets(dir) {
  let changed = 0;
  for (const name of readdirSync(dir).filter((n) => n.endsWith(".json"))) {
    const rules = JSON.parse(readFileSync(join(dir, name), "utf8")).map((rule) => {
      const fixed = firefoxRule(rule);
      if (JSON.stringify(fixed) !== JSON.stringify(rule)) changed += 1;
      return JSON.stringify(fixed);
    });
    writeFileSync(join(dir, name), `[\n${rules.join(",\n")}\n]\n`);
  }
  return changed;
}

export function build(options = {}) {
  const browser = options.browser ?? "chrome";
  if (browser !== "chrome" && browser !== "firefox") {
    throw new Error(`unknown browser ${browser}: chrome or firefox`);
  }
  const out = resolve(root, options.out ?? (browser === "firefox" ? "dist-firefox" : "dist"));
  const rulesets = resolve(root, options.rulesets ?? "rulesets.toml");
  const compiled = resolve(root, options.compiled ?? "build/compiled");

  const compileArgs = ["run", "--release", "--quiet", "-p", "sinkhole-cli", "--"];
  compileArgs.push("compile", "--rulesets", rulesets, "--out", compiled);
  if (options.cache) compileArgs.push("--cache", resolve(options.cache));
  if (options.offline) compileArgs.push("--offline");
  const stdio = options.quiet ? "ignore" : "inherit";
  execFileSync("cargo", compileArgs, { cwd: repo, stdio });

  const wasmTarget = "wasm32-unknown-unknown";
  execFileSync(
    "cargo",
    ["build", "--quiet", "-p", "sinkhole-engine-wasm", "--target", wasmTarget, "--profile", "wasm"],
    { cwd: repo, stdio },
  );
  const wasm = join(repo, "target", wasmTarget, "wasm", "sinkhole_engine_wasm.wasm");

  const tsc = join(root, "node_modules", ".bin", "tsc");
  execFileSync(tsc, ["-p", join(root, "tsconfig.json")], { cwd: root, stdio: "inherit" });

  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  for (const file of [
    "background.js",
    "content.js",
    "core.js",
    "engine.js",
    "farble.js",
    "gpc.js",
    "popup.js",
  ]) {
    cpSync(join(root, "build", "js", file), join(out, file));
  }
  cpSync(wasm, join(out, "engine.wasm"));
  for (const file of ["popup.html", "popup.css", "icons"]) {
    cpSync(join(root, "static", file), join(out, file), { recursive: true });
  }
  for (const file of [
    "rulesets",
    "war",
    "page",
    "scriptlets",
    "rulesets.json",
    "scriptlets.json",
    "trackers.json",
    "suffixes.json",
    "NOTICES.txt",
    ...(browser === "firefox" ? ["uncloak.json"] : []),
  ]) {
    cpSync(join(compiled, file), join(out, file), { recursive: true });
  }

  const adjusted = browser === "firefox" ? firefoxRulesets(join(out, "rulesets")) : 0;

  const index = JSON.parse(readFileSync(join(compiled, "rulesets.json"), "utf8"));
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  let manifest = JSON.parse(readFileSync(join(root, "static", "manifest.json"), "utf8"));
  if (browser === "firefox") {
    manifest = firefoxManifest(manifest);
  }
  manifest.version = pkg.version;
  manifest.declarative_net_request.rule_resources = index.map((r) => ({
    id: r.id,
    enabled: r.enabled,
    path: r.path,
  }));
  if (options.dev) {
    manifest.permissions.push("declarativeNetRequestFeedback");
  }
  writeFileSync(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

  const rules = index.reduce((n, r) => n + r.rules, 0);
  return { browser, out, rules, adjusted, rulesets: index.length, bytes: size(out) };
}

/** Total size of the files under `dir`. */
function size(dir) {
  return readdirSync(dir, { recursive: true })
    .map((name) => statSync(join(dir, name)))
    .filter((s) => s.isFile())
    .reduce((n, s) => n + s.size, 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({
    options: {
      browser: { type: "string" },
      out: { type: "string" },
      rulesets: { type: "string" },
      cache: { type: "string" },
      offline: { type: "boolean" },
      dev: { type: "boolean" },
    },
  });
  const result = build(values);
  console.log(
    `Built ${result.out} (${result.browser}): ${result.rulesets} rulesets, ${result.rules} rules` +
      (result.adjusted ? ` (${result.adjusted} adjusted for Firefox), ` : ", ") +
      `${(result.bytes / 1024 / 1024).toFixed(1)} MB unpacked`,
  );
}
