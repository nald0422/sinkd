// Builds the unpacked extension.
//
//   node scripts/build.mjs [--browser chrome|firefox] [--out DIR]
//                          [--rulesets rulesets.toml]
//                          [--cache DIR] [--offline] [--dev]
//
// 1. `sinkd compile` turns the lists named in rulesets.toml into DNR
//    rulesets, surrogates, the page index, scriptlet files and a report
//    (build/compiled/).
// 2. cargo builds the page engine for wasm32 (crates/engine-wasm).
// 3. tsc compiles src/ (build/js/).
// 4. Everything is assembled in --out (dist/ for Chrome, dist-firefox/
//    for Firefox), and the manifest's rule_resources are filled in from
//    the compiled rulesets. Firefox gets the same code with its own
//    manifest (see firefoxManifest) and the host lists for uncloaking.
// 5. NOTICES.txt, THIRD-PARTY-NOTICES.txt and licenses/ say which files
//    are under which license, and where the rules' source is (see notices).
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
export const FIREFOX_ID = "sinkd@nald0422.github.io";
/** The longest manifest description the Chrome Web Store accepts. */
const MAX_DESCRIPTION = 132;
/** Where the source of each release is published (see notices). */
const REPOSITORY = "https://github.com/nald0422/sinkd";
const WASM_TARGET = "wasm32-unknown-unknown";

/** The license texts a package carries, in licenses/. */
const LICENSE_FILES = {
  "LICENSE-MIT": join(repo, "LICENSE-MIT"),
  "LICENSE-APACHE": join(repo, "LICENSE-APACHE"),
  "GPL-3.0.txt": join(root, "licenses", "GPL-3.0.txt"),
};
/** The list licenses notices() is written for; any other stops the build. */
const LIST_LICENSES = new Set([
  "GPL-3.0-only",
  "GPL-3.0-or-later OR CC-BY-SA-3.0",
  "MIT OR Apache-2.0",
]);

/**
 * NOTICES.txt: which files are sinkd's own and which are compiled from the
 * lists, under which license, and where their source is. `lists` is the
 * compiler's attribution, one entry per list, appended as it is.
 *
 * The compiled rules are a translation of the lists, so they ship under the
 * lists' license: GPL-3.0, since the uBlock Origin lists are GPL-3.0-only
 * and EasyList offers GPL-3.0 among others. sinkd's code only loads them,
 * as data files beside it, so it keeps its own license.
 */
export function notices({ version, browser, lists }) {
  const licenses = [...lists.matchAll(/^ {2}license: +(.+)$/gm)].map((m) => m[1]);
  const other = licenses.filter((l) => !LIST_LICENSES.has(l));
  if (licenses.length === 0 || other.length > 0) {
    throw new Error(
      `NOTICES.txt does not cover the list license ${other.join(", ") || "(none found)"}; update notices() in scripts/build.mjs`,
    );
  }
  const compiled = [
    ["rulesets/", "the network rules"],
    ["page/index.bin", "the element-hiding rules"],
    ["scriptlets/", "sinkd's scriptlet library, each file joined with a table"],
    ["", "compiled from the lists, so under the GPL as a whole"],
    ["scriptlets.json", "where each scriptlet file runs"],
    ["popups.json", "the lists' rules for tabs that pages open"],
    ["trackers.json", "tracker hosts, for the cookie and Referer rules"],
    ...(browser === "firefox"
      ? [["uncloak.json", "each ruleset's hosts, for CNAME uncloaking"]]
      : []),
  ];
  const rows = compiled.map(([file, what]) => `  ${file.padEnd(16)} ${what}`).join("\n");
  return `sinkd ${version}

sinkd's own code is licensed MIT OR Apache-2.0, at your option
(licenses/LICENSE-MIT, licenses/LICENSE-APACHE): the scripts, the popup,
the page engine (engine.wasm), the surrogates in war/ and the scriptlet
library.

The blocking rules are not sinkd's own work. They are compiled from the
filter lists named below, and the files that hold them are distributed
under the GNU General Public License, version 3 (licenses/GPL-3.0.txt),
the license of the uBlock Origin lists. EasyList and EasyPrivacy are used
under their GPL option.

${rows}

Their source, the lists exactly as compiled and the compiler, is
sinkd-source-${version}.zip at
${REPOSITORY}/releases/tag/v${version}
Its extension/BUILDING.md rebuilds this package byte for byte.

The libraries compiled into engine.wasm, with their licenses, are in
THIRD-PARTY-NOTICES.txt.

${"-".repeat(72)}

${lists}`;
}

/**
 * THIRD-PARTY-NOTICES.txt: the crates compiled into engine.wasm, each with
 * its MIT license text, which has to travel with the code. Every one offers
 * MIT (some among others), and any that doesn't stops the build. Proc
 * macros run at build time and put nothing in the wasm, so cargo tree
 * leaves them out.
 */
function thirdPartyNotices() {
  // `cargo metadata` prints a few MB, more than execFileSync's 1 MB default.
  const cargo = (...args) =>
    execFileSync("cargo", args, { cwd: repo, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  const tree = cargo(
    "tree",
    "--locked",
    "-p",
    "sinkd-engine-wasm",
    "--target",
    WASM_TARGET,
    "-e",
    "normal,no-proc-macro",
    "--prefix",
    "none",
    "--format",
    "{p}",
  );
  // "name v1.2.3"; the workspace's own crates carry their path.
  const wanted = new Set(
    tree
      .split("\n")
      .map((line) => line.replace(/ \(\*\)$/, "").trim())
      .filter((line) => line && !line.includes(" ("))
      .map((line) => line.replace(" v", "@")),
  );
  const { packages } = JSON.parse(
    cargo("metadata", "--locked", "--format-version", "1", "--filter-platform", WASM_TARGET),
  );
  const crates = packages
    .filter((p) => wanted.has(`${p.name}@${p.version}`))
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  if (crates.length !== wanted.size) {
    throw new Error(`cargo metadata is missing some of ${[...wanted].join(", ")}`);
  }
  const sections = crates.map((p) => {
    if (!/\bMIT\b/.test(p.license ?? "")) {
      throw new Error(
        `${p.name} ${p.version} is not offered under MIT (${p.license}); THIRD-PARTY-NOTICES.txt needs its license`,
      );
    }
    const dir = dirname(p.manifest_path);
    const file = readdirSync(dir)
      .sort()
      .find(
        (name) =>
          /^LICENSE[-_.]?MIT/i.test(name) ||
          (/^(LICENSE|COPYING)/i.test(name) &&
            readFileSync(join(dir, name), "utf8").includes("Permission is hereby granted")),
      );
    if (!file) throw new Error(`no MIT license file for ${p.name} ${p.version} in ${dir}`);
    const head = [`${p.name} ${p.version}`, `  license: ${p.license}, used under MIT`];
    if (p.authors?.length) head.push(`  authors: ${p.authors.join(", ")}`);
    if (p.repository) head.push(`  ${p.repository}`);
    return `${head.join("\n")}\n\n${readFileSync(join(dir, file), "utf8").trim()}\n`;
  });
  return (
    "The page engine (engine.wasm) is sinkd's own code, MIT OR Apache-2.0,\n" +
    "compiled together with the libraries below. Each offers the MIT license\n" +
    "and is used under it here.\n\n" +
    `${"-".repeat(72)}\n\n` +
    sections.join(`\n${"-".repeat(72)}\n\n`)
  );
}

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
  manifest.permissions = [
    ...new Set([...manifest.permissions, "dns", "webRequest", "webRequestBlocking"]),
  ];
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

  const compileArgs = ["run", "--release", "--quiet", "-p", "sinkd-cli", "--"];
  compileArgs.push("compile", "--rulesets", rulesets, "--out", compiled);
  if (options.cache) compileArgs.push("--cache", resolve(options.cache));
  if (options.offline) compileArgs.push("--offline");
  const stdio = options.quiet ? "ignore" : "inherit";
  execFileSync("cargo", compileArgs, { cwd: repo, stdio });

  execFileSync(
    "cargo",
    ["build", "--quiet", "-p", "sinkd-engine-wasm", "--target", WASM_TARGET, "--profile", "wasm"],
    { cwd: repo, stdio },
  );
  const wasm = join(repo, "target", WASM_TARGET, "wasm", "sinkd_engine_wasm.wasm");

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
    "popups.json",
    "scriptlets.json",
    "trackers.json",
    "suffixes.json",
    ...(browser === "firefox" ? ["uncloak.json"] : []),
  ]) {
    cpSync(join(compiled, file), join(out, file), { recursive: true });
  }

  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const lists = readFileSync(join(compiled, "NOTICES.txt"), "utf8");
  writeFileSync(join(out, "NOTICES.txt"), notices({ version: pkg.version, browser, lists }));
  writeFileSync(join(out, "THIRD-PARTY-NOTICES.txt"), thirdPartyNotices());
  mkdirSync(join(out, "licenses"));
  for (const [name, path] of Object.entries(LICENSE_FILES)) {
    cpSync(path, join(out, "licenses", name));
  }

  const adjusted = browser === "firefox" ? firefoxRulesets(join(out, "rulesets")) : 0;

  const index = JSON.parse(readFileSync(join(compiled, "rulesets.json"), "utf8"));
  let manifest = JSON.parse(readFileSync(join(root, "static", "manifest.json"), "utf8"));
  if (browser === "firefox") {
    manifest = firefoxManifest(manifest);
  }
  manifest.version = pkg.version;
  // The Chrome Web Store refuses a longer one at upload.
  if (manifest.description.length > MAX_DESCRIPTION) {
    throw new Error(
      `manifest description is ${manifest.description.length} characters; the store allows ${MAX_DESCRIPTION}`,
    );
  }
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
