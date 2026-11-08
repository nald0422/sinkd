// Release packages, in ../release/ (git-ignored):
//
//   sinkd-chrome-<version>.zip    for the Chrome Web Store
//   sinkd-firefox-<version>.zip   for addons.mozilla.org
//   sinkd-source-<version>.zip    the source Mozilla asks for with each
//                                 upload, with the exact lists the two
//                                 packages were compiled from
//
//   npm run package [-- --cache DIR]
//
// The builds are release builds (no test-only permission) and read the
// lists from the cache only, `build/list-cache` by default, so the source
// bundle rebuilds byte-identical packages (see BUILDING.md). The bundle
// holds the files git tracks, as they are in the working tree; package
// from a clean checkout for a submission, so it matches a commit.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { build } from "./build.mjs";

const root = resolve(import.meta.dirname, "..");
const repo = resolve(root, "..");
const { values } = parseArgs({ options: { cache: { type: "string" } } });
const cache = resolve(root, values.cache ?? "build/list-cache");
if (!existsSync(cache)) {
  throw new Error(`no list cache at ${cache}; build once without --offline, or pass --cache`);
}
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const release = join(repo, "release");
mkdirSync(release, { recursive: true });

const git = (...args) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();

/** Zips the contents of `dir` into `zip`, without macOS metadata files. */
function zipDir(dir, zip) {
  rmSync(zip, { force: true });
  execFileSync("zip", ["-q", "-r", "-X", zip, ".", "-x", "*.DS_Store"], { cwd: dir });
}

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

const made = [];
for (const browser of ["chrome", "firefox"]) {
  const result = build({ browser, cache, offline: true, quiet: true });
  const zip = join(release, `sinkd-${browser}-${version}.zip`);
  zipDir(result.out, zip);
  made.push(zip);
}

// The source: every file git tracks (or would, if untracked and not
// ignored), plus the list cache.
const commit = git("rev-parse", "--short", "HEAD");
const dirty = git("status", "--porcelain") !== "";
const staging = mkdtempSync(join(tmpdir(), "sinkd-source-"));
const top = join(staging, `sinkd-${version}`);
try {
  const files = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    .split("\0")
    .filter((f) => f && existsSync(join(repo, f)));
  for (const file of files) {
    mkdirSync(dirname(join(top, file)), { recursive: true });
    cpSync(join(repo, file), join(top, file));
  }
  cpSync(cache, join(top, "extension", "build", "list-cache"), { recursive: true });
  writeFileSync(
    join(top, "SOURCE-VERSION"),
    `sinkd ${version}, commit ${commit}${dirty ? " with uncommitted changes" : ""}\n` +
      "Build instructions: extension/BUILDING.md\n",
  );
  const zip = join(release, `sinkd-source-${version}.zip`);
  zipDir(staging, zip);
  made.push(zip);
} finally {
  rmSync(staging, { recursive: true, force: true });
}

for (const zip of made) {
  const mb = (readFileSync(zip).length / 1024 / 1024).toFixed(1);
  console.log(`${zip}  ${mb} MB  sha256 ${sha256(zip)}`);
}
if (dirty) {
  console.log(
    "note: the working tree has uncommitted changes; commit, then package again to submit",
  );
}
