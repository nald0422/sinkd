# Building the extension from source

These steps rebuild the store packages, file for file, from the source
bundle (`sinkd-source-<version>.zip`, made by `npm run package`). For
addons.mozilla.org reviewers: every generated file in the Firefox package
comes from the steps below. Nothing is minified or obfuscated, and the
extension loads no remote code.

## What is generated, and from what

| In the package | Made by | From |
|---|---|---|
| `background.js`, `content.js`, `popup.js`, `core.js`, `engine.js`, `farble.js`, `gpc.js` | `tsc` (TypeScript compiler; no bundler, no minifier, comments removed) | `extension/src/*.ts` |
| `engine.wasm` | `cargo build -p sinkd-engine-wasm --target wasm32-unknown-unknown --profile wasm` | `crates/engine-wasm`, `crates/core` (Rust) |
| `rulesets/`, `page/index.bin`, `rulesets.json`, `trackers.json`, `uncloak.json`, `suffixes.json`, `NOTICES.txt` | `sinkd compile` (`crates/cli`, `crates/compiler`) | the filter lists in `extension/build/list-cache/` and `extension/lists/` |
| `scriptlets/*.js`, `scriptlets.json` | `sinkd compile` | the hand-written scriptlet library (`crates/compiler/scriptlets/`), with the calls the lists select |
| `war/*` (stand-ins for blocked ad and analytics scripts) | copied by `sinkd compile` | `crates/compiler/resources/` (hand-written) |
| `manifest.json` | `scripts/build.mjs` | `static/manifest.json`, with the version from `package.json` and the rulesets |
| `popup.html`, `popup.css`, `icons/` | copied | `static/` |

Filter lists can only select bundled scriptlets and pass them arguments;
they never supply code.

The lists in `extension/build/list-cache/` are the copies the packages were
compiled from (EasyList, EasyPrivacy and uBlock Origin's lists; their
licenses are in `NOTICES.txt`). The bundle includes them so the output is
identical; the build does not download them (`--offline`).

## Tools

- macOS 14 or Linux, x86-64 or arm64
- Rust 1.95.0 through rustup, with the wasm32 target:
  `rustup toolchain install 1.95.0 --target wasm32-unknown-unknown`
- Node.js 20.19 and npm 10.8
- `zip` (only for `npm run package`)

## Steps

```bash
cd sinkd-<version>/extension
npm ci
npm run build:firefox -- --cache build/list-cache --offline
```

The Firefox package is then `dist-firefox/`. For Chrome:

```bash
npm run build -- --cache build/list-cache --offline
```

which writes `dist/`. `npm run package` does both and zips them into
`../release/`. `npm ci` downloads the npm packages pinned in
`package-lock.json`, and cargo the crates pinned in `Cargo.lock`.

## Checking a build against a package

```bash
mkdir /tmp/uploaded && unzip -q sinkd-firefox-<version>.zip -d /tmp/uploaded
diff -r /tmp/uploaded dist-firefox && echo identical
```
