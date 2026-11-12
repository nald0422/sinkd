# Developing sinkd

The repository's layout, and how to build and test each part: the Rust
crates, the browser extension and the website. Using sinkd is in
[guide.md](guide.md); the decisions behind it, with measurements, are in
[DESIGN.md](../DESIGN.md).

## Layout

```
crates/core      domain normalization, DNS domain matcher, config types (no I/O)
crates/filters   ABP / uBlock Origin / AdGuard filter syntax → structured rules
crates/lists     fetch lists over HTTPS, check them, keep the last good copy
crates/compiler  lists → Chrome rulesets, surrogates, cosmetic index, scriptlets, the resolver's domain set, a report
crates/engine-wasm  the cosmetic lookup, built for wasm32, for the extension's background script
crates/resolver  the DNS daemon: block, forward, serve UDP and TCP, hot reload
crates/cli       the `sinkd` binary
extension/       the MV3 extension for Chromium and Firefox (TypeScript glue over compiled rules)
testbed/         local pages that detect blockers and track, and the harness that loads them
fuzz/            fuzz targets for the parsers, the DNS handling and the config
config/          a trial config (port 5300) and a tiny blocklist
docs/            the manual breakage checklist, privacy policy, store listing and brand kit
site/            the landing page (React, TypeScript, Tailwind)
DESIGN.md        decisions and measurements
```

## Build and test

Rust 1.88 or newer.

```bash
cargo test --workspace
```

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

```bash
cargo bench --workspace
```

```bash
cargo run --release -p sinkd-filters --example dns_budget
```

The last command checks the resolver matcher against its budgets with 1M
synthetic names.

Fuzzing (list parsers, the compiler, DNS queries and answers, the config,
the metrics endpoint) runs on stable Rust, without cargo-fuzz:

```bash
fuzz/run.sh
```

It runs each target for a minute; `fuzz/run.sh dns_query 600` runs one for
ten. With nightly and cargo-fuzz installed, `cargo fuzz run dns_query`
works too. To see how real filter lists parse, download them yourself
and run:

```bash
cargo run --release -p sinkd-filters --example coverage -- --oracle easylist.txt easyprivacy.txt
```

## Build the extension

Node 20 or newer, and Rust's wasm32 target for the page engine
(`rustup target add wasm32-unknown-unknown`; `rustup target remove
wasm32-unknown-unknown` undoes it). From `extension/`:

```bash
npm ci
```

```bash
npm run build
```

```bash
npm run build:firefox
```

`npm run build` runs `sinkd compile`, which downloads the lists named in
`extension/rulesets.toml` (EasyList, EasyPrivacy, uBlock Origin's lists) and
compiles them. It writes the unpacked Chrome extension to `extension/dist/`
and a full account of what could not be translated, and why, to
`extension/build/compiled/report.json`. `npm run build:firefox` does the
same for Firefox, in `extension/dist-firefox/`.

To try it, open `chrome://extensions`, turn on Developer mode, choose **Load
unpacked** and pick `extension/dist/`. That installs it in your browser
profile, so it is your call. **Remove** on the same page undoes it,
including the one browser setting it changes (WebRTC's IP handling, which
Chrome restores when the extension goes). The toolbar popup switches
sinkd, or one privacy feature, off for the current site, or turns off
one kind of protection everywhere.

Besides blocking, it strips cookies and the referrer from tracker
requests, caps analytics cookies at a week, sends Global Privacy Control,
keeps WebRTC from revealing your local address, and adds noise to canvas,
WebGL and audio readback so fingerprints can't link sites or sessions. It
does not change your user agent. Chrome 128 or newer.

To try it in Firefox, open `about:debugging#/runtime/this-firefox`, choose
**Load Temporary Add-on…** and pick `extension/dist-firefox/manifest.json`.
Firefox removes a temporary add-on when it quits; **Remove** on the same
page does it at once, and Firefox then restores the WebRTC setting too. A
permanent install needs the add-on signed by Mozilla. In Firefox it also
blocks trackers hidden behind a site's own subdomain (CNAME uncloaking),
which Chrome gives extensions no way to do. Firefox 140 or newer.

Checks:

```bash
npm run typecheck && npm run lint && npm test
```

```bash
npm run build -- --dev && npm run e2e
```

```bash
npm run build:firefox -- --dev && npm run e2e:firefox
```

The end-to-end test runs Playwright's Chromium or Firefox headless with a
throwaway profile; it never touches your own browsers. It needs those
builds, which `npx playwright-core install chromium firefox` downloads if
they are missing.

The testbed loads local pages that detect ad blockers and track, with and
without the extension (see `testbed/README.md`):

```bash
npm run testbed
```

```bash
npm run testbed -- --real --bench
```

```bash
npm run testbed:firefox -- --real --bench
```

The second form also checks the build in `dist/` and measures the
performance budgets; the third does both in Firefox, on `dist-firefox/`.

The rules compile from GPL-3.0 lists, so the files that hold them ship
under GPL-3.0, beside sinkd's own MIT OR Apache-2.0 code. Each build's
`NOTICES.txt` says which files are which and where their source is,
`THIRD-PARTY-NOTICES.txt` covers the crates in `engine.wasm`, and
`licenses/` has the texts.

For the stores, `npm run package` makes release builds (without the test
permission `--dev` adds) from the cached lists. It zips them into
`release/`, with the source bundle Mozilla asks for; the bundle rebuilds
the packages file for file (see `extension/BUILDING.md`). Each release's
`NOTICES.txt` names the source bundle at
`https://github.com/nald0422/sinkd/releases/tag/v<version>`, so attach
`sinkd-source-<version>.zip` to a GitHub release of that tag when the
packages go to the stores.
`node scripts/store-images.mjs` makes the five store screenshots and the
promo tile, and
`node scripts/logo.mjs` the logo, the icons and the brand kit in
`docs/brand/`. The
listing text and the privacy policy are in `docs/store-listing.md` and
`docs/privacy.md`.

## The website

`site/` is the landing page: React, TypeScript and Tailwind, built with
Vite. On a wide screen it scrolls sideways, one idea per panel; on a phone,
or with reduced motion asked for, it is an ordinary page. From `site/`:

```bash
npm ci && npm run dev
```

`npm run build` writes a static site to `site/dist/`, with relative paths,
so it can be served from a domain's root or a path such as GitHub Pages'
`/sinkd/`. Its "On a page" panel builds the news page the store
screenshots are taken of (`site/src/components/PageSweep.tsx`).
