<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/graphite/wordmark.png">
    <img alt="sinkd" src="docs/brand/paper/wordmark.png" width="280">
  </picture>

  https://chromewebstore.google.com/detail/abgodfdohgofhleaaenojdpjhapecknf?utm_source=item-share-cb
</p>

# sinkd

A Rust ad blocker and anti-tracking tool in three parts that share one rule
engine:

1. **Resolver**: a local DNS sinkhole that blocks ad and tracker domains for
   every app on the machine.
2. **Browser extension** (Chromium MV3 and Firefox): page-level blocking,
   anti-tracking, anti-fingerprinting and defense against ad-blocker detection.
   This covers what DNS cannot see.
3. **Rule compiler**: one set of filter lists in, target-specific outputs out.

**Status: all nine milestones done.** The shared core, the filter-list
parser, the rule compiler, the DNS resolver with its installer, the
extension for Chrome and Firefox, and the command line that ties them
together exist and are tested. Nothing is published to a browser store yet.

The resolver:
- blocks listed names, including trackers hidden behind a CNAME;
- forwards the rest over DNS-over-HTTPS (or DNS-over-TLS) with failover;
- caches answers;
- keeps its lists current, and reloads lists and config without a restart.

The extension:
- blocks ads and trackers, and in Firefox trackers hidden behind a site's
  own subdomain (CNAME uncloaking);
- serves harmless stand-ins for the ad and analytics scripts pages depend
  on;
- hides ad elements and runs the lists' scriptlets, without leaving traces
  a page could detect;
- strips tracking parameters from links;
- strips cookies and the referrer from tracker requests, caps analytics
  cookies, sends Global Privacy Control, and adds fingerprinting noise.

The command line:
- installs the resolver as a system service and points the system's DNS
  at it (`sudo sinkd install`), and puts everything back exactly as it
  was (`sudo sinkd uninstall`);
- explains what happens to any name or URL, and which rule decides it
  (`sinkd check`);
- pauses blocking, edits the local allowlist and blocklist, shows
  counters, and checks the whole setup (`pause`, `allow`, `block`,
  `stats`, `doctor`);
- passes `allow`, `block` and `pause` on to the extension, if you set up
  the optional browser bridge.

Nothing changes your system's DNS settings or your browsers unless you run
`sinkd install` or `sinkd bridge install` (or load the extension)
yourself.

## Honest expectations

- **"Untrackable" is not achievable.** The goal is to defeat third-party
  tracking and the common fingerprinting and ad-blocker-detection techniques,
  measurably, without breaking sites.
- **Out of reach, plainly:** your IP address (use a VPN or Tor), first-party
  tracking while you are logged in, server-side tracking, and behavioral
  fingerprinting.
- **Over-aggressive spoofing makes a browser *more* unique.** sinkd prefers
  blending in to randomizing everything. It never spoofs the user agent or
  platform.
- **Ad-blocker detection is an arms race.** Rules update without a new
  release. Lists can only select bundled scriptlets and pass them arguments,
  never deliver code.
- **No HTTPS interception and no locally trusted root CA, ever.** Page-level
  work belongs in the extension.
- **DNS-only mode cannot hide itself.** A page can tell that its ad script
  never loaded. Defeating detection is the extension's job.
- **Encrypted DNS hides your queries from the network, not from the
  upstream.** Quad9 (or whichever resolver you configure) still sees every
  name sinkd does not block or answer from its cache.
- **Same-domain ads (e.g. YouTube)** cannot be blocked by DNS. The extension
  handles them best-effort through community rules only.

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

## Try the resolver

This runs sinkd on port 5300. It only listens; nothing on the machine uses
it unless you point a query at it, and Ctrl-C stops it.

```bash
cargo run --release -p sinkd-cli -- run --config config/dev.toml
```

In another terminal:

```bash
dig @127.0.0.1 -p 5300 doubleclick.net
```

```bash
dig @127.0.0.1 -p 5300 example.com
```

The first answers `0.0.0.0` from sinkd itself. The second is forwarded to
Quad9 over DNS-over-HTTPS, and asked again it comes from the cache.
`RUST_LOG=debug` adds per-query detail, which is off by default.

What else it does:
- **CNAME uncloaking.** A tracker behind a first-party name
  (`smetrics.walmart.com` → `…2o7.net`) is blocked when the name it points
  to is listed. Names on your allowlist are never uncloaked.
- **Failover.** Upstreams are tried in order. One that stops answering
  costs a single timeout, then is skipped and checked in the background
  until it answers again.
- **Serve-stale.** When no upstream answers at all, names you already use
  keep resolving from expired cache entries for up to a day.
- **Local names stay local.** `localhost`, reverse lookups of private
  addresses, `.local` and `home.arpa` are answered here, not sent to the
  internet.
- **No bypass.** Firefox's DoH canary (`use-application-dns.net`) and
  encrypted-resolver discovery (`resolver.arpa`) are answered so that apps
  keep using sinkd.

Edit `config/dev-blocklist.txt` or `config/dev.toml` while it runs: changes
apply within two seconds, and a broken edit is logged and ignored while the
previous rules keep working. `kill -HUP` applies changes at once.

Throughput and latency over loopback sockets, and the cost of a reload:

```bash
cargo run --release -p sinkd-resolver --example loadgen
```

```bash
cargo run --release -p sinkd-resolver --example reload
```

## Install it system-wide

This makes sinkd the DNS resolver for every app on the machine. macOS
(primary) and Linux with systemd. It needs sudo, and it changes your DNS
settings, so look at what it would do first:

```bash
cargo build --release -p sinkd-cli
```

```bash
./target/release/sinkd install --dry-run
```

Then, when you're ready:

```bash
sudo ./target/release/sinkd install
```

What it does, in this order:

1. Copies the binary to `/usr/local/bin/sinkd` and writes a config
   (`/usr/local/etc/sinkd/sinkd.toml` on macOS,
   `/etc/sinkd/sinkd.toml` on Linux) with EasyList, EasyPrivacy and
   uBlock Origin's badware list, and Quad9 then Cloudflare over
   DNS-over-HTTPS. An existing config is kept.
2. Starts the resolver as a service that never runs as root:
   - macOS: a launchd daemon binds port 53, then hands the sockets to an
     unprivileged `_sinkd` user it creates;
   - Linux: a sandboxed systemd unit with a dynamic user.
3. Waits until the resolver answers. Only then does it save your current
   DNS settings and point them at 127.0.0.1 and ::1:
   - macOS: every network service;
   - Linux: systemd-resolved, or `/etc/resolv.conf`.
4. Checks that a blocked name now resolves to 0.0.0.0 through the system.

To undo all of it, restoring the DNS settings exactly as they were:

```bash
sudo sinkd uninstall
```

`--purge` also removes the config. A DNS setting you changed yourself after
install is left alone. `sinkd doctor` checks the whole chain and says
what to fix.

## The command line

| Command | What it does |
|---|---|
| `sinkd check ads.example.com` | What the resolver and the extension do with a name, and which list entry or filter rule decides it. |
| `sinkd check https://site.com/page` | The same for a page, plus the hiding rules and scriptlets that run on it. |
| `sinkd check URL --from PAGE --type script` | A subresource of a page. |
| `sinkd stats` | Counters from the running resolver: queries, blocks, cache, upstream health. |
| `sinkd stats --top 10 --recent 20` | The most frequent and the latest names (needs the query log). |
| `sinkd pause --for 5m` | Pause blocking, for everything (and the browser, with the bridge). Without `--for`, until `resume`. |
| `sinkd resume` | Blocking back on. |
| `sinkd allow add NAME…` / `rm` / `list` | The local allowlist, which beats every list. `*.example.com` means names below it only. |
| `sinkd block add NAME…` / `rm` / `list` | The local blocklist. |
| `sinkd update` | Check every list for a new version now. |
| `sinkd doctor` | Check the setup end to end. |
| `sinkd install` / `uninstall` | See above. |
| `sinkd bridge install` / `uninstall` / `status` | The browser bridge, below. |
| `sinkd run` | The resolver in the foreground. |
| `sinkd compile` | Lists into the extension's rules. |

Every command reads the installed config unless you pass `--config` (or set
`SINKD_CONFIG`). `pause`, `resume` and the query log answer only to root,
the service's own user and the user ids in `control.users`. The installer
adds the user who ran it. Anyone may read the counters.

**The query log** is off by default. With `[query_log] enabled = true` the
resolver keeps the latest queries in memory only, at most
`retention_hours` old and `max_entries` long. Nothing is written to disk.
**Prometheus metrics** are off by default too. With `[metrics] enabled =
true` they are served on `127.0.0.1:9153/metrics`, loopback only, counters
only.

## The browser bridge

Optional. It lets `sinkd allow`, `block` and `pause` reach the extension,
so a name you allow or block on the command line is allowed or blocked in
the browser too. Run it as yourself, not with sudo. Firefox needs nothing
else; for Chrome, Edge, Brave or Arc, pass the extension's ID from the
browser's extensions page:

```bash
sinkd bridge install --chrome-id <the extension's ID>
```

Then choose **Connect** under "sinkd on this computer" in the
extension's popup, which asks for the browser's permission. It writes one
small file per browser and a launcher script in your home directory. It
works one way only: the extension learns the lists and the pause, and can
change nothing on the computer.

To undo it:

```bash
sinkd bridge uninstall
```

## Lists from the web

A list with a `url` is downloaded over HTTPS and kept in a cache directory
(`~/Library/Caches/sinkd` on macOS, `~/.cache/sinkd` on Linux, or
`updates.cache_dir`):

```toml
[[list]]
name = "my-list"
url = "https://example.org/hosts.txt"
```

- The resolver starts from the cached copy, so it works offline and starts
  instantly. A list with no copy yet applies as soon as its first download
  finishes.
- Each list is checked daily, or as often as its `! Expires:` header asks
  (at least hourly, at most every 14 days), or every `refresh_hours`.
  Unchanged lists cost a `304 Not Modified`.
- **A failed or broken download never replaces a working list.** An error
  page, a captive-portal login page, an empty file or a list that suddenly
  lost 90% of its rules is refused, and the last good copy stays in use.
- `!#include` is followed, but only to files beside the list on the same
  server.

To check every list now, for example before the first start:

```bash
cargo run --release -p sinkd-cli -- update --config config/dev.toml
```

A running resolver picks up what `update` downloads within seconds. `update
--force` downloads in full and accepts a list that shrank drastically.

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
`/sinkd/`. Its before/after images come from `extension/scripts/store-images.mjs`.

## Recovery

`sudo sinkd uninstall` restores the DNS settings exactly as they were
before install. If sinkd is broken and DNS stops working, use one of
these one-liners.

macOS, exact restore without sinkd (install wrote this script):

```bash
sudo sh '/Library/Application Support/sinkd/restore-dns.sh'
```

macOS, last resort: every network service back to automatic DNS:

```bash
networksetup -listallnetworkservices | tail -n +2 | tr -d '*' | while IFS= read -r s; do sudo networksetup -setdnsservers "$s" Empty; done
```

Linux, exact restore:

```bash
sudo sh /var/lib/sinkd/restore-dns.sh
```

Without an install, the only thing sinkd writes outside this repository
is the cache of downloaded lists. This removes it on macOS (on Linux it is
`~/.cache/sinkd`):

```bash
rm -rf ~/Library/Caches/sinkd
```

To check sites by hand after a change, see
[docs/breakage-checklist.md](docs/breakage-checklist.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Scriptlets and surrogates are original implementations. No code is taken from
uBlock Origin, AdGuard or Brave, whose resources are GPLv3. Brave's `adblock`
crate (MPL-2.0) is used only as a test oracle and is never shipped.

The extension's compiled rules are not sinkd's own: they are translated from
EasyList, EasyPrivacy and uBlock Origin's lists and are distributed under the
GNU GPL, version 3 (see `NOTICES.txt` in a build).
