# Using sinkd

How to run the resolver, install it for every app on your computer, use
the command line and the browser bridge, and get everything back the way
it was. For the browser extension alone, add it from the
[Chrome Web Store](https://chromewebstore.google.com/detail/abgodfdohgofhleaaenojdpjhapecknf);
to build it yourself, see [development.md](development.md).

Nothing changes your system's DNS settings or your browsers unless you run
`sinkd install` or `sinkd bridge install` (or load the extension)
yourself.

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
[breakage-checklist.md](breakage-checklist.md).

## What it can't do

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
