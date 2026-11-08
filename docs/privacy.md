# Privacy policy

*sinkd, version 0.1. Last updated 2026-11-09.*

**sinkd collects no data about you.** It has no account, no analytics, no
telemetry, no crash reporting and no server of its own. Nothing it sees
is sent to the developer or to anyone else.

## The browser extension

- **What it sees.** To block ads and trackers it acts on the pages you
  visit: the browser matches requests against the rules it ships with, and
  the extension looks up the hiding rules for each page's hostname. This
  happens on your device and goes nowhere.
- **What it stores.** Your settings (which protections are on, the sites
  where you switched it off) in the browser's extension storage on your
  device. A random key for fingerprint protection, kept only for the
  browser session. If you connect the browser bridge, the allowlist,
  blocklist and pause state it receives from sinkd on your computer.
- **Network.** The extension makes no network requests of its own. It
  updates only when the store updates it.
- **Cookies.** It removes cookies from requests to known trackers, and
  shortens the lifetime of known analytics cookies (`_ga`, `_fbp` and the
  like) by setting them again with an earlier expiry. It changes nothing
  else about them and keeps no copy.
- **The browser bridge** (optional; off until you allow it) talks only to
  the sinkd program on your own computer, through the browser's native
  messaging. It never contacts anything else.

## The resolver (the `sinkd` program)

When you install it, sinkd becomes your computer's DNS resolver:

- **DNS queries** for names it doesn't block go to the upstream
  resolvers in its config, encrypted (by default Quad9, then Cloudflare,
  over DNS-over-HTTPS). Those providers see the names you look up, as
  your normal DNS provider would; their privacy policies apply. You can
  change them in the config.
- **Filter lists** are downloaded from their publishers (EasyList, uBlock
  Origin), as configured, about once a day.
- **The query log** is off by default. If you turn it on, it is kept in
  memory on your computer only, for at most the time you set, and is
  never written to disk or sent anywhere.
- **Metrics** are off by default, and when on are served only to your own
  computer (127.0.0.1) and hold counts, never names.

## Contact

Questions: open an issue at <https://github.com/nald0422/sinkd/issues>.
