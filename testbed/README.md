# testbed

Local pages that do what websites do to detect ad blockers and to track
people, and a Playwright harness that loads them with and without the
extension, in Chromium or Firefox. Everything is served by `server.mjs` on
random local ports (HTTP, and HTTPS for the third-party cookie pages), so
no real site is ever contacted: Chromium resolves every hostname to it;
Firefox, which can't, uses it as its proxy. The HTTPS certificate is made
by `openssl` for the run, and only the test's own throwaway browsers are
told to accept it; nothing is installed or trusted anywhere.

```bash
node testbed/run.mjs            # testbed build only (what CI runs)
node testbed/run.mjs --real     # also the build in extension/dist
node testbed/run.mjs --bench    # also the performance budgets, on extension/dist
node testbed/run.mjs --browser firefox [--real] [--bench]   # the same in Firefox, on dist-firefox
```

From `extension/`, `npm run testbed` does the first and `npm run
testbed:firefox` the last. `--real` and `--bench` need `npm run build` (or
`npm run build:firefox`) first.

Playwright loads extensions into Chromium only. For Firefox,
`extension/scripts/firefox.mjs` starts Playwright's Firefox with its remote
debugging server on 127.0.0.1, installs the build as a temporary add-on,
and drives the background page over that connection. The CNAME pages need
Firefox to look names up, so those names skip the proxy, and Firefox's DNS
override service (meant for its own tests) answers them with their aliases.

## How a check works

Each detection page opens in three browsers:

| browser | what it is | what must happen |
|---|---|---|
| plain | the browser, no extension | no detection: the page is honest |
| naive | ad and tracker hosts aborted, bait classes hidden | detection: the page catches a blocker without surrogates or scriptlets |
| sinkd | the extension, built from `rulesets.toml` | no detection, and no ad request reaches the server |

`rulesets.toml` builds the extension from `lists/testbed.txt` (rules for
the testbed's hosts only) plus the real surrogate and parameter lists.

## Pages

`detect.test` — Part C, how sites detect blockers:

| page | technique | defense under test |
|---|---|---|
| `globals.html` | ad scripts' globals missing, `onerror` fired, queues never run (`googletag.cmd`, `adsbygoogle.loaded`, `ga` hitCallback), and a site's own `ads.js` setting `canRunAds` | surrogates; `redirect=noop.js` plus `set-constant`; scriptlets run before the first page script |
| `bait.html` | bait elements with ad class names and ids checked for zero size or `display:none` | generic hiding leaves out bait names |
| `probes.html` | `fetch`, XHR and image requests to an ad URL, and a pristine `fetch` taken from a fresh iframe | `prevent-fetch`, `prevent-xhr` (an empty 200), `redirect=1x1.gif`; scriptlets in `about:blank` frames |
| `detectors.html` | seven detection scripts that report only if the bait script was blocked | `abort-on-property-write/read`, `abort-current-script`, `prevent-setTimeout/setInterval`, `json-prune`, `addEventListener-defuser` |
| `stealth.html` | what a page can learn about an extension: patched functions' source, name, length and descriptors; new globals; stack frames; DOM nodes, style sheets and mutations; resource timing; fetching extension files by ID | compared field by field with the same page without the extension |

`cosmetic.test`, `exempt.test`, `generichide.test`, `elemhide.test` —
specific, generic, `:style()`, procedural (`:has-text()`, `:remove()`,
`:upward()`) and scriptlet (`remove-class`) rules, elements added after
load, `#@#`, `$generichide`, `$elemhide`, pausing a site and switching a
ruleset off.

`track.test` — Part B:
- `trackers.html`: third-party tracker requests as image, script,
  `sendBeacon`, `fetch` and `<a ping>`, plus a first-party image that must
  load, plus twelve well-known tracker endpoints for the `--real` run.
- `links.html`: a link carrying `utm_*`, `fbclid`, `gclid`, `dclid`,
  `msclkid`, `mc_eid`, `igshid`, `yclid` and `_hsenc`; only `id=42` may
  arrive.

`track.test` and friends — Part B, privacy features (M7):

| page | technique | checked |
|---|---|---|
| `fp.test/fingerprint.html` (also served as `fp-b.test`) | canvas (whole and in part), WebGL pixels and renderer, an OfflineAudioContext rendering, CPU and memory figures, and a third-party frame (`fp-frame.test`) hashing its own canvas | without the extension both sites hash alike; with it, hashes are stable within a site and session, differ across sites (the frame too) and across sessions (the browser is restarted on the same profile), are never the true values, a site exception restores them, and the user agent is unchanged |
| `gpc.test` | — | `Sec-GPC: 1` on the page, a third-party image and a third-party frame, `navigator.globalPrivacyControl`; neither with a site exception |
| `ref.test/page.html?secret=1` | served with `Referrer-Policy: unsafe-url` | other origins of the site (`static.ref.test`) and other sites get the origin, a tracker nothing, the page's own origin the full URL. (Firefox trims cross-site referrers to the origin on its own; the other origin shows the rule at work there.) |
| `cookie.test` | two-year `_ga`, `_ga_*` (script) and `_fbp` (server) next to ordinary cookies | tracking ones expire within a week, others untouched |
| `news.test/embed.html` (HTTPS) | a tracker, let through by a list exception, that had set a cookie when visited directly | it gets no cookie back and can't set one |

WebRTC is checked in the background script: the policy is
`default_public_interface_only` while the feature is on and handed back when
it is off.

`cloak.test` — CNAME uncloaking (M8, Firefox only). The page loads images
from names whose DNS aliases the harness sets:

| name | alias | must |
|---|---|---|
| `metrics.cloak.test` | `collect.cname-tracker.test` (listed) | be blocked, and never reach the server |
| `cdn.cloak.test` | `edge.cloak.test` (listed, same site) | load: not cloaking |
| `img.cloak.test` | `img.cdn-provider.test` (not listed) | load |
| `api.cloak.test` | `api.cname-tracker.test` (excepted with `@@`) | load |
| `stats.cloak.test` | `collect.cname-tracker.test`, through the proxy | load: proxied requests aren't looked up |

and the blocked one loads again with a site exception, with the feature or
the Trackers ruleset off. It stays blocked after Firefox suspends the event
page. With `--real`, `realnews.test` aliases two names to Adobe
(`omtrdc.net`) and Eulerian, which the public lists name.

In Firefox the popup is also checked to ask for site access back when it
was taken away (Firefox's add-on settings allow that).

## Known browser differences

- Firefox runs content scripts in a new `about:blank` frame a task late, so
  the fresh-iframe probe on `probes.html` catches blocking there. It is
  reported as a known gap, not a failure (DESIGN.md, Firefox).
- Firefox sends no `<a ping>` unless the user turns pings on, so the plain
  browser isn't expected to send one.

## Not here yet

- Link-wrapper unwrapping (`$urlskip`) is not translated yet, so it has no
  page.
- Server-side detection (the impression never arrived) can't be defeated
  and isn't modeled.
