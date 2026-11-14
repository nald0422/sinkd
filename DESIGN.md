# sinkd design

This document records the decisions behind sinkd and the reasons for them.
(The project was called sinkhole until after M9. Its permanent IDs live
under `io.github.nald0422`: the Firefox add-on is `sinkd@nald0422.github.io`;
the macOS service and the browser bridge are `io.github.nald0422.sinkd`.)
It grew with each milestone. Status: **all nine milestones done**; the
last one (M9) added the command line, install and uninstall, the browser
bridge, hardening and fuzzing.

## Shape of the system

```
filter lists ──► sinkd-filters (parse, lossless AST) ──► sinkd-compiler
                                                              ├─► domain set ──► resolver (DNS, every app)
                                                              ├─► DNR JSON   ──► extension (Chrome/Firefox)
                                                              ├─► cosmetic + scriptlet index ──► engine-wasm
                                                              └─► report of untranslatable rules
```

One parser feeds every target, so the resolver, the extension and `sinkd
check` can never disagree about what a rule means.

| crate | role | I/O |
|---|---|---|
| `sinkd-core` | domain normalization, DNS domain matcher, config types | none |
| `sinkd-filters` | ABP / uBO / AdGuard syntax → structured rules; DNS-list syntaxes | none |
| `sinkd-lists` | fetch lists over HTTPS, check them, cache them; follow `!#include` | HTTPS, cache files |
| `sinkd-resolver` | the DNS daemon: decide, block, cache, forward over DoH/DoT/UDP, serve, hot reload | sockets, HTTPS/TLS, list and cache files |
| `sinkd-compiler` | lists → DNR rulesets, surrogates, the resolver's domain set, a report of what each target cannot use | none (the CLI reads and writes) |
| `sinkd-cli` | the `sinkd` binary: `run`, `update`, `compile`, `check`, `stats`, `pause`, `resume`, `allow`, `block`, `install`, `uninstall`, `doctor`, `bridge` | sockets, the system's DNS settings (install), browser host manifests (bridge) |
| `extension/` | MV3 extension for Chromium and Firefox: TypeScript glue over the compiled rulesets | |
| `engine-wasm` | the cosmetic and scriptlet index (M6) | |
| `fuzz/` | fuzz targets (outside the workspace) | |

Every crate has `#![forbid(unsafe_code)]`, also enforced as a workspace lint.

## Decision: our own parser, not a wrapper around Brave's `adblock` crate

**Evaluated:** `adblock` 0.13.5 (MPL-2.0), from its source and with a probe build
(`wasm32-unknown-unknown`, `opt-level = "s"`, LTO).

| Question | Finding |
|---|---|
| Maturity | Excellent. It runs in Brave for millions of users and handles real-list quirks. |
| License | MPL-2.0 is file-level copyleft. It is compatible with MIT/Apache as an unmodified dependency. |
| wasm size | A module that deserializes an engine and does a cosmetic lookup is **1.37 MB raw, 447 KB gzipped**, within our 1.5 MB budget. Not a blocker. |
| Can the compiler get domain strings for DNR? | **No.** `NetworkFilter.opt_domains`, `opt_not_domains`, `opt_to_domains` and `CosmeticFilter.hostnames`/`entities` are `Vec<Hash>`. DNR's `initiatorDomains` / `requestDomains` need the strings. The only route back is re-parsing `raw_line`, which means writing a second option parser anyway, and two parsers can disagree. |
| Lossless AST available? | No. `AbstractNetworkFilter` / `NetworkFilterOption` (which do keep strings) are `pub(crate)`. |
| Scriptlet model | `UrlSpecificResources.injected_script` is a **JavaScript string** assembled from resources and arguments. Our model requires lists to *select* a bundled function and pass data. In MV3 that means `{name, args}` handed to code shipped in the package, never a code string. |
| Syntax coverage | Rejects AdGuard `#%#//scriptlet(…)` and `#$#` (CSS injection and ABP snippets), `$denyallow`, `$header`, `$popup`, `$elemhide`, `$specifichide`, `$genericblock`, `$strict1p/3p`, `$permissions`, `$urlskip`, `$cookie`, `$removeheader`, `$cname`, `$inline-script/font`, regex `$removeparam`, `$match-case` on non-regex rules. Several of these are exactly what the spec needs: AdGuard scriptlet syntax, `$urlskip` for link unwrapping, `$cookie` for cookie capping. |
| Safety | With default features it **accepts** `##.a{} body{x:y}` (escapes its CSS rule block) and `:style(background: url(https://…))` (remote load from a stylesheet). `css-validation` exists but pulls in Servo's `cssparser`/`selectors`. |
| Index format | Hash-keyed flatbuffers with a format that changes between versions. That would tie our wasm engine to its hash function and release cadence. |

**Decision:** `sinkd-filters` is our own lossless parser, and `adblock` is a
**dev-dependency used as a differential oracle** (`crates/filters/tests/oracle.rs`).
Both parsers read a hand-written corpus. Every disagreement must be listed in
the test with its reason, so a new divergence or a stale one fails CI. The
first run surfaced 45 disagreements. 44 were intentional, and one (generic
`##+js(…)`) led us to adopt Brave's stricter behavior. adblock-rust is never
linked into a shipped binary, so its license does not reach users.

**What would change this:** if adblock-rust exposed a stable lossless AST
(strings for domains, structured scriptlet calls), the case would flip: we would
wrap its parser and keep only our compiler. That is worth re-checking each
release.

## Decision: license MIT OR Apache-2.0

Chosen 2026-11-05. Consequences:

- Scriptlets and surrogates (milestones 5–6) are **our own implementations**,
  written from documented behavior (argument semantics in the uBO and AdGuard
  wikis), not ported from uBO, AdGuard or Brave code (all GPLv3 or derived).
- Community lists keep working because we accept their syntax and scriptlet
  names, and our implementations follow the same argument semantics.
- The test corpus is hand-written, never copied from a list (EasyList is
  GPLv3 / CC BY-SA).
- The rules the extension ships are a translation of the lists, so they
  are distributed under the lists' license (decided 2026-11-09, version
  0.1.1): GPL-3.0, since uBlock Origin's lists are GPL-3.0-only and
  EasyList offers GPL-3.0 (its CC BY-SA 3.0 option cannot be combined with
  the GPL). They are separate data files that sinkd's code loads, so the
  code keeps MIT OR Apache-2.0. Each scriptlet file joins the library with
  a table compiled from the lists, so it is GPL-3.0 as a whole; it carries
  no header, because it runs in the page and names nothing (see *Page
  target*). `scripts/build.mjs` writes `NOTICES.txt` (which files, which
  license, where the source is), `THIRD-PARTY-NOTICES.txt` (the MIT
  notices of the crates in `engine.wasm`) and `licenses/` into every
  package, and stops if a list or a crate has a license it does not cover.
  The source is the source bundle, attached to the GitHub release of each
  version.

## Domain normalization (`core::domain`)

Every name is compared as bytes after one normalization: trim, strip one
trailing dot, lowercase ASCII, UTS-46 non-transitional IDNA to punycode
(browser behavior: `faß.de` stays distinct from `fass.de`), then validate labels
of 1–63 bytes from `[a-z0-9_-]`, at most 253 bytes total, and not an IP
address. The IP check runs again after IDNA because full-width digits
(`１.２.３.４`) only become an address then. That second check is needed for
idempotence, and a property test found the bug.

Underscores are allowed because real names have them (`_dmarc`, some
trackers). Leading and trailing hyphens are allowed because DNS allows them and
lists contain them. For ASCII input with `xn--` labels we lowercase but do not
validate the punycode. A bogus label is still just bytes that never match a real
query.

`QueryName` is the hot-path form for names off the wire. It folds case on the
stack and does **not** validate the charset. A wire name may contain any byte,
and `we\032ird.ads.example.com` must still be blocked by `ads.example.com`.

## DNS matcher (`core::matcher`)

Semantics:

1. **The allowlist always wins.** If the name or any parent is allowlisted,
   the name is allowed, even if a more specific entry blocks it.
2. **A blocked parent blocks its children.** `example.com` covers itself and
   everything below it. `*.example.com` covers only names below it.
3. Everything else is forwarded.

Property tests check these directly, plus agreement with a naive reference
model on random overlapping sets.

**Why subtree semantics for hosts files too.** Traditionally a hosts entry is
exact-match. We block the subtree, as Blocky and NextDNS do and as uBO's
`||name^` means, because tracker CNAME and subdomain rotation defeats
exact-match lists. The cost: a list that names a parent domain on purpose
blocks more. The allowlist is the escape hatch.

**Representation.** A lookup probes each label-aligned suffix (`a.b.c.com`,
`b.c.com`, `c.com`, `com`). Each suffix is hashed once with a randomly seeded
`ahash`, and that hash serves both the allow and the block table. Names live
back to back in one byte arena, each followed by a 1-byte scope tag. The hash
table (`hashbrown::HashTable<u32>`) stores only arena offsets. Tag bytes (0, 1)
never occur in a normalized name, so they double as terminators. Queries
containing control bytes are probed only from the label after the last one,
which also prevents a crafted query from matching across an arena boundary.

Why not a trie: a reversed-label trie costs a pointer chase per label and far
more memory per node. Why not `HashSet<String>`: about 60 bytes per entry
against our ~28, and an allocation per name.

Seeds are per process (`ahash` `runtime-rng`) so a hostile list or query stream
cannot precompute collisions. On `wasm32` the engine does not use this matcher,
and `ahash` keeps fixed keys because there is no OS randomness without JS glue.

**Measured (M1 Pro, 1M synthetic names, `dns_budget` example):**

| Budget | Target | Measured |
|---|---|---|
| RSS with 1M names | < 150 MB | **67.6 MiB** steady state (34.0 MiB of it is the matcher), 99.5 MiB peak during load |
| cold load (text → parse → normalize → insert) | < 2 s | **450–500 ms** |
| lookup p99 | < 1 µs | **460–540 ns** per call, including ~40 ns timer overhead. p50 125 ns, batched mean 152 ns (6.6 M lookups/s on one core) |

p99.9 is a few µs and the max tens of µs. These are scheduler and interrupt
noise, measured one call at a time. Criterion on a 100k set gives 22 ns for an
exact hit and about 50 ns for a 4-label miss.

## Filter parser (`filters`)

**Never broaden a rule.** An unknown or unimplemented option rejects the whole
rule (`ParseError::Unsupported`). Dropping only the option would turn
`||x^$replace=…` into `||x^`, which is how ad blockers break sites. The
compiler report groups rejections by `ParseError::feature()`.

**Network rules.** Patterns keep ABP wildcard syntax because DNR's
`urlFilter` speaks it natively. The host after `||` is lowercased and
punycoded. The path keeps its case, since `$match-case` may matter. Redundant
`*` are trimmed, and an anchor followed by `*` anchors nothing.

- The `$` that starts options is the **rightmost unescaped `$` followed by
  something that looks like an option list**. This lets `/ads\.js$/` and
  `$removeparam=/^utm$/` both parse (adblock-rust gets the first wrong).
- Options split on commas, except `\,` and commas inside a `/regex/` value. A
  regex opens at a `/` right after `=`, `|`, `~` or `:` and closes at the next
  unescaped `/`. uBO's own lists rely on this
  (`header=via:/1\.1, google/`, `urlskip=/…{0,2}…/`).
- `$domain=` items keep `/regex/` whole even when the regex contains `|`.
  Domain lists also accept IP literals (`~127.0.0.1|~[::1]`), which EasyPrivacy
  uses to exempt local pages.
- `$1p`/`$3p` (site) and `$strict1p`/`$strict3p` (exact host) are independent.
  `$1p,strict3p` means "same site, other host". `$3p,strict1p` can never match
  and is refused.
- Any run of underscores (`$_____`) is uBO's no-op option. Resource names may
  contain `/` (`redirect=google-analytics.com/ga.js:5`), but not `..` or empty
  segments.
- A rule that matches every request with no options is refused.
- Types follow ABP. No type option means "subresources" (not `document`, not
  `popup`), and only-negated types mean "subresources minus those".
- `$csp` / `$permissions` values may not contain line breaks (header
  splitting). `$removeheader` refuses security and protocol headers (CSP,
  CORS, COOP/COEP/CORP, HSTS, XFO, `sec-*`, …), because lists are untrusted
  input.

**Cosmetic rules.** One separator scan decides the rule type. The first
`#`/`$` token that forms a separator wins, and only if what precedes it could be
a domain list. That is how `||example.com/##ad` stays a network rule.
Selectors end up in an injected stylesheet, so `{ } ; <` and comments outside
quotes are rejected, and `:style()` may not contain `url(`, `image-set(`,
`expression(`, `@import`, backslashes (escape obfuscation such as `u\72l(`) or
braces. Procedural operators are parsed into a tree of CSS chunks and
operators under uBO's names (ABP `:-abp-*` and AdGuard `:contains/:if/:if-not/
:nth-ancestor` map onto them). Native `:has()`/`:not()` stay CSS unless their
argument is procedural.

- EasyList's `##selector { declarations }` is treated as AdGuard's `#$#` CSS
  injection, with the same declaration sanitizing. Brave effectively applies it
  the same way.
- uBO's `hostname>>##…` and `hostname/path##…` are reported
  (`cosmetic-prefix:>>`, `cosmetic-prefix:path`). They are not parsed as
  network rules, which could never match.

**Scriptlets.** Lists only *select*. `scriptlet::SCRIPTLETS` is the bundle
(canonical names from the spec, aliases for uBO short forms, AdGuard and ABP
spellings, `.js` suffixes and AdGuard's `ubo-` prefix). Anything else is
`scriptlet:unknown`. AdGuard's raw `#%#` JavaScript is `arbitrary-js` and always
rejected. Each call records its `Dialect`, because AdGuard and uBO differ in
places (AdGuard's `abort-current-inline-script` only looks at inline scripts).
Generic scriptlet rules (no positive domain) are rejected, as in Brave: one
list line should not run code on every page. Generic *exceptions* are allowed.
Arguments are capped (32 args, 4 KiB each). A uBO argument that starts with a
quote is quoted only if its first closing quote is followed by a comma or the
end. Otherwise the quote is text (`nostif, '0x`, `rpnt, script, "a":true, …`),
as in uBO.

**Preprocessor.** `!#if` uses `&&`, `||`, `!` and parentheses, and unknown tokens are
false. We claim uBO Lite's tokens for Chromium MV3 (`ext_ublock`, `ext_ubol`,
`env_chromium`, `env_mv3`, `cap_user_stylesheet`) and the Firefox equivalents.
We never claim `cap_html_filtering`. `!#include` is returned to the fetcher,
which must keep it same-origin (M3). uBO line continuation (` \`) is supported.

**Measured:** 0.25 µs (`||host^`) to 1.5 µs (several options and domains) per
rule. 1.4 M lines/s on a synthetic EasyList-shaped list, and 36 ms for the real
EasyList (see below).

## DNS list syntaxes (`filters::dns`)

The resolver sees a hostname and nothing else. A rule that depends on the page,
the request type or the URL is reported (`dns:options`, `dns:not-hostname`,
`dns:page-rule`), never applied more broadly.

- Hosts entries count as blocks only when they point at `0.0.0.0`,
  `127.0.0.0/8`, `::` or `::1`. Any other address is a redirect and is reported.
  The machine's own names (`localhost`, `ip6-*`, …) are skipped.
- `||name` without `^` is accepted. In URL matching it is a prefix, but our
  matcher is label-aligned, so DNS applies it *more narrowly*, never more
  broadly.
- `$important` has no effect, because the allowlist always wins. (In AdGuard Home
  it would beat allow rules.)
- `$badfilter` cancels the identical entry from any list, applied after all
  lists are read.
- IP-literal rules (`||141.98.82.232^`) are `dns:ip-literal`, because an
  address is never looked up. With per-line auto-detection, a domain-looking
  line that is not a valid name (`.120x600.`) is retried as adblock syntax, so
  it is reported as `dns:not-hostname`, not as invalid.

## Coverage on real lists (2026-11-07)

`cargo run --release -p sinkd-filters --example coverage -- --oracle <lists>`
parses whole lists, groups rejections by feature, runs the adblock-rust oracle
on every rule line and feeds the same lists to the DNS builder. Lists were
fetched on 2026-11-07 (EasyList 202611070318, uBO's uAssets of the same day).
They are not checked in. Environment: `chromium_mv3`.

| list | lines | rules | unsupported | invalid | accepted |
|---|---:|---:|---:|---:|---:|
| EasyList | 78,554 | 78,277 | 0 | 0 | 100.00% |
| EasyPrivacy | 57,266 | 56,477 | 15 | 0 | 99.97% |
| uBO filters | 10,824 | 5,468 | 533 | 0 | 91.12% |
| uBO privacy | 3,408 | 1,502 | 250 | 0 | 85.73% |
| uBO unbreak | 6,105 | 2,481 | 72 | 0 | 97.18% |
| uBO quick-fixes | 661 | 283 | 116 | 0 | 70.93% |
| uBO badware | 7,034 | 4,807 | 52 | 0 | 98.93% |
| **total** | **163,852** | **149,295** | **1,038** | **0** | **99.31%** |

The first run accepted 99.24% and had 104 invalid lines. All 104 were parser
bugs, now fixed: regex option values, `$1p,strict3p`, `$_`, resource names
with `/`, IP literals in domain lists, uBO quote handling and EasyList CSS
injection. Every rejection left is a deliberate one:

| feature | lines | why |
|---|---:|---|
| `scriptlet:unknown` | 909 | not bundled yet (M6), see below |
| `html-filtering` | 51 | MV3 has no response-body access |
| `option:ipaddress` | 37 | needs the resolved IP |
| `option:popunder` | 15 | not detectable from an extension |
| `option:uritransform` | 13 | not implemented (DNR `regexSubstitution` later) |
| `option:replace` | 7 | rewrites bodies, MV3 cannot |
| `cosmetic-prefix:>>` / `:path` | 3 / 3 | uBO syntax not implemented |

**Scriptlet demand.** The 12 bundled scriptlets cover 2,332 of 3,241 scriptlet
rules (72%). The next ten by use are:

| scriptlet | rules |
|---|---:|
| `aeld` (addEventListener-defuser) | 208 |
| `href-sanitizer` | 69 |
| `set-local-storage-item` | 61 |
| `nano-sib` | 53 |
| `rmnt` (remove-node-text) | 52 |
| `remove-cookie` | 50 |
| `nano-stb` | 49 |
| `nowebrtc` | 47 |
| `aost` | 35 |
| `noeval` | 24 |

These ten take coverage to about 92%, which is the M6 target. 118 rules use
uBO's `trusted-*` scriptlets, which take arbitrary values or HTML. uBO accepts
them only from its own lists, and sinkd needs a policy for them before
bundling any (M6).

**Oracle.** Both parsers agree on 145,931 rule lines. We reject 908 lines that
adblock-rust accepts: 903 are unbundled scriptlets, and the rest are the
unsupported prefixes above. We accept 3,494 lines that it rejects, mostly
`$popup` (3,036), plus `$urlskip`, generic `#@#` exceptions and uBO-style
quoting. No line gets a different kind from the two parsers.

**DNS.** The seven lists yield 89,063 block entries and 5 allow entries in
125 ms, with a 2.4 MiB matcher. 61,287 lines are not DNS-able: 30,461 page
rules, 17,741 non-hostname patterns, 12,850 `||host^$options` (type, party or
page conditions) and 119 IP literals. These lists are written for browsers, so
the resolver's default lists are a separate choice (M3).

**Throughput.** All seven lists (4.9 MB) parse in 76 ms on one M1 Pro core,
about 2.1 M lines/s.

## Config (`core::config`)

- **Never an open resolver.** Non-loopback `listen.addrs` need
  `allow_non_loopback = true` *and* a non-empty `client_allowlist`. `/0` is
  refused. IPv4-mapped loopback counts as loopback.
- DoH upstreams whose URL host is a name need `bootstrap` IPs. Once sinkd is
  the system resolver it cannot resolve its own upstream.
- UDP/DoT upstreams equal to one of our listen addresses (forwarding loop) are
  refused. `metrics.listen` must be loopback.
- `deny_unknown_fields` everywhere, so a typo is an error, not a silent default.
- Validation returns every problem at once.
- Defaults: loopback `:53`, null-address block responses with TTL 10 s,
  HTTPS/SVCB blocking on, query log and metrics off, upstreams Quad9 DoH then
  Cloudflare DoH. The upstream choice is an open question for review.
- M4 added three settings:
  - `blocking.cname_uncloaking` (default on).
  - `cache.serve_stale_secs` (default 86,400, at most 7 days).
  - `[special_names] forward_private` (default off).
- `[updates]` (M3): `interval_hours` (default 24, range 1–720) and
  `cache_dir` (default: the per-user cache directory). Each `[[list]]` may
  set `refresh_hours`, which only `url` lists accept.

## Resolver (`resolver`, M2)

**Shape.** `Engine::decide(bytes) → Decision` is synchronous and does no I/O:
`Blocked(reply)`, `Error(reply)`, `Forward(state)` or `Drop`. `Server` owns
the sockets and `Upstreams` does the forwarding. All of the DNS semantics
can be tested without the network, and the property tests feed it raw bytes.

**hickory-proto for the wire format only.** It parses and builds messages,
handles name compression and EDNS, and is fuzzed upstream. We do not use
`hickory-server` or `hickory-resolver`. Their authority/zone machinery and
recursive caching are not what a sinkhole needs, and we need exact control
over EDNS, truncation and what is forwarded.

**Block answers.**
- A gets `0.0.0.0` and AAAA gets `::`, with the block TTL (10 s).
- Every other type gets NODATA. That includes HTTPS/SVCB (type 65/64), so a
  browser learns no alternative endpoint or ECH key for a blocked name.
  `blocking.block_https_records = false` forwards those instead.
- `nxdomain` mode answers NXDOMAIN for every type.
- Negative answers carry an SOA, so they are cacheable for the block TTL
  (RFC 2308 §5):
  - Its owner is the list entry that matched, which is the query name or a
    parent of it, standing in for the zone apex.
  - Its names are under `.invalid`, so nobody mistakes it for a real zone:
    `ads.example. 10 IN SOA sinkd.invalid. blocked.sinkd.invalid. 1 3600 600 86400 10`.
- Only class IN (and ANY) is matched; CHAOS and friends are forwarded.

**Matching wire names.** A DNS label may hold any byte, dots included.
- Bytes that cannot occur in a list entry become `\x01`, and so does a dot
  inside a label, which would otherwise shift label boundaries. The matcher
  never probes a suffix that contains one.
- So the two-label name `x` + `ads.example` (written `x.ads\.example`) cannot
  match `ads.example`.
- But `a\032b.ads.example` (a space in the first label) is still blocked by
  its parent.

**Forwarding over plain DNS** (the encrypted transports are M4, below).
Each forwarded query gets a fresh ID from a CSPRNG and a fresh connected UDP
socket, so the source port is random and the kernel drops datagrams from
anyone but the upstream. A reply is accepted only when its ID, QR/opcode and
question all match. Anything else is skipped, not treated as fatal: one
forged packet must not be able to fail a query.

**EDNS is hop-by-hop** (RFC 6891 §6.1.1).
- The upstream query carries our own OPT record (payload 1232) and the
  client's DO, CD, AD and RD bits.
- It does **not** carry the client's options. EDNS Client Subnet would tell
  the upstream the client's network; cookies and padding belong to the other
  hop.
- The reply carries our OPT record only if the client sent one.

**Other upstream behavior.**
- The question goes upstream in the client's spelling and comes back in it,
  so 0x20 case-randomization checks pass.
- A truncated UDP answer is retried over TCP.
- SERVFAIL, REFUSED and the like move on to the next upstream.
- Each upstream gets 2 s for UDP plus any TCP retry. Two upstreams fail over
  within 4 s, inside the 5 s stub resolvers wait.
- "Port unreachable" fails the attempt immediately, so a dead upstream costs
  milliseconds, not a timeout (tested: under 500 ms).

**Reply size.**
- UDP replies are capped at the client's EDNS payload, clamped to 512–1232,
  or at 512 without EDNS. 1232 is the DNS Flag Day 2020 value: one packet on
  any common path, so nothing is ever fragmented.
- A reply too big for that becomes header + question + OPT with TC set, and
  the client retries over TCP.
- Records are never partially dropped, since a partial answer would be
  cached as complete.

**Errors and refusals.**
- Unparseable queries get FORMERR, keeping the query's ID, opcode and RD bit.
- Opcodes other than QUERY get NOTIMP.
- AXFR/IXFR get REFUSED.
- EDNS versions above 0 get BADVERS. It shares code 16 with TSIG's BADSIG,
  which is what hickory decodes it as.
- Responses sent to us are dropped, never answered, so two misconfigured
  resolvers cannot ping-pong.

**Never an open resolver, enforced twice.**
- `ClientFilter` checks every packet and connection: loopback is always
  allowed, other addresses only inside `listen.client_allowlist`. This holds
  whatever the sockets are bound to, so even a hand-built config bound to
  `0.0.0.0` with an empty allowlist answers only this machine.
- Config validation refuses such a config anyway, and `from_config`
  validates even configs that were built in code.
- Out-of-allowlist traffic is dropped silently. Refusing it would still
  answer spoofed sources.

**Load limits.**
- At most 1,024 upstream queries are in flight; past that, a query gets an
  immediate SERVFAIL instead of queueing without bound.
- At most 256 TCP connections; past that, new ones are closed.
- TCP clients get 10 s to send each query and to accept each reply, so a
  stalled connection cannot pin a slot for long. That is tested.
- Each TCP connection is served one query at a time (RFC 7766 allows it;
  stub resolvers rarely pipeline).
- UDP sockets get four receive loops each and ask for a 1 MiB kernel buffer.

**Sockets.**
- IPv6 sockets set `IPV6_V6ONLY`, so `[::]:53` and `0.0.0.0:53` can both be
  listed on Linux.
- TCP listeners set `SO_REUSEADDR`, so a restart does not wait out
  TIME_WAIT.
- Port 0 binds UDP first, then TCP on the same port, so tests get one
  address for both.


### Measured (M2, 2026-11-07, M1 Pro, release build)

Engine, per query (criterion, no sockets):

| step | time |
|---|---:|
| decide + encode a block answer (100k-entry list) | 1.22 µs |
| decide to forward | 0.34 µs |
| build + encode the upstream query | 0.52 µs |
| parse + check + rewrite a 3-record upstream answer | 2.05 µs |

Over loopback UDP (`examples/loadgen`). Load generator, server and a scripted
upstream share 8 cores:

| workload | clients | q/s | p50 | p99 | p99.9 | errors |
|---|---:|---:|---:|---:|---:|---:|
| blocked (answered locally) | 1 | 39,400 | 22.5 µs | 46.5 µs | 82 µs | 0 |
| blocked | 64 | 105,400 | 538 µs | 1.0 ms | 1.2 ms | 0 |
| forwarded | 1 | 7,900 | 111 µs | 292 µs | 526 µs | 0 |
| forwarded | 64 | 9,700 | 5.8 ms | 15.9 ms | 20.8 ms | 0 |
| direct to upstream (baseline) | 1 | 34,200 | 26.7 µs | 44.2 µs | 78 µs | 0 |

- The blocked path is the path cache hits will take in M4. It already beats
  the M4 budgets: 105k q/s against ≥ 20k, and 47 µs p99 at low load against
  < 1 ms added. The 64-client latency is queueing: 64 queries in flight ÷
  105k q/s.
- **Forwarding adds about 85 µs (p50) and caps near 10k q/s.** Almost all of
  that is the fresh socket per query (bind + connect + close is 30–70 µs on
  macOS, measured). A desktop sends tens of queries per second, so this is
  not a practical limit. M4 reuses DoH/DoT connections, and the cache takes
  repeat names off this path.
- The daemon itself was measured with `sinkd run`:
  - The seven real lists from the coverage check load in 130 ms, giving
    89,063 block entries, at 11 MB RSS.
  - A synthetic 1M-entry hosts file loads in 487 ms (999,528 unique), at
    69 MB RSS steady and 72 MB peak. The M1 budgets are < 2 s and < 150 MB.

**Real lists do not block what people expect at DNS level.** EasyList and
EasyPrivacy write their big-name tracker rules with `$third-party` or a type
option: `||google-analytics.com^$script,third-party,xmlhttprequest` and
`||doubleclick.net^$popup`. A resolver cannot honor those, so they are
skipped rather than broadened. With these lists alone, `www.google-analytics.com`
resolves normally; `pagead2.googlesyndication.com` is blocked. The resolver's
default lists must be DNS-oriented lists (M3). AdGuard Home makes the same
call for rules with `$third-party`.

**The DNS-oriented lists: OISD big and the AdGuard DNS filter (2026-11-13).**
The starter config adds both to the extension's three lists. They were
chosen by measurement, on three sets of names: the 165 hosts an ad-block
tester probes, 132 names people use and expect to work (dashboards, CDNs,
sign-in, payments), and 95 ad and tracker addresses that apps really call.
Names blocked by the resolver alone, lists fetched that day:

| Lists | Tester (165) | Everyday (132) | Real trackers (95) | Load, RSS |
|---|---|---|---|---|
| the extension's three | 48 | 2 | 41 | 0.15 s, 13 MB |
| + HaGeZi Multi PRO | 124 | 13 | 85 | 0.36 s, 25 MB |
| + OISD big | 111 | 5 | 68 | 0.36 s, 25 MB |
| + AdGuard DNS filter | 102 | 6 | 80 | not measured |
| + OISD big + AdGuard DNS filter | 126 | 7 | 83 | 0.58 s, 42 MB |

- **HaGeZi Multi PRO covers the most alone, and breaks the most.** It
  lists whole vendor domains that are also where people sign in to a
  dashboard: `sentry.io`, `newrelic.com`, `bugsnag.com`, `mixpanel.com`,
  `amplitude.com`, `segment.com`, `hotjar.com`. A default must not do that.
- **The other two fill each other's gaps.** OISD breaks the least but
  leaves analytics alone (`www.google-analytics.com`,
  `app-measurement.com`). AdGuard's list covers analytics but misses most
  mobile ad networks. Together they match HaGeZi with about half the
  false blocks.
- The pair's 7 everyday names: 2 that the three lists block already
  (`imasdk.googleapis.com`, `statsig.anthropic.com`), and
  `app.optimizely.com`, `segment.com`, `app.segment.com`, `hotjar.com`,
  `insights.hotjar.com`. `sinkd allow add` is the way out, and the
  starter config says so.
- OISD's header asks for an hourly check (`! Expires: 1 hours`). The
  starter config holds it to a day with `refresh_hours = 24`.
- AdGuard's list carries 216 `@@||name^` exceptions. An exception from any
  list beats every blocklist, so they apply to the other four lists too:
  `go.redirectingat.com`, which EasyList blocks, now resolves. Accepted:
  they are that list's fixes for breakage.
- Through a running resolver with the five lists from their URLs (`dig`):
  127 of 165, 7 of 132, 83 of 95. The extra tester host is CNAME
  uncloaking. The five lists give 369,740 block entries and 188
  exceptions.
- **Still open at DNS level,** because the name also serves content or
  the lists leave it: `s.youtube.com`, `redirector.googlevideo.com`,
  `dai.google.com`, `cdn.onesignal.com`, `static.klaviyo.com`,
  `widget.intercom.io`, `cdn.optimizely.com`. In a browser the extension
  deals with those in the page.
- **The resolver now blocks names the extension does not.** That is the
  point (it has no page to look at), and `sinkd check` shows both
  verdicts. The lists are downloaded by each install from their
  publishers (both GPLv3) and are not shipped with sinkd.

## Lists (`lists`, M3)

**The cache is the single source of truth for URL lists.** A refresh writes
to it; a build only reads it (and local files). So a build never waits on
the network, startup works offline, and the daemon and `sinkd update`
cooperate through the directory with no other channel: `update` writes a
file, the daemon notices it on its next poll.

**Fetching** (`lists::fetch`).
- reqwest with rustls. HTTPS only, redirects included: `https_only` plus a
  redirect policy that refuses any non-HTTPS target and stops after 5 hops.
- Conditional: the cached copy's ETag and Last-Modified go out as
  `If-None-Match` / `If-Modified-Since`. Both hosts in the live test send
  weak ETags (`W/"…"`) and Last-Modified, and answer 304.
- gzip accepted (lists compress about 4:1). The 64 MiB limit applies to the
  *decompressed* bytes, counted as they stream, so a small compressed body
  cannot expand without bound. That is tested.
- Timeouts: 10 s to connect, 30 s per read, 5 min in total.
- `User-Agent: sinkd/<version>`. HTTPS_PROXY/ALL_PROXY are honored;
  macOS system proxy settings are not read.

**TLS: rustls with *ring*, certificates checked by the OS.**
- *ring* rather than reqwest's default aws-lc-rs: a smaller build with no
  CMake step, and the TLS stack's licenses are ISC/Apache-2.0/MIT. reqwest is
  built with `rustls-no-provider` and *ring* is installed as the process
  default when the first fetcher is built.
- Certificates are verified by `rustls-platform-verifier`, i.e. the OS
  (Security.framework on macOS), so the system's trust settings and
  revocation apply. sinkd never adds a root of its own.
- cargo-deny now allows ISC (ring, rustls-webpki, untrusted) and
  BSD-3-Clause (subtle), and checks only the platforms we ship for.

**List servers are resolved through the upstreams**, via a `Resolve` hook in
the fetcher that the resolver implements with its own upstreams. This avoids
three traps:
- Once sinkd is the system resolver, asking the system would ask
  sinkd itself.
- A list could otherwise block its own host and so prevent its own fix.
- The lookups stay on the configured path, which becomes encrypted in M4.
The daemon uses whatever upstreams are in force at the time of each lookup.

**Accepting a download** (`lists::check`). The dangerous failures arrive as
`200 OK`, so a download must look like a list before it replaces the copy in
use:
- **Markup:** if the first non-blank byte is `<`, it is refused. No list
  syntax starts that way, and every captive portal, CDN error page and S3
  XML error does.
- **Binary:** a NUL in the first 64 KiB is refused. A `.gz` served without
  `Content-Encoding` is one example.
- **Empty:** no rule lines at all is refused.
- **Collapse:** fewer than 10% of the previous copy's rules is refused when
  that copy had at least 100. `sinkd update --force` overrides only this
  check.
- A server without validators sends the whole list every time. A body
  whose FNV-1a digest matches the cached copy counts as unchanged, so it
  triggers no rewrite and no rebuild.

**Cache format.** Each list is one file:
- A magic line, a JSON metadata line (URL, ETag, Last-Modified, fetch time,
  rule count, `Expires`, digest), then the body exactly as downloaded.
- One file means one atomic rename per update: the writer writes a temporary
  file, fsyncs, renames, then fsyncs the directory. Readers see the old copy
  with its old ETag or the new copy with its new one, never a mix, even with
  the daemon and `update` writing at once.
- Files are named `host_file-<FNV-1a of URL>.list`. FNV-1a is used because
  it is stable across releases, unlike std's hasher.
- A file that does not parse, or belongs to another URL, reads as absent
  and is replaced on the next download.

**Schedule.**
- Each list's interval is its `refresh_hours` if set, else its own
  `! Expires:` header (clamped to 1 h–14 d), else `updates.interval_hours`
  (default 24). EasyList says 4 days.
- Each check is jittered ±10%, so lists, and machines, do not all ask at
  once.
- A failed check retries after 5 min, doubling up to the interval.
- A 304 is not written to disk, so a restart re-checks once. That costs one
  304 per list and saves rewriting multi-megabyte files to record a
  timestamp.

**`!#include`**, as uBO does it.
- It is followed only to the including list's directory or below, on the
  same origin (or in the same directory, for local lists).
- At most 3 levels and 16 files per list.
- Each included file is cached and checked on its own, and handed to the
  DNS builder as a list of its own. A parent's unclosed `!#if` therefore
  cannot swallow an included file.
- This mattered more than expected. uBO's `filters.txt` pulls in nine more
  files (about 18,000 rules) that the M1/M2 coverage numbers never saw.
  Almost all of them are cosmetic or scriptlet rules, so DNS entries went
  from 89,063 to 89,461.

**The preprocessor is shared.**
- `filters::Lines` evaluates `!#if`/`!#else`/`!#endif`, joins `" \"`
  continuations, strips a BOM and surfaces `!#include`. `parse_list`, the
  DNS builder and the include scanner all use it, so they agree on which
  lines are live.
- The resolver's environment, `Env::dns()`, has no true tokens.

**Local entries beat `$badfilter`.** The config's `allow`/`block` entries
are put back after a list's `$badfilter`s apply. Lists are third-party; the
local entries are how the user overrides them.

## Hot reload (`resolver::reload`, M3)

**`ArcSwap<Policy>`.**
- The policy is the engine, the upstreams, the answer cache and the client
  allowlist, replaced as a whole, so no query sees half an update.
- A rebuild that leaves the upstreams unchanged keeps the live ones, with
  their connections and health. If the cache settings are unchanged too, it
  keeps the cache. Cached answers never depend on the lists (see M4), so a
  list update does not empty it.
- Each query runs against the policy it started with. A forwarded query
  holds an `Arc` of it until it completes.
- The UDP loop's cheap arc-swap guard is dropped before the send.
- Measured cost: none visible (see below).

**Polling, not a file-watching API.**
- The config file, local lists (with their includes) and the cache files of
  URL lists are `stat`ed every 2 s: size, mtime and inode.
- A dozen `stat` calls cost nothing measurable, need no FSEvents/inotify
  dependency, and see editors that save by renaming (the inode changes).
- Watching the cache files is what makes a parallel `sinkd update` take
  effect.

**Rebuilds.**
- Rebuilds run on a blocking thread while the old policy keeps serving.
- While list checks are in flight, rebuilds happen at most once per poll
  interval, so a batch of updates costs one build. On a first start, all 17
  files landed in one rebuild.
- A config edit is applied only if a full build with it succeeds. A syntax
  error, a validation error or a build error (a list file that does not
  exist) is logged once, and the config in force stays.
- **Half-written files are never loaded** (fixed in M4, after a test caught
  it under load). A save that truncates and then writes leaves an empty file
  for a moment, and a rebuild that read it then would drop every rule in it.
  So a changed file must stay unchanged for 250 ms before it is read. A build
  is also discarded if any file it read changed while it was reading; the
  next poll builds again.
- A change to `listen.addrs` logs that a restart is needed; everything else
  applies live.
- SIGHUP re-reads everything at once. `ReloadHandle::refresh` (not wired to
  a signal) checks every list at once.

**Last known-good, at every level.**
- A failed download keeps the cached copy.
- A broken config keeps the config in force.
- A failed rebuild, say a local list deleted mid-edit, keeps the policy in
  force.
- All three are covered by integration tests, alongside a restart while the
  list server is down, which blocks from the first query.

### Measured (M3, 2026-11-07, M1 Pro, release build)

Reload cost with a 1M-entry hosts list (`examples/reload`, 4 closed-loop UDP
clients asking for blocked names throughout):

| | |
|---|---|
| build + swap, 10 reloads | min 419 ms, median 429 ms, max 440 ms |
| RSS serving, before reloads | 81 MiB |
| RSS after each of 10 reloads | 119 MiB, flat (no growth) |

| queries for blocked names | queries | p50 | p99 | p99.9 | max | errors |
|---|---:|---:|---:|---:|---:|---:|
| idle | 281,425 | 34 µs | 121 µs | 218 µs | 0.9 ms | 0 |
| during back-to-back reloads | 387,458 | 35 µs | 133 µs | 333 µs | 1.2 ms | 0 |

- **RSS.** During a build the old and new rule sets coexist, plus the list
  text: 81 → 119 MiB. Afterwards the allocator keeps those pages for the
  next build, so RSS stays at the peak instead of growing. That is inside
  the 150 MB budget.
- **Query path.** The `ArcSwap` costs nothing measurable (`examples/loadgen`
  rerun):
  - Blocked, 1 client: 41,364 q/s, p50 21.9 µs, p99 36.4 µs. M2 had 39,400,
    22.5 µs and 46.5 µs.
  - Blocked, 64 clients: 113,223 q/s. M2 had 105,400.
  - Forwarded, 1 client: 8,964 q/s, p50 106 µs. M2 had 7,900 and 111 µs.

Live fetch of the seven lists from the M1 coverage check: 17 files with
includes, 6.6 MB, 4 at a time:

| | |
|---|---|
| `sinkd update`, empty cache | 3.45 s |
| `sinkd update` again (all 304) | 0.51 s |
| `sinkd run`, empty cache | serves at once; all lists applied in one 183 ms rebuild a few seconds later |
| `sinkd run` from the cache | 189 ms to load 89,461 entries; 29 MiB RSS |

## Upstreams, cache and answers (`resolver`, M4)

**DNS over HTTPS is the default** (RFC 8484), through reqwest over HTTP/2.
- One HTTP client per upstream, so each keeps its own pool. After the first
  query, queries share one HTTP/2 connection, multiplexed, with no
  handshake. This also removed M2's ~10k q/s forwarding ceiling, which came
  from a fresh socket per query. Measured below: 3.5× UDP forwarding.
- `POST` with `application/dns-message`, message ID 0 (RFC 8484 §4.1).
- The answer's content type is checked strictly, it is capped at 64 KiB,
  and its question must match.
- The URL's host is pinned to the configured `bootstrap` addresses, so
  reaching the upstream never needs a DNS lookup, which would come back to
  sinkd itself. Config validation already required `bootstrap` for a
  host name.
- No proxies, so no stranger sits between sinkd and its upstream (and a
  proxy configured by name would need resolving). No redirects.

**DNS over TLS** (RFC 7858) keeps one long-lived, pipelined connection per
upstream.
- Each query gets an ID unique among those in flight (a counter is enough
  inside TLS). Answers are matched by ID in any order (RFC 7766
  §6.2.1.1), and a reader task owns the receiving half.
- A dead connection fails every waiting query at once; the next query
  reconnects, and concurrent callers share that one connect.
- Servers close idle connections, and a query can race that close. A query
  that loses the race on a *reused* connection is retried once on a fresh
  one. sinkd closes its own side after 8 s idle.

**Padding.** DoH and DoT queries carry an EDNS Padding option that brings
them to a multiple of 128 bytes (RFC 8467). Otherwise the length of an
encrypted query hints at the name in it.

**Certificates** are checked by the OS verifier, as for list downloads:
`rustls-platform-verifier` for DoT, reqwest's default for DoH. Tests pass
`Roots::Only` with a throwaway CA. Nothing is ever added to the system's
trust store.

**Health-aware failover.** Upstreams are tried in config order.
- An upstream that fails (a timeout, a refused connection, a TLS or HTTP
  error) is not asked on a client's behalf while a healthy one remains. It
  is paused for 1 s after the first failure, doubling up to 30 s.
- When its pause ends, client queries are *also* sent to it in the
  background, as probes. Only a successful probe puts it back first in line.
- The first version probed with a real client query instead. The live
  failover check caught the cost: a permanently dead primary made one query
  wait 2 s every pause. Now a dead upstream costs one client one timeout,
  when it dies.
- SERVFAIL or REFUSED moves on to the next upstream **without** a penalty:
  the upstream is up, and the *domain* is broken, or fails DNSSEC there.
- If every healthy upstream fails, the paused ones are tried too, rather
  than give up while one might answer.
- Each query has a 4.5 s deadline across all attempts, inside the 5 s stub
  resolvers wait, so the client gets SERVFAIL rather than silence.

**Answer cache** (moka: TinyLFU admission, per-entry expiry, bounded by
`cache.max_entries`).
- **Key:** the question (name in lower case, type, class) plus the DO and CD
  bits, which change what the upstream sends.
- **Not cached:** queries with RD=0, since such a client wants something
  else than everyone else; truncated answers; errors such as SERVFAIL; and
  anything with TTL 0.
- **Positive TTL:** the lowest TTL in the answer section, clamped to
  `min_ttl_secs`..`max_ttl_secs`.
- **Negative TTL** (NXDOMAIN, or NODATA): the lesser of the SOA's TTL and
  MINIMUM, capped at `max_negative_ttl_secs`. Without an SOA, not cached
  (RFC 2308 §5).
- Served TTLs count down, and are at least 1.
- **AD bit:** it reaches only clients that asked with AD or DO (RFC 6840
  §5.8). An answer fetched for one client can be served to another.
- **Serve-stale** (RFC 8767): an expired entry is kept for
  `serve_stale_secs` (default a day). It is used only when no upstream
  answers, with TTL 30 s. When upstreams are down, names people already use
  keep resolving.
- **Blocking is never cached.** The question's name is checked on every
  query, before the cache. Uncloaking (below) runs on every answer served,
  cached or not. A list change applies to cached names at once (tested),
  which is why reloads can keep the cache.
- A hit is answered inline on the socket task: no spawned task, no
  forwarding slot.

**CNAME uncloaking.** A tracker hidden behind a first-party name
(`smetrics.walmart.com` CNAME `walmart.com.102.112.2o7.net`, Adobe) passes a
name check. So after resolution, every CNAME target in the answer is
checked, and so is every HTTPS/SVCB target name.
- If one is blocked, the client gets the block answer for its *own*
  question (`0.0.0.0`, or NODATA), with no chain. Its SOA is owned by the
  query name, since the rule names the target.
- A name on the allowlist is never uncloaked: an explicit allow means the
  user wants it to work.
- `blocking.cname_uncloaking = false` turns it off. An HTTPS target of `.`
  means the owner and is skipped.
- DNAME records are not parsed (hickory does not decode them), but servers
  send a synthesized CNAME alongside, and that is checked.

**HTTPS/SVCB (type 65/64).**
- A blocked name's HTTPS/SVCB query gets NODATA, as since M2.
- New in M4: an HTTPS/SVCB *answer* whose target is blocked is uncloaked.
- `block_https_records = false` turns both off.

**Special names** are answered here (`resolver::special`), each with the RFC
that asks for it:

| names | answer |
|---|---|
| `localhost` and below | `127.0.0.1` / `::1`; NODATA for other types (RFC 6761) |
| `1.0.0.127.in-addr.arpa`, `::1` reversed | PTR `localhost.` (RFC 6303) |
| `.invalid`; reverse zones of `0/8`, `127/8`, broadcast, `::`, the documentation networks | NXDOMAIN |
| reverse zones of `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT), `169.254/16`, `fd00::/8`, `fe80::/10`; `.local`; `home.arpa` | NXDOMAIN, unless `special_names.forward_private` (RFC 6303, 7793, 6762 §22.1, 8375) |
| `use-application-dns.net` | NXDOMAIN, unless allowlisted: Firefox's canary, which keeps it on this resolver |
| `resolver.arpa` | NODATA: no designated resolvers (RFC 9462) |

- Private reverse zones, `.local` and `home.arpa` cannot be answered by a
  public upstream, and asking leaks LAN details. `forward_private = true` is
  for setups whose upstream is a router or company server that knows them.
- `resolver.arpa` is the other bypass, beside the canary. Through Discovery
  of Designated Resolvers, a client asks its resolver for an encrypted one.
  Forwarded to Quad9, the question would come back with Quad9's DoH
  endpoint, and the client would switch to it, bypassing sinkd.

### Measured (M4, 2026-11-07, M1 Pro, release build)

**Caveat:** the machine was busy (load average 7.2 on 8 cores from other
processes). Every socket figure is lower than M3's, including the
direct-to-upstream baseline, so compare rows with each other rather than
with earlier milestones.

Over loopback UDP (`examples/loadgen`): scripted UDP and HTTP/2 DoH
upstreams, a 10,000-entry cache, and a blocklist of 100,000 names.

| workload | clients | q/s | p50 | p99 | errors |
|---|---:|---:|---:|---:|---:|
| blocked | 1 | 34,602 | 23.2 µs | 75 µs | 0 |
| **cached** | 1 | **35,585** | 23.2 µs | 75 µs | 0 |
| forwarded, UDP upstream | 1 | 6,393 | 128 µs | 449 µs | 0 |
| forwarded, DoH upstream | 1 | 9,607 | 89 µs | 290 µs | 0 |
| direct to UDP upstream (baseline) | 1 | 33,326 | 24.4 µs | 77 µs | 0 |
| blocked | 64 | 79,719 | 786 µs | 1.6 ms | 0 |
| **cached** | 64 | **79,376** | 785 µs | 1.5 ms | 0 |
| forwarded, UDP upstream | 64 | 8,393 | 6.9 ms | 16.5 ms | 0 |
| forwarded, DoH upstream | 64 | 29,739 | 2.1 ms | 3.7 ms | 0 |
| direct to UDP upstream (baseline) | 64 | 59,606 | 911 µs | 2.5 ms | 0 |

- **Budgets:**
  - Cached throughput: 79k q/s against ≥ 20k, with no errors.
  - Added latency on a cache hit: the cached row matches the direct
    baseline (75 µs p99 at one client), against < 1 ms p99.
  - The 64-client latency is queueing: 64 queries in flight at ~80k q/s.
- **DoH forwarding outruns plain UDP**, 3.5× at 64 clients, because the
  HTTP/2 connection is reused while UDP opens a socket per query.

Engine, per query (criterion, no sockets):

| step | time |
|---|---:|
| decide + encode a block answer (100k-entry list) | 1.43 µs (M2: 1.22) |
| decide to forward | 0.35 µs |
| decide + answer a special name (`localhost`) | 0.69 µs |
| cache hit → key, lookup, TTL count-down, uncloak check, reply | 1.94 µs |

Live, through Quad9, with `dig` against `sinkd run` and the default config:

| | |
|---|---|
| first query (opens the DoH connection) | 210 ms |
| new names on the warm connection | 62–99 ms |
| cached | 0 ms |
| DoT to Quad9: first query, then later ones | 189 ms, then ~57 ms |
| dead first upstream: first query, then 10 queries over 13 s | 2,192 ms, then 59–64 ms each |
| `smetrics.walmart.com` with `block = ["2o7.net"]` | `0.0.0.0`, fresh and cached; `walmart.com` unaffected |
| canary, `localhost`, private PTR, `.local`, `_dns.resolver.arpa` | answered locally, nothing sent upstream |

## Compiler (`compiler`, M5)

`sinkd compile --rulesets extension/rulesets.toml --out DIR` reads the
lists a build manifest names, and writes:
- `rulesets/<id>.json`, the DNR rules, with `rulesets.json` indexing them;
- `war/`, the surrogates;
- `dns/block.txt` and `dns/allow.txt`, the resolver's domain set in the
  "domains" format;
- `report.json`, every rule a target could not take, with list, line, text,
  feature and reason;
- `NOTICES.txt`, each list with its license.

Each list is read through the shared preprocessor with the target's
environment: `chromium_mv3` for DNR, `dns` for the domain set.

**Never broaden.** A rule DNR cannot express exactly is reported, not
approximated. The one narrowing allowed is dropping request types DNR has no
name for (`popup`, `webrtc`) from a rule that has others; the drop is
counted in the report.

**Translation**, filter syntax → DNR:

| filter | DNR |
|---|---|
| `\|\|host^` | `requestDomains: [host]` (exactly "this host and below"; these then merge) |
| other patterns | `urlFilter`, same `\|\|`/`\|`/`^`/`*` syntax; non-ASCII percent-encoded |
| `/regex/` | `regexFilter`, if RE2 can run it within Chrome's limit (below) |
| `$domain` / `$to` / `$denyallow` | `initiatorDomains` / `requestDomains` / `excludedRequestDomains` |
| types | `resourceTypes`; `subdocument` → `sub_frame`, `document` → `main_frame`; `other` also takes DNR's `csp_report`, `webtransport`, `webbundle`, so "every type" means every type |
| `$1p` / `$3p` | `domainType` |
| `$method` | `requestMethods` / `excludedRequestMethods` |
| `$match-case` | `isUrlFilterCaseSensitive` |
| `@@…$document` | `allowAllRequests` on `main_frame` + `sub_frame` |
| `$redirect=name` | redirect to `/war/<file>` (uBO names and aliases) |
| `@@…$redirect` | a block that outranks the redirect: uBO's semantics |
| `$removeparam=name` / bare | `queryTransform.removeParams` / `query: ""` |
| `$csp` / `$permissions` | `modifyHeaders`, append response header, on documents |
| `$removeheader`, `##^responseheader(…)` | `modifyHeaders` remove (uBO's safe header list) |
| `$badfilter` | cancels its twin across every list before translation |

**Priorities** reproduce uBO's precedence, because DNR lets the highest
priority win:

| priority | rules |
|---:|---|
| 1 | `$removeparam` (generic), header edits |
| 2 | `$removeparam` limited to sites or URLs |
| 3 | exceptions to modifying rules (`@@…$removeparam`, `@@…$csp`), e.g. signed URLs |
| 10 | block |
| 20–29 | redirect (surrogate), plus uBO's `:N` priority; beats block |
| 30 | `@@…$redirect` → block |
| 40 | `@@` exceptions, `allowAllRequests` |
| 50 / 60–69 / 70 | `$important` block / redirect / exception |
| 1000 | the extension's "off on this site" switch |

- An exception to a *modifying* rule (priority 3) cancels only priorities
  1–2. It never unblocks anything. That makes `@@*X-Amz-Signature=$removeparam`
  an exact signed-URL exception.
- A real `@@` exception (40) also cancels parameter stripping and header
  edits on its URLs. DNR has no per-action exceptions.

**Merging is what fits a full list set in the quota.**
- Rules that differ only in `requestDomains` become one rule. Domains
  covered by a parent in the same rule are dropped.
- 118,735 translated filter rules become 20,062 DNR rules.

**One redirect per request.**
- Chrome applies a single redirect when several match. uBO's lists have
  `$removeparam=s_cid,document` beside the generic parameter rules. On a page
  load, that rule alone won, and `utm_source` stayed. The end-to-end test
  against the real build caught this.
- So generic parameter rules are regrouped by request type. Each type gets
  one rule with every parameter that applies to it; that is exact.
- Site-specific parameter rules carry the generic parameters and outrank
  them (priority 2).

**Regexes.** Chrome compiles `regexFilter` with RE2 in at most 2 KB.
- In testing, a single rule over that limit kept the whole extension from
  loading, with no visible error. So the compiler estimates the RE2 program
  size (`translate::regex_cost`).
- The model counts bytes, not Unicode. A byte range costs 1 and `.` costs 3.
  A case-insensitive `[a-zA-Z]` costs 1, because RE2 folds case. Each
  optional copy in `{n,m}` adds a split, and repetitions over 1,000 are a
  syntax error.
- Calibration: Chrome's own `isRegexSupported` judged all 360 regex rules of
  the default lists plus synthetic patterns. Chrome refused 96, every one
  scoring 115 or more.
- The threshold is 100. Nothing Chrome refuses is kept; some it would accept
  (16% of accepted regexes, by estimate) are dropped.
- The end-to-end test re-checks every regex in a build with Chrome.

**Validation and quotas** (`validate`):
- Every emitted rule passes the checks Chromium's `indexed_rule.cc` applies.
  A property test feeds the compiler random filter rules and asserts this,
  along with unique IDs and deterministic output.
- Quotas checked: 30,000 guaranteed static rules, 1,000 regex rules per
  ruleset, and 100 rulesets (50 enabled).

**Surrogates** (`resources/`) are original implementations, MIT OR
Apache-2.0:
- Scripts: `googletag` (a working `cmd` queue, slots, and `slotRenderEnded`
  events), `adsbygoogle`, `ga()` (calls `hitCallback`), legacy `_gaq`, GTM and
  gtag event callbacks, `apstag`, comScore.
- Blank files: js, html, css, json, txt, mp3, gif and png.
- They carry no comments, because a page can read a web-accessible resource.
- Names follow uBO's, so lists' `$redirect=` works.
- `google-ima.js` (207 rules) is not written yet.

**The DNS output** uses the same parse (with the DNS environment). Only
`||host^` rules with no page-level options qualify, as in the resolver.

## Chrome extension (`extension/`, M5)

- **Thin glue; Chrome does the matching.** The worker enables rulesets,
  keeps one dynamic rule for paused sites, and answers the popup. It never
  sees page traffic. Its decisions are pure functions in `core.ts`, tested
  without a browser.
- **Permissions:**
  - `declarativeNetRequest`, `scripting` (M6: registering scriptlets and
    inserting cosmetic CSS), `storage`, `cookies` (M7: capping tracking
    cookies) and `privacy` (M7: the WebRTC IP policy; Chrome shows "Change
    your privacy-related settings" for it).
  - Host access to every site, because surrogate redirects, parameter
    stripping, header edits and (M6) the content script need it. Plain
    blocking would not.
  - `activeTab` and `webRequest`, for the popup's log: `getMatchedRules`
    for the tab the popup was opened on, then that tab's requests while
    the popup is open. (`declarativeNetRequestFeedback` would read every
    tab, and Chrome warns about it; `webRequest` adds no warning to the
    host access sinkd already has.) The worker never listens.
  - Development builds (`--dev`) add `declarativeNetRequestFeedback` for
    `testMatchOutcome` in the end-to-end test.
  - Firefox (M8) adds `dns`, `webRequest` and `webRequestBlocking` for
    CNAME uncloaking and the header rules on navigations. Firefox lets the
    user take site access away; the popup then says so and offers to ask
    for it again (Chrome's site access menu can do the same).
- **No remote code.** Rules and surrogates ship in the package.
  Web-accessible resources use `use_dynamic_url`.
- **Switches:**
  - Each ruleset (Ads, Trackers, Badware, Fixes, Tracking parameters) can be
    turned off on its own.
  - "Off on this site" is a priority-1000 `allowAllRequests` over the site's
    pages and frames.
  - DNR cannot turn off *one* feature on one site (an allow rule cancels
    everything below it), so the per-site switch is all-or-nothing.
- **New tabs:** DNR can't act on a tab a page opens, only on requests, so
  the compiler translates the lists' `$popup` rules (and `$all`, which
  includes them) like page loads instead, with `$domain` as the opening
  page (the initiator), into `popups.json`, which Chrome never sees. The
  worker checks each tab that has an opener at its first web address, for
  its first 8 seconds (a tab opened blank is checked once it navigates),
  and closes it when the enabled rulesets block it, as uBlock Origin does.
  Off where sinkd is off. No permission: `tabs.onCreated` and the tab's
  address come with the site access sinkd has. Popup closings are not in
  the badge count, which is Chrome's.
- **Badge:** `displayActionCountAsBadgeText` counts each match in the tab
  of a rule that did something: a block, a redirect, a header change.
  Allow rules are left out. The Global Privacy Control header is a header
  change on every request, so on a busy page most of the count is GPC.
- **Log:** the popup's second view is a live console of those matches, so
  it adds up to the badge.
  - What happened before opening: `getMatchedRules` for the tab, minus
    the allow rules, grouped by rule. Chrome reports the rule, not the
    request, so these lines say what their rule targets. A rule over a
    list of domains is named by the page's hosts it covers, unless another
    matched rule names that host outright; it would rather say "one of
    43,479 sites" than a wrong name.
  - It is read from the click (or key) that first shows the Log tab, not
    on opening. Reads outside a click are capped at 20 per 10 minutes, so
    reading on every opening left the log empty while the badge counted
    once the popup had been opened often (the cap does not seem to apply
    to unpacked builds, so it showed only in the store's). And most
    openings never show the log, while describing the matches parses the
    rulesets they came from: about 4 MB and 50 ms, and 15 MB of memory,
    measured on the development Mac. Should a read still be refused by the
    cap, the notice has a "Show them" button that reads in its click.
    The tab's count appears once the read is in, so it always matches
    the badge. The live part never polls, for the same cap.
  - From then on, `webRequest` in the popup, for that tab only, with the
    request's address: a block is `ERR_BLOCKED_BY_CLIENT`; a stand-in is a
    redirect to a `war/` file (on a random per-session host, as
    `use_dynamic_url` serves them); a cleaned link is a redirect that only
    drops parameters; a header change is a difference between
    `onBeforeSendHeaders` and `onSendHeaders` (requests) or
    `onHeadersReceived` and `onResponseStarted` (responses). Chrome counts
    a header rule only when it changed a header, so each difference is one
    match. Only requests that start after opening count, so nothing is
    counted twice.
  - A new page in the tab starts the count over, as the badge does.
  - Measured against the badge in Chromium: equal on opening, after new
    requests while open, and after a reload. A block by another extension
    looks the same to `webRequest`, so with a second blocker installed the
    live lines can run ahead of the badge.
  - Firefox has neither the count nor `getMatchedRules`, so its popup has
    no log.
- **Splash:** the first time the popup opens after install, it opens on
  the mark putting itself together (the website's Absorb splash,
  shortened), holds it still for 0.8 s and fades: about 2.7 s in all,
  while the controls load underneath. Every later open goes straight to
  the controls; a flag in the popup's `localStorage` remembers it played,
  and uninstalling clears it. It runs on its own clock, so clicks and keys
  neither speed it up nor reach the switches (Escape still closes the
  popup). It is hidden until the script shows it, so it never flashes on
  a later open or stays up if the script fails, and it never shows with
  reduced motion. The popup's last height stays in `localStorage` too, so
  every open starts at full height instead of growing as the controls
  arrive.
- **Version and updates:** the popup shows the installed version beside
  the name. The store downloads a new version by itself, but the browser
  installs it only once the background script stops, and while the bridge
  is connected it never does (the open native port keeps it running), so
  an update could wait for a browser restart. `runtime.onUpdateAvailable`
  restarts into it as soon as it is downloaded instead: after any settings
  change in flight, and not while the popup is open (`runtime.getContexts`,
  retried every 30 s), which the restart would close. On restart
  `onInstalled` applies the settings again, as on any update. Nothing is
  fetched for this; the browser already has the update.
- **Messages:** settings change only from the extension's own pages. The
  content script (M6) may ask for its own frame's cosmetic rules and
  nothing else; its messages are validated like any untrusted input,
  since a compromised renderer can send anything.
- **Toolchain:** TypeScript 7, Biome, Node's test runner and playwright-core
  1.55. These are the only npm dependencies, 9 packages in total, all pinned.

**End-to-end** (`npm run e2e`):
- Playwright's Chromium runs headless with a throwaway profile, so the
  user's own browsers are never involved. Port 80 of every host maps to a
  local server, so nothing leaves the machine.
- A fixture build is checked with real pages: blocking, `@@` exceptions,
  third-party rules, three surrogates (and that the real scripts are never
  fetched), parameter stripping (with competing rules), signed URLs, the
  per-site switch, per-ruleset switches and the popup.
- The real build is checked with Chrome itself: all rulesets enabled, every
  regex supported, and `testMatchOutcome` expectations for surrogates,
  blocks, stripping and untouched requests.

### Measured (M5, 2026-11-07, M1 Pro)

| | |
|---|---|
| `sinkd compile`, 7 public lists + 9 includes + 3 own lists | 670–690 ms, 276 MB peak RSS |
| filter rules translated / not translatable | 118,735 / 4,741 |
| DNR rules (ads 7,391 · trackers 9,941 · badware 1,184 · fixes 1,367 · parameters 179) | 20,062 of 30,000 guaranteed |
| regex rules | 222, all accepted by Chrome |
| extension size | 5.1 MB unpacked, 1.17 MB zipped |
| install → every ruleset enabled (real build) | 89–97 ms |

Not translatable, by feature:

| feature | rules | why |
|---|---:|---|
| `type:popup` | 3,054 | DNR cannot block popups |
| `option:redirect-rule` | 457 | "redirect only if blocked elsewhere" has no DNR form |
| `domain:entity` | 302 | `example.*` (any suffix) has no DNR form |
| `redirect:unknown-resource` | 300 | mostly `google-ima.js` (207); the rest are media and niche scripts |
| `option:urlskip` | 242 | needs URL decoding |
| `regex:too-large` / `unsupported-syntax` | 140 / 39 | over RE2's limit in Chrome / lookaround |
| others (`$header`, `$ipaddress`, `$popunder`, `$strict1p`, …) | ~200 | each listed in report.json |

The rest of what the lists contain is for the page index (M6): 33,650
cosmetic rules, 6,860 scriptlet rules, and 3,472 unbundled-scriptlet rules.

## Page target: cosmetic filtering and scriptlets (M6)

What the extension does inside pages. The compiler's third target writes
a cosmetic index and scriptlet files next to the DNR rulesets.

**Cosmetic index** (`core::page`, served by `crates/engine-wasm`):
- Per hostname and per entity (`example.*`): hiding selectors, exceptions,
  `:style()` rules, procedural rules, and `$elemhide` / `$generichide` /
  `$specifichide` flags. Generic rules are keyed by their rightmost class or
  id (`.ad-banner`), or kept in a short always-on list when they have none.
- Every entry carries a bit for its ruleset, so switching a ruleset off
  drops its cosmetic rules, and an exception in "Fixes" cancels a selector
  from "Ads". Lookups take the mask of the rulesets that are on.
- Serialized with postcard: 1.4 MB, 511 KB gzipped for the public lists.

**Decision: a five-function wasm ABI, not wasm-bindgen.** The spec named
wasm-bindgen. The interface is bytes in, a string out: `input(len)`,
`load()`, `page(mask)`, `generic(mask, always)`, `output()`. wasm-bindgen's
glue has to be generated by a CLI whose version must match the crate's,
and that CLI could not be installed in this environment (the install was
blocked), so the engine exports five functions itself and
`extension/src/engine.ts` is the whole binding (70 lines). The module has
no imports. The cost: the exports need `#[unsafe(no_mangle)]`, which the
`unsafe_code` lint flags, so this one crate has `unsafe_code = "deny"` with
an `allow` on each export, instead of `forbid`. There is no `unsafe` block
anywhere. Switching to wasm-bindgen later touches only `lib.rs` and
`engine.ts`.

**Cosmetic flow:**
1. A static content script (`content.ts`, isolated world, every frame,
   `document_start`) asks the worker for its frame's rules.
2. The worker looks the hostname up in the engine and inserts the CSS with
   `insertCSS` at the **user** origin, into that document only
   (`documentIds`). User-origin sheets beat the page's `!important`, are not
   in `document.styleSheets`, and add no node.
3. Procedural rules (`:has-text()`, `:upward()`, `:xpath()`, `:remove()`,
   `:remove-attr()`, …) come back to the content script, which evaluates
   them on load and again (debounced) as the page changes, with uBO's
   semantics (`:has()` / `:not()` evaluate relative to the subject).
4. For generic hiding, the content script reports the page's class and id
   tokens (`.x`, `#y`, deduplicated, capped), on load and as nodes appear.
   The worker inserts only the generic rules those tokens can match.

**Bait-safe generic hiding.** Detectors create bait (`<div class="adsbox
pub_300x250">`) and check whether it got hidden. The compiler leaves out
generic rules whose token is a known bait name (`compiler::page::BAIT`, 43
names from FuckAdBlock, BlockAdBlock, AdSense and common custom
detectors). Site-specific rules still apply, `#@#` and `$generichide`
are honored, and scriptlets defuse the detector itself. On the public
lists, 97 generic rules are dropped this way.

**Decision: scriptlets as registered content scripts
(`chrome.scripting`, `world: "MAIN"`), not the `userScripts` API.**
- Timing, measured in Chromium 140: a registered `document_start` script
  ran before the page's first inline script 20 times out of 20.
  `executeScript` from `webNavigation.onCommitted` did 0 of 20.
- `userScripts` needs the user to turn on a developer switch ("Allow User
  Scripts") for the extension, and its matching and timing are the same.
  Its one advantage is code from strings, which would let scriptlet
  updates ship without a release (see *Updates* below).
- Lists only select bundled scriptlets and pass arguments. The library
  (`compiler/scriptlets/library.js`, 22 scriptlets, original code under the
  project license) is bundled into each file; no list text becomes code.

**Scriptlet files.** Each ruleset's scriptlet sites are bucketed into
files of 500 sites (by the site's label, so a hostname, its parents and the
exceptions for them share a file), each registered for exactly its sites.
A file is: its table as a JSON string, the prelude (`prelude.js`: the
page's host keys, and a substring check that the table has any of them),
then the library, which runs only when the check passes.

**What registration costs.** Chrome checks each URL against every
registered match pattern, one by one, in every frame. Measured: about
0.1 µs a pattern on the M1 Pro, so the first layout (one pattern per site
plus 20 TLD patterns per entity: 52,035 patterns) cost about 5 ms of
DOMContentLoaded per navigation. Now:
- One pattern per site, and none for a site whose parent is listed.
- A ruleset with 300+ entities puts them in one file that runs on every
  page (the ads ruleset: 1,526 entities). It costs a page with no entry
  about 1 ms, mostly V8 pre-parsing the library. Entities now match every
  TLD, not 20.
- Rulesets with fewer entities expand them over 20 common TLDs.
- 21,796 patterns in all. The paint numbers below include this cost.

**Stealth** (asserted by the testbed against the same page without the
extension):
- No globals beyond what a rule asks to define (`set-constant`'s property,
  the trap of `abort-on-property-*`).
- Replaced functions are Proxies of the originals: name, length and own
  keys survive. `Function.prototype.toString` (itself a masked Proxy)
  reports the original's source for them. Descriptors keep their flags.
- Stack traces: errors thrown on purpose (`abort-*`), errors raised inside
  a wrapped built-in (`JSON.parse("{")` under `json-prune`), and
  `toString` on a non-function have this extension's frames removed.
- No nodes, attributes, style sheets or mutations. Cosmetic CSS goes in
  at the user origin. Registered scripts are not DOM `<script>` elements.
- Resource timing shows no `chrome-extension:` URL. No file is fetchable
  at a static `chrome-extension://<id>/` URL (`use_dynamic_url`; scriptlet
  files are not web-accessible at all).
- **Residual:**
  - A page callback that a wrapped native calls synchronously (a
    `JSON.parse` reviver under `json-prune`) sees our frame in
    `new Error().stack`. Hiding it needs `eval` with a fake
    `sourceURL`, which page CSP blocks with a violation report, so that was
    rejected.
  - Procedural rules change the elements they target (inline
    `display: none`, removal), on sites a rule names.
  - The rule-defined globals are visible as own properties, as with any
    uBO-compatible blocker.

**Updates without releases** (Part C §5) are not built yet. The cosmetic
index is data, so the worker could fetch and compile lists into it. Scriptlet
tables could be refreshed only through `userScripts` (code strings built
from the bundled library plus list arguments), which needs the user's
developer switch. That is a decision for you.

### Measured (M6, 2026-11-07, M1 Pro, `node testbed/run.mjs --bench`)

| | | budget |
|---|---|---|
| page engine | 79 KB wasm, 29 KB gzipped | |
| cosmetic index | 1,424 KB, 511 KB gzipped | engine + index < 1.5 MB gzipped |
| engine init (Node 20 / Chromium worker) | 15–16 ms / 21–25 ms | < 100 ms |
| cosmetic lookup per navigation, 5,000 hostnames | p50 0.006 ms, p99 0.021 ms | p99 < 1 ms |
| generic lookup, 213 tokens | p50 0.10 ms, p99 0.15 ms | |
| entity file, page it has nothing for | p50 1.0 ms, p99 1.2 ms | |
| largest site file, page it has calls for | p50 1.5 ms, p99 2.1 ms | |
| first contentful paint, bench page, 0 ms latency | 54.4 → 57.5 ms, **+5.7% ± 2.2%** | < 5% |
| first contentful paint, 40 ms emulated latency | 92.6 → 95.8 ms, +3.5% ± 1.1% | < 5% |
| DOMContentLoaded end, 0 ms / 40 ms latency | +7.7 ms / +11.6 ms | |
| service worker | 2.2 MB JS heap + 7.6 MB wasm memory | "modest" |

- Re-measured in M7 with a same-run A/B (80 rounds), the extension at the
  end of M6 cost about +11% first contentful paint on the zero-latency
  page, not +5.7%: that run was optimistic. Runs vary by a few ms.
- Page target on the public lists: 42,603 cosmetic and scriptlet rules
  taken, 1,611 not. 28,844 selectors, 13,236 sites, 13,817 generic rules.
  11,720 scriptlet calls in 45 files (2.5 MB).
- FCP is coarsened to 4 ms by Chromium, so the bench takes means of 40
  alternating loads against a persistent profile without the extension.
- Where the paint time goes (DOMContentLoaded, ±1 ms run to run): about
  2.5 ms is DNR plus the content script, about 4–6 ms is scriptlet
  registration (pattern matching plus the entity file). A one-rule DNR
  extension costs nothing measurable, and neither does any single ruleset
  on its own.

## testbed/ (M6)

Local pages for each detection technique of Part C and the tracking
techniques built so far (Part B 1, 2, 6), served from one local server
for every hostname. Each page opens in three browsers:
- **plain**, no extension: detectors must stay quiet (the page is honest).
- **naive**, ad and tracker hosts aborted and bait hidden: detectors must
  fire (the page catches a blocker that has no surrogates or scriptlets).
- **sinkd**, built from `testbed/lists/testbed.txt` plus the real
  surrogate and parameter lists: no detection, and no ad or tracker request
  reaches the server.

`--real` repeats the parts that matter with the public-list build;
`--bench` measures the budgets. 33 checks; see `testbed/README.md`.

## Privacy features (M7)

Five features beside the rulesets. Each switches off on its own (popup:
Privacy), and all but WebRTC can be switched off for one site (popup: On
this site). Settings gain `disabledFeatures` and `siteExceptions`
(feature → sites). Pausing a site still turns everything off there.

**Header features are dynamic DNR rules** (`core.ts` `privacyRules`),
rebuilt on every settings change:
- A per-site exception is an excluded domain on that feature's rule. An
  allow rule would also cancel blocking on the site, so it can't be one.
- Priority 900: above every compiled rule, so a list's `@@` exception that
  lets a tracker request through doesn't also let its cookies through;
  below the pause rule (1000), which ends them all.

| feature | how | per-site exception |
|---|---|---|
| GPC | `Sec-GPC: 1` on every request type, navigations included (in Firefox, navigations through webRequest: see Firefox); `navigator.globalPrivacyControl === true` from `gpc.js` (main world, `document_start`) | excluded initiator and request domains; `gpc.js` not registered there |
| Referrer | documents whose `Referrer-Policy` is `unsafe-url` or `no-referrer-when-downgrade` get `strict-origin-when-cross-origin` instead (matched with Chrome 128's `responseHeaders` condition, hence `minimum_chrome_version` 128); `Referer` removed from third-party requests to tracker hosts | excluded domains |
| Cookies | `Cookie` and `Set-Cookie` removed from third-party requests to tracker hosts; first-party tracking cookies capped at 7 days | excluded initiator domains; the cap checks the cookie's site |
| WebRTC | `chrome.privacy.network.webRTCIPHandlingPolicy` = `default_public_interface_only` | none: a browser-wide setting |
| Fingerprinting | `farble.js` (below) | not registered there; frames on an excepted page get no seed |

- **Tracker hosts** come from rulesets marked `trackers = true` in
  `rulesets.toml` (Trackers). They are the hosts of `||host^` block rules
  with nothing narrowing them but `$third-party` and request types, minus
  hosts an unrestricted `@@||host^` frees, parents only. That is 47,242
  hosts on the public lists, in `trackers.json`. Chrome takes them as one
  rule's `requestDomains`, and the rules cost no measurable paint time. The
  cookie rule matters for tracker requests that get through: a list
  exception, or the Trackers ruleset switched off.
- **Cookie cap:** `chrome.cookies.onChanged` re-sets a tracking cookie
  (`_ga`, `_ga_*`, `_gid`, `_gcl_*`, `_fbp`, `_fbc`, `_uetsid`, …) that
  would outlive 7 days, as Safari does for script-set cookies. This covers
  cookies set by the server and by page scripts alike. Host-only stays
  host-only, and partitioned stays partitioned. (Chrome caps every cookie at
  400 days anyway.)
- **WebRTC:** set while the feature is on, cleared when it is off. Chrome
  reverts it when the extension is disabled or removed. The popup says so
  when a policy or another extension controls it.
- **DNT** is not sent: it is a fingerprinting bit and widely ignored.

**Fingerprinting (`farble.js`, after Brave's "farbling").** It runs in the
page's main world at `document_start`, in every frame, and changes what
readback returns, deterministically:
- **Canvas:** `toDataURL`, `toBlob`, `getImageData`, and `OffscreenCanvas`
  `convertToBlob` / `getImageData`. About one pixel in sixteen that isn't
  fully transparent gets the low bit of one channel set from a keyed hash
  of its position in the canvas. A part read alone matches the whole.
  Setting (not flipping) the bit makes repeated reads, and read-write-read,
  stable. Blank canvases stay blank, so "is canvas blocked?" checks pass.
- **WebGL:** `readPixels` gets the same noise. The unmasked renderer
  string is bucketed to one common string per GPU maker and graphics API
  (`… Apple M1 …`, `… GeForce GTX 1650 …`, `… UHD Graphics 620 …`); software
  renderers pass through. WebGL is patched when the page first creates a
  WebGL context, or at the first idle moment after load. Building those
  interfaces eagerly cost every page about 1.4 ms.
- **Audio:** each channel of an `AudioBuffer` is noised once in place
  (about ±1e-7, below −120 dB), so `getChannelData` and `copyFromChannel`
  agree on every read. `AnalyserNode` float data is noised too.
- **Hardware:** `hardwareConcurrency` and `deviceMemory` are bucketed to 2,
  4 or 8. The user agent and platform are not touched.
- **Seed:** HMAC-SHA256(session key, registrable domain of the tab's
  top-level site), computed by the worker. The key is random per browser
  session, in `chrome.storage.session`, which content scripts can't read.
  Keying by the top-level site means a third-party fingerprinting frame
  gets a different seed on each site that embeds it.
- **Getting the seed into the main world**, which can't call extension
  APIs:
  1. `farble.js` dispatches a fresh random token in a DOM event.
  2. The isolated-world content script, listening since before any page
     script, takes it and asks the worker for the seed.
  3. The seed comes back in an event that carries the token. `farble.js`'s
     capture listener, registered first, stops that event before any page
     listener sees it.

  A page can't read the token or the seed. A forged event lacks the token
  and is left alone, so a page also can't tell anyone is listening.
  `READY` covers either injection order.
- **Until the seed arrives** (a few ms; longer if the worker was asleep),
  readbacks use a random per-load seed. Values are never the true ones,
  but a script that reads in the page's first inline script sees
  different values on each load.
- **Stealth:** the same approach as the scriptlet library (Proxies,
  `toString` masking, descriptors, scrubbed errors), checked by the
  testbed's stealth page.

**Residual, and out of an extension's reach:**
- A script that copies `readPixels` off the WebGL prototype before any
  WebGL context exists, and before the idle patch, can call the copy
  unnoised.
- Low-bit noise defeats common fingerprinting scripts, not an adversary
  who averages it out with repeated or redundant drawing.
- `<meta name="referrer">` and `referrerpolicy` attributes can still
  loosen the policy, since the rule rewrites only the response header.
  Same-site cross-origin requests are trimmed too (Chrome's default
  already does).
- The registrable domain uses the compiler's two-label suffix list, not
  the full Public Suffix List, so `a.github.io` and `b.github.io` share a
  seed.
- Content scripts don't run in workers: `navigator.hardwareConcurrency`
  in a Web Worker, and `OffscreenCanvas` drawn in a worker, are not covered.
- Not changed, by choice (spoofing makes a browser rarer) or out of reach:
  screen size, time zone, language, fonts (`measureText`, CSS), WebGPU
  adapter info, client hints, speech voices, media devices, the TLS and
  HTTP/2 fingerprint, the IP address, and behavior.
- `navigator.globalPrivacyControl` is a bound native getter: it prints
  `function () { [native code] }` where a native one would print
  `function get globalPrivacyControl() …`.

### Measured (M7, 2026-11-07, M1 Pro)

| | |
|---|---|
| testbed | 50 checks on the testbed build, 7 more on the public-list build |
| `farble.js` per page (evaluation) | 0.9 ms (2.0 ms before WebGL was made lazy) |
| `gpc.js` per page | 0.1 ms |
| M7 over M6, same-run A/B, 80 rounds | first contentful paint +0.6 ± 0.7 ms; DOMContentLoaded +3.5 ms |
| whole extension, first contentful paint, 0 / 40 ms latency | +12.6% ± 1.7% / +7.2% ± 0.8% |
| dynamic rules | 4 (two with 47,242 hosts each), no measurable paint cost |
| service worker | 3.6 MB JS heap + 7.6 MB wasm memory |
| extension size | 11.0 MB unpacked (`trackers.json` 1.2 MB) |

## Firefox (M8)

One codebase, two packages. `npm run build:firefox` writes `dist-firefox/`
from the same compiled output and the same JavaScript, with:

- **Its own manifest** (`build.mjs` `firefoxManifest`):
  - an event page (`background.scripts`, an ES module) instead of a service
    worker, which Firefox doesn't offer extensions;
  - the `dns`, `webRequest` and `webRequestBlocking` permissions;
  - `browser_specific_settings.gecko`: the ID `sinkd@nald0422.github.io`
    (a placeholder, permanent once published), `strict_min_version` 140
    (the current ESR; tested on 141), and `data_collection_permissions:
    none`, which AMO requires of new extensions.

  `use_dynamic_url` goes: Firefox addresses each install by its own random
  UUID, never by the add-on ID.
- **Rules Firefox can parse** (`firefoxRule`). Firefox drops a rule that
  names a resource type it doesn't know. 360 compiled rules list
  `webtransport` and `webbundle` (the compiler spells out every type for
  `$all` and negated types), most of them badware blocks. The Firefox build
  removes those two types. Firefox then holds all 20,133 rules; the e2e test
  checks the count.
- **uncloak.json**: the lists' hosts, for CNAME uncloaking (below).

The background script tells the browsers apart by its own URL scheme
(`moz-extension:`, `core.ts` `browserOf`):

| | Chrome | Firefox |
|---|---|---|
| background | service worker | event page: suspended after idling; webRequest wakes it, and Firefox holds the requests until it is up |
| toolbar count | DNR's action count | none: Firefox has no `setExtensionActionOptions` |
| cosmetic CSS target | `documentIds` | `frameIds`: Firefox has no document IDs |
| GPC, cookie and Referer header rules | DNR, every request | DNR for subresources; webRequest for navigations, whose headers Firefox's DNR doesn't modify |
| loose Referrer-Policy | DNR, with the `responseHeaders` condition | webRequest: Firefox's DNR has no response-header conditions |
| `navigator.globalPrivacyControl` | added | replaced when Firefox's own says false (on only in private windows, or if the user turned it on) |
| WebGL renderer | bucketed | Firefox's own coarse name ("Apple M1, or similar") passed through: a Chrome-style name would stand out |
| CNAME uncloaking | no way to do it | webRequest and `dns.resolve` |

**Found by porting:**
- `||142.91.159.` (the start of an address range) was parsed as the host
  `142.91.159.` and grouped into a rule's `requestDomains`. Chrome took it
  and never matched it; Firefox rejected the whole rule, 300 domains with
  it. A host can't have an empty label now, so such filters become URL
  filters in both builds (71 more rules).
- Firefox's DNR applies `modifyHeaders` to subresources only. Without the
  webRequest fallback there was no `Sec-GPC` on page loads, link clicks or
  frames, and tracker frames kept their cookies.
- Firefox's `testMatchOutcome` needs the `extensions.dnr.feedback` pref. It
  also reports a parameter-stripping redirect that has nothing to strip,
  which Chrome leaves out.

**CNAME uncloaking** (`core.ts` `uncloakCandidate`, `aliasBlocked`): the
`cname` feature, which switches off on its own and has a per-site
exception. Trackers hide behind a site's own subdomain (`metrics.site.com`
CNAME `site.com.sc.omtrdc.net`). DNR matches names, not DNS answers, so it
can't see them. Firefox's `dns.resolve(host, ["canonical_name"])` returns
the alias:
1. `webRequest.onBeforeRequest` runs, blocking, for every subresource and
   frame. When the host's alias is cached, the decision is synchronous; a
   lookup makes the request wait for it.
2. These are never looked up:
   - the page itself, as in uBlock Origin;
   - requests that don't come from a page;
   - IP addresses and single-label names;
   - proxied requests: looking them up would tell the local resolver what
     the proxy was meant to hide (uBO's `cnameUncloakProxied` default);
   - pages where the feature is off, the site is paused, or a `$document`
     exception turns blocking off;
   - hosts the lists name themselves, blocked or exempt. DNR has already
     decided those, and looking up a blocked host would send it to the
     resolver for nothing.
3. A request is blocked when its alias, or a parent of it, is a host an
   enabled ruleset blocks and doesn't exempt, on another site. An alias
   within the site (`www.site.com` → `site.com`) is not cloaking.
4. Aliases are cached for an hour, 4,096 hosts at most. Concurrent
   requests share one lookup in flight, and a failed lookup means "no
   alias".

- **Host sets** (`uncloak.json`, the compiler's `Hosts`), per ruleset:
  - `block`: the plain `||host^` blocks the tracker list is made of, from
    every ruleset (98.6k hosts on the public lists);
  - `exempt`: unrestricted `@@||host^` and `@@||host^$cname`;
  - `documents`: `@@||host^$document`.

  The event page builds one `Map` per kind, from host to a bit per ruleset,
  so a lookup costs one probe per label.
- **Limits:**
  - Firefox returns only the end of the alias chain, so a list that names
    an intermediate alias misses it, as with uBO.
  - A type-restricted rule (`||host^$image`) blocks every request type when
    reached through an alias.
  - The lookup adds a DNS round trip before the first request to each new
    host. The request needed the address anyway, and the system resolver
    caches it, so most of that is absorbed.

**Firefox's own protections**, which sinkd meets there:
- Total Cookie Protection partitions third-party cookies. Playwright's
  Firefox runs without it, so the testbed still sees them flow.
- Firefox trims cross-site referrers to the origin, whatever the page asks
  (`network.http.referer.disallowCrossSiteRelaxingDefault`).
- The WebGL renderer name is already coarse.
- GPC is built in, and on in private windows.

**Testing in Firefox** (`scripts/firefox.mjs`). Playwright loads extensions
into Chromium only, so the launcher:
1. starts Playwright's Firefox, in a throwaway profile, with its remote
   debugging server on 127.0.0.1;
2. installs the unpacked build as a temporary add-on, which is gone when
   the browser closes;
3. drives the background page and the parent process over that protocol.

The popup is loaded in a frame of the background page, because Playwright
can't open moz-extension pages in tabs. Firefox has no host-resolver
rules, so the testbed server doubles as its proxy. The CNAME names go
direct, so that Firefox looks them up, and the DNS override service
Firefox has for its own tests answers them, aliases included.

**Firefox gaps:**
- Firefox runs content scripts in a newly created `about:blank` frame a
  task late; Chrome runs them before the frame is handed back. A page that
  takes `fetch`, or any other built-in, from a fresh frame in the same task
  gets the browser's own. The testbed's fresh-iframe probe catches blocking
  that way. `Function.prototype.toString` taken from such a frame would
  also show patched functions as proxies.

  A fix means the scriptlet library patching same-origin child frames from
  the parent when a page reaches them (`contentWindow`). That is a rewrite
  of the library around a window parameter, and `window[0]` would still
  get past it.
- The toolbar button shows no count.
- The page engine takes about 130 ms to start in the event page, over the
  100 ms budget; the first page after the event page wakes waits for its
  cosmetic rules that long.
- Cosmetic CSS goes to a frame, not a document. If the frame navigates
  while the CSS is on its way, the new document gets the old one's rules.
- Untested: Firefox for Android, and versions before 141 (the manifest
  asks for 140).
- AMO wants the source of machine-generated code (the wasm engine, the
  compiled TypeScript) with a submission. `web-ext lint`, AMO's linter,
  isn't run: it is an npm package that isn't installed.

### Measured (M8, 2026-11-08, M1 Pro, Firefox 141 from Playwright)

| | |
|---|---|
| testbed, Firefox | 56 checks on the testbed build (the fresh-iframe probe reported as a known gap), 8 more on the public-list build |
| testbed, Chrome | 50 checks on the testbed build, 7 more on the public-list build |
| end-to-end | Chrome 9 fixture + 8 public-list checks; Firefox 9 + 9, which include "all 20,133 static rules loaded" and "all 222 regex rules accepted" |
| first contentful paint, Firefox, 0 / 40 ms latency, means of 99 | +7.6% ± 4.9% / +10.6% ± 2.2% (an earlier run: +7.2% ± 4.8% / +4.9% ± 2.2%). Firefox times paints by its refresh ticks, hence the spread. About 1 load in 100 reports no paint and is left out |
| first contentful paint, Chrome, the same run | +14.9% ± 1.6% / +7.1% ± 1.2% (M7: +12.6% ± 1.7% / +7.2% ± 0.8%): no change beyond noise |
| scriptlet files in Firefox | the every-page entity file p50 2.0 ms, the largest site file p50 3.0 ms (Chrome: 1.2 / 1.8 ms); Firefox's timer has 1 ms steps |
| CNAME uncloaking | 99,366 hosts (`uncloak.json`, 2.1 MB), loaded in 30 ms in the event page, 3.5 MiB as maps (measured in Node); the decision per request with a known alias, p99 0.009 ms (Node) |
| page engine in Firefox's event page | init 129 ms at start, alongside loading the host lists (Node 15 ms, Chrome's worker 21 ms): over the 100 ms budget there |
| Firefox's extension process | 123 MiB resident: the one process for all extensions, Firefox's own overhead included |
| packages | Chrome 11.0 MB unpacked, 3.0 MB zipped; Firefox 13.0 MB, 3.8 MB (`uncloak.json`) |
| compiled rules | 20,133: 71 more, now that address prefixes are URL filters; 360 rewritten for Firefox |

## The command line and the daemon's controls (M9)

### The control socket

`stats`, `pause`, `resume`, the bridge and `doctor` talk to the running
daemon over a Unix stream socket: one JSON request line in, one JSON
response line out.

- **Why a Unix socket, not a TCP port.** A web page can reach any port on
  localhost (DNS rebinding, `fetch` to `127.0.0.1`); it cannot reach a Unix
  socket, and nothing off the machine can either.
- **Who may do what.** The socket is mode 0666, so anyone may ask for the
  counters. Everything else needs root, the daemon's own user, or a uid in
  `control.users`: pausing, reloading, and reading the query log (which
  shows what every user on the machine looked up). The daemon learns the
  caller from the kernel (`SO_PEERCRED` / `getpeereid`, through tokio), and
  its own uid from the owner of the socket file it just created. No unsafe
  code is needed for either.
- **Where it lives.** `control.socket`, else `control.sock` in the cache
  directory. A stale socket from a daemon that died is replaced; one that
  still answers is an error; a path that is not a socket is never deleted.
  Paths over 103 bytes are refused with a clear message (macOS `sun_path`).
- **What happens if it fails.** The socket is not essential: if it can't
  be bound, the daemon warns and keeps answering DNS.

### Pause

`pause` is an atomic deadline the server reads on every query: one relaxed
load while blocking is on. While paused:

- listed names are forwarded, and answers are not uncloaked;
- special names are still answered locally, the Firefox canary included,
  so pausing doesn't send Firefox off to its own DoH.

A pause lives in memory, so a daemon that restarts comes back blocking. A
pause that began after a query was decided still stops that query's
uncloaking.

### Query log and metrics

The config types existed since M2; M9 implements them.

**The query log** is off by default, in memory only, and pruned by age
(`retention_hours`) and count (`max_entries`) on every write and read.
Switching it off in the config empties it at once. When it is off, the
cost is one atomic load per query. When it is on, it costs a mutex and two
small allocations per query; measured below.

**`/metrics`** is a tiny HTTP/1.1 responder, not a framework. It reads one
request head (8 KiB, 5 s), answers `GET /metrics`, and closes the
connection. Config validation already refuses a non-loopback address, and
the server also drops non-loopback peers. It exposes counters and gauges
only, never names.

### `sinkd check`

`check` reads what is on disk and nothing else: the resolver's config and
its cached lists, and the extension's lists from the compile cache.

- **Resolver:** the `DomainMatcher` verdict, with the entry that decided
  it, and whether that entry is local.
- **Extension, network:** `compiler::explain` evaluates the *source* rules
  with adblock precedence: `$important` blocks, then a `$document`
  exception on the page, then exceptions, then blocks (with the best
  `$redirect`). So it names the filter and the list line, not an anonymous
  DNR rule id. Each deciding rule then goes through the DNR translation,
  which says whether the extension applies it, applies it narrowed, or
  can't (a `$popup` rule, an IPv6 `$domain`).
  - Wildcard patterns use an iterative glob matcher, with a literal-piece
    prefilter that rejects almost every rule cheaply. Regex rules compile
    lazily with a 1 MiB size limit.
  - Untyped `$removeparam` rules act on navigations, and `$csp` and
    `$permissions` rules on documents, as the translation has them.
- **Extension, page:** for a page, it compiles everything (about 0.7 s)
  and asks the page index what Chrome would apply: site-specific
  selectors, procedural rules, whether generic hiding is on, and the
  scriptlet calls (`PageOutput::calls_for`, which mirrors the scriptlet
  files' own lookup).

Sites (for `$third-party`) use the extension's short list of two-label
public suffixes, not the full Public Suffix List.

### `allow` and `block`

They edit the config's `allow` / `block` arrays with `toml_edit`, so
comments and layout survive. The whole edited file is checked with
`Config::from_toml` before anything is written, then replaced atomically
(write a sibling, keep the permissions, rename). The daemon applies edits
within seconds by itself; when it is running, the CLI also asks it to
reload at once. Entries are normalized (lower case, punycode, `*.` for
subdomains only) before they are compared, so `Ads.Example.` and
`ads.example` are the same entry.

## Install and uninstall (M9)

**Order:**

- *Install:* the service first. Only once it answers on 127.0.0.1:53
  (`localhost.` A, which needs no upstream) does install save the DNS
  settings and change them. A service that doesn't come up is stopped
  again, and the DNS settings are left alone.
- *Uninstall:* the DNS settings first, so the machine keeps working even
  if a later step fails. Then the service, the files, the user.

**Exact restoration.** Install saves the settings it found
(`dns-backup.json`) and keeps the first backup across reinstalls, so a
reinstall never saves sinkd's own settings as "the original". Uninstall
puts back exactly what was saved, and only where the setting still points
at sinkd. A setting the user changed since install is left alone and
reported. Next to the backup, install writes `restore-dns.sh`: the same
restoration as plain commands, for the README's one-line recovery when the
binary itself is gone.

### macOS

- **DNS.** `networksetup` sets each network service's servers, disabled
  services included, since one enabled later should use sinkd too.
  "There aren't any DNS Servers set" is saved as an empty list and restored
  as `Empty`, which hands the choice back to DHCP or the VPN. The caches
  are flushed (`dscacheutil -flushcache`, then HUP to mDNSResponder).
- **The service.** A launchd daemon (`/Library/LaunchDaemons/
  io.github.nald0422.sinkd.plist`, `KeepAlive`, `ThrottleInterval` 5) runs
  `sinkd run --user _sinkd`.
- **Privilege separation.** Binding 127.0.0.1:53 needs root on macOS: a
  test bind as uid 501 got EACCES. Only the wildcard address is exempt,
  and binding that would expose the port to the network. So the root
  parent binds the sockets, clears their close-on-exec flag, and starts
  `sinkd run --inherited udp=N,tcp=M` as `_sinkd`. `Command::uid`
  drops the supplementary groups too (it calls `setgroups(0)`).
  - The child takes the sockets over by opening `/dev/fd/N`, which
    duplicates the descriptor with no unsafe code, then checks that each
    one is the expected kind of socket.
  - The parent never reads a packet. It passes TERM, INT and HUP on and
    exits with the child's status.
  - launchd's own socket activation would avoid the root parent, but
    getting the descriptors from it needs an FFI call, and the crates
    have `#![forbid(unsafe_code)]`.
- **The user.** `_sinkd` and its group get the first id free for both
  in 200–400 (below 500, so it stays out of the login window), with no
  shell and no home. Uninstall deletes them.
- **Logs.** `/Library/Logs/sinkd.log`. Without per-query logging that
  is a few lines a day, so there is no rotation.

### Linux (systemd)

- **The service.** A unit with `DynamicUser=yes`: an unprivileged per-boot
  user, given `CAP_NET_BIND_SERVICE` and nothing else. The sandbox:
  - `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`;
  - `RestrictAddressFamilies` (inet, inet6, unix);
  - `MemoryDenyWriteExecute`, `NoNewPrivileges`;
  - a `@system-service` syscall allowlist without `@privileged`;
  - a filtered call fails with EPERM rather than killing the daemon.
- **Readiness and the watchdog.** `Type=notify` makes `systemctl start`
  return only once the sockets are bound. `WatchdogSec=30` restarts a
  daemon whose self-test (a local `localhost.` query through the engine
  in force) stops passing.
- **DNS**, chosen by what `/etc/resolv.conf` is:
  - *systemd-resolved's stub:* a drop-in sets `DNS=127.0.0.1 ::1` and
    `Domains=~.`. A global `~.` routing domain outranks the per-link
    servers from DHCP, so every name goes to sinkd. Uninstall deletes
    the drop-in.
  - *a plain file:* saved byte for byte and replaced; uninstall writes
    the saved bytes back if the file is still sinkd's.
  - *a link to anything else* (NetworkManager, say): left alone, with
    instructions, since whatever owns it would undo the change. The
    service is installed and running either way.

### What has been run

| What | Where |
|---|---|
| Install and uninstall logic, against a scripted fake system (the order of steps, exact restore, reinstall, a failed start, changed settings, the Linux variants) | unit tests |
| The dry run on this Mac, which runs only read-only commands: `networksetup -get…`, `dscl -read`, `launchctl print` | here |
| A real install and uninstall on a GitHub Linux runner | in CI, but not run yet: it runs on the first push |
| A real install on macOS | not run: it needs sudo and changes your DNS, so it is your call |

## The browser bridge (M9)

`sinkd bridge install` registers a native-messaging host (`sinkd.
bridge`) with every installed browser, for the current user:

- a manifest per browser;
- a launcher script, because a host can't be given arguments and the host
  needs the config path.

The extension connects once the user grants the optional `nativeMessaging`
permission from the popup.

- **One way.** The host sends the local allowlist, the local blocklist and
  the pause (from the daemon's status, which anyone may read). It sends
  them on connect, then again whenever they change; it checks every 2 s,
  which costs a `stat`, a small config read and one control request. The
  only message it accepts is "send it again". A compromised extension can
  read the local lists through it, but can't change them or pause the
  machine.
- **Sizes are capped:**
  - 64 KiB in;
  - under Chrome's 1 MiB out;
  - 5,000 entries per list, since dynamic rules are a shared quota.
- **Untrusted on both ends.** The extension parses each message field by
  field, keeps only well-formed names and drops anything else.

| From the resolver | In the extension |
|---|---|
| `allow` | A dynamic `allow` rule at the user priority (1000) for every request type, so a list's block can't beat it. It also stops CNAME uncloaking in Firefox. |
| `block` | A dynamic `block` rule at 999: under the allowlist and the per-site pause, which win as they do in the resolver; over every compiled rule, so a list's `@@` can't undo it. |
| `*.example.com` | One regex rule each, since `requestDomains` always covers the name itself; at most 200, from the shared regex quota. |
| pause | `pausedAll`: an `allowAllRequests` rule for every page and frame, no page scripts registered, the privacy features off. It is never stored, and it ends when the connection drops, so a crashed host can't leave blocking off. |

While the port is open, Chrome keeps the service worker running. That is
the price of `pause` taking effect at once. Without the bridge, nothing
changes.

**How it's tested.** `extension/e2e/bridge.mjs` runs the whole chain,
scratch only: a resolver on a free port, the host registered in the test
profile only, and `HOME` pointed at a temporary directory.

- Chromium reads hosts from its user-data directory.
- Firefox on macOS ignores `$HOME` for host manifests. In the test
  Firefox only, the harness points its manifest lookup at the scratch
  directory from the parent process.
- The test build declares `nativeMessaging` as required, because
  automation can't click a permission prompt.

## Hardening (M9)

| Where | What |
|---|---|
| Daemon, macOS | Never parses a packet as root: privilege separation (above). |
| Daemon, Linux | Never root at all; the systemd sandbox (above). |
| Daemon | A root service refuses a config, or config directory, that other users can write: whoever edits it chooses where every lookup goes. In the foreground it warns, and `doctor` reports it. |
| Daemon | The hang guard: a plain thread aborts the process when the async runtime hasn't ticked for 60 s, and the service manager restarts it. A hung resolver takes the machine's DNS with it. |
| Daemon | Every input has a cap and a deadline: UDP 4 KiB; TCP 10 s per message; control requests 4 KiB in 5 s, 16 at once; metrics heads 8 KiB in 5 s, 8 at once; lists 64 MiB. |
| Daemon | Only the control socket's peer credentials decide who may pause. |
| Extension | CSP for its pages: `script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; form-action 'none'`. |
| Extension | Messages from content scripts can only ask for their own frame's rules (M6). Bridge messages are validated field by field. |
| Everywhere | `#![forbid(unsafe_code)]` in every crate; CI builds with `--locked`; `cargo-deny` checks advisories, licenses and sources. |
| Everywhere | Fuzzing, below. |

## Fuzzing (M9)

Ten targets in `fuzz/`, in cargo-fuzz's layout:

| Target | What it checks |
|---|---|
| `filter_line` | One line through the parser and the DNR or CSS translation. |
| `filter_list` | A whole list through the preprocessor and the parser, for Chromium and DNS. |
| `compile` | The compiler. Every emitted DNR rule must pass the compiler's own model of Chrome's checks and serialize, and the page index must survive a round trip. |
| `explain` | `check`'s matcher, on arbitrary rules. |
| `dns_list` | DNS lists into the matcher. |
| `dns_query` | The engine on client bytes, UDP and TCP, blocking on and off. Every local reply must parse, carry the query's id and fit a UDP payload. |
| `dns_answer` | Upstream answers through uncloaking, the reply and the cache. |
| `config` | Config loading; a config that loads must survive being written out and read back. |
| `domain` | Normalization is idempotent. |
| `metrics_request` | The metrics endpoint's request parser. |

**On stable Rust.** cargo-fuzz itself needs nightly, but libFuzzer doesn't.
`fuzz/run.sh` builds the targets with the same coverage instrumentation,
using stable `-C` flags, and an explicit `--target` keeps those flags off
build scripts. It skips AddressSanitizer, which matters little for code
with no `unsafe`. `cargo fuzz run` still works for anyone on nightly.

Seeds come only from the project's own lists and configs, never from the
public lists, whose licenses would follow the files. The corpus and any
crashes stay out of git.

**First run:** five minutes per target, ten at once on 8 cores. About 41
million runs, and no crash in sinkd's code.

The one crash was in a target: its assertion was wrong. libFuzzer gives a
`&str` target the valid-UTF-8 start of its input, here `a.a..`, and
`QueryName::new` strips exactly one trailing dot by design (names off the
wire never end in two). The assertion now states the documented behavior,
and a further two minutes on that target found nothing.

| Target | Runs | Runs per second | Coverage (edges) |
|---|---:|---:|---:|
| `filter_line` | 5,503,109 | 18,282 | 5,241 |
| `filter_list` | 2,864,335 | 9,516 | 2,244 |
| `compile` | 291,168 | 967 | 6,544 |
| `explain` | 655,292 | 2,177 | 8,613 |
| `dns_list` | 4,967,861 | 16,504 | 3,029 |
| `dns_query` | 4,557,302 | 15,140 | 2,340 |
| `dns_answer` | 4,804,638 | 15,962 | 3,468 |
| `config` | 6,132,398 | 20,373 | 4,081 |
| `domain` (after the fix, alone) | 1,820,325 | 15,044 | 1,308 |
| `metrics_request` | 9,360,265 | 31,097 | 51 |

CI runs every target for 30 s on each push.

### Measured (M9, 2026-11-09, M1 Pro)

| | |
|---|---|
| Resolver, cached queries, query log off / on (`loadgen`, 64 clients) | 93,400 / 89,400 q/s, p99 1.1 ms both |
| Resolver, blocked queries, query log off / on | 90,500 / 89,800 q/s |
| `sinkd check <name>` (release) | 0.38 s, 110 MB peak |
| `sinkd check <page>` (release; compiles every list) | 1.29 s, 270 MB peak |
| A `sinkd block add`, until the rule is in the browser (bridge) | 2.06–2.08 s, Chromium and Firefox |
| The native host | 5.8 MiB resident, 0% CPU idle; exits within 1 ms of the browser hanging up |
| Release binary | 15.2 MB, line tables included |
| Fuzzing | about 41 million runs, no crash in sinkd's code (above) |

## Known gaps

- `$uritransform` is reported unsupported (DNR `regexSubstitution` could do a
  subset later).
- Procedural argument parsing does not understand unbalanced parentheses
  inside regex character classes (`/[(]/`). Such rules are rejected, not
  misapplied.
- **A rejected exception broadens blocking.** Dropping `@@…$popunder`, or
  `site.com/path#@#.x`, leaves the rule it carved out applying everywhere. The
  compiler (M5) must drop or narrow the block rules that a rejected exception
  would have matched, starting with identical cosmetic selectors. The DNS
  builder has the same issue with page-scoped `@@` rules, which DNS cannot
  apply at all.
- **M9:**
  - A real install has not run on macOS here: it needs sudo and changes
    the DNS settings. The Linux install runs for real only in CI, which
    hasn't run yet.
  - New network services and VPNs. A network service added after install
    uses DHCP's servers until `sudo sinkd install` runs again; `doctor`
    lists the ones not using sinkd. A VPN that sets its own DNS wins,
    by design.
  - `control.users` takes numeric ids. The installer writes the invoking
    user's (`SUDO_UID`).
  - Linux without systemd: no installer. `sinkd run` works under any
    init system.
  - The bridge keeps Chrome's service worker running while it is
    connected (see above). It checks for changes every 2 s rather than
    being told, so an edit reaches the browser in about 2 s.
  - The bridge's `*.example.com` entries need a regex rule each (at most
    200).
  - `check` uses the short public-suffix list, so `$third-party` can be
    wrong for hosts under `github.io`-style suffixes. It explains the
    source rules, not the merged DNR rules: a rule that is valid but lost
    to a quota would still show as applied.
  - The Firefox add-on ID and the bridge's host name are placeholders
    until the stores are chosen (see the open questions).
- **Firefox, M8:** the gaps listed under Firefox above.
- **Privacy features, M7:** the residual items above, plus:
  - No link-wrapper unwrapping yet (`$urlskip`, 242 rules): it needs URL
    decoding, which DNR can't do.
  - The cookie cap needs the worker to wake on each cookie change; a
    burst of cookie writes wakes it once.
- **Page target, M6:**
  - First contentful paint on the zero-latency bench page is about +12%
    (+7% with 40 ms latency), over the 5% budget. Most of it is Chrome
    matching URLs against ~22k registered scriptlet patterns and running
    the entity file. Registering scriptlets only for sites the user visits
    would remove it but miss the first visit; that is a decision for you.
  - Scriptlet updates without a release need `userScripts` (above).
  - Not bundled: `trusted-*` scriptlets (396 rules; they can write arbitrary
    values, which needs a policy), `rpnt` / `replace-node-text` (245),
    `noeval-if` (148), `set-cookie` (51), `json-prune-fetch-response` (49).
    Scriptlet coverage: about 89% of scriptlet rules.
  - `##^` HTML filtering (154 rules) has no MV3 equivalent.
  - Page exceptions with a path or wildcard (`@@||site.com/path$elemhide`,
    172 rules) are reported, not applied.
  - `:matches-prop()` sees only the DOM's own properties: expandos set by
    page scripts live in the page's world, not the content script's.
  - On a paused site, scriptlets still run in third-party frames (match
    patterns see the frame's URL, not the tab's). Cosmetic rules respect the
    tab.
  - Generic hiding lands after the worker round trip, so a generically
    hidden ad can show for a frame or two.
- **Compiler and extension, M5:**
  - `$popup`, `$redirect-rule`, `example.*` domains and `$urlskip` are not
    translated (see the table above). `$genericblock` and `$header` are
    neither.
  - A `@@` exception also cancels parameter stripping and header edits on
    its URLs. An exception for one named parameter spares them all on those
    URLs. DNR has no per-action exceptions.
  - Two site-specific parameter rules that match the same request still
    compete for the one redirect.
  - The regex estimate drops some regexes Chrome would accept (about 16% of
    them).
  - No `google-ima.js` surrogate yet (207 rules wait on it).
  - The per-site switch is all-or-nothing.
- **Resolver, M4:**
  - Encrypted DNS hides queries from the network, not from the upstream.
    Quad9 (or whoever is configured) still sees every name that is neither
    blocked nor cached.
  - No DNSSEC validation. DO, CD and AD pass through, and the upstream's AD
    is trusted (and given only to clients that ask).
  - No coalescing of identical in-flight queries: a burst of the same
    uncached name sends one upstream query per client query.
  - NXDOMAIN is cached per (name, type), not for the whole name and the
    names below it (RFC 8020).
  - The cache lives in memory and is empty after a restart.
  - A stale answer stands in only when every upstream fails, not when they
    are merely slow (RFC 8767's 1.8 s client-response timer).
  - reqwest drops an idle HTTP/2 connection after 90 s. On a quiet machine
    the next query pays a new handshake (~150 ms).
  - `bootstrap` addresses are static. If the provider renumbers, the config
    must be edited.
  - The plain-UDP upstream remains spoofable off-path by ID-plus-port
    guessing. It is an option, not the default.
- **Lists and reload, M3:**
  - The default cache directory is per-user. A daemon running as root or as
    a service user needs `updates.cache_dir` set; the installer writes it.
  - The collapse guard holds a list that legitimately shrank by more than
    90% until someone runs `sinkd update --force`. It is logged as a
    warning on every check.
  - `Cache-Control: max-age` is not consulted; the list's `Expires` header
    and the config decide.
  - Lists are trusted on HTTPS alone. List authors do not sign their lists,
    so there is nothing else to check.
  - The cache is never pruned: files of removed lists, or includes a list
    stopped using, stay until deleted by hand.
  - A change to `listen.addrs` needs a restart.
  - macOS system proxy settings are not read (environment proxies are).
