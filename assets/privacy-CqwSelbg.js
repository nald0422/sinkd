import{c as e}from"./src-D1Pu5bm0.js";import{t}from"./Page-D7FddT_Y.js";var n=`# Privacy policy

*sinkd, version 0.1. Last updated 2026-11-13.*

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
- **New tabs.** When a page opens a tab, the extension compares that
  tab's address with the filter lists it ships with, and closes the tab if
  they block it. This happens on your device and goes nowhere.
- **The log** (Chrome). When you open the popup's Log tab, it asks Chrome
  which of sinkd's rules acted in that tab, and reads the hostnames the page loaded
  from, to say which ones a rule over a list of sites acted on. While the
  popup stays open, it watches that tab's requests (their addresses and
  headers) to show what sinkd does to each as it happens. It shows this in
  the popup and keeps nothing once the popup closes.
- **Network.** The extension makes no network requests of its own. It
  updates only when the store updates it.
- **Cookies.** It removes cookies from requests to known trackers, and
  shortens the lifetime of known analytics cookies (\`_ga\`, \`_fbp\` and the
  like) by setting them again with an earlier expiry. It changes nothing
  else about them and keeps no copy.
- **The browser bridge** (optional; off until you allow it) talks only to
  the sinkd program on your own computer, through the browser's native
  messaging. It never contacts anything else.

## The resolver (the \`sinkd\` program)

When you install it, sinkd becomes your computer's DNS resolver:

- **DNS queries** for names it doesn't block go to the upstream
  resolvers in its config, encrypted (by default Quad9, then Cloudflare,
  over DNS-over-HTTPS). Those providers see the names you look up, as
  your normal DNS provider would; their privacy policies apply. You can
  change them in the config.
- **Filter lists** are downloaded from their publishers (EasyList, uBlock
  Origin, OISD, AdGuard), as configured, about once a day.
- **The query log** is off by default. If you turn it on, it is kept in
  memory on your computer only, for at most the time you set, and is
  never written to disk or sent anywhere.
- **Metrics** are off by default, and when on are served only to your own
  computer (127.0.0.1) and hold counts, never names.

## Contact

Questions: email <bill22.db@gmail.com>, or open an issue at
<https://github.com/nald0422/sinkd/issues>. The support page,
<https://nald0422.github.io/sinkd/support.html>, has fixes for common
problems. We see only what you choose to send.
`,r=e(),i=`underline underline-offset-2 break-words`;function a(e){let t=[],n=/\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|<((?:https?:\/\/|[^\s@<>]+@)[^\s<>]+)>/g,o=0;for(let s of e.matchAll(n)){let n=s.index??0;n>o&&t.push(e.slice(o,n));let c=`${n}`;if(s[1]!==void 0)t.push((0,r.jsx)(`strong`,{children:a(s[1])},c));else if(s[2]!==void 0)t.push((0,r.jsx)(`em`,{children:a(s[2])},c));else if(s[3]!==void 0)t.push((0,r.jsx)(`code`,{className:`rounded bg-snow px-1.5 py-0.5 font-mono text-[0.9em]`,children:s[3]},c));else if(s[4]!==void 0){let e=s[4].includes(`@`)&&!s[4].includes(`://`)?`mailto:${s[4]}`:s[4];t.push((0,r.jsx)(`a`,{href:e,className:i,children:s[4]},c))}o=n+s[0].length}return o<e.length&&t.push(e.slice(o)),t}function o(e){return e.trim().split(/\n\s*\n/).map((e,t)=>{let n=`b${t}`,i=e.trim();if(i.startsWith(`## `))return(0,r.jsx)(`h2`,{className:`mt-12 text-xl font-medium tracking-tight md:text-2xl`,children:a(i.slice(3))},n);if(i.startsWith(`# `))return(0,r.jsx)(`h1`,{className:`text-[2rem] font-medium leading-[1.12] tracking-tight md:text-5xl md:leading-tight`,children:a(i.slice(2))},n);if(i.startsWith(`- `)){let e=i.split(/\n(?=- )/).map(e=>e.slice(2).replace(/\s*\n\s*/g,` `));return(0,r.jsx)(`ul`,{className:`mt-5 space-y-3`,children:e.map(e=>(0,r.jsxs)(`li`,{className:`flex gap-3 leading-relaxed text-carbon`,children:[(0,r.jsx)(`span`,{"aria-hidden":!0,className:`mt-2.5 inline-block size-1.5 shrink-0 rounded-full bg-ink`}),(0,r.jsx)(`span`,{children:a(e)})]},e))},n)}let o=i.replace(/\s*\n\s*/g,` `);return/^\*[^*].*\*$/.test(o)?(0,r.jsx)(`p`,{className:`mt-3 text-sm text-smoke`,children:o.slice(1,-1)},n):(0,r.jsx)(`p`,{className:`mt-5 leading-relaxed text-carbon`,children:a(o)},n)})}t((0,r.jsxs)(`article`,{children:[(0,r.jsx)(`div`,{className:`mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-smoke md:text-xs`,children:`Privacy`}),o(n)]}));