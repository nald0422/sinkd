# Store listings

Text to paste into the Chrome Web Store and addons.mozilla.org (AMO).

## Shared

- **Name:** sinkd
- **Homepage:** https://github.com/nald0422/sinkd
- **Support:** https://github.com/nald0422/sinkd/issues
- **Privacy policy:** https://github.com/nald0422/sinkd/blob/main/docs/privacy.md
- **Category:** Privacy & Security (AMO); Privacy & Security, or
  Productivity → Tools if offered (Chrome)

**Summary** (Chrome allows 132 characters, AMO 250):

> Blocks ads and trackers, strips tracking parameters and cookies, adds fingerprinting protection. No remote code, no data collected.

**Description:**

> sinkd blocks ads and trackers with rules compiled from the community filter lists (EasyList, EasyPrivacy, uBlock Origin's lists), and protects your privacy beyond blocking:
>
> • Blocks ads, trackers and known malware sites, and serves harmless stand-ins for the ad and analytics scripts pages depend on, so sites keep working.
> • Closes the ad and scam tabs that pages open on their own.
> • Hides leftover ad elements, and neutralizes ad-blocker detectors without leaving traces a page could notice.
> • Removes tracking parameters (utm_*, fbclid, gclid…) from links.
> • Strips cookies and the referrer from requests to trackers, and caps analytics cookies at a week.
> • Sends Global Privacy Control, a legally meaningful opt-out in several US states.
> • Keeps WebRTC from revealing your local IP address.
> • Adds slight, consistent noise to canvas, WebGL and audio readback, so fingerprints can't link your visits across sites or browser sessions. It never changes your user agent: blending in beats standing out.
> • In Firefox, also blocks trackers hidden behind a site's own subdomain (CNAME uncloaking).
> • In Chrome, a live log in the popup shows what sinkd does on the page as it happens: what it blocks, replaces and cleans, and which headers it changes. It adds up to the count on the toolbar icon.
>
> Every protection can be switched off on its own, everywhere or for one site.
>
> What it can't do, honestly: hide your IP address (use a VPN or Tor), stop tracking by sites you are logged in to, or stop server-side tracking.
>
> Optional: with the sinkd program installed on your computer, the same blocking applies to every app (it is a local DNS resolver), and its allowlist, blocklist and pause reach the browser too.
>
> No account, no analytics, no remote code. Everything runs on your device. Open source: https://github.com/nald0422/sinkd

## Chrome Web Store

**Single purpose:**

> Block ads and trackers on web pages and reduce cross-site tracking.

**Permission justifications:**

| Permission | Why |
|---|---|
| `declarativeNetRequest` | Blocks ad and tracker requests, redirects ad scripts to bundled harmless stand-ins, removes tracking parameters and strips cookies and the referrer from tracker requests, all through Chrome's own rule engine. |
| Host permission `<all_urls>` | Ads and trackers appear on every site. It is needed to hide ad elements and run the filter lists' page fixes on any page, and for the header rules to apply there. |
| `scripting` | Registers the bundled page scripts that neutralize ad-blocker detectors and add fingerprinting noise, and inserts the hiding styles for each page. All scripts are packaged with the extension. |
| `cookies` | Shortens the lifetime of known analytics cookies (`_ga`, `_fbp`…). |
| `privacy` | Sets WebRTC to use only the public network interface, so pages can't learn the local IP address. |
| `storage` | Keeps the user's settings on the device. |
| `activeTab` | Lets the popup's log read which of sinkd's rules acted in the tab it was opened on (declarativeNetRequest.getMatchedRules), so the log adds up to the toolbar count. Chrome grants it only when the user opens the popup, for that tab alone. Nothing is stored or sent. |
| `webRequest` | Keeps the popup's log live: while the popup is open, it observes the requests of the tab it was opened on, to show each block, stand-in, cleaned link and header change as it happens. It only observes (no blocking), stops when the popup closes, and stores and sends nothing. The background script doesn't use it in Chrome. |
| `nativeMessaging` (optional, off until the user allows it) | Receives the allowlist, blocklist and pause state from the sinkd program on the user's own computer. The extension sends it nothing but a request for that state. |

**Remote code:** No. All JavaScript and WebAssembly is in the package.

**Data usage:** collects none of the listed data types. Certify: data is
not sold, not used for purposes unrelated to the single purpose, and not
used for creditworthiness or lending.

## addons.mozilla.org

- **Add-on ID:** `sinkd@nald0422.github.io` (in the manifest).
- **License:** the package holds two licenses, so pick **Custom** and
  paste:

  > sinkd's own code is licensed MIT OR Apache-2.0. The blocking rules are
  > compiled from EasyList, EasyPrivacy and uBlock Origin's filter lists
  > and are distributed under the GNU GPL, version 3. NOTICES.txt in the
  > package says which files are which; the full texts are in licenses/.
  > Source: https://github.com/nald0422/sinkd
- **Source code:** upload `sinkd-source-<version>.zip`. The package
  contains generated files (compiled TypeScript, WebAssembly, rules).

**Notes to reviewer:**

> The generated files are rebuilt from the attached source with `npm ci` and `npm run build:firefox -- --cache build/list-cache --offline` in `extension/`; extension/BUILDING.md lists the tools (Rust 1.95.0 with the wasm32 target, Node 20.19) and what each file is made from. Nothing is minified. The filter lists the rules were compiled from are included in the source at `extension/build/list-cache/`; the extension downloads nothing.
>
> Permissions: `dns` is for CNAME uncloaking: a request to a site's own subdomain that is a DNS alias of a listed tracker is cancelled. `webRequest` and `webRequestBlocking` do that cancelling, and apply the Global Privacy Control, referrer and tracker-cookie header rules to page loads, which Firefox's declarativeNetRequest doesn't modify. `nativeMessaging` is optional and connects only to the sinkd program on the user's computer, if the user installs it and allows the permission.
