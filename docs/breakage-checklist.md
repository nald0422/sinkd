# Manual breakage checklist

CI only ever loads the local testbed. Real sites change every day, so
before a release, or after a change to the rulesets, the scriptlets or the
privacy features, check these by hand. Use a normal browser profile with
the extension loaded and the resolver installed. Sign in where the flow
needs it.

For each row, do the flow with everything on. If it breaks:

1. Pause the site from the popup and try again. If that fixes it,
   sinkhole is the cause.
2. Narrow it down: switch off one privacy feature for the site, then one
   ruleset everywhere, until the flow works.
3. For a request, `sinkhole check <url> --from <page> --type <type>` names
   the rule.
4. Record the site, the flow, the browser and what fixed it.

Do the same with the extension alone, then with the resolver alone
(`sinkhole pause` stops the resolver; removing the extension stops the
rest).

| Area | Flows to try | Watch for |
|---|---|---|
| **Login** | Sign in with a password, with "Sign in with Google / Apple / Microsoft", and with a passkey. Two-factor by SMS, app and email link. Log out. | Login pop-ups that close without signing in; SSO redirects that loop; a missing CAPTCHA (see below); cookies the sign-in needs that the cookie cap shortened. |
| **Checkout** | Add to cart, change quantity, apply a coupon, pay on the shop's own form and through PayPal or Klarna. | Address autocomplete; the payment iframe; "accept terms" boxes behind a hidden element; Referer-checking payment gateways (the referrer trim). |
| **Payments** | Stripe- and Adyen-hosted card fields; 3-D Secure challenge; Apple Pay or Google Pay buttons; a bank's own transfer page. | 3-D Secure iframes that stay blank; fraud scripts the lists block (the payment may still work, but must not hang). |
| **Video** | YouTube (with and without being signed in), Twitch, Vimeo, a news site's embedded player, a streaming service with DRM. | Players that never start; ads skipped by a scriptlet that breaks playback; captions; picture-in-picture. |
| **Maps** | Google Maps search, directions and Street View; an embedded map on a store locator; OpenStreetMap. | Grey tiles (the canvas noise must not show); the location prompt; "use precise location". |
| **CAPTCHA** | reCAPTCHA v2 checkbox and v3 (invisible), hCaptcha, Cloudflare Turnstile. | Endless challenges. Fingerprint noise can raise a risk score. Note how many rounds it took with sinkhole on and off. |
| **Forms and uploads** | A contact form, a file upload, a support chat widget. | Chat widgets are often on tracker lists; uploads behind a blocked CDN. |
| **Email and documents** | Gmail and Outlook on the web; opening an attachment; Google Docs and Microsoft 365 editing. | Links in mail go through link wrappers (not unwrapped yet); tracking-parameter stripping on signed links. |
| **Social and news** | Logged-in feeds, embedded posts on a news site, a paywalled article you have access to. | Comment sections; consent banners that reappear on every visit. |
| **Video calls and WebRTC** | A Meet, Zoom (web) or Teams (web) call with camera and screen share. | The WebRTC policy (public interface only) can force a TURN relay; calls should still connect. |

## Fingerprinting and tracking, by hand

[Cover Your Tracks](https://coveryourtracks.eff.org/), from the EFF, tests
what a site can learn:

1. Run it with the extension off, then on.
2. With the extension on, expect:
   - "Is your browser blocking tracking ads?" and "invisible trackers?" →
     yes;
   - canvas and WebGL fingerprints marked "randomized";
   - "Does your browser unmask you with fingerprinting?" → "your browser
     has a randomized fingerprint".
3. Run it twice in one session: the canvas hash stays the same. Restart
   the browser and run it again: the hash changes.
4. It will still report a unique fingerprint from things sinkhole leaves
   alone on purpose: the user agent, the screen size, the time zone and
   the fonts. Spoofing those would make you stand out more, not less.

The resolver alone (no extension) blocks the tracker domains but changes
nothing a page can measure, so the fingerprint result is the same as
without sinkhole.

## The resolver, by hand

- `sinkhole doctor` reports everything OK.
- `sinkhole check doubleclick.net` reports it blocked; `dig doubleclick.net`
  answers `0.0.0.0`.
- Switch Wi-Fi networks, sleep and wake the machine, connect and
  disconnect a VPN: lookups keep working, and `sinkhole doctor` says
  whether the VPN took DNS over (many do, by design).
- `sudo sinkhole uninstall` leaves `networksetup -getdnsservers Wi-Fi` (or
  `resolvectl status`) exactly as it was before install.
