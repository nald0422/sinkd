# Surrogates

Stand-ins served, through declarativeNetRequest redirects, in place of
blocked ad and analytics resources. The scripts expose the API a page expects
(`googletag.cmd.push`, `adsbygoogle.push`, `ga()`, `gtag()` callbacks, …) and
do nothing, so pages that wait on them keep working and checks for the
global pass.

All of them are original implementations for sinkd, licensed MIT OR
Apache-2.0 like the rest of the project. None is derived from uBlock Origin's
or AdGuard's (GPLv3) resources; only the *names* match uBO's, so community
lists' `$redirect=` rules select them unchanged.

The files carry no comments: a page can fetch a web-accessible resource and
read it, so nothing in them names the extension.

`noop-1s.mp4` is one black 64×64 H.264 frame shown for one second, with no
audio track. The frame was encoded with macOS's AVFoundation and wrapped in
a minimal MP4 container written by hand: no edit list, no encoder SEI, no
metadata.
