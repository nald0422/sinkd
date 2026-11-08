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
