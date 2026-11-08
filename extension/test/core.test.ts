import assert from "node:assert/strict";
import { test } from "node:test";

import {
  aliasBlocked,
  BRIDGE_BLOCK_PRIORITY,
  BRIDGE_MAX_REGEX,
  BRIDGE_REGEX_FIRST,
  type Bridge,
  bridgeAllows,
  bridgePaused,
  bridgeRules,
  browserOf,
  COOKIE_CAP_SECONDS,
  cappedCookie,
  cssTarget,
  effectiveSettings,
  exemptSites,
  featureActive,
  featureScripts,
  featuresFor,
  frameHost,
  framePaused,
  GPC_RULE_ID,
  HostSets,
  hostAndParents,
  isPaused,
  isTrackingCookie,
  MAX_TOKENS_PER_MESSAGE,
  type Navigation,
  NO_BRIDGE,
  navigationRequestHeaders,
  navigationResponseHeaders,
  normalizeBridge,
  normalizeSettings,
  PAUSE_RULE_ID,
  PRIVACY_PRIORITY,
  pageMask,
  parseBridgeMessage,
  parseContentRequest,
  pauseRule,
  privacyRules,
  REFERRER_POLICY_RULE_ID,
  type RulesetInfo,
  registrableDomain,
  rulesetChanges,
  type ScriptletEntry,
  type Settings,
  scriptChanges,
  scriptletScripts,
  siteOf,
  storedSettings,
  TRACKER_COOKIES_RULE_ID,
  TRACKER_REFERER_RULE_ID,
  tightenReferrerPolicy,
  type UncloakRequest,
  USER_PRIORITY,
  uncloakCandidate,
  withFeature,
  withRuleset,
  withSite,
  withSiteException,
} from "../src/core.js";

const ruleset = (id: string, mask = 1): RulesetInfo => ({
  id,
  name: id,
  description: "",
  enabled: true,
  path: `rulesets/${id}.json`,
  rules: 1,
  regexRules: 0,
  mask,
});

/** Settings with defaults for whatever a test doesn't care about. */
const settingsWith = (partial: Partial<Settings> = {}): Settings => ({
  disabledRulesets: [],
  pausedSites: [],
  disabledFeatures: [],
  siteExceptions: {},
  ...partial,
});

const entry = (ruleset: string, name: string, matches: string[]): ScriptletEntry => ({
  ruleset,
  file: `scriptlets/${name}.js`,
  matches,
  calls: 1,
});

test("siteOf takes the hostname of web pages only", () => {
  assert.equal(siteOf("https://www.Example.com/path?q=1"), "example.com");
  assert.equal(siteOf("http://news.example.co.uk:8080/"), "news.example.co.uk");
  assert.equal(siteOf("https://example.com./"), "example.com");
  assert.equal(siteOf("chrome://extensions"), null);
  assert.equal(siteOf("chrome-extension://abc/popup.html"), null);
  assert.equal(siteOf("file:///tmp/x.html"), null);
  assert.equal(siteOf("https://[::1]/"), null);
  assert.equal(siteOf("not a url"), null);
  assert.equal(siteOf(""), null);
});

test("settings survive junk in storage", () => {
  assert.deepEqual(normalizeSettings(undefined), settingsWith());
  assert.deepEqual(
    normalizeSettings({
      disabledRulesets: ["params", 3, "params", null, "ads"],
      pausedSites: ["WWW.Example.com", "example.com", {}, "bad host!", "b.example"],
    }),
    settingsWith({
      disabledRulesets: ["ads", "params"],
      pausedSites: ["b.example", "example.com"],
    }),
  );
  assert.deepEqual(normalizeSettings("nonsense"), settingsWith());
});

test("a paused site covers the names below it", () => {
  const settings: Settings = settingsWith({ disabledRulesets: [], pausedSites: ["example.com"] });
  assert.ok(isPaused(settings, "example.com"));
  assert.ok(isPaused(settings, "shop.example.com"));
  assert.ok(!isPaused(settings, "badexample.com"));
  assert.ok(!isPaused(settings, "example.org"));
});

test("the pause rule outranks every compiled rule", () => {
  assert.equal(pauseRule([]), null);
  const rule = pauseRule(["b.example", "a.example"]);
  assert.ok(rule);
  assert.equal(rule.id, PAUSE_RULE_ID);
  assert.equal(rule.priority, USER_PRIORITY);
  assert.equal(rule.action.type, "allowAllRequests");
  assert.deepEqual(rule.condition.requestDomains, ["a.example", "b.example"]);
  assert.deepEqual(rule.condition.resourceTypes, ["main_frame", "sub_frame"]);
  // Above the compiler's highest priority (important exceptions, 70).
  assert.ok(USER_PRIORITY > 70);
});

test("ruleset changes are the difference, nothing more", () => {
  const all = ["ads", "privacy", "params"].map(ruleset);
  const settings: Settings = settingsWith({ disabledRulesets: ["params"], pausedSites: [] });
  assert.deepEqual(rulesetChanges(all, settings, ["ads", "privacy", "params"]), {
    enableRulesetIds: [],
    disableRulesetIds: ["params"],
  });
  assert.deepEqual(rulesetChanges(all, settings, ["ads"]), {
    enableRulesetIds: ["privacy"],
    disableRulesetIds: [],
  });
  assert.deepEqual(rulesetChanges(all, settings, ["ads", "privacy"]), {
    enableRulesetIds: [],
    disableRulesetIds: [],
  });
  // A ruleset that no longer exists is switched off.
  assert.deepEqual(
    rulesetChanges(all, settingsWith({ disabledRulesets: [], pausedSites: [] }), ["gone"]),
    {
      enableRulesetIds: ["ads", "params", "privacy"],
      disableRulesetIds: ["gone"],
    },
  );
});

test("toggles are idempotent", () => {
  let s: Settings = settingsWith({ disabledRulesets: [], pausedSites: [] });
  s = withSite(s, "a.example", true);
  s = withSite(s, "a.example", true);
  assert.deepEqual(s.pausedSites, ["a.example"]);
  s = withSite(s, "a.example", false);
  assert.deepEqual(s.pausedSites, []);
  s = withRuleset(s, "ads", false);
  s = withRuleset(s, "ads", false);
  assert.deepEqual(s.disabledRulesets, ["ads"]);
  s = withRuleset(s, "ads", true);
  assert.deepEqual(s.disabledRulesets, []);
});

test("the page mask has the bits of the rulesets that are on", () => {
  const all = [ruleset("ads", 1), ruleset("privacy", 2), ruleset("annoyances", 4)];
  const none: Settings = settingsWith({ disabledRulesets: [], pausedSites: [] });
  assert.equal(pageMask(all, none), 7);
  assert.equal(pageMask(all, { ...none, disabledRulesets: ["privacy"] }), 5);
  assert.equal(pageMask(all, { ...none, disabledRulesets: ["ads", "privacy", "annoyances"] }), 0);
});

test("scriptlet files follow the rulesets and skip paused sites", () => {
  const entries = [
    entry("ads", "ads-0", ["*://*.example.com/*"]),
    entry("ads", "ads-1", ["*://*.news.test/*"]),
    entry("privacy", "privacy-0", ["*://*.example.org/*"]),
  ];
  const settings: Settings = settingsWith({
    disabledRulesets: ["privacy"],
    pausedSites: ["example.com"],
  });
  const scripts = scriptletScripts(entries, settings);
  assert.deepEqual(
    scripts.map((s) => s.id),
    ["ads-0", "ads-1"],
  );
  const first = scripts[0];
  assert.ok(first);
  assert.deepEqual(first.js, ["scriptlets/ads-0.js"]);
  assert.deepEqual(first.excludeMatches, ["*://*.example.com/*"]);
  // In the page's own world, before its first script, in every frame.
  assert.equal(first.world, "MAIN");
  assert.equal(first.runAt, "document_start");
  assert.equal(first.allFrames, true);
  assert.equal(first.matchOriginAsFallback, true);
});

test("script changes register, update and unregister only what differs", () => {
  const entries = [
    entry("ads", "ads-0", ["*://*.a.test/*"]),
    entry("ads", "ads-1", ["*://*.b.test/*"]),
  ];
  const before = scriptletScripts(entries, settingsWith({ disabledRulesets: [], pausedSites: [] }));
  const same = scriptChanges(before, before);
  assert.deepEqual(same, { unregister: [], register: [], update: [] });

  // Chrome reports no excludeMatches when there are none.
  const reported = before.map(({ excludeMatches: _, ...rest }) => rest);
  assert.deepEqual(scriptChanges(before, reported).update, []);

  const paused = scriptletScripts(
    entries,
    settingsWith({ disabledRulesets: [], pausedSites: ["a.test"] }),
  );
  assert.deepEqual(
    scriptChanges(paused, before).update.map((s) => s.id),
    ["ads-0", "ads-1"],
  );
  const off = scriptletScripts(
    entries,
    settingsWith({ disabledRulesets: ["ads"], pausedSites: [] }),
  );
  assert.deepEqual(scriptChanges(off, before).unregister, ["ads-0", "ads-1"]);
  assert.deepEqual(
    scriptChanges(before, off).register.map((s) => s.id),
    ["ads-0", "ads-1"],
  );
});

test("content messages are checked like untrusted input", () => {
  assert.deepEqual(parseContentRequest({ type: "page" }), { type: "page" });
  assert.equal(parseContentRequest({ type: "setSite", site: "x", paused: true }), null);
  assert.equal(parseContentRequest(null), null);
  assert.equal(parseContentRequest("page"), null);
  assert.equal(parseContentRequest({ type: "generic" }), null);
  assert.deepEqual(
    parseContentRequest({
      type: "generic",
      tokens: [".ad", "#top", "plain", ".", "#a b", 7, `.${"x".repeat(300)}`],
      always: "yes",
    }),
    { type: "generic", tokens: [".ad", "#top"], always: false },
  );
  const many = Array.from({ length: 5000 }, (_, i) => `.t${i}`);
  const parsed = parseContentRequest({ type: "generic", tokens: many, always: true });
  assert.equal(parsed?.type === "generic" && parsed.tokens.length, MAX_TOKENS_PER_MESSAGE);
});

test("frames without a URL of their own go by their origin", () => {
  assert.equal(
    frameHost("https://www.Example.com/a", "https://www.example.com"),
    "www.example.com",
  );
  assert.equal(frameHost("about:blank", "https://news.test"), "news.test");
  assert.equal(frameHost("about:srcdoc", undefined), null);
  assert.equal(frameHost("chrome-extension://abc/popup.html", undefined), null);
  assert.equal(frameHost(undefined, "null"), null);
});

test("a frame is paused by its tab's site or its own", () => {
  const settings: Settings = settingsWith({ disabledRulesets: [], pausedSites: ["example.com"] });
  assert.ok(framePaused(settings, "https://www.example.com/", "ads.other.test"));
  assert.ok(framePaused(settings, "https://news.test/", "www.example.com"));
  assert.ok(framePaused(settings, "https://news.test/", "cdn.example.com"));
  assert.ok(!framePaused(settings, "https://news.test/", "other.test"));
  assert.ok(!framePaused(settings, undefined, "other.test"));
});

test("features and their site exceptions survive junk in storage", () => {
  const s = normalizeSettings({
    disabledFeatures: ["gpc", "nonsense", "gpc", 3],
    siteExceptions: {
      cookies: ["www.Shop.example", "bad url", 4],
      webrtc: ["example.com"],
      unknown: ["x.example"],
    },
  });
  assert.deepEqual(s.disabledFeatures, ["gpc"]);
  // WebRTC is browser-wide: it has no per-site exceptions.
  assert.deepEqual(s.siteExceptions, { cookies: ["shop.example"] });
});

test("a feature is off where it is switched off, paused or excepted", () => {
  let s = settingsWith({ pausedSites: ["paused.example"] });
  s = withSiteException(s, "cookies", "shop.example", true);
  assert.ok(featureActive(s, "cookies", null));
  assert.ok(featureActive(s, "cookies", "news.example"));
  assert.ok(!featureActive(s, "cookies", "www.shop.example"));
  assert.ok(featureActive(s, "gpc", "shop.example"), "only cookies are excepted there");
  assert.ok(!featureActive(s, "gpc", "paused.example"));
  assert.deepEqual(exemptSites(s, "cookies"), ["paused.example", "shop.example"]);
  s = withFeature(s, "gpc", false);
  assert.ok(!featureActive(s, "gpc", null));
  s = withSiteException(withFeature(s, "gpc", true), "cookies", "shop.example", false);
  assert.deepEqual(s.siteExceptions, {});
  assert.deepEqual(s.disabledFeatures, []);
});

test("privacy rules: one per feature, above list rules, below the pause rule", () => {
  const trackers = ["tracker.example", "pixel.example"];
  const rules = privacyRules(settingsWith(), trackers);
  assert.deepEqual(
    rules.map((r) => r.id).sort(),
    [GPC_RULE_ID, REFERRER_POLICY_RULE_ID, TRACKER_COOKIES_RULE_ID, TRACKER_REFERER_RULE_ID].sort(),
  );
  for (const rule of rules) {
    assert.equal(rule.priority, PRIVACY_PRIORITY);
    assert.ok(PRIVACY_PRIORITY < USER_PRIORITY);
    assert.equal(rule.action.type, "modifyHeaders");
  }
  const byId = new Map(rules.map((r) => [r.id, r]));
  const gpc = byId.get(GPC_RULE_ID);
  assert.deepEqual(gpc?.action.requestHeaders, [
    { header: "Sec-GPC", operation: "set", value: "1" },
  ]);
  assert.ok(gpc?.condition.resourceTypes?.includes("main_frame" as never), "navigations too");
  const cookies = byId.get(TRACKER_COOKIES_RULE_ID);
  assert.deepEqual(cookies?.condition.requestDomains, trackers);
  assert.equal(cookies?.condition.domainType, "thirdParty");
  assert.deepEqual(cookies?.action.responseHeaders, [
    { header: "Set-Cookie", operation: "remove" },
  ]);
  const policy = byId.get(REFERRER_POLICY_RULE_ID);
  assert.ok(policy);
  assert.deepEqual((policy.condition as { responseHeaders?: unknown }).responseHeaders, [
    { header: "referrer-policy", values: ["*unsafe-url", "*no-referrer-when-downgrade"] },
  ]);
});

test("a site exception excludes the site from that feature's rule only", () => {
  let s = withSiteException(settingsWith(), "cookies", "shop.example", true);
  s = withSiteException(s, "gpc", "bank.example", true);
  const rules = new Map(privacyRules(s, ["t.example"]).map((r) => [r.id, r]));
  assert.deepEqual(rules.get(TRACKER_COOKIES_RULE_ID)?.condition.excludedInitiatorDomains, [
    "shop.example",
  ]);
  assert.equal(rules.get(TRACKER_REFERER_RULE_ID)?.condition.excludedInitiatorDomains, undefined);
  assert.deepEqual(rules.get(GPC_RULE_ID)?.condition.excludedRequestDomains, ["bank.example"]);
  assert.deepEqual(rules.get(GPC_RULE_ID)?.condition.excludedInitiatorDomains, ["bank.example"]);
  // Switched off everywhere: no rule at all. No trackers: no tracker rules.
  const off = privacyRules(withFeature(settingsWith(), "referrer", false), []);
  assert.deepEqual(
    off.map((r) => r.id),
    [GPC_RULE_ID],
  );
});

test("feature scripts register where their feature acts", () => {
  let s = withSiteException(settingsWith({ pausedSites: ["p.example"] }), "gpc", "g.example", true);
  const scripts = featureScripts(s);
  assert.deepEqual(
    scripts.map((x) => [x.id, x.js, x.excludeMatches]),
    [
      ["gpc", ["gpc.js"], ["*://*.g.example/*", "*://*.p.example/*"]],
      ["farble", ["farble.js"], ["*://*.p.example/*"]],
    ],
  );
  assert.ok(
    scripts.every((x) => x.world === "MAIN" && x.runAt === "document_start" && x.allFrames),
  );
  s = withFeature(s, "fingerprinting", false);
  assert.deepEqual(
    featureScripts(s).map((x) => x.id),
    ["gpc"],
  );
});

const cookie = (fields: Partial<chrome.cookies.Cookie>): chrome.cookies.Cookie => ({
  name: "_ga",
  value: "GA1.1.123.456",
  domain: ".shop.example",
  hostOnly: false,
  path: "/",
  secure: true,
  httpOnly: false,
  sameSite: "lax" as chrome.cookies.SameSiteStatus,
  session: false,
  expirationDate: 2_000_000_000,
  storeId: "0",
  ...fields,
});

test("tracking cookies are capped at a week, nothing else", () => {
  assert.ok(isTrackingCookie("_ga"));
  assert.ok(isTrackingCookie("_ga_ABC123"));
  assert.ok(isTrackingCookie("_gcl_au"));
  assert.ok(isTrackingCookie("_fbp"));
  assert.ok(!isTrackingCookie("_gac"));
  assert.ok(!isTrackingCookie("session"));
  const now = 1_700_000_000;
  const capped = cappedCookie(cookie({}), now);
  assert.deepEqual(capped, {
    url: "https://shop.example/",
    name: "_ga",
    value: "GA1.1.123.456",
    domain: ".shop.example",
    path: "/",
    secure: true,
    httpOnly: false,
    sameSite: "lax",
    expirationDate: now + COOKIE_CAP_SECONDS,
    storeId: "0",
  });
  // A host-only cookie stays host-only: no domain.
  const hostOnly = cappedCookie(
    cookie({ domain: "shop.example", hostOnly: true, secure: false }),
    now,
  );
  assert.equal(hostOnly?.domain, undefined);
  assert.equal(hostOnly?.url, "http://shop.example/");
  assert.equal(cappedCookie(cookie({ name: "session" }), now), null);
  const { expirationDate: _, ...sessionCookie } = cookie({ session: true });
  assert.equal(cappedCookie(sessionCookie, now), null);
  assert.equal(cappedCookie(cookie({ expirationDate: now + 3600 }), now), null, "already short");
  // Setting the capped cookie fires onChanged again; it must not loop.
  assert.equal(cappedCookie(cookie({ expirationDate: now + COOKIE_CAP_SECONDS }), now), null);
});

test("registrable domains seed fingerprint noise per site", () => {
  const suffixes = ["co.uk", "com.au"];
  assert.equal(registrableDomain("www.news.example.com", suffixes), "example.com");
  assert.equal(registrableDomain("shop.example.co.uk", suffixes), "example.co.uk");
  assert.equal(registrableDomain("example.co.uk", suffixes), "example.co.uk");
  assert.equal(registrableDomain("example.com", suffixes), "example.com");
  assert.equal(registrableDomain("192.168.1.10", suffixes), "192.168.1.10");
  assert.equal(registrableDomain("Example.COM.", suffixes), "example.com");
});

test("a seed request carries nothing else", () => {
  assert.deepEqual(parseContentRequest({ type: "seed", site: "x" }), { type: "seed" });
});

// ------------------------------------------------------------- Firefox (M8)

test("the browser is told apart by the extension's own URL scheme", () => {
  assert.equal(browserOf("moz-extension://8c0b5c9e-1f2a-4b0e-9d4a-5a7c3e2f1b00/"), "firefox");
  assert.equal(browserOf("chrome-extension://abcdefghijklmnopabcdefghijklmnop/"), "chrome");
  assert.deepEqual(
    featuresFor("chrome").map((f) => f.id),
    ["fingerprinting", "cookies", "referrer", "gpc", "webrtc"],
  );
  assert.deepEqual(featuresFor("firefox")[0]?.id, "cname");
});

test("Firefox gets privacy rules it can parse", () => {
  const types = (rules: ReturnType<typeof privacyRules>) =>
    rules.find((r) => r.id === GPC_RULE_ID)?.condition.resourceTypes ?? [];
  const chrome = privacyRules(settingsWith(), ["t.example"], "chrome");
  const firefox = privacyRules(settingsWith(), ["t.example"], "firefox");
  assert.ok(types(chrome).includes("webtransport" as never));
  assert.ok(!types(firefox).includes("webtransport" as never));
  assert.ok(!types(firefox).includes("webbundle" as never));
  assert.ok(types(firefox).includes("main_frame" as never));
  // No response-header conditions in Firefox: webRequest does that rule.
  assert.ok(chrome.some((r) => r.id === REFERRER_POLICY_RULE_ID));
  assert.ok(!firefox.some((r) => r.id === REFERRER_POLICY_RULE_ID));
});

test("a loose Referrer-Policy is tightened, by the last policy named", () => {
  const strict = { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" };
  const other = { name: "Content-Type", value: "text/html" };
  assert.deepEqual(
    tightenReferrerPolicy([other, { name: "referrer-policy", value: "unsafe-url" }]),
    [other, strict],
  );
  // Two headers, or a list in one: the last valid token is in force.
  assert.deepEqual(
    tightenReferrerPolicy([
      { name: "Referrer-Policy", value: "no-referrer" },
      { name: "Referrer-Policy", value: "no-referrer-when-downgrade, bogus" },
    ]),
    [strict],
  );
  assert.equal(
    tightenReferrerPolicy([{ name: "Referrer-Policy", value: "unsafe-url, same-origin" }]),
    null,
  );
  assert.equal(tightenReferrerPolicy([{ name: "Referrer-Policy", value: "origin" }]), null);
  assert.equal(tightenReferrerPolicy([other]), null);
});

test("navigations get the header rules Firefox's DNR leaves out", () => {
  const nav = (partial: Partial<Navigation> = {}): Navigation => ({
    url: "https://news.example/article",
    thirdParty: false,
    tracker: false,
    ...partial,
  });
  const headers = [
    { name: "Cookie", value: "id=1" },
    { name: "Referer", value: "https://site.example/page" },
  ];
  const gpc = { name: "Sec-GPC", value: "1" };
  assert.deepEqual(navigationRequestHeaders(headers, nav(), settingsWith()), [...headers, gpc]);
  // A third-party tracker frame: no cookies, no Referer, and GPC.
  const tracker = nav({ url: "https://t.example/frame", thirdParty: true, tracker: true });
  const fromSite = { ...tracker, initiator: "https://site.example/page" };
  assert.deepEqual(navigationRequestHeaders(headers, fromSite, settingsWith()), [gpc]);
  // Off where the feature is excepted: for GPC the page or the target, for
  // the others the page the frame is on.
  const shopOff = withSiteException(settingsWith(), "cookies", "site.example", true);
  assert.deepEqual(navigationRequestHeaders(headers, fromSite, shopOff), [headers[0], gpc]);
  const gpcOff = withSiteException(settingsWith(), "gpc", "news.example", true);
  assert.equal(navigationRequestHeaders(headers, nav(), gpcOff), null);
  const paused = settingsWith({ pausedSites: ["site.example"] });
  assert.equal(navigationRequestHeaders(headers, fromSite, paused), null);
  // Responses: a tracker frame sets no cookie; a loose policy is tightened.
  const setCookie = { name: "Set-Cookie", value: "id=2" };
  const loose = { name: "Referrer-Policy", value: "unsafe-url" };
  assert.deepEqual(navigationResponseHeaders([setCookie], fromSite, settingsWith()), []);
  assert.equal(navigationResponseHeaders([setCookie], nav(), settingsWith()), null);
  assert.deepEqual(navigationResponseHeaders([loose], nav(), settingsWith()), [
    { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  ]);
  const referrerOff = withSiteException(settingsWith(), "referrer", "news.example", true);
  assert.equal(navigationResponseHeaders([loose], nav(), referrerOff), null);
});

test("a frame's CSS goes to its document in Chrome, its frame in Firefox", () => {
  assert.deepEqual(cssTarget({ tab: { id: 3 }, documentId: "D", frameId: 7 }), {
    tabId: 3,
    documentIds: ["D"],
  });
  assert.deepEqual(cssTarget({ tab: { id: 3 }, frameId: 0 }), { tabId: 3, frameIds: [0] });
  assert.equal(cssTarget({ frameId: 0 }), null);
});

test("Firefox's cookie fields are kept when a cookie is capped", () => {
  const capped = cappedCookie(
    cookie({
      storeId: "firefox-container-2",
      firstPartyDomain: "",
      partitionKey: { topLevelSite: "https://news.example" },
    } as never),
    1_700_000_000,
  );
  assert.equal(capped?.storeId, "firefox-container-2");
  assert.equal((capped as { firstPartyDomain?: string }).firstPartyDomain, "");
  assert.deepEqual((capped as { partitionKey?: unknown }).partitionKey, {
    topLevelSite: "https://news.example",
  });
});

const sets = new HostSets([
  {
    ruleset: "privacy",
    block: ["cname-tracker.example", "edge.site.example"],
    exempt: ["api.cname-tracker.example"],
    documents: [],
  },
  { ruleset: "unbreak", block: [], exempt: ["cdn.example"], documents: ["shop.example"] },
]);
const all = sets.mask(settingsWith());
const request = (partial: Partial<UncloakRequest> = {}): UncloakRequest => ({
  url: "https://metrics.site.example/p.gif",
  type: "image",
  documentUrl: "https://www.site.example/",
  proxied: false,
  ...partial,
});

test("hosts match themselves and their parents", () => {
  assert.deepEqual(hostAndParents("a.b.example"), ["a.b.example", "b.example", "example"]);
  assert.ok(sets.has("block", "x.cname-tracker.example", all));
  assert.ok(!sets.has("block", "cname-tracker.example.evil", all));
  // Only rulesets that are on count.
  const privacyOff = sets.mask(settingsWith({ disabledRulesets: ["privacy"] }));
  assert.ok(!sets.has("block", "cname-tracker.example", privacyOff));
  assert.ok(sets.has("exempt", "cdn.example", privacyOff));
});

test("uncloaking looks up only what DNR can't decide", () => {
  const s = settingsWith();
  assert.equal(uncloakCandidate(request(), s, sets, all), "metrics.site.example");
  for (const [why, partial] of [
    ["the page itself", { type: "main_frame" }],
    ["not from a page", { documentUrl: undefined }],
    ["proxied", { proxied: true }],
    ["an address", { url: "https://192.168.1.2/p.gif" }],
    ["IPv6", { url: "https://[::1]/p.gif" }],
    ["one label", { url: "https://intranet/p.gif" }],
    ["not http", { url: "ftp://files.example/x" }],
    ["listed already", { url: "https://cname-tracker.example/p.gif" }],
    ["exempt", { url: "https://cdn.example/x.js" }],
    ["a $document page", { documentUrl: "https://shop.example/" }],
    [
      "a $document page above",
      { frameAncestors: [{ url: "https://ads.example/" }, { url: "https://shop.example/" }] },
    ],
  ] as const) {
    const r = { ...request(), ...partial } as UncloakRequest;
    if ("documentUrl" in partial && partial.documentUrl === undefined) delete r.documentUrl;
    assert.equal(uncloakCandidate(r, s, sets, all), null, why);
  }
  const off = withSiteException(s, "cname", "site.example", true);
  assert.equal(uncloakCandidate(request(), off, sets, all), null, "excepted here");
  const paused = settingsWith({ pausedSites: ["site.example"] });
  assert.equal(uncloakCandidate(request(), paused, sets, all), null, "paused");
  assert.equal(uncloakCandidate(request(), withFeature(s, "cname", false), sets, all), null);
});

test("an alias is blocked when it is a listed host on another site", () => {
  const suffixes = ["co.uk"];
  const blocked = (alias: string | undefined) =>
    aliasBlocked("metrics.site.example", alias, sets, all, suffixes);
  assert.ok(blocked("site-example.cname-tracker.example"));
  assert.ok(blocked("Site-Example.CNAME-tracker.example."), "case and the root dot");
  assert.ok(!blocked("edge.site.example"), "same site: not cloaking");
  assert.ok(!blocked("api.cname-tracker.example"), "exempt");
  assert.ok(!blocked("img.cdn.example"), "not listed");
  assert.ok(!blocked("metrics.site.example"), "no alias");
  assert.ok(!blocked(undefined));
  const privacyOff = sets.mask(settingsWith({ disabledRulesets: ["privacy"] }));
  assert.ok(!aliasBlocked("metrics.site.example", "x.cname-tracker.example", sets, privacyOff, []));
});

test("the bridge takes only well-formed state", () => {
  assert.equal(parseBridgeMessage(null), null);
  assert.equal(parseBridgeMessage({ type: "pause" }), null);
  assert.equal(parseBridgeMessage({ type: "state", allow: "x", block: [] }), null);
  const state = parseBridgeMessage({
    type: "state",
    running: true,
    paused: { until_ms: 1700000000000 },
    allow: ["ok.example", "*.cdn.example", "ok.example", "Bad Name", 7, "a..b", "-x.example"],
    block: ["ads.example"],
    extra: "ignored",
  });
  assert.deepEqual(state, {
    running: true,
    paused: { until: 1700000000000 },
    allow: ["*.cdn.example", "ok.example"],
    block: ["ads.example"],
    truncated: false,
  });
  const forever = parseBridgeMessage({ type: "state", paused: {}, allow: [], block: [] });
  assert.deepEqual(forever?.paused, { until: null });
});

test("the resolver's pause turns everything off, and only while connected", () => {
  const settings = normalizeSettings({});
  const bridge: Bridge = { ...NO_BRIDGE, connected: true, paused: { until: null } };
  const paused = effectiveSettings(settings, bridge, 1000);
  assert.equal(paused.pausedAll, true);
  assert.equal(isPaused(paused, "any.example"), true);
  assert.equal(featureActive(paused, "gpc", null), false);
  assert.deepEqual(featureScripts(paused), []);
  assert.deepEqual(
    scriptletScripts(
      [{ ruleset: "ads", file: "scriptlets/ads-0.js", matches: ["*://*/*"], calls: 1 }],
      paused,
    ),
    [],
  );
  const rule = pauseRule(paused.pausedSites, true);
  assert.equal(rule?.condition.requestDomains, undefined);
  assert.deepEqual(rule?.condition.resourceTypes, ["main_frame", "sub_frame"]);
  // Never stored.
  assert.equal("pausedAll" in storedSettings(paused), false);
  // A timed pause ends by itself; a lost connection ends it too.
  const timed: Bridge = { ...bridge, paused: { until: 2000 } };
  assert.equal(bridgePaused(timed, 1999), true);
  assert.equal(bridgePaused(timed, 2000), false);
  assert.equal(bridgePaused({ ...bridge, connected: false }, 0), false);
  assert.equal(effectiveSettings(settings, NO_BRIDGE, 0).pausedAll, undefined);
});

test("the resolver's lists become dynamic rules, allow over block", () => {
  const bridge: Bridge = {
    ...NO_BRIDGE,
    connected: true,
    allow: ["ok.example", "*.cdn.example"],
    block: ["ads.example", "*.track.example"],
  };
  const rules = bridgeRules(bridge, "firefox");
  const allow = rules.find((r) => r.action.type === "allow" && r.condition.requestDomains);
  const block = rules.find((r) => r.action.type === "block" && r.condition.requestDomains);
  assert.deepEqual(allow?.condition.requestDomains, ["ok.example"]);
  assert.equal(allow?.priority, USER_PRIORITY);
  assert.deepEqual(block?.condition.requestDomains, ["ads.example"]);
  assert.equal(block?.priority, BRIDGE_BLOCK_PRIORITY);
  assert.ok(
    block?.condition.resourceTypes?.includes(
      "main_frame" as chrome.declarativeNetRequest.ResourceType,
    ),
  );
  assert.ok(
    !block?.condition.resourceTypes?.includes(
      "webbundle" as chrome.declarativeNetRequest.ResourceType,
    ),
  );
  const regexes = rules.filter((r) => r.condition.regexFilter);
  assert.equal(regexes.length, 2);
  const re = new RegExp(regexes[0]?.condition.regexFilter ?? "");
  assert.ok(re.test("https://img.cdn.example/a.png"));
  assert.ok(re.test("wss://a.b.cdn.example:8443/socket"));
  assert.ok(!re.test("https://cdn.example/a.png"));
  assert.ok(!re.test("https://evilcdn.example/"));
  assert.ok(!re.test("https://x.example/?u=a.cdn.example"));
  // Highest-priority allow, then every rule id distinct.
  assert.equal(new Set(rules.map((r) => r.id)).size, rules.length);
  // Past the regex quota, `*.` entries are left out.
  const many: Bridge = {
    ...bridge,
    allow: Array.from({ length: BRIDGE_MAX_REGEX + 5 }, (_, i) => `*.s${i}.example`),
  };
  const capped = bridgeRules(many).filter((r) => r.condition.regexFilter);
  assert.equal(capped.length, BRIDGE_MAX_REGEX);
  assert.ok(
    capped.every((r) => r.id >= BRIDGE_REGEX_FIRST && r.id < BRIDGE_REGEX_FIRST + BRIDGE_MAX_REGEX),
  );
  assert.equal(bridgeAllows(bridge, "ok.example"), true);
  assert.equal(bridgeAllows(bridge, "a.ok.example"), true);
  assert.equal(bridgeAllows(bridge, "cdn.example"), false);
  assert.equal(bridgeAllows(bridge, "x.cdn.example"), true);
});

test("stored bridge state survives a round trip and drops junk", () => {
  const stored = {
    connected: true,
    error: null,
    running: true,
    paused: { until: null },
    allow: ["ok.example"],
    block: [],
    truncated: false,
  };
  assert.deepEqual(normalizeBridge(stored), stored);
  assert.deepEqual(normalizeBridge(undefined), NO_BRIDGE);
  assert.deepEqual(normalizeBridge({ allow: 3 }), NO_BRIDGE);
  // The privacy rules don't change with the bridge.
  assert.deepEqual(
    privacyRules(normalizeSettings({}), ["t.example"]).map((r) => r.id),
    privacyRules(effectiveSettings(normalizeSettings({}), NO_BRIDGE, 0), ["t.example"]).map(
      (r) => r.id,
    ),
  );
});
