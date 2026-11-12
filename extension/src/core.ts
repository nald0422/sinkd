// The extension's decisions, as pure functions, so they can be tested
// without a browser. The background script and the popup only glue these
// to chrome.* APIs. Request matching happens in the browser's DNR engine,
// from the rulesets `sinkd compile` produced; cosmetic matching in the
// Rust page engine (engine.ts); scriptlets pick their own calls by
// hostname. Firefox adds CNAME uncloaking, the one thing matched here.

/** An entry of rulesets.json, written by `sinkd compile`. */
export interface RulesetInfo {
  id: string;
  name: string;
  description: string;
  /** Enabled on install. */
  enabled: boolean;
  path: string;
  rules: number;
  regexRules: number;
  /** This ruleset's bit in the page index (cosmetic rules). */
  mask: number;
}

/** An entry of scriptlets.json: one file of scriptlet calls for some sites. */
export interface ScriptletEntry {
  ruleset: string;
  /** Its path in the package: scriptlets/<ruleset>-<n>.js */
  file: string;
  /** Match patterns of the sites it has calls for. */
  matches: string[];
  calls: number;
}

/** The browsers this extension is built for. */
export type Browser = "chrome" | "firefox";

/** Which browser runs the extension, from the URL of one of its pages. */
export function browserOf(extensionUrl: string): Browser {
  return extensionUrl.startsWith("moz-extension:") ? "firefox" : "chrome";
}

/**
 * Protections that are not rulesets. Each switches off on its own, and all
 * but WebRTC can be switched off for one site (WebRTC's IP policy is a
 * browser-wide setting, not per page). CNAME uncloaking needs a DNS API
 * only Firefox has.
 */
export const FEATURES = [
  {
    id: "cname",
    name: "CNAME uncloaking",
    description: "Blocks a site's own subdomains that are DNS aliases of a blocked tracker.",
    perSite: true,
    firefoxOnly: true,
  },
  {
    id: "fingerprinting",
    name: "Fingerprinting",
    description: "Noise in canvas, WebGL and audio readback; coarser hardware details.",
    perSite: true,
    firefoxOnly: false,
  },
  {
    id: "cookies",
    name: "Tracking cookies",
    description: "No cookies to or from trackers; analytics cookies expire within a week.",
    perSite: true,
    firefoxOnly: false,
  },
  {
    id: "referrer",
    name: "Referrer",
    description: "Other sites see where you came from, not the page; trackers see nothing.",
    perSite: true,
    firefoxOnly: false,
  },
  {
    id: "gpc",
    name: "Global Privacy Control",
    description: "Tells sites not to sell or share your data (Sec-GPC).",
    perSite: true,
    firefoxOnly: false,
  },
  {
    id: "webrtc",
    name: "WebRTC IP",
    description: "WebRTC uses only the public interface, so it can't reveal your local address.",
    perSite: false,
    firefoxOnly: false,
  },
] as const;

export type FeatureId = (typeof FEATURES)[number]["id"];

/** The features `browser` can offer. */
export function featuresFor(browser: Browser): (typeof FEATURES)[number][] {
  return FEATURES.filter((f) => browser === "firefox" || !f.firefoxOnly);
}

const FEATURE_IDS: readonly string[] = FEATURES.map((f) => f.id);
const isFeature = (id: unknown): id is FeatureId =>
  typeof id === "string" && FEATURE_IDS.includes(id);

/** What the user chose. Everything else is derived. */
export interface Settings {
  /** Rulesets switched off, by id. */
  disabledRulesets: string[];
  /** Hostnames where sinkd is off (and every name below them). */
  pausedSites: string[];
  /** Features switched off everywhere. */
  disabledFeatures: FeatureId[];
  /** Per feature, the sites where it is off (and every name below them). */
  siteExceptions: Partial<Record<FeatureId, string[]>>;
  /**
   * Runtime only, never stored: the resolver on this computer is paused
   * (`sinkd pause`, through the bridge), so sinkd is off everywhere.
   */
  pausedAll?: boolean;
}

/** Priority of the "off on this site" rule: above every compiled rule. */
export const USER_PRIORITY = 1000;
/** The one dynamic rule, holding every paused site. */
export const PAUSE_RULE_ID = 1;

/** Settings as stored, cleaned up: anything malformed is dropped. */
export function normalizeSettings(raw: unknown): Settings {
  const value = (raw ?? {}) as Partial<Record<keyof Settings, unknown>>;
  const strings = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [];
  const sites = (v: unknown): string[] => [
    ...new Set(
      strings(v)
        .map((s) => siteOf(`https://${s}/`))
        .filter((s): s is string => s !== null),
    ),
  ];
  const exceptions: Partial<Record<FeatureId, string[]>> = {};
  const rawExceptions = value.siteExceptions;
  if (typeof rawExceptions === "object" && rawExceptions !== null) {
    for (const feature of FEATURES) {
      const list = sites((rawExceptions as Record<string, unknown>)[feature.id]).sort();
      if (feature.perSite && list.length > 0) {
        exceptions[feature.id] = list;
      }
    }
  }
  return {
    disabledRulesets: [...new Set(strings(value.disabledRulesets))].sort(),
    pausedSites: sites(value.pausedSites).sort(),
    disabledFeatures: [...new Set(strings(value.disabledFeatures).filter(isFeature))].sort(),
    siteExceptions: exceptions,
  };
}

/**
 * The site a URL belongs to, for the per-site switch: its hostname without
 * a leading `www.`. `null` for pages sinkd does not act on (extension
 * pages, `chrome://`, `file://`).
 */
export function siteOf(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return null;
  }
  // DNR domains are lowercase ASCII without brackets or a trailing dot.
  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (host === "" || host.startsWith("[")) {
    return null;
  }
  return host.startsWith("www.") ? host.slice(4) : host;
}

const covers = (sites: readonly string[], site: string): boolean =>
  sites.some((p) => site === p || site.endsWith(`.${p}`));

/** Whether `site` is paused, directly or through a parent, or everything is. */
export function isPaused(settings: Settings, site: string): boolean {
  return settings.pausedAll === true || covers(settings.pausedSites, site);
}

/** Settings as they are stored: without what only applies at run time. */
export function storedSettings(settings: Settings): Settings {
  const { pausedAll: _, ...stored } = settings;
  return stored;
}

/** Whether `feature` is switched off on `site` alone (not paused, not off everywhere). */
export function isExcepted(settings: Settings, feature: FeatureId, site: string): boolean {
  return covers(settings.siteExceptions[feature] ?? [], site);
}

/** Whether `feature` acts on `site` (or anywhere, for `null`). */
export function featureActive(
  settings: Settings,
  feature: FeatureId,
  site: string | null,
): boolean {
  if (settings.disabledFeatures.includes(feature) || settings.pausedAll === true) {
    return false;
  }
  return site === null || !(isPaused(settings, site) || isExcepted(settings, feature, site));
}

/** The sites where `feature` must not act: paused ones and its exceptions. */
export function exemptSites(settings: Settings, feature: FeatureId): string[] {
  return [
    ...new Set([...settings.pausedSites, ...(settings.siteExceptions[feature] ?? [])]),
  ].sort();
}

/** Settings with one feature switched on or off everywhere. */
export function withFeature(settings: Settings, feature: FeatureId, enabled: boolean): Settings {
  const rest = settings.disabledFeatures.filter((f) => f !== feature);
  return { ...settings, disabledFeatures: (enabled ? rest : [...rest, feature]).sort() };
}

/** Settings with one feature switched off (or back on) for one site. */
export function withSiteException(
  settings: Settings,
  feature: FeatureId,
  site: string,
  off: boolean,
): Settings {
  const rest = (settings.siteExceptions[feature] ?? []).filter((s) => s !== site);
  const list = (off ? [...rest, site] : rest).sort();
  const siteExceptions = { ...settings.siteExceptions };
  if (list.length > 0) {
    siteExceptions[feature] = list;
  } else {
    delete siteExceptions[feature];
  }
  return { ...settings, siteExceptions };
}

/**
 * The dynamic rule that turns sinkd off on the paused sites:
 * allowAllRequests on their pages and frames, above every compiled rule, so
 * nothing on them is blocked, redirected or rewritten. With `all`, on every
 * page. `null` when nothing is paused.
 */
export function pauseRule(sites: string[], all = false): chrome.declarativeNetRequest.Rule | null {
  if (sites.length === 0 && !all) {
    return null;
  }
  return {
    id: PAUSE_RULE_ID,
    priority: USER_PRIORITY,
    action: { type: "allowAllRequests" as chrome.declarativeNetRequest.RuleActionType },
    condition: {
      ...(all ? {} : { requestDomains: [...sites].sort() }),
      resourceTypes: [
        "main_frame" as chrome.declarativeNetRequest.ResourceType,
        "sub_frame" as chrome.declarativeNetRequest.ResourceType,
      ],
    },
  };
}

/** Rulesets to switch on and off so that exactly the wanted ones run. */
export function rulesetChanges(
  all: RulesetInfo[],
  settings: Settings,
  enabledNow: string[],
): { enableRulesetIds: string[]; disableRulesetIds: string[] } {
  const wanted = new Set(
    all.map((r) => r.id).filter((id) => !settings.disabledRulesets.includes(id)),
  );
  const now = new Set(enabledNow);
  return {
    enableRulesetIds: [...wanted].filter((id) => !now.has(id)).sort(),
    disableRulesetIds: [...now].filter((id) => !wanted.has(id)).sort(),
  };
}

/** Settings with one site switched on or off. */
export function withSite(settings: Settings, site: string, paused: boolean): Settings {
  const rest = settings.pausedSites.filter((s) => s !== site);
  return {
    ...settings,
    pausedSites: (paused ? [...rest, site] : rest).sort(),
  };
}

/** Settings with one ruleset switched on or off. */
export function withRuleset(settings: Settings, id: string, enabled: boolean): Settings {
  const rest = settings.disabledRulesets.filter((r) => r !== id);
  return {
    ...settings,
    disabledRulesets: (enabled ? rest : [...rest, id]).sort(),
  };
}

/** The page-index bits of the rulesets the user has on. */
export function pageMask(all: RulesetInfo[], settings: Settings): number {
  return all
    .filter((r) => !settings.disabledRulesets.includes(r.id))
    .reduce((mask, r) => mask | r.mask, 0);
}

/** Match patterns for the paused sites, and every name below them. */
export function pausedPatterns(sites: string[]): string[] {
  return sites.map((site) => `*://*.${site}/*`);
}

type ContentScript = chrome.scripting.RegisteredContentScript;

/**
 * The content scripts that should be registered: each scriptlet file of a
 * ruleset that is on, in the page's main world before any page script,
 * and not on paused sites.
 */
export function scriptletScripts(entries: ScriptletEntry[], settings: Settings): ContentScript[] {
  if (settings.pausedAll === true) {
    return [];
  }
  const excludeMatches = pausedPatterns(settings.pausedSites);
  return entries
    .filter((e) => !settings.disabledRulesets.includes(e.ruleset))
    .map((e) => ({
      id: e.file.replace(/^.*\//, "").replace(/\.js$/, ""),
      js: [e.file],
      matches: e.matches,
      excludeMatches,
      runAt: "document_start" as chrome.extensionTypes.RunAt,
      world: "MAIN" as chrome.scripting.ExecutionWorld,
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true,
    }));
}

/** What to unregister, register and update so exactly `wanted` is registered. */
export function scriptChanges(
  wanted: ContentScript[],
  registered: ContentScript[],
): { unregister: string[]; register: ContentScript[]; update: ContentScript[] } {
  const key = (s: ContentScript): string =>
    JSON.stringify([s.js ?? [], s.matches ?? [], [...(s.excludeMatches ?? [])].sort()]);
  const now = new Map(registered.map((s) => [s.id, s]));
  const ids = new Set(wanted.map((s) => s.id));
  const unregister = registered.map((s) => s.id).filter((id) => !ids.has(id));
  const register: ContentScript[] = [];
  const update: ContentScript[] = [];
  for (const script of wanted) {
    const current = now.get(script.id);
    if (!current) {
      register.push(script);
    } else if (key(current) !== key(script)) {
      update.push(script);
    }
  }
  return { unregister: unregister.sort(), register, update };
}

/**
 * The registered main-world scripts for features: GPC's
 * `navigator.globalPrivacyControl`, and fingerprint noise. Each is left off
 * the sites where its feature is excepted or paused.
 */
export function featureScripts(settings: Settings): ContentScript[] {
  const scripts: [FeatureId, string][] = [
    ["gpc", "gpc"],
    ["fingerprinting", "farble"],
  ];
  return scripts
    .filter(([feature]) => featureActive(settings, feature, null))
    .map(([feature, file]) => ({
      id: file,
      js: [`${file}.js`],
      matches: ["*://*/*"],
      excludeMatches: pausedPatterns(exemptSites(settings, feature)),
      runAt: "document_start" as chrome.extensionTypes.RunAt,
      world: "MAIN" as chrome.scripting.ExecutionWorld,
      allFrames: true,
      matchOriginAsFallback: true,
      persistAcrossSessions: true,
    }));
}

// ------------------------------------------------------------ header rules

/**
 * Priority of the privacy header rules: above every compiled rule, so a
 * list's `@@` exception (which lets a tracker request through) does not
 * also let its cookies through; below the pause rule, which ends them all.
 */
export const PRIVACY_PRIORITY = 900;
export const GPC_RULE_ID = 2;
export const REFERRER_POLICY_RULE_ID = 3;
export const TRACKER_COOKIES_RULE_ID = 4;
export const TRACKER_REFERER_RULE_ID = 5;
export const PRIVACY_RULE_IDS = [
  GPC_RULE_ID,
  REFERRER_POLICY_RULE_ID,
  TRACKER_COOKIES_RULE_ID,
  TRACKER_REFERER_RULE_ID,
];

type DnrRule = chrome.declarativeNetRequest.Rule;
type DnrCondition = chrome.declarativeNetRequest.RuleCondition;
const MODIFY = "modifyHeaders" as chrome.declarativeNetRequest.RuleActionType;
const op = (o: "set" | "remove") => o as chrome.declarativeNetRequest.HeaderOperation;
const types = (...t: string[]) => t as chrome.declarativeNetRequest.ResourceType[];
const EVERY_TYPE = types(
  "main_frame",
  "sub_frame",
  "stylesheet",
  "script",
  "image",
  "font",
  "object",
  "xmlhttprequest",
  "ping",
  "csp_report",
  "media",
  "websocket",
  "other",
);
/** Resource types only Chrome knows; Firefox rejects a rule naming them. */
const CHROME_ONLY_TYPES = types("webtransport", "webbundle");

/** The referrer policies that send a cross-site page more than an origin. */
export const LOOSE_REFERRER_POLICIES = ["*unsafe-url", "*no-referrer-when-downgrade"];

const REFERRER_POLICIES = [
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
];

/**
 * The Referrer-Policy rule for webRequest (Firefox): response headers with
 * a loose policy replaced by `strict-origin-when-cross-origin`, or `null`
 * to leave them alone. As in the Fetch standard, the last policy named
 * across all Referrer-Policy headers is the one in force.
 */
export function tightenReferrerPolicy<H extends { name: string; value?: string | undefined }>(
  headers: H[],
): (H | { name: string; value: string })[] | null {
  const isPolicy = (h: H) => h.name.toLowerCase() === "referrer-policy";
  const named = headers
    .filter(isPolicy)
    .flatMap((h) => (h.value ?? "").split(","))
    .map((token) => token.trim().toLowerCase())
    .filter((token) => REFERRER_POLICIES.includes(token));
  const policy = named.at(-1);
  if (policy !== "unsafe-url" && policy !== "no-referrer-when-downgrade") {
    return null;
  }
  return [
    ...headers.filter((h) => !isPolicy(h)),
    { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  ];
}

type Header = { name: string; value?: string | undefined };

/** A navigation (a main_frame or sub_frame request), as Firefox reports it. */
export interface Navigation {
  url: string;
  /** The page that started it (originUrl), if a page did. */
  initiator?: string | undefined;
  /** Whether it is to another site than the page it is in. */
  thirdParty: boolean;
  /** Whether the lists name its host as a tracker (trackers.json). */
  tracker: boolean;
}

/** Whether `feature` is on and acts on every one of `sites` (`null`: no site). */
const actsOn = (settings: Settings, feature: FeatureId, ...sites: (string | null)[]) =>
  featureActive(settings, feature, null) &&
  sites.every((site) => site === null || featureActive(settings, feature, site));

/**
 * The request header rules of privacyRules for a navigation, which
 * Firefox's DNR leaves alone: the headers to send instead, or `null` to
 * send them as they are. The exceptions are the rules' excluded domains.
 */
export function navigationRequestHeaders<H extends Header>(
  headers: H[],
  navigation: Navigation,
  settings: Settings,
): (H | { name: string; value: string })[] | null {
  const site = siteOf(navigation.url);
  const from = navigation.initiator ? siteOf(navigation.initiator) : null;
  const drop = new Set<string>();
  const gpc = actsOn(settings, "gpc", site, from);
  if (gpc) drop.add("sec-gpc");
  if (navigation.tracker && navigation.thirdParty) {
    if (actsOn(settings, "referrer", from)) drop.add("referer");
    if (actsOn(settings, "cookies", from)) drop.add("cookie");
  }
  if (drop.size === 0) {
    return null;
  }
  const kept = headers.filter((h) => !drop.has(h.name.toLowerCase()));
  return gpc ? [...kept, { name: "Sec-GPC", value: "1" }] : kept;
}

/**
 * The response header rules of privacyRules for a navigation: no cookies
 * set by a third-party tracker frame, and no loose Referrer-Policy. The
 * headers to use instead, or `null` to leave them alone.
 */
export function navigationResponseHeaders<H extends Header>(
  headers: H[],
  navigation: Navigation,
  settings: Settings,
): (H | { name: string; value: string })[] | null {
  let result: (H | { name: string; value: string })[] = headers;
  const from = navigation.initiator ? siteOf(navigation.initiator) : null;
  const isSetCookie = (h: Header) => h.name.toLowerCase() === "set-cookie";
  if (
    navigation.tracker &&
    navigation.thirdParty &&
    actsOn(settings, "cookies", from) &&
    result.some(isSetCookie)
  ) {
    result = result.filter((h) => !isSetCookie(h));
  }
  const site = siteOf(navigation.url);
  if (site !== null && actsOn(settings, "referrer", site)) {
    result = tightenReferrerPolicy(result) ?? result;
  }
  return result === headers ? null : result;
}

/**
 * The dynamic rules for the header features, rebuilt whenever settings
 * change. Their exceptions are excluded domains, so turning a feature off
 * for a site leaves every other rule there in place (an allow rule would
 * not). `trackers` comes from trackers.json. Firefox's DNR can't match on
 * response headers, so there the Referrer-Policy rule is left out; nor
 * does it modify the headers of navigations. webRequest does both there:
 * see navigationRequestHeaders and navigationResponseHeaders.
 */
export function privacyRules(
  settings: Settings,
  trackers: string[],
  browser: Browser = "chrome",
): DnrRule[] {
  const rules: DnrRule[] = [];
  const unless = (feature: FeatureId, keys: (keyof DnrCondition)[]): Partial<DnrCondition> => {
    const sites = exemptSites(settings, feature);
    return sites.length === 0 ? {} : Object.fromEntries(keys.map((k) => [k, sites]));
  };
  if (featureActive(settings, "gpc", null)) {
    rules.push({
      id: GPC_RULE_ID,
      priority: PRIVACY_PRIORITY,
      action: {
        type: MODIFY,
        requestHeaders: [{ header: "Sec-GPC", operation: op("set"), value: "1" }],
      },
      condition: {
        resourceTypes: browser === "chrome" ? [...EVERY_TYPE, ...CHROME_ONLY_TYPES] : EVERY_TYPE,
        ...unless("gpc", ["excludedInitiatorDomains", "excludedRequestDomains"]),
      },
    });
  }
  if (browser === "chrome" && featureActive(settings, "referrer", null)) {
    // Chrome trims cross-site referrers to the origin unless the page asks
    // for more; this takes back a page's looser policy. (A <meta> tag or a
    // referrerpolicy attribute can still loosen it: see DESIGN.md.)
    rules.push({
      id: REFERRER_POLICY_RULE_ID,
      priority: PRIVACY_PRIORITY,
      action: {
        type: MODIFY,
        responseHeaders: [
          {
            header: "Referrer-Policy",
            operation: op("set"),
            value: "strict-origin-when-cross-origin",
          },
        ],
      },
      condition: {
        resourceTypes: types("main_frame", "sub_frame"),
        responseHeaders: [{ header: "referrer-policy", values: LOOSE_REFERRER_POLICIES }],
        ...unless("referrer", ["excludedRequestDomains"]),
      } as DnrCondition,
    });
  }
  if (trackers.length > 0 && featureActive(settings, "referrer", null)) {
    rules.push({
      id: TRACKER_REFERER_RULE_ID,
      priority: PRIVACY_PRIORITY,
      action: {
        type: MODIFY,
        requestHeaders: [{ header: "Referer", operation: op("remove") }],
      },
      condition: {
        requestDomains: trackers,
        domainType: "thirdParty" as chrome.declarativeNetRequest.DomainType,
        ...unless("referrer", ["excludedInitiatorDomains"]),
      },
    });
  }
  if (trackers.length > 0 && featureActive(settings, "cookies", null)) {
    rules.push({
      id: TRACKER_COOKIES_RULE_ID,
      priority: PRIVACY_PRIORITY,
      action: {
        type: MODIFY,
        requestHeaders: [{ header: "Cookie", operation: op("remove") }],
        responseHeaders: [{ header: "Set-Cookie", operation: op("remove") }],
      },
      condition: {
        requestDomains: trackers,
        domainType: "thirdParty" as chrome.declarativeNetRequest.DomainType,
        ...unless("cookies", ["excludedInitiatorDomains"]),
      },
    });
  }
  return rules;
}

// ----------------------------------------------------------------- cookies

/** First-party analytics and ad cookies whose lifetime is capped. */
export const TRACKING_COOKIES = [
  "_ga",
  "_ga_*",
  "_gid",
  "_gcl_*",
  "__utma",
  "__utmb",
  "__utmz",
  "_fbp",
  "_fbc",
  "_uetsid",
  "_uetvid",
  "_ttp",
  "_pin_unauth",
  "_hjSessionUser_*",
];

/** How long a tracking cookie may live: a week, as Safari allows script-set cookies. */
export const COOKIE_CAP_SECONDS = 7 * 24 * 60 * 60;

export function isTrackingCookie(name: string): boolean {
  return TRACKING_COOKIES.some((p) =>
    p.endsWith("*") ? name.startsWith(p.slice(0, -1)) : name === p,
  );
}

/**
 * The same cookie with its lifetime capped, to set in its place; `null`
 * when it is not a tracking cookie or already expires in time.
 */
export function cappedCookie(
  cookie: chrome.cookies.Cookie,
  nowSeconds: number,
): chrome.cookies.SetDetails | null {
  const limit = nowSeconds + COOKIE_CAP_SECONDS;
  if (
    !isTrackingCookie(cookie.name) ||
    cookie.session ||
    cookie.expirationDate === undefined ||
    cookie.expirationDate <= limit
  ) {
    return null;
  }
  const host = cookie.domain.replace(/^\./, "");
  const details: chrome.cookies.SetDetails = {
    url: `http${cookie.secure ? "s" : ""}://${host}${cookie.path}`,
    name: cookie.name,
    value: cookie.value,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    expirationDate: limit,
    storeId: cookie.storeId,
  };
  if (!cookie.hostOnly) {
    details.domain = cookie.domain;
  }
  // Firefox's: a cookie's partition (Total Cookie Protection) and, with
  // first-party isolation, its first party. Chrome has only the first.
  const extra = cookie as { partitionKey?: unknown; firstPartyDomain?: unknown };
  if (extra.partitionKey !== undefined && extra.partitionKey !== null) {
    (details as { partitionKey?: unknown }).partitionKey = extra.partitionKey;
  }
  if (typeof extra.firstPartyDomain === "string") {
    (details as { firstPartyDomain?: string }).firstPartyDomain = extra.firstPartyDomain;
  }
  return details;
}

/**
 * The registrable domain of a hostname (`news.example.co.uk` →
 * `example.co.uk`), with `suffixes` the two-label public suffixes the
 * compiler knows (suffixes.json). Fingerprint noise is seeded per such
 * site, so a site's subdomains agree.
 */
export function registrableDomain(host: string, suffixes: readonly string[]): string {
  const name = host.toLowerCase().replace(/\.$/, "");
  const labels = name.split(".");
  if (labels.length < 3 || /^\d+\.\d+\.\d+\.\d+$/.test(name) || name.includes(":")) {
    return name;
  }
  const lastTwo = labels.slice(-2).join(".");
  return labels.slice(suffixes.includes(lastTwo) ? -3 : -2).join(".");
}

// ------------------------------------------------------- CNAME uncloaking

/** An entry of uncloak.json, written by `sinkd compile`. */
export interface UncloakEntry {
  ruleset: string;
  /** Hosts its plain `||host^` block rules name. */
  block: string[];
  /** Hosts its unrestricted `@@||host^` and `@@||host^$cname` rules name. */
  exempt: string[];
  /** Hosts its `@@||host^$document` rules name. */
  documents: string[];
}

/** Whether `host`, or a parent of it, is in `hosts`. */
export function hasHost(hosts: ReadonlySet<string>, host: string): boolean {
  return hostAndParents(host).some((name) => hosts.has(name));
}

/** A host and the parents it is matched by (`a.b.example` → `b.example`, `example`). */
export function hostAndParents(host: string): string[] {
  const names = [host];
  for (let dot = host.indexOf("."); dot !== -1; dot = host.indexOf(".", dot + 1)) {
    names.push(host.slice(dot + 1));
  }
  return names;
}

const IPV4 = /^\d+\.\d+\.\d+\.\d+$/;

/**
 * Every ruleset's hosts from uncloak.json, as one map per kind from host to
 * a bit per ruleset, so a lookup costs one probe per label whatever the
 * number of rulesets.
 */
export class HostSets {
  readonly #bits = new Map<string, number>();
  readonly #kinds: Record<"block" | "exempt" | "documents", Map<string, number>> = {
    block: new Map(),
    exempt: new Map(),
    documents: new Map(),
  };

  constructor(entries: UncloakEntry[]) {
    for (const [i, entry] of entries.slice(0, 31).entries()) {
      const bit = 1 << i;
      this.#bits.set(entry.ruleset, bit);
      for (const kind of ["block", "exempt", "documents"] as const) {
        const map = this.#kinds[kind];
        for (const host of entry[kind]) {
          map.set(host, (map.get(host) ?? 0) | bit);
        }
      }
    }
  }

  /** The bits of the rulesets that are on. */
  mask(settings: Settings): number {
    let mask = 0;
    for (const [id, bit] of this.#bits) {
      if (!settings.disabledRulesets.includes(id)) mask |= bit;
    }
    return mask;
  }

  /** Whether a ruleset in `mask` names `host`, or a parent of it, as `kind`. */
  has(kind: "block" | "exempt" | "documents", host: string, mask: number): boolean {
    const map = this.#kinds[kind];
    return hostAndParents(host).some((name) => ((map.get(name) ?? 0) & mask) !== 0);
  }
}

/** A request as Firefox's webRequest reports it, as much as uncloaking needs. */
export interface UncloakRequest {
  url: string;
  type: string;
  /** The document that made the request. */
  documentUrl?: string;
  /** The frames above that document, the top-level page last. */
  frameAncestors?: { url: string }[];
  /** Whether the request goes through a proxy. */
  proxied: boolean;
}

/**
 * The hostname whose DNS alias to look up before `request` may go, or
 * `null` when uncloaking doesn't apply: the top-level page itself (as in
 * uBlock Origin), requests not made by a page, an IP address, a proxied
 * request (looking it up here would leak it to the local resolver), a
 * page where the feature is off or blocking is (pause, `$document`), and
 * hosts the lists name themselves: DNR acts on those already.
 */
export function uncloakCandidate(
  request: UncloakRequest,
  settings: Settings,
  sets: HostSets,
  mask: number,
): string | null {
  if (request.type === "main_frame" || request.proxied || request.documentUrl === undefined) {
    return null;
  }
  let host: string;
  try {
    const url = new URL(request.url);
    if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol)) return null;
    host = url.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return null;
  }
  if (host === "" || host.startsWith("[") || IPV4.test(host) || !host.includes(".")) {
    return null;
  }
  const pages = [request.documentUrl, ...(request.frameAncestors ?? []).map((a) => a.url)];
  for (const page of pages) {
    const site = siteOf(page);
    if (site === null) continue;
    if (!featureActive(settings, "cname", site) || sets.has("documents", site, mask)) {
      return null;
    }
  }
  if (sets.has("block", host, mask) || sets.has("exempt", host, mask)) {
    return null;
  }
  return host;
}

/**
 * Whether `host`, whose DNS alias (canonical name) is `canonical`, is to be
 * blocked: the alias is a host the lists block and don't exempt, on
 * another site (an alias within the same site, `www.example.com` →
 * `example.com`, is not cloaking).
 */
export function aliasBlocked(
  host: string,
  canonical: string | undefined,
  sets: HostSets,
  mask: number,
  suffixes: readonly string[],
): boolean {
  const alias = (canonical ?? "").toLowerCase().replace(/\.$/, "");
  if (alias === "" || alias === host) {
    return false;
  }
  if (registrableDomain(alias, suffixes) === registrableDomain(host, suffixes)) {
    return false;
  }
  return sets.has("block", alias, mask) && !sets.has("exempt", alias, mask);
}

/** Longest class or id token the worker accepts; and tokens per message. */
export const MAX_TOKEN_LENGTH = 256;
export const MAX_TOKENS_PER_MESSAGE = 1000;

/** Messages from the content script. Pages can't send these, but a
 * compromised renderer can, so they are checked like any input. */
export type ContentRequest =
  | { type: "page" }
  | { type: "generic"; tokens: string[]; always: boolean }
  | { type: "seed" };

export function parseContentRequest(raw: unknown): ContentRequest | null {
  if (typeof raw !== "object" || raw === null) {
    return null;
  }
  const value = raw as Record<string, unknown>;
  if (value.type === "page" || value.type === "seed") {
    return { type: value.type };
  }
  if (value.type === "generic" && Array.isArray(value.tokens)) {
    const tokens = value.tokens
      .slice(0, MAX_TOKENS_PER_MESSAGE)
      .filter(
        (t): t is string =>
          typeof t === "string" &&
          t.length > 1 &&
          t.length <= MAX_TOKEN_LENGTH &&
          (t.startsWith(".") || t.startsWith("#")) &&
          !/\s/.test(t),
      );
    return { type: "generic", tokens, always: value.always === true };
  }
  return null;
}

/**
 * The hostname a frame's cosmetic rules are looked up by. A frame without
 * a URL of its own (about:blank, srcdoc, blob:) goes by its origin.
 */
export function frameHost(url: string | undefined, origin: string | undefined): string | null {
  for (const candidate of [url, origin]) {
    if (!candidate) continue;
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
        if (host !== "" && !host.startsWith("[")) return host;
      }
    } catch {
      // Not a URL; try the next.
    }
  }
  return null;
}

/**
 * Where a frame's cosmetic CSS goes: its document where the browser names
 * documents (Chrome), else its frame (Firefox). `null` without a tab.
 */
export function cssTarget(sender: {
  tab?: { id?: number | undefined } | undefined;
  documentId?: string | undefined;
  frameId?: number | undefined;
}): chrome.scripting.InjectionTarget | null {
  const tabId = sender.tab?.id;
  if (tabId === undefined) {
    return null;
  }
  if (sender.documentId !== undefined) {
    return { tabId, documentIds: [sender.documentId] };
  }
  return sender.frameId === undefined ? null : { tabId, frameIds: [sender.frameId] };
}

/**
 * Whether a frame is exempt from cosmetic filtering: its tab's site or its
 * own site is paused. The same as the pause rule in DNR, which allows a
 * paused page and everything in it, and a paused site's frames anywhere.
 */
export function framePaused(settings: Settings, tabUrl: string | undefined, host: string): boolean {
  const tabSite = tabUrl ? siteOf(tabUrl) : null;
  const site = host.startsWith("www.") ? host.slice(4) : host;
  return (tabSite !== null && isPaused(settings, tabSite)) || isPaused(settings, site);
}

/** Messages from the popup to the service worker. */
export type Request =
  | { type: "state"; url: string }
  | { type: "bridgeConnect" }
  | { type: "bridgeDisconnect" }
  | { type: "setSite"; site: string; paused: boolean }
  | { type: "setRuleset"; id: string; enabled: boolean }
  | { type: "setFeature"; id: FeatureId; enabled: boolean }
  | { type: "setSiteException"; feature: FeatureId; site: string; off: boolean };

// --------------------------------------------------------------- the bridge

/** The native-messaging host (`sinkd native-host`, crates/cli/src/bridge.rs). */
export const BRIDGE_HOST = "io.github.nald0422.sinkd";
export const BRIDGE_ALLOW_RULE_ID = 10;
export const BRIDGE_BLOCK_RULE_ID = 11;
/** `*.example.com` entries need a regex rule each, numbered from here. */
export const BRIDGE_REGEX_FIRST = 100;
/** Regex rules come from a small shared quota (1000 per extension). */
export const BRIDGE_MAX_REGEX = 200;
/** As many entries as the host sends at most. */
export const BRIDGE_MAX_ENTRIES = 5000;
/** Every rule id the bridge may use, to clear them all at once. */
export const BRIDGE_RULE_IDS = [
  BRIDGE_ALLOW_RULE_ID,
  BRIDGE_BLOCK_RULE_ID,
  ...Array.from({ length: BRIDGE_MAX_REGEX }, (_, i) => BRIDGE_REGEX_FIRST + i),
];
/**
 * The blocklist sits just under the allowlist and the pause, which win, as
 * the resolver's allowlist beats its blocklists; and above every compiled
 * rule, so a list's `@@` exception does not undo it.
 */
export const BRIDGE_BLOCK_PRIORITY = USER_PRIORITY - 1;

/** What the bridge last said, and whether it is connected. */
export interface Bridge {
  connected: boolean;
  /** Why the last connection failed or ended. */
  error: string | null;
  /** Whether a resolver answered the host. */
  running: boolean;
  /** The resolver's pause: `null` when it isn't paused; `until` is when it
   * ends (ms since the epoch), `null` until resumed. */
  paused: { until: number | null } | null;
  /** The resolver's local entries: `example.com`, or `*.example.com`. */
  allow: string[];
  block: string[];
  truncated: boolean;
}

export const NO_BRIDGE: Bridge = {
  connected: false,
  error: null,
  running: false,
  paused: null,
  allow: [],
  block: [],
  truncated: false,
};

const LABEL = "[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?";
const BRIDGE_ENTRY = new RegExp(`^(?:\\*\\.)?${LABEL}(?:\\.${LABEL})*$`);

function bridgeEntries(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) {
    return null;
  }
  return [
    ...new Set(
      raw
        .slice(0, BRIDGE_MAX_ENTRIES)
        .filter(
          (e): e is string => typeof e === "string" && e.length <= 255 && BRIDGE_ENTRY.test(e),
        ),
    ),
  ].sort();
}

/**
 * A state message from the host, checked field by field. `null` for
 * anything else: the host is trusted to report, never to command.
 */
export function parseBridgeMessage(raw: unknown): Omit<Bridge, "connected" | "error"> | null {
  if (typeof raw !== "object" || raw === null) {
    return null;
  }
  const value = raw as Record<string, unknown>;
  if (value.type !== "state") {
    return null;
  }
  const allow = bridgeEntries(value.allow);
  const block = bridgeEntries(value.block);
  if (allow === null || block === null) {
    return null;
  }
  let paused: Bridge["paused"] = null;
  if (typeof value.paused === "object" && value.paused !== null) {
    const until = (value.paused as Record<string, unknown>).until_ms;
    paused = {
      until: typeof until === "number" && Number.isFinite(until) && until > 0 ? until : null,
    };
  }
  return {
    running: value.running === true,
    paused,
    allow,
    block,
    truncated: value.truncated === true,
  };
}

/** The stored bridge state, cleaned up. */
export function normalizeBridge(raw: unknown): Bridge {
  const parsed = parseBridgeMessage({ ...(raw as object), type: "state" });
  if (parsed === null) {
    return NO_BRIDGE;
  }
  const value = raw as Record<string, unknown>;
  const paused = (value.paused as Bridge["paused"]) ?? null;
  return {
    ...parsed,
    paused:
      paused && (paused.until === null || typeof paused.until === "number")
        ? { until: paused.until }
        : null,
    connected: value.connected === true,
    error: typeof value.error === "string" ? value.error : null,
  };
}

/** Whether the resolver's pause is in force at `now`. */
export function bridgePaused(bridge: Bridge, now: number): boolean {
  return (
    bridge.connected &&
    bridge.paused !== null &&
    (bridge.paused.until === null || bridge.paused.until > now)
  );
}

/** Settings as they apply now: with the resolver's pause, if any. */
export function effectiveSettings(settings: Settings, bridge: Bridge, now: number): Settings {
  return bridgePaused(bridge, now) ? { ...settings, pausedAll: true } : storedSettings(settings);
}

const escapeRegex = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The dynamic rules for the resolver's local allowlist and blocklist. A
 * plain entry covers the name and everything below it (`requestDomains`
 * does too); a `*.` entry only the names below it, which needs a regex.
 * Regex rules beyond the quota are left out.
 */
export function bridgeRules(bridge: Bridge, browser: Browser = "chrome"): DnrRule[] {
  const resourceTypes = browser === "chrome" ? [...EVERY_TYPE, ...CHROME_ONLY_TYPES] : EVERY_TYPE;
  const rules: DnrRule[] = [];
  let regexId = BRIDGE_REGEX_FIRST;
  const add = (entries: string[], id: number, type: "allow" | "block", priority: number) => {
    const domains = entries.filter((e) => !e.startsWith("*."));
    if (domains.length > 0) {
      rules.push({
        id,
        priority,
        action: { type: type as chrome.declarativeNetRequest.RuleActionType },
        condition: { requestDomains: domains, resourceTypes },
      });
    }
    for (const entry of entries.filter((e) => e.startsWith("*."))) {
      if (regexId >= BRIDGE_REGEX_FIRST + BRIDGE_MAX_REGEX) {
        break;
      }
      rules.push({
        id: regexId++,
        priority,
        action: { type: type as chrome.declarativeNetRequest.RuleActionType },
        condition: {
          regexFilter: `^[a-z]+://[^/?#@]+\\.${escapeRegex(entry.slice(2))}(?::[0-9]+)?(?:[/?#]|$)`,
          resourceTypes,
        },
      });
    }
  };
  // The allowlist first, so it has the regex quota if it comes to that.
  add(bridge.allow, BRIDGE_ALLOW_RULE_ID, "allow", USER_PRIORITY);
  add(bridge.block, BRIDGE_BLOCK_RULE_ID, "block", BRIDGE_BLOCK_PRIORITY);
  return rules;
}

/** Whether `host` is on the resolver's allowlist, as the bridge reported it. */
export function bridgeAllows(bridge: Bridge, host: string): boolean {
  return bridge.allow.some((entry) =>
    entry.startsWith("*.")
      ? host.endsWith(entry.slice(1))
      : host === entry || host.endsWith(`.${entry}`),
  );
}

/** What the popup shows. */
export interface State {
  site: string | null;
  paused: boolean;
  rulesets: (RulesetInfo & { on: boolean })[];
  /** Static rules Chrome can still give this extension. */
  availableStaticRules: number;
  /** The page engine, once loaded: how long it took and the index size. */
  page: { initMs: number; indexBytes: number } | null;
  features: {
    id: FeatureId;
    name: string;
    description: string;
    perSite: boolean;
    /** On everywhere (not switched off). */
    on: boolean;
    /** Switched off for this site alone. */
    offHere: boolean;
  }[];
  /** Set when something else (policy, another extension) controls the WebRTC setting. */
  webrtcBlockedBy: string | null;
  /** The bridge to the sinkd command line; `granted` once the user allowed it. */
  bridge: Bridge & { granted: boolean; supported: boolean };
}

// ------------------------------------------------------------------ the log
//
// The toolbar badge is Chrome's own count (displayActionCountAsBadgeText):
// each time one of sinkd's rules did something to a request in the tab. A
// block, a redirect, a scheme upgrade and a header change all count, so the
// Global Privacy Control header, sent with every request, counts on every
// request. Allow rules change nothing, and the badge leaves them out.
// getMatchedRules lists the same matches plus the allow rules; without
// those, the log adds up to the badge. Chrome names the rule that acted,
// not the request, so each line says what its rule targets.

/** Chrome's name for the dynamic rules in a match. */
export const DYNAMIC_RULESET = "_dynamic";
/** Chrome's name for the session rules in a match. */
export const SESSION_RULESET = "_session";

/** What a rule did to a request. */
export type LogAction = "blocked" | "replaced" | "cleaned" | "upgraded" | "headers" | "other";

/** The kinds of action, in the order the log shows them. */
export const LOG_ACTIONS: readonly { id: LogAction; name: string }[] = [
  { id: "blocked", name: "Blocked" },
  { id: "replaced", name: "Replaced" },
  { id: "cleaned", name: "Cleaned" },
  { id: "upgraded", name: "Upgraded" },
  { id: "headers", name: "Headers" },
  { id: "other", name: "Other" },
];

/** A rule match, as getMatchedRules reports it. */
export interface Match {
  rulesetId: string;
  ruleId: number;
  /** When it matched, in ms since the epoch. */
  timeStamp: number;
}

/** What a rule does, in words. */
export interface RuleSummary {
  action: LogAction;
  /** What it acts on: a host, an address pattern, "every request". */
  target: string;
  /** What it does there; empty for a block, which says it all. */
  detail: string;
}

/** One line of the log: one rule, and how often it acted. */
export interface LogEntry extends RuleSummary {
  /** `<ruleset>#<rule id>` */
  key: string;
  /** The switch it belongs to: a ruleset's name, or a feature's. */
  source: string;
  count: number;
  /** When it last acted, in ms since the epoch. */
  last: number;
}

export const ruleKey = (rulesetId: string, ruleId: number): string => `${rulesetId}#${ruleId}`;

const count = (n: number): string => n.toLocaleString("en-US");

/** A list in words: "a", "a and b", "a, b and c", "a, b, c and 4 more". */
export function inWords(items: readonly string[], max = 3): string {
  if (items.length <= 1) {
    return items[0] ?? "";
  }
  if (items.length > max) {
    return `${items.slice(0, max).join(", ")} and ${count(items.length - max)} more`;
  }
  return `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}

/** What a rule's condition matches, as briefly as it can be said. */
export function ruleTarget(condition: DnrCondition): string {
  if (condition.urlFilter) {
    // `||host^` and `|https://…|` read better without their anchors.
    const plain = condition.urlFilter.replace(/^\|\|?/, "").replace(/\^?\|?$/, "");
    if (plain !== "") {
      return plain;
    }
  }
  if (condition.regexFilter) {
    return condition.regexFilter;
  }
  const domains = condition.requestDomains ?? [];
  if (domains.length > 0) {
    return domains.length <= 3 ? inWords(domains) : `one of ${count(domains.length)} sites`;
  }
  const types = (condition.resourceTypes ?? []) as string[];
  if (types.length > 0 && types.every((t) => t === "main_frame" || t === "sub_frame")) {
    return "pages";
  }
  return "every request";
}

/** "set-cookie" → "Set-Cookie"; a name already in capitals stays as it is. */
const headerName = (name: string): string =>
  HEADER_SPELLINGS[name] ??
  (name === name.toLowerCase()
    ? name.replace(/(^|-)([a-z])/g, (_, dash: string, c: string) => dash + c.toUpperCase())
    : name);
/** Headers whose usual spelling isn't the capitalized words. */
const HEADER_SPELLINGS: Record<string, string> = { "sec-gpc": "Sec-GPC", dnt: "DNT" };

/** What a modifyHeaders action does, in words. */
function headerChanges(action: chrome.declarativeNetRequest.RuleAction): string {
  const removed: string[] = [];
  const changes: string[] = [];
  const read = (
    headers: chrome.declarativeNetRequest.ModifyHeaderInfo[] | undefined,
    request: boolean,
  ) => {
    for (const h of headers ?? []) {
      const name = headerName(h.header);
      switch (h.operation as string) {
        case "remove":
          removed.push(name);
          break;
        case "set":
          changes.push(`${request ? "Sent" : "Set"} ${name}: ${h.value ?? ""}`);
          break;
        default:
          changes.push(`Added to ${name}`);
      }
    }
  };
  read(action.requestHeaders, true);
  read(action.responseHeaders, false);
  if (removed.length > 0) {
    changes.unshift(`Removed ${inWords(removed)}`);
  }
  return changes.join("; ") || "Changed headers";
}

/** The harmless file a redirect serves instead, by its extension. */
function standIn(path: string): string {
  if (path.endsWith(".js")) return "Stand-in script";
  if (path.endsWith(".html")) return "Blank page";
  if (/\.(gif|png|jpe?g|svg)$/.test(path)) return "Blank image";
  if (/\.(mp3|mp4|webm)$/.test(path)) return "Silent media";
  return "Empty response";
}

/** What `rule` does, or `null` for an allow rule, which does nothing. */
export function describeRule(rule: DnrRule): RuleSummary | null {
  const action = rule.action;
  const target = ruleTarget(rule.condition);
  switch (action.type as string) {
    case "block":
      return { action: "blocked", target, detail: "" };
    case "redirect": {
      const redirect = action.redirect ?? {};
      const params = redirect.transform?.queryTransform?.removeParams ?? [];
      if (params.length > 0) {
        // The general rule names over a hundred; a site's own, one or two.
        const detail =
          params.length <= 3 ? `Removed ${inWords(params)}` : "Removed tracking parameters";
        return { action: "cleaned", target, detail };
      }
      if (redirect.transform?.query === "") {
        return { action: "cleaned", target, detail: "Removed the query string" };
      }
      if (redirect.extensionPath) {
        return {
          action: "replaced",
          target,
          detail: standIn(redirect.extensionPath),
        };
      }
      return { action: "replaced", target, detail: "Redirected" };
    }
    case "upgradeScheme":
      return { action: "upgraded", target, detail: "Switched to HTTPS" };
    case "modifyHeaders":
      return { action: "headers", target, detail: headerChanges(action) };
    default:
      return null;
  }
}

/**
 * The hosts in `hosts` that a rule's domain list covers: which of the
 * names on the page a rule like "one of 43,479 sites" acted on. `hosts`
 * are the ones the tab's frames loaded from or point elements at.
 */
export function hitHosts(condition: DnrCondition, hosts: readonly string[]): string[] {
  const listed = new Set(condition.requestDomains ?? []);
  const excluded = new Set(condition.excludedRequestDomains ?? []);
  const covered = (host: string, names: Set<string>) =>
    hostAndParents(host).some((name) => names.has(name));
  return [...new Set(hosts)]
    .filter((host) => covered(host, listed) && !covered(host, excluded))
    .sort();
}

/** The feature each privacy rule belongs to. */
const PRIVACY_RULE_FEATURES: Record<number, FeatureId> = {
  [GPC_RULE_ID]: "gpc",
  [REFERRER_POLICY_RULE_ID]: "referrer",
  [TRACKER_REFERER_RULE_ID]: "referrer",
  [TRACKER_COOKIES_RULE_ID]: "cookies",
};

/** The switch a matched rule belongs to, by name. */
export function logSource(
  rulesetId: string,
  ruleId: number,
  rulesetNames: ReadonlyMap<string, string>,
): string {
  if (rulesetId !== DYNAMIC_RULESET) {
    return rulesetNames.get(rulesetId) ?? "sinkd";
  }
  const feature = PRIVACY_RULE_FEATURES[ruleId];
  if (feature) {
    return FEATURES.find((f) => f.id === feature)?.name ?? "sinkd";
  }
  return BRIDGE_RULE_IDS.includes(ruleId) ? "sinkd on this computer" : "sinkd";
}

/**
 * The privacy rules as they are with every feature on, for matches of one
 * that has since been switched off: the badge still counts those.
 */
let privacyRulesOn: Map<number, DnrRule> | undefined;
const privacyRuleOn = (id: number): DnrRule | undefined => {
  privacyRulesOn ??= new Map(
    privacyRules(normalizeSettings(undefined), ["tracker.invalid"]).map((r) => [r.id, r]),
  );
  return privacyRulesOn.get(id);
};

/** What a dynamic rule that matched, and is gone now, did. */
function goneRule(match: Match): RuleSummary | null {
  if (match.rulesetId === DYNAMIC_RULESET) {
    if (match.ruleId === PAUSE_RULE_ID || match.ruleId === BRIDGE_ALLOW_RULE_ID) {
      return null;
    }
    const privacy = privacyRuleOn(match.ruleId);
    if (privacy) {
      return describeRule(privacy);
    }
  }
  return { action: "other", target: `rule ${match.ruleId}`, detail: "Since switched off" };
}

/**
 * The log: the tab's matches (getMatchedRules), one entry per rule that
 * acted, allow rules left out. `rules` holds the rules by ruleKey; a rule
 * that isn't there any more is still counted, as the badge counts it. A
 * rule over a list of domains is named by the page's hosts it covers
 * (`pageHosts`, see hitHosts). Ordered by action (LOG_ACTIONS), then most
 * recent first.
 */
export function logEntries(
  matches: readonly Match[],
  rules: ReadonlyMap<string, DnrRule>,
  rulesetNames: ReadonlyMap<string, string>,
  pageHosts: readonly string[] = [],
): LogEntry[] {
  // A host that a matched rule names outright (`||host/path`) went to that
  // rule, so a rule over a list of domains acted on the page's other hosts.
  // Better "one of 43,479 sites" than a wrong name.
  const named = new Set(
    matches.flatMap((m) => {
      const filter = rules.get(ruleKey(m.rulesetId, m.ruleId))?.condition.urlFilter;
      const host = filter?.match(/^\|\|([a-z0-9.-]+)/i)?.[1]?.toLowerCase();
      return host ? [host] : [];
    }),
  );
  const unnamed = pageHosts.filter((h) => !hostAndParents(h).some((name) => named.has(name)));
  const entries = new Map<string, LogEntry | null>();
  for (const match of matches) {
    const key = ruleKey(match.rulesetId, match.ruleId);
    let entry = entries.get(key);
    if (entry === undefined) {
      const rule = rules.get(key);
      const summary = rule ? describeRule(rule) : goneRule(match);
      const condition = rule?.condition;
      const hits =
        condition && !condition.urlFilter && !condition.regexFilter
          ? hitHosts(condition, unnamed)
          : [];
      const trackerRule =
        match.rulesetId === DYNAMIC_RULESET &&
        (match.ruleId === TRACKER_COOKIES_RULE_ID || match.ruleId === TRACKER_REFERER_RULE_ID);
      entry =
        summary === null
          ? null
          : {
              ...summary,
              ...(hits.length > 0
                ? { target: inWords(hits) }
                : // The tracker list is tens of thousands of names.
                  trackerRule
                  ? { target: "known trackers" }
                  : {}),
              key,
              source: logSource(match.rulesetId, match.ruleId, rulesetNames),
              count: 0,
              last: 0,
            };
      entries.set(key, entry);
    }
    if (entry) {
      entry.count += 1;
      entry.last = Math.max(entry.last, match.timeStamp);
    }
  }
  const order = (a: LogAction) => LOG_ACTIONS.findIndex((x) => x.id === a);
  return [...entries.values()]
    .filter((e): e is LogEntry => e !== null)
    .sort((a, b) => order(a.action) - order(b.action) || b.last - a.last);
}

// ------------------------------------------------------------- the console
//
// The log, live. On opening, the popup reads what sinkd did on the page so
// far (logEntries); from then on it watches the tab's requests through
// webRequest, which sees what the browser's rules did to each one:
// - a block fails with ERR_BLOCKED_BY_CLIENT;
// - a stand-in is a redirect into the extension;
// - a cleaned link is a redirect to the same address, less some parameters;
// - a header change is a difference between a request's headers before the
//   rules ran and as sent (or a response's, as received and as passed on).
// Each of these is one rule match, so the total goes on matching the badge.
// Unlike the earlier matches, these lines have the request's address.

/** One line of the console. */
export interface ConsoleLine {
  action: LogAction;
  /** The address; for a match from before the popup opened, what its rule targets. */
  text: string;
  /** What was done, where the tag doesn't say it all. */
  detail: string;
  /** The same, in a few characters before the text: "+Sec-GPC", "−fbclid". */
  mark: string;
  /** The switch it belongs to, when it's known. */
  source: string;
  /** When, in ms since the epoch. */
  at: number;
  /** How many times: earlier matches of one rule, or the same line in a row. */
  count: number;
  /** Seen as it happened, rather than read back from the browser. */
  live: boolean;
}

/** The error a request blocked by an extension's rules fails with. */
export const BLOCKED_ERROR = "net::ERR_BLOCKED_BY_CLIENT";

/** Each action's tag in the console, five characters at most. */
export const CONSOLE_TAGS: Record<LogAction, string> = {
  blocked: "block",
  replaced: "stub",
  cleaned: "clean",
  upgraded: "https",
  headers: "hdr",
  other: "misc",
};

/** Targets that say nothing about one request. */
const GENERAL_TARGETS = ["every request", "pages"];

/**
 * The matches from before the popup opened, as console lines, oldest first.
 * Most lead with what was hit; header changes and rules over every request,
 * with what was done.
 */
export function earlierLines(entries: readonly LogEntry[]): ConsoleLine[] {
  return entries
    .map((e) => {
      const byDetail =
        e.action === "headers" || e.action === "other" || GENERAL_TARGETS.includes(e.target);
      return {
        action: e.action,
        text: byDetail ? e.detail : e.target,
        detail: byDetail ? e.target : e.detail,
        mark: "",
        source: e.source,
        at: e.last,
        count: e.count,
        live: false,
      };
    })
    .sort((a, b) => a.at - b.at);
}

/** An address as the console shows it: without the scheme. */
export const shortUrl = (url: string): string => url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");

/**
 * The parameters a redirect took off an address, or `null` if it did
 * anything else: another path, another host, a changed value.
 */
export function removedParams(from: string, to: string): string[] | null {
  let a: URL;
  let b: URL;
  try {
    a = new URL(from);
    b = new URL(to);
  } catch {
    return null;
  }
  if (a.origin !== b.origin || a.pathname !== b.pathname || a.hash !== b.hash) {
    return null;
  }
  const kept = new Set(b.searchParams.keys());
  for (const key of kept) {
    if (a.searchParams.getAll(key).join("\n") !== b.searchParams.getAll(key).join("\n")) {
      return null;
    }
  }
  const removed = [...new Set(a.searchParams.keys())].filter((key) => !kept.has(key));
  return removed.length > 0 ? removed : null;
}

const liveLine = (
  action: LogAction,
  url: string,
  detail: string,
  source: string,
  at: number,
  mark = "",
): ConsoleLine => ({ action, text: shortUrl(url), detail, mark, source, at, count: 1, live: true });

/** A stand-in's address (war/ in the package), with its path. */
const STAND_IN_URL = /^(?:chrome|moz)-extension:\/\/[^/]+(\/war\/[^?#]*)/;

/** Whether a request is for one of the extension's own files. */
export const isExtensionUrl = (url: string): boolean => /^(?:chrome|moz)-extension:/.test(url);

/** A blocked request's line, from webRequest's onErrorOccurred. */
export function blockedLine(url: string, error: string, at: number): ConsoleLine | null {
  return error === BLOCKED_ERROR ? liveLine("blocked", url, "", "", at) : null;
}

/**
 * A redirect's line, from webRequest's onBeforeRedirect: a stand-in from
 * the extension, or a cleaned link. Other redirects (the site's own, HSTS)
 * aren't sinkd's.
 */
export function redirectLine(
  url: string,
  redirectUrl: string,
  at: number,
  paramsSource = "Tracking parameters",
): ConsoleLine | null {
  // The stand-ins are web-accessible with use_dynamic_url, so a redirect
  // goes to a random per-session host, not the extension's id.
  const standInPath = redirectUrl.match(STAND_IN_URL)?.[1];
  if (standInPath) {
    return liveLine("replaced", url, standIn(standInPath), "", at);
  }
  const removed = removedParams(url, redirectUrl);
  if (removed === null) {
    return null;
  }
  const detail =
    removed.length <= 3 ? `Removed ${inWords(removed)}` : "Removed tracking parameters";
  const mark =
    removed.length <= 2 ? removed.map((p) => `−${p}`).join(" ") : `−${removed.length} params`;
  return liveLine("cleaned", url, detail, paramsSource, at, mark);
}

/** The feature each header sinkd changes belongs to. */
const HEADER_FEATURES: Record<string, FeatureId> = {
  "sec-gpc": "gpc",
  referer: "referrer",
  "referrer-policy": "referrer",
  cookie: "cookies",
  "set-cookie": "cookies",
};

type HeaderList = readonly { name: string; value?: string | undefined }[];

/**
 * The header changes between `before` and `after`, one line each: the
 * request's headers before the rules ran and as sent (`request`), or the
 * response's as received and as passed on.
 */
export function headerLines(
  url: string,
  before: HeaderList,
  after: HeaderList,
  request: boolean,
  at: number,
): ConsoleLine[] {
  // As the browser spells them ("Sec-GPC"), when it does; matched by lowercase.
  const spelled = new Map<string, string>();
  const byName = (headers: HeaderList) => {
    const map = new Map<string, string>();
    for (const h of headers) {
      const name = h.name.toLowerCase();
      if (!spelled.has(name) || h.name !== name) spelled.set(name, headerName(h.name));
      map.set(name, map.has(name) ? `${map.get(name)}\n${h.value ?? ""}` : (h.value ?? ""));
    }
    return map;
  };
  const was = byName(before);
  const now = byName(after);
  const display = (name: string) => spelled.get(name) ?? headerName(name);
  const source = (name: string) => {
    const feature = HEADER_FEATURES[name];
    return FEATURES.find((f) => f.id === feature)?.name ?? "sinkd";
  };
  const lines: ConsoleLine[] = [];
  const change = (name: string, detail: string, mark: string) =>
    lines.push(liveLine("headers", url, detail, source(name), at, `${mark}${display(name)}`));
  for (const [name, value] of now) {
    if (!was.has(name)) {
      change(name, `${request ? "Sent" : "Added"} ${display(name)}: ${value}`, "+");
    } else if (was.get(name) !== value) {
      change(name, `Set ${display(name)}: ${value}`, "~");
    }
  }
  for (const name of was.keys()) {
    if (!now.has(name)) {
      change(name, `Removed ${display(name)}`, "−");
    }
  }
  return lines;
}

/** Whether two lines say the same thing, so the second only adds to the count. */
export const sameLine = (a: ConsoleLine, b: ConsoleLine): boolean =>
  a.live === b.live &&
  a.action === b.action &&
  a.text === b.text &&
  a.detail === b.detail &&
  a.source === b.source;

/** A time of day as the console shows it: 14:02:11. */
export function clock(at: number): string {
  const d = new Date(at);
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
}

// ------------------------------------------------------------- new tabs
//
// Pages open ad tabs (window.open, target=_blank, a click handler), and DNR
// cannot act on a tab being opened, only on requests. So the background
// checks each tab a page opens against the lists' `$popup` rules, which
// `sinkd compile` writes to popups.json in DNR's shape, and closes the tab
// if they block it, as uBlock Origin does. Matching follows DNR: the
// highest priority wins, and an allow beats a block of the same priority.
// `initiatorDomains` names the page that opened the tab.

/** An entry of popups.json: a ruleset's rules for new tabs. */
export interface PopupRules {
  ruleset: string;
  rules: DnrRule[];
}

/** DNR's separator `^`: anything but a letter, a digit or `_-.%`, or the end. */
const SEPARATOR = "(?:[^a-zA-Z0-9_.%-]|$)";

/** A DNR `urlFilter` as a regular expression, with its anchors and wildcards. */
export function urlFilterRegExp(filter: string, caseSensitive = false): RegExp {
  let body = filter;
  let start = "";
  let end = "";
  if (body.startsWith("||")) {
    // The start of the host or of one of its labels.
    start = "^[a-z][a-z0-9+.-]*:\\/\\/(?:[^/?#@]*@)?(?:[^/?#]*\\.)?";
    body = body.slice(2);
  } else if (body.startsWith("|")) {
    start = "^";
    body = body.slice(1);
  }
  if (body.endsWith("|")) {
    end = "$";
    body = body.slice(0, -1);
  }
  const source = [...body]
    .map((c) =>
      c === "*" ? ".*" : c === "^" ? SEPARATOR : c.replace(/[.+?${}()|[\]\\/]/g, "\\$&"),
    )
    .join("");
  return new RegExp(start + source + end, caseSensitive ? "" : "i");
}

/** A rule made ready to match: its address test, and its domain lists as sets. */
interface PopupMatcher {
  address: RegExp | null;
  to: Set<string> | null;
  notTo: Set<string>;
  from: Set<string> | null;
  notFrom: Set<string>;
}

const popupMatchers = new WeakMap<DnrRule, PopupMatcher | null>();

function popupMatcher(rule: DnrRule): PopupMatcher | null {
  let matcher = popupMatchers.get(rule);
  if (matcher === undefined) {
    const c = rule.condition;
    const sensitive = c.isUrlFilterCaseSensitive === true;
    try {
      matcher = {
        address: c.regexFilter
          ? new RegExp(c.regexFilter, sensitive ? "" : "i")
          : c.urlFilter
            ? urlFilterRegExp(c.urlFilter, sensitive)
            : null,
        to: c.requestDomains ? new Set(c.requestDomains) : null,
        notTo: new Set(c.excludedRequestDomains ?? []),
        from: c.initiatorDomains ? new Set(c.initiatorDomains) : null,
        notFrom: new Set(c.excludedInitiatorDomains ?? []),
      };
    } catch {
      // A regex JavaScript can't read (RE2 differs at the edges): skip it.
      matcher = null;
    }
    popupMatchers.set(rule, matcher);
  }
  return matcher;
}

const inSet = (host: string, set: Set<string>) => hostAndParents(host).some((h) => set.has(h));

/**
 * Whether `rule` applies to a tab opened at `url` by a page at `openerHost`
 * (`null` when no page opened it, or it can't be told). `sites` gives the
 * registrable domain of a host, for `domainType`.
 */
export function popupRuleMatches(
  rule: DnrRule,
  url: URL,
  openerHost: string | null,
  sites: (host: string) => string,
): boolean {
  const m = popupMatcher(rule);
  if (m === null) {
    return false;
  }
  const host = url.hostname;
  if (m.to && !inSet(host, m.to)) return false;
  if (inSet(host, m.notTo)) return false;
  if (m.from && (openerHost === null || !inSet(openerHost, m.from))) return false;
  if (openerHost !== null && inSet(openerHost, m.notFrom)) return false;
  const party = rule.condition.domainType as string | undefined;
  if (party) {
    if (openerHost === null) return false;
    const third = sites(host) !== sites(openerHost);
    if ((party === "thirdParty") !== third) return false;
  }
  return m.address === null || m.address.test(url.href);
}

/**
 * Whether to close a tab opened at `url` by a page at `opener`: what the
 * enabled rulesets' popup rules decide. Never on a site where sinkd is off,
 * and only for web addresses (a tab opened blank is checked again once it
 * has one).
 */
export function closesPopup(
  url: string,
  opener: string | null,
  sets: readonly PopupRules[],
  settings: Settings,
  suffixes: readonly string[],
): boolean {
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return false;
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return false;
  }
  let openerHost: string | null = null;
  try {
    const page = opener ? new URL(opener) : null;
    if (page && (page.protocol === "http:" || page.protocol === "https:")) {
      openerHost = page.hostname;
    }
  } catch {
    // No page to speak of.
  }
  if (settings.pausedAll) {
    return false;
  }
  const openerSite = opener ? siteOf(opener) : null;
  if (openerSite !== null && isPaused(settings, openerSite)) {
    return false;
  }
  const sites = (host: string) => registrableDomain(host, suffixes);
  let best: { priority: number; allow: boolean } | null = null;
  for (const set of sets) {
    if (settings.disabledRulesets.includes(set.ruleset)) continue;
    for (const rule of set.rules) {
      const priority = rule.priority ?? 1;
      const allow = (rule.action.type as string) !== "block";
      if (best && (priority < best.priority || (priority === best.priority && !allow))) continue;
      if (popupRuleMatches(rule, target, openerHost, sites)) {
        best = { priority, allow };
      }
    }
  }
  return best !== null && !best.allow;
}

// ------------------------------------------------------------- the splash
//
// The popup opens on the mark putting itself together out of the web's
// junk, as the website's splash does, only quicker: a banner, a skyscraper
// and a rectangle at their standard proportions, and a tracking pixel, are
// pulled in and become the three contours and the clay low point. Then it
// fades, and the controls (loaded meanwhile) are there. The geometry, by
// time, is here; popup.ts draws it.

/** The mark on its 128 grid, as scripts/logo.mjs draws it. */
export const MARK = {
  radii: [43, 31, 19],
  cy: [62, 67, 72],
  low: 79.5,
  dot: 5.5,
  stroke: 3.6,
} as const;

/** The splash's timing, in ms: it is whole at `hold`, then fades for `fade`. */
export const SPLASH = {
  appear: 260,
  morphAt: 420,
  morph: 900,
  stagger: 110,
  pixel: 740,
  /** The wordmark rises in from `word`, for `wordFor`. */
  word: 1150,
  wordFor: 420,
  /** Whole by about 1570 ms, then still for 0.8 s, so the mark is seen. */
  hold: 2370,
  fade: 360,
} as const;

/** A shape of the splash: a rectangle by its centre, size, corners and turn. */
export interface SplashShape {
  cx: number;
  cy: number;
  w: number;
  h: number;
  rx: number;
  rot: number;
  strokeWidth: number;
  opacity: number;
}

/** Where the frames start: a 970×90 banner, a 160×600 skyscraper, a 300×250 rectangle. */
const SPLASH_FROM = [
  { cx: 64, cy: 18, w: 106, h: 20, rot: -4 },
  { cx: 109, cy: 80, w: 22, h: 72, rot: 6 },
  { cx: 24, cy: 94, w: 38, h: 32, rot: -8 },
] as const;
const SPLASH_PIXEL = { cx: 90, cy: 116, size: 4.4, rot: 18 };

const unit = (t: number) => Math.min(1, Math.max(0, t));
/** From `a` to `b`; exactly `b` at the end, so the finished mark is the mark. */
const mix = (a: number, b: number, t: number) => a * (1 - t) + b * t;
const outCubic = (t: number) => 1 - (1 - t) ** 3;
const inOutCubic = (t: number) => (t < 0.5 ? 4 * t ** 3 : 1 - (-2 * t + 2) ** 3 / 2);
/** Past the mark and back: something coming to rest. */
const comeToRest = (t: number) => 1 + 2.4 * (t - 1) ** 3 + 1.4 * (t - 1) ** 2;

/**
 * The splash `t` ms in: the three frames, then the pixel. Any `t` gives
 * finite numbers (before the start is the start, after `hold` is the
 * finished mark, anything else is the finished mark too), so a frame can
 * never come out broken.
 */
export function splashShapes(t: number): SplashShape[] {
  const time = Number.isFinite(t) ? Math.min(SPLASH.hold, Math.max(0, t)) : SPLASH.hold;
  const appear = unit(time / SPLASH.appear);
  const frames = SPLASH_FROM.map((from, i) => {
    const p = unit((time - SPLASH.morphAt - i * SPLASH.stagger) / SPLASH.morph);
    const e = comeToRest(p);
    const r = MARK.radii[i] ?? 0;
    return {
      cx: mix(from.cx, 64, e),
      cy: mix(from.cy, MARK.cy[i] ?? 0, e),
      w: mix(from.w, 2 * r, e),
      h: mix(from.h, 2 * r, e),
      rx: mix(1.5, r, inOutCubic(p)),
      rot: mix(from.rot, 0, outCubic(p)),
      strokeWidth: mix(1.3, MARK.stroke, outCubic(p)),
      opacity: appear,
    };
  });
  const q = unit((time - SPLASH.morphAt - SPLASH_FROM.length * SPLASH.stagger) / SPLASH.pixel);
  const e = comeToRest(q);
  const size = mix(SPLASH_PIXEL.size, 2 * MARK.dot, e);
  const pixel = {
    cx: mix(SPLASH_PIXEL.cx, 64, e),
    cy: mix(SPLASH_PIXEL.cy, MARK.low, e),
    w: size,
    h: size,
    rx: mix(0, MARK.dot, inOutCubic(q)),
    rot: mix(SPLASH_PIXEL.rot, 0, outCubic(q)),
    strokeWidth: 0,
    opacity: appear,
  };
  return [...frames, pixel];
}

/** The wordmark under the mark, `t` ms in: it rises into place as the mark finishes. */
export function splashWordmark(t: number): { opacity: number; rise: number } {
  const time = Number.isFinite(t) ? t : SPLASH.hold;
  const p = outCubic(unit((time - SPLASH.word) / SPLASH.wordFor));
  return { opacity: p, rise: 6 * (1 - p) };
}
