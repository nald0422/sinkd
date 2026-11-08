// The extension's decisions, as pure functions, so they can be tested
// without a browser. The background script and the popup only glue these
// to chrome.* APIs. Request matching happens in the browser's DNR engine,
// from the rulesets `sinkhole compile` produced; cosmetic matching in the
// Rust page engine (engine.ts); scriptlets pick their own calls by
// hostname. Firefox adds CNAME uncloaking, the one thing matched here.

/** An entry of rulesets.json, written by `sinkhole compile`. */
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
  /** Hostnames where sinkhole is off (and every name below them). */
  pausedSites: string[];
  /** Features switched off everywhere. */
  disabledFeatures: FeatureId[];
  /** Per feature, the sites where it is off (and every name below them). */
  siteExceptions: Partial<Record<FeatureId, string[]>>;
  /**
   * Runtime only, never stored: the resolver on this computer is paused
   * (`sinkhole pause`, through the bridge), so sinkhole is off everywhere.
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
 * a leading `www.`. `null` for pages sinkhole does not act on (extension
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
 * The dynamic rule that turns sinkhole off on the paused sites:
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

/** An entry of uncloak.json, written by `sinkhole compile`. */
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

/** The native-messaging host (`sinkhole native-host`, crates/cli/src/bridge.rs). */
export const BRIDGE_HOST = "sinkhole.bridge";
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
  /** The bridge to the sinkhole command line; `granted` once the user allowed it. */
  bridge: Bridge & { granted: boolean; supported: boolean };
}
