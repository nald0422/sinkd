// The background script (Chrome's service worker, Firefox's event page):
// applies the user's settings to the browser's DNR engine, the registered
// page scripts and the browser's WebRTC policy; caps the lifetime of
// tracking cookies; answers the popup; answers the content script with
// its page's cosmetic rules and fingerprint seed; and, once the user allows
// it, listens to the bridge to the sinkd command line. Requests are matched by
// the browser itself, from the static and dynamic rules. Only in Firefox
// does this script see requests: webRequest there uncloaks CNAMEs, and
// applies the header rules to navigations, which Firefox's DNR doesn't.
// It closes the ad tabs pages open, which no request rule can stop.

import {
  aliasBlocked,
  BRIDGE_HOST,
  BRIDGE_RULE_IDS,
  type Bridge,
  bridgeAllows,
  bridgeRules,
  browserOf,
  type ContentRequest,
  cappedCookie,
  closesPopup,
  cssTarget,
  effectiveSettings,
  FEATURES,
  featureActive,
  featureScripts,
  featuresFor,
  frameHost,
  framePaused,
  HostSets,
  hasHost,
  isExcepted,
  isPaused,
  type Navigation,
  NO_BRIDGE,
  navigationRequestHeaders,
  navigationResponseHeaders,
  normalizeBridge,
  normalizeSettings,
  PAUSE_RULE_ID,
  type PopupRules,
  PRIVACY_RULE_IDS,
  pageMask,
  parseBridgeMessage,
  parseContentRequest,
  pauseRule,
  privacyRules,
  type Request,
  type RulesetInfo,
  registrableDomain,
  rulesetChanges,
  type ScriptletEntry,
  type Settings,
  type State,
  scriptChanges,
  scriptletScripts,
  siteOf,
  storedSettings,
  type UncloakEntry,
  uncloakCandidate,
  withFeature,
  withRuleset,
  withSite,
  withSiteException,
} from "./core.js";
import { Engine } from "./engine.js";

const dnr = chrome.declarativeNetRequest;
const BROWSER = browserOf(chrome.runtime.getURL(""));

async function packaged<T>(path: string): Promise<T> {
  const response = await fetch(chrome.runtime.getURL(path));
  return (await response.json()) as T;
}

let rulesetsCache: Promise<RulesetInfo[]> | undefined;
const rulesets = (): Promise<RulesetInfo[]> => {
  rulesetsCache ??= packaged<RulesetInfo[]>("rulesets.json");
  return rulesetsCache;
};

let scriptletsCache: Promise<ScriptletEntry[]> | undefined;
const scriptletIndex = (): Promise<ScriptletEntry[]> => {
  scriptletsCache ??= packaged<ScriptletEntry[]>("scriptlets.json");
  return scriptletsCache;
};

let trackersCache: Promise<string[]> | undefined;
const trackers = (): Promise<string[]> => {
  trackersCache ??= packaged<string[]>("trackers.json");
  return trackersCache;
};

let popupsCache: Promise<PopupRules[]> | undefined;
/** The lists' `$popup` rules; none if the build has no popups.json. */
const popupRules = (): Promise<PopupRules[]> => {
  popupsCache ??= packaged<PopupRules[]>("popups.json").catch(() => []);
  return popupsCache;
};

let suffixesCache: Promise<string[]> | undefined;
const suffixes = (): Promise<string[]> => {
  suffixesCache ??= packaged<string[]>("suffixes.json");
  return suffixesCache;
};

/** The open connection to the bridge's host, in this worker. */
let port: chrome.runtime.Port | undefined;

// Every page load asks for settings, so they are kept in memory; storage
// changes (from this worker or another instance of it) refresh them.
// webRequest listeners answer synchronously when they can, from `settingsNow`.
// The settings in memory are the ones in effect: the user's, plus the
// resolver's pause when the bridge reports one.
let settingsCache: Promise<Settings> | undefined;
let settingsNow: Settings | undefined;
let bridgeNow: Bridge = NO_BRIDGE;
function loadSettings(): Promise<Settings> {
  settingsCache ??= chrome.storage.local.get(["settings", "bridge"]).then((stored) => {
    const bridge = normalizeBridge(stored.bridge);
    // Only a connection this worker holds counts: one that was open in a
    // worker that has since stopped can't still be pausing anything.
    bridgeNow = { ...bridge, connected: bridge.connected && port !== undefined };
    settingsNow = effectiveSettings(normalizeSettings(stored.settings), bridgeNow, Date.now());
    return settingsNow;
  });
  return settingsCache;
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && ("settings" in changes || "bridge" in changes)) {
    settingsCache = undefined;
    settingsNow = undefined;
  }
});

let engineStats: State["page"] = null;
let engineCache: Promise<Engine> | undefined;
/** The page engine, loaded once per worker lifetime. */
function engine(): Promise<Engine> {
  engineCache ??= (async () => {
    const started = performance.now();
    const [wasm, index] = await Promise.all(
      ["engine.wasm", "page/index.bin"].map((path) =>
        fetch(chrome.runtime.getURL(path)).then((r) => r.arrayBuffer()),
      ),
    );
    const loaded = await Engine.load(wasm as ArrayBuffer, new Uint8Array(index as ArrayBuffer));
    engineStats = {
      initMs: Math.round((performance.now() - started) * 10) / 10,
      indexBytes: (index as ArrayBuffer).byteLength,
    };
    return loaded;
  })();
  // A failed load is tried again on the next page rather than remembered.
  engineCache.catch(() => {
    engineCache = undefined;
  });
  return engineCache;
}

/** Registers exactly the page scripts wanted: scriptlet files of the
 * enabled rulesets, and the GPC and fingerprint scripts. */
async function applyScripts(settings: Settings): Promise<void> {
  const wanted = [
    ...scriptletScripts(await scriptletIndex(), settings),
    ...featureScripts(settings),
  ];
  const registered = await chrome.scripting.getRegisteredContentScripts();
  const changes = scriptChanges(wanted, registered);
  if (changes.unregister.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: changes.unregister });
  }
  if (changes.register.length > 0) {
    await chrome.scripting.registerContentScripts(changes.register);
  }
  if (changes.update.length > 0) {
    await chrome.scripting.updateContentScripts(changes.update);
  }
}

/** Applies the WebRTC feature: a browser setting, so all or nothing. */
async function applyWebrtc(settings: Settings): Promise<void> {
  const policy = chrome.privacy?.network?.webRTCIPHandlingPolicy;
  if (!policy) {
    return;
  }
  if (featureActive(settings, "webrtc", null)) {
    await policy.set({
      value: "default_public_interface_only" as chrome.privacy.IPHandlingPolicy,
    });
  } else {
    await policy.clear({});
  }
}

/** Makes Chrome's state match `settings`: rulesets, dynamic rules, page
 * scripts, WebRTC. */
async function applyNow(settings: Settings): Promise<void> {
  const changes = rulesetChanges(await rulesets(), settings, await dnr.getEnabledRulesets());
  if (changes.enableRulesetIds.length > 0 || changes.disableRulesetIds.length > 0) {
    await dnr.updateEnabledRulesets(changes);
  }
  const pause = pauseRule(settings.pausedSites, settings.pausedAll === true);
  await dnr.updateDynamicRules({
    removeRuleIds: [PAUSE_RULE_ID, ...PRIVACY_RULE_IDS, ...BRIDGE_RULE_IDS],
    addRules: [
      ...(pause ? [pause] : []),
      ...privacyRules(settings, await trackers(), BROWSER),
      ...bridgeRules(bridgeNow, BROWSER),
    ],
  });
  await applyScripts(settings);
  await applyWebrtc(settings);
}

// One application at a time: registering scripts twice fails, and the
// last settings saved must be the ones that end up applied.
let applying: Promise<void> = Promise.resolve();
function apply(settings: Settings): Promise<void> {
  const run = applying.then(() => applyNow(settings));
  applying = run.catch(() => {});
  return run;
}

async function save(settings: Settings): Promise<void> {
  settingsCache = Promise.resolve(settings);
  settingsNow = settings;
  await apply(settings);
  await chrome.storage.local.set({ settings: storedSettings(settings) });
}

async function start(): Promise<void> {
  // The toolbar badge counts the requests sinkd acted on in each tab.
  // (Chrome only: Firefox has no such count.)
  if (typeof dnr.setExtensionActionOptions === "function") {
    await dnr.setExtensionActionOptions({ displayActionCountAsBadgeText: true });
  }
  await apply(await loadSettings());
  await connectBridge();
}

// ------------------------------------------------------------- the bridge
//
// `sinkd bridge install` registers a native-messaging host that sends
// the resolver's local allowlist, blocklist and pause, then again on every
// change. Nothing is sent back but "send the state again". The connection
// needs the optional nativeMessaging permission, which the popup asks for;
// while it is open, Chrome keeps this worker running.

/** Whether this build can have the bridge at all (both builds declare it). */
const bridgeSupported = (): boolean => {
  const manifest = chrome.runtime.getManifest();
  return [...(manifest.permissions ?? []), ...(manifest.optional_permissions ?? [])].includes(
    "nativeMessaging",
  );
};

const bridgeGranted = (): Promise<boolean> =>
  bridgeSupported()
    ? chrome.permissions.contains({ permissions: ["nativeMessaging"] })
    : Promise.resolve(false);

/**
 * `runtime.connectNative`, which the browser adds to this worker only once
 * the permission is granted, a moment after the grant at the latest.
 */
async function nativeConnect(): Promise<typeof chrome.runtime.connectNative | null> {
  for (let i = 0; i < 20; i++) {
    if (typeof chrome.runtime.connectNative === "function") {
      return chrome.runtime.connectNative;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return null;
}

/** Stores what the bridge said and applies it. */
async function updateBridge(bridge: Bridge): Promise<void> {
  await chrome.storage.local.set({ bridge });
  settingsCache = undefined;
  await apply(await loadSettings());
}

async function connectBridge(): Promise<void> {
  if (port || !(await bridgeGranted())) {
    return;
  }
  const connect = await nativeConnect();
  if (connect === null) {
    await loadSettings();
    await updateBridge({
      ...bridgeNow,
      connected: false,
      error: "the browser hasn't enabled native messaging yet; reload sinkd or restart the browser",
    });
    return;
  }
  if (port) {
    return;
  }
  const opened = connect(BRIDGE_HOST);
  port = opened;
  opened.onMessage.addListener((message: unknown) => {
    const state = parseBridgeMessage(message);
    if (state) {
      updateBridge({ ...state, connected: true, error: null }).catch((e) =>
        console.error("sinkd: bridge update failed", e),
      );
    }
  });
  opened.onDisconnect.addListener((closed) => {
    // Chrome reports why in lastError, Firefox in the port.
    const error =
      chrome.runtime.lastError?.message ??
      (closed as { error?: { message?: string } }).error?.message ??
      "the host closed the connection";
    if (port === opened) {
      port = undefined;
    }
    // Keep the lists, drop the pause: a lost connection never leaves
    // blocking off. A host that is still missing, on every wake of the
    // worker, changes nothing and is not written again.
    loadSettings()
      .then(() => {
        const changed =
          bridgeNow.connected || bridgeNow.paused !== null || bridgeNow.error !== error;
        return changed
          ? updateBridge({ ...bridgeNow, connected: false, error, paused: null })
          : undefined;
      })
      .catch((e) => console.error("sinkd: bridge update failed", e));
  });
}

function disconnectBridge(): Promise<void> {
  port?.disconnect();
  port = undefined;
  return updateBridge(NO_BRIDGE);
}

// Every time the worker starts: a connection doesn't survive it.
connectBridge().catch((e) => console.error("sinkd: bridge failed", e));

chrome.permissions.onAdded.addListener((permissions) => {
  if (permissions.permissions?.includes("nativeMessaging")) {
    connectBridge().catch((e) => console.error("sinkd: bridge failed", e));
  }
});
chrome.permissions.onRemoved.addListener((permissions) => {
  if (permissions.permissions?.includes("nativeMessaging")) {
    disconnectBridge().catch((e) => console.error("sinkd: bridge failed", e));
  }
});

/** Who controls the WebRTC policy, when it isn't this extension. */
async function webrtcBlockedBy(): Promise<string | null> {
  const policy = chrome.privacy?.network?.webRTCIPHandlingPolicy;
  if (!policy) {
    return null;
  }
  const { levelOfControl } = await policy.get({});
  switch (levelOfControl) {
    case "not_controllable":
      return "a browser policy";
    case "controlled_by_other_extensions":
      return "another extension";
    default:
      return null;
  }
}

async function handle(request: Request): Promise<State | null> {
  const settings = await loadSettings();
  switch (request.type) {
    case "state": {
      const site = siteOf(request.url);
      const enabled = new Set(await dnr.getEnabledRulesets());
      return {
        site,
        paused: site !== null && isPaused(settings, site),
        rulesets: (await rulesets()).map((r) => ({ ...r, on: enabled.has(r.id) })),
        availableStaticRules: await dnr.getAvailableStaticRuleCount(),
        page: engineStats,
        features: featuresFor(BROWSER).map((f) => ({
          id: f.id,
          name: f.name,
          description: f.description,
          perSite: f.perSite,
          on: !settings.disabledFeatures.includes(f.id),
          offHere: site !== null && f.perSite && isExcepted(settings, f.id, site),
        })),
        webrtcBlockedBy: await webrtcBlockedBy(),
        bridge: {
          ...bridgeNow,
          granted: await bridgeGranted(),
          supported: bridgeSupported(),
        },
      };
    }
    case "bridgeConnect":
      await connectBridge();
      return null;
    case "bridgeDisconnect":
      await disconnectBridge();
      return null;
    case "setFeature":
      if (FEATURES.some((f) => f.id === request.id)) {
        await save(withFeature(settings, request.id, request.enabled));
      }
      return null;
    case "setSiteException": {
      const site = siteOf(`https://${request.site}/`);
      const feature = FEATURES.find((f) => f.id === request.feature);
      if (site !== null && feature?.perSite) {
        await save(withSiteException(settings, feature.id, site, request.off));
      }
      return null;
    }
    case "setSite": {
      const site = siteOf(`https://${request.site}/`);
      if (site !== null) {
        await save(withSite(settings, site, request.paused));
      }
      return null;
    }
    case "setRuleset":
      await save(withRuleset(settings, request.id, request.enabled));
      return null;
  }
}

/**
 * Cosmetic rules for the frame that asked: CSS goes straight into that
 * document at the user origin; procedural rules go back to the content
 * script, which is the only thing that can evaluate them.
 */
async function handleContent(
  request: ContentRequest,
  sender: chrome.runtime.MessageSender,
): Promise<{ procedural: unknown[]; generic: boolean } | { seed: string } | null> {
  const target = cssTarget(sender);
  const host = frameHost(sender.url, sender.origin);
  if (target === null || host === null) {
    return null;
  }
  const settings = await loadSettings();
  if (request.type === "seed") {
    return seedFor(settings, sender.tab?.url, host);
  }
  if (framePaused(settings, sender.tab?.url, host)) {
    return null;
  }
  const mask = pageMask(await rulesets(), settings);
  const page = await engine();
  let css: string;
  let reply: { procedural: unknown[]; generic: boolean } | null = null;
  if (request.type === "page") {
    const answer = page.page(host, mask);
    css = answer.css;
    reply = { procedural: answer.procedural, generic: answer.generic };
  } else if (request.type === "generic") {
    css = page.generic(host, mask, request.tokens, request.always);
  } else {
    return null;
  }
  if (css !== "") {
    await chrome.scripting.insertCSS({ target, css, origin: "USER" });
  }
  return reply;
}

// --------------------------------------------------------------- new tabs
//
// A tab a page opens (it has an opener) is checked against the lists'
// `$popup` rules at its first web address, and closed if they block it
// (see "new tabs" in core.ts). A tab opened blank and sent somewhere
// after is checked when it gets there. Only the first few seconds of a
// tab count: after that it is the user's.

/** How long after it opens a tab is still checked. */
const POPUP_WINDOW_MS = 8000;

/** Tabs pages opened, by id: when, and the address of the page that opened them. */
const openedTabs = new Map<number, { at: number; opener: Promise<string | null> }>();

async function checkOpenedTab(tabId: number, url: string | undefined): Promise<void> {
  const opened = openedTabs.get(tabId);
  if (!opened || !url || !/^https?:/.test(url)) {
    return;
  }
  if (Date.now() - opened.at > POPUP_WINDOW_MS) {
    openedTabs.delete(tabId);
    return;
  }
  const settings = await loadSettings();
  // What the resolver's allowlist frees, sinkd doesn't block here either.
  if (bridgeAllows(bridgeNow, new URL(url).hostname)) {
    return;
  }
  const [opener, rules, suffixList] = await Promise.all([opened.opener, popupRules(), suffixes()]);
  if (closesPopup(url, opener, rules, settings, suffixList)) {
    openedTabs.delete(tabId);
    // Gone already, if the user was quicker.
    await chrome.tabs.remove(tabId).catch(() => {});
  }
}

chrome.tabs.onCreated.addListener((tab) => {
  if (tab.id === undefined || tab.openerTabId === undefined) {
    return;
  }
  const opener = chrome.tabs.get(tab.openerTabId).then(
    (page) => page.url ?? null,
    () => null,
  );
  openedTabs.set(tab.id, { at: Date.now(), opener });
  checkOpenedTab(tab.id, tab.pendingUrl || tab.url).catch((e) =>
    console.error("sinkd: new tab check failed", e),
  );
});
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url) {
    checkOpenedTab(tabId, change.url).catch((e) => console.error("sinkd: new tab check failed", e));
  }
});
chrome.tabs.onRemoved.addListener((tabId) => {
  openedTabs.delete(tabId);
});

// ------------------------------------------------------- fingerprint seeds

let sessionKey: Promise<CryptoKey> | undefined;
/** A random key for this browser session: chrome.storage.session is
 * emptied when the browser closes, and content scripts can't read it. */
function fingerprintKey(): Promise<CryptoKey> {
  sessionKey ??= (async () => {
    const stored = await chrome.storage.session.get("fingerprintKey");
    let hex = typeof stored.fingerprintKey === "string" ? stored.fingerprintKey : "";
    if (!/^[0-9a-f]{64}$/.test(hex)) {
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
      await chrome.storage.session.set({ fingerprintKey: hex });
    }
    const raw = new Uint8Array(hex.match(/../g)?.map((h) => Number.parseInt(h, 16)) ?? []);
    return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  })();
  return sessionKey;
}

const seeds = new Map<string, string>();

/**
 * HMAC(session key, site) for the tab's top-level site, so a third-party
 * frame gets a different seed on every site that embeds it. `null` (noise
 * off) where fingerprint protection doesn't act: switched off, paused, or
 * excepted for the tab's site or the frame's own.
 */
async function seedFor(
  settings: Settings,
  tabUrl: string | undefined,
  host: string,
): Promise<{ seed: string } | null> {
  const tabSite = tabUrl ? siteOf(tabUrl) : null;
  const frameSite = host.startsWith("www.") ? host.slice(4) : host;
  if (
    tabSite === null ||
    !featureActive(settings, "fingerprinting", tabSite) ||
    !featureActive(settings, "fingerprinting", frameSite)
  ) {
    return null;
  }
  const site = registrableDomain(new URL(tabUrl as string).hostname, await suffixes());
  let seed = seeds.get(site);
  if (seed === undefined) {
    const mac = await crypto.subtle.sign(
      "HMAC",
      await fingerprintKey(),
      new TextEncoder().encode(site),
    );
    seed = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
    seeds.set(site, seed);
  }
  return { seed };
}

// ---------------------------------------------------------------- cookies

/** Caps first-party tracking cookies (`_ga`, `_fbp`, …) at a week, however
 * they were set: by the server or by a page script. */
chrome.cookies?.onChanged.addListener(({ removed, cookie }) => {
  if (removed) {
    return;
  }
  const details = cappedCookie(cookie, Date.now() / 1000);
  if (details === null) {
    return;
  }
  void loadSettings().then((settings) => {
    const site = siteOf(`https://${cookie.domain.replace(/^\./, "")}/`);
    if (site !== null && featureActive(settings, "cookies", site)) {
      chrome.cookies.set(details).catch((e) => console.error("sinkd: cookie cap", e));
    }
  });
});

// ------------------------------------------------ Firefox: webRequest

/** What Firefox's webRequest adds to Chrome's request details. */
interface FirefoxDetails {
  documentUrl?: string;
  originUrl?: string;
  frameAncestors?: { url: string }[];
  proxyInfo?: { type: string } | null;
  thirdParty?: boolean;
}
/** Firefox's DNS API (the `dns` permission). */
interface FirefoxDns {
  resolve(host: string, flags: string[]): Promise<{ canonicalName?: string }>;
}
type Blocking = chrome.webRequest.BlockingResponse | undefined;

let hostSetsCache: Promise<HostSets> | undefined;
let hostSetsNow: HostSets | undefined;
let suffixesNow: string[] | undefined;
/** The lists' hosts and the public suffixes, for uncloaking. */
function uncloakData(): Promise<[HostSets, string[]]> {
  hostSetsCache ??= packaged<UncloakEntry[]>("uncloak.json").then((entries) => {
    hostSetsNow = new HostSets(entries);
    return hostSetsNow;
  });
  return Promise.all([
    hostSetsCache,
    suffixes().then((list) => {
      suffixesNow = list;
      return list;
    }),
  ]);
}

let trackerSetCache: Promise<Set<string>> | undefined;
let trackerSetNow: Set<string> | undefined;
/** trackers.json as a set, for navigations to tracker frames. */
function trackerSet(): Promise<Set<string>> {
  trackerSetCache ??= trackers().then((list) => {
    trackerSetNow = new Set(list);
    return trackerSetNow;
  });
  return trackerSetCache;
}

// A host's alias, looked up once an hour at most; the lookup in flight is
// shared by the requests waiting on it. Lookups that fail count as "no
// alias", so an unresolvable name is let through to fail on its own.
const ALIAS_TTL_MS = 60 * 60 * 1000;
const ALIAS_CACHE_SIZE = 4096;
const aliases = new Map<
  string,
  { expires: number; alias: string | null | Promise<string | null> }
>();
function aliasOf(host: string): string | null | Promise<string | null> {
  const now = Date.now();
  const cached = aliases.get(host);
  if (cached && cached.expires > now) {
    return cached.alias;
  }
  if (aliases.size >= ALIAS_CACHE_SIZE) {
    aliases.clear();
  }
  const dns = (globalThis as unknown as { browser?: { dns?: FirefoxDns } }).browser?.dns;
  const entry = {
    expires: now + ALIAS_TTL_MS,
    alias: (dns ? dns.resolve(host, ["canonical_name"]) : Promise.reject())
      .then((r) => r.canonicalName ?? null)
      .catch(() => null)
      .then((alias) => {
        entry.alias = alias;
        return alias;
      }) as string | null | Promise<string | null>,
  };
  aliases.set(host, entry);
  return entry.alias;
}

/** Cancels a request whose host is a DNS alias of a blocked tracker. */
function uncloak(
  details: chrome.webRequest.OnBeforeRequestDetails & FirefoxDetails,
  settings: Settings,
  sets: HostSets,
  suffixList: string[],
): Blocking | Promise<Blocking> {
  const mask = sets.mask(settings);
  const host = uncloakCandidate(
    {
      url: details.url,
      type: details.type,
      ...(details.documentUrl === undefined ? {} : { documentUrl: details.documentUrl }),
      ...(details.frameAncestors ? { frameAncestors: details.frameAncestors } : {}),
      proxied: !!details.proxyInfo && details.proxyInfo.type !== "direct",
    },
    settings,
    sets,
    mask,
  );
  // The resolver's allowlist frees a name from uncloaking too.
  if (host === null || bridgeAllows(bridgeNow, host)) {
    return undefined;
  }
  const verdict = (alias: string | null): Blocking =>
    alias !== null && aliasBlocked(host, alias, sets, mask, suffixList)
      ? { cancel: true }
      : undefined;
  const alias = aliasOf(host);
  return alias instanceof Promise ? alias.then(verdict) : verdict(alias);
}

/** A navigation's details, as the header rules need them. */
function navigation(
  details: { url: string } & FirefoxDetails,
  trackerHosts: Set<string>,
): Navigation {
  let host = "";
  try {
    host = new URL(details.url).hostname;
  } catch {
    // Not a URL: not a tracker either.
  }
  return {
    url: details.url,
    initiator: details.originUrl,
    thirdParty: details.thirdParty === true,
    tracker: host !== "" && hasHost(trackerHosts, host),
  };
}

/** Calls `fn` with the settings and tracker hosts: at once when loaded. */
function withHeaderData(fn: (settings: Settings, hosts: Set<string>) => Blocking): Blocking {
  if (settingsNow && trackerSetNow) {
    return fn(settingsNow, trackerSetNow);
  }
  return Promise.all([loadSettings(), trackerSet()]).then(([s, hosts]) =>
    fn(s, hosts),
  ) as unknown as Blocking;
}

if (BROWSER === "firefox") {
  // Firefox runs a listener that returns a promise as a blocking one, and
  // keeps its requests waiting while the event page starts.
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      const settings = settingsNow;
      if (settings && hostSetsNow && suffixesNow) {
        return uncloak(details, settings, hostSetsNow, suffixesNow) as Blocking;
      }
      return Promise.all([loadSettings(), uncloakData()]).then(([s, [sets, list]]) =>
        uncloak(details, s, sets, list),
      ) as unknown as Blocking;
    },
    { urls: ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"] },
    ["blocking"],
  );
  // Firefox's DNR modifies the headers of subresources only; these apply
  // the same header rules to navigations.
  const navigations: chrome.webRequest.RequestFilter = {
    urls: ["http://*/*", "https://*/*"],
    types: ["main_frame", "sub_frame"],
  };
  chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) =>
      withHeaderData((settings, hosts) => {
        const headers = navigationRequestHeaders(
          details.requestHeaders ?? [],
          navigation(details as typeof details & FirefoxDetails, hosts),
          settings,
        );
        return headers ? { requestHeaders: headers } : undefined;
      }),
    navigations,
    ["blocking", "requestHeaders"],
  );
  chrome.webRequest.onHeadersReceived.addListener(
    (details) =>
      withHeaderData((settings, hosts) => {
        const headers = navigationResponseHeaders(
          details.responseHeaders ?? [],
          navigation(details as typeof details & FirefoxDetails, hosts),
          settings,
        );
        return headers ? { responseHeaders: headers } : undefined;
      }),
    navigations,
    ["blocking", "responseHeaders"],
  );
  uncloakData().catch((e) => console.error("sinkd: uncloak.json failed to load", e));
  trackerSet().catch((e) => console.error("sinkd: trackers.json failed to load", e));
  loadSettings().catch(() => {});
}

chrome.runtime.onInstalled.addListener(() => {
  start().catch((e) => console.error("sinkd: setup failed", e));
});
chrome.runtime.onStartup.addListener(() => {
  start().catch((e) => console.error("sinkd: setup failed", e));
});
// ------------------------------------------------------------- updates
//
// The store downloads a new version by itself, but the browser installs it
// only once this script stops, and while the bridge is connected it never
// does (the open native port keeps it running), so an update could wait
// for the browser to restart. Restart into it as soon as it arrives
// instead: after any settings change in flight is applied, and not while
// the popup is open, which the restart would close under the user. The
// restart is an update like any other: onInstalled applies the settings
// again. Nothing here contacts anything; the browser fetched the update.

const UPDATE_RETRY_MS = 30_000;
let updateWaiting = false;

/** How many of this extension's popups are open. */
async function openPopups(): Promise<number> {
  if (typeof chrome.runtime.getContexts === "function") {
    const popups = await chrome.runtime.getContexts({
      contextTypes: ["POPUP" as chrome.runtime.ContextType],
    });
    return popups.length;
  }
  // Older Firefox: its event page can list its own views.
  return chrome.extension?.getViews?.({ type: "popup" }).length ?? 0;
}

async function restartIntoUpdate(version: string): Promise<void> {
  await applying;
  if ((await openPopups()) > 0) {
    // Should this script stop meanwhile, the browser installs it anyway.
    setTimeout(() => {
      restartIntoUpdate(version).catch((e) => console.error("sinkd: update failed", e));
    }, UPDATE_RETRY_MS);
    return;
  }
  console.info(`sinkd: restarting into ${version}`);
  chrome.runtime.reload();
}

chrome.runtime.onUpdateAvailable.addListener(({ version }) => {
  if (updateWaiting) {
    return;
  }
  updateWaiting = true;
  restartIntoUpdate(version).catch((e) => console.error("sinkd: update failed", e));
});

// Load the engine as soon as the worker starts, not on the first page.
engine().catch((e) => console.error("sinkd: page engine failed to load", e));

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    return false;
  }
  const respond = (work: Promise<unknown>): true => {
    work.then(sendResponse, (e) => {
      console.error("sinkd:", e);
      sendResponse(null);
    });
    return true;
  };
  // Only this extension's own pages may change its settings. (Content
  // scripts never run in them, so their URL tells them apart.)
  if (sender.url?.startsWith(chrome.runtime.getURL(""))) {
    return respond(handle(message as Request));
  }
  // Content scripts may only ask for their own frame's cosmetic rules.
  const request = sender.tab ? parseContentRequest(message) : null;
  if (request) {
    return respond(handleContent(request, sender));
  }
  return false;
});
