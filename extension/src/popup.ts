// The toolbar popup, in two views. Protection: switch sinkd, or one
// privacy feature, off for the current site; or a kind of protection off
// everywhere. Log: a live console of what sinkd does in the current tab,
// which adds up to the count on the toolbar badge (see "the log" and "the
// console" in core.ts). It only talks to the background script and the
// browser, asks for site access back if the user took it away (Chrome's
// site access menu, Firefox's add-on permissions), and connects the bridge
// to the sinkd command line when asked to.

import {
  blockedLine,
  browserOf,
  CONSOLE_TAGS,
  type ConsoleLine,
  clock,
  DYNAMIC_RULESET,
  earlierLines,
  headerLines,
  isExtensionUrl,
  LOG_ACTIONS,
  type LogAction,
  logEntries,
  type Match,
  type Request,
  type RulesetInfo,
  redirectLine,
  ruleKey,
  SESSION_RULESET,
  SPLASH,
  type State,
  sameLine,
  splashShapes,
  splashWordmark,
} from "./core.js";

type Rule = chrome.declarativeNetRequest.Rule;

const dnr = chrome.declarativeNetRequest;
const ALL_SITES = { origins: ["<all_urls>"] };
const NATIVE: chrome.permissions.Permissions = { permissions: ["nativeMessaging"] };
const BROWSER_NAME = browserOf(location.href) === "firefox" ? "Firefox" : "Chrome";

const $ = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`missing #${id}`);
  }
  return element as T;
};

/** An element with a class and text, the popup's building block. */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text = "",
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text) element.textContent = text;
  return element;
}

async function send(request: Request): Promise<State | null> {
  return (await chrome.runtime.sendMessage(request)) as State | null;
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/** A list item: a name, maybe a description, and a switch. */
function switchItem(
  name: string,
  description: string | null,
  checked: boolean,
  onChange: (checked: boolean) => Promise<void>,
): HTMLLIElement {
  const item = el("li");
  const label = el("label", "row");
  const text = el("span", "text");
  text.append(el("span", "name", name));
  if (description) {
    text.append(el("span", "desc", description));
  }
  const box = el("input", "toggle");
  box.type = "checkbox";
  box.setAttribute("role", "switch");
  box.checked = checked;
  box.onchange = () => {
    onChange(box.checked).catch((e) => console.error("sinkd popup:", e));
  };
  label.append(text, box);
  item.append(label);
  return item;
}

async function reload(tab: chrome.tabs.Tab | undefined): Promise<void> {
  if (tab?.id !== undefined) {
    await chrome.tabs.reload(tab.id);
  }
}

let current: { state: State; tab: chrome.tabs.Tab | undefined } | null = null;

function render(state: State, tab: chrome.tabs.Tab | undefined): void {
  const siteToggle = $<HTMLInputElement>("site-toggle");
  $("site").textContent = state.site ?? "Not active on this page";
  siteToggle.disabled = state.site === null;
  siteToggle.checked = state.site !== null && !state.paused;
  const pausedAll = state.bridge.connected && state.bridge.paused !== null;
  if (pausedAll) {
    siteToggle.disabled = true;
  }
  $("site-label").textContent = pausedAll
    ? "Paused everywhere by `sinkd pause`"
    : state.paused
      ? "Off for this site"
      : "On for this site";
  siteToggle.onchange = async () => {
    if (state.site === null) {
      return;
    }
    await send({ type: "setSite", site: state.site, paused: !siteToggle.checked });
    await reload(tab);
    await refresh();
  };

  // Per-site switches for each privacy feature that is on everywhere.
  const site = state.site;
  $("site-features").replaceChildren(
    ...(site === null || state.paused
      ? []
      : state.features
          .filter((f) => f.perSite && f.on)
          .map((f) =>
            switchItem(f.name, null, !f.offHere, async (on) => {
              await send({ type: "setSiteException", feature: f.id, site, off: !on });
              await reload(tab);
              await refresh();
            }),
          )),
  );

  $("rulesets").replaceChildren(
    ...state.rulesets.map((r) =>
      switchItem(r.name, r.description, r.on, async (on) => {
        await send({ type: "setRuleset", id: r.id, enabled: on });
        await refresh();
      }),
    ),
  );
  $("features").replaceChildren(
    ...state.features.map((f) =>
      switchItem(f.name, f.description, f.on, async (on) => {
        await send({ type: "setFeature", id: f.id, enabled: on });
        await refresh();
      }),
    ),
  );
  const note = $("webrtc-note");
  note.hidden = state.webrtcBlockedBy === null;
  note.textContent = state.webrtcBlockedBy
    ? `The WebRTC setting is controlled by ${state.webrtcBlockedBy}.`
    : "";
  renderBridge(state);
  const rules = state.rulesets.filter((r) => r.on).reduce((n, r) => n + r.rules, 0);
  $("quota").textContent =
    `${rules.toLocaleString()} rules in use; ${BROWSER_NAME} can give ` +
    `${state.availableStaticRules.toLocaleString()} more.`;
}

/** The bridge to the command line: off until the user connects it. */
function renderBridge(state: State): void {
  const bridge = state.bridge;
  $("bridge").hidden = !bridge.supported;
  const status = $("bridge-status");
  const button = $<HTMLButtonElement>("bridge-button");
  if (!bridge.granted) {
    status.textContent =
      "Lets `sinkd allow`, `block` and `pause` on the command line apply here too. " +
      "Set it up first with `sinkd bridge install`.";
    button.textContent = "Connect";
    button.onclick = async () => {
      // A user gesture, so the browser asks.
      if (await chrome.permissions.request(NATIVE)) {
        await send({ type: "bridgeConnect" });
        await refresh();
      }
    };
  } else if (bridge.connected) {
    const paused =
      bridge.paused === null
        ? ""
        : bridge.paused.until === null
          ? "; blocking paused until `sinkd resume`"
          : `; blocking paused until ${new Date(bridge.paused.until).toLocaleTimeString()}`;
    status.textContent =
      `Connected: ${bridge.allow.length} allowed and ${bridge.block.length} blocked from ` +
      `the resolver's config${paused}.` +
      (bridge.running ? "" : " The resolver itself isn't running.") +
      (bridge.truncated ? " Some entries were left out (too many)." : "");
    button.textContent = "Disconnect";
    button.onclick = async () => {
      await chrome.permissions.remove(NATIVE);
      await send({ type: "bridgeDisconnect" });
      await refresh();
    };
  } else {
    status.textContent = `Not connected: ${bridge.error ?? "not started"}. Is \`sinkd bridge install\` done?`;
    button.textContent = "Retry";
    button.onclick = async () => {
      await send({ type: "bridgeConnect" });
      // The host answers within a moment, or the connection fails.
      await new Promise((resolve) => setTimeout(resolve, 500));
      await refresh();
    };
  }
}

/** Shows the site access notice when the extension can't act on pages. */
async function renderAccess(): Promise<void> {
  const granted = await chrome.permissions.contains(ALL_SITES);
  $("access").hidden = granted;
  $<HTMLButtonElement>("grant").onclick = async () => {
    // A user gesture, so the browser asks.
    if (await chrome.permissions.request(ALL_SITES)) {
      await refresh();
    }
  };
}

async function refresh(): Promise<void> {
  await renderAccess();
  const tab = await activeTab();
  const state = await send({ type: "state", url: tab?.url ?? "" });
  if (state) {
    current = { state, tab };
    render(state, tab);
  }
}

// ----------------------------------------------------------------- the log

/** The packaged rulesets, by rule id, each read once per popup. */
const packagedRules = new Map<string, Promise<Map<number, Rule>>>();
function rulesOf(info: RulesetInfo): Promise<Map<number, Rule>> {
  let rules = packagedRules.get(info.id);
  if (!rules) {
    rules = fetch(chrome.runtime.getURL(info.path))
      .then((r) => r.json() as Promise<Rule[]>)
      .then((list) => new Map(list.map((rule) => [rule.id, rule])));
    packagedRules.set(info.id, rules);
  }
  return rules;
}

/** The rules behind `matches`, by ruleKey. */
async function rulesFor(matches: Match[], rulesets: RulesetInfo[]): Promise<Map<string, Rule>> {
  const found = new Map<string, Rule>();
  await Promise.all(
    [...new Set(matches.map((m) => m.rulesetId))].map(async (id) => {
      const info = rulesets.find((r) => r.id === id);
      const byId =
        id === DYNAMIC_RULESET || id === SESSION_RULESET
          ? new Map(
              (id === DYNAMIC_RULESET
                ? await dnr.getDynamicRules()
                : await dnr.getSessionRules()
              ).map((rule) => [rule.id, rule]),
            )
          : info
            ? await rulesOf(info)
            : new Map<number, Rule>();
      for (const m of matches) {
        const rule = m.rulesetId === id ? byId.get(m.ruleId) : undefined;
        if (rule) found.set(ruleKey(id, m.ruleId), rule);
      }
    }),
  );
  return found;
}

/** `limited`: refused by the cap on reads outside a click, so a click can read it. */
type Earlier = { lines: ConsoleLine[] } | { error: string; limited: boolean };

/**
 * What sinkd did in the tab before `since`, from the browser: from then on
 * the console sees it happen (watch).
 */
async function readEarlier(state: State, tabId: number, since: number): Promise<Earlier> {
  let matches: Match[];
  try {
    const { rulesMatchedInfo } = await dnr.getMatchedRules({ tabId });
    matches = rulesMatchedInfo
      .filter((m) => m.timeStamp < since)
      .map((m) => ({ rulesetId: m.rule.rulesetId, ruleId: m.rule.ruleId, timeStamp: m.timeStamp }));
  } catch (e) {
    // Reads outside a click are limited to 20 in 10 minutes.
    return /quota/i.test(String(e))
      ? {
          error: `${BROWSER_NAME} limits how often sinkd may read what it did earlier.`,
          limited: true,
        }
      : { error: `${BROWSER_NAME} didn't let sinkd read what it did earlier.`, limited: false };
  }
  const names = new Map(state.rulesets.map((r) => [r.id, r.name]));
  const [rules, hosts] = await Promise.all([rulesFor(matches, state.rulesets), pageHosts(tabId)]);
  return { lines: earlierLines(logEntries(matches, rules, names, hosts)) };
}

/**
 * The hosts the tab's frames loaded from or point elements at, to name the
 * hosts a rule over a list of domains acted on (hitHosts). Read in the
 * page, kept in the popup, gone when it closes. None where sinkd has no
 * access.
 */
async function pageHosts(tabId: number): Promise<string[]> {
  try {
    const frames = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: () => {
        const hosts = new Set<string>();
        const add = (url: string | null) => {
          try {
            if (url) hosts.add(new URL(url, location.href).hostname);
          } catch {
            // Not a URL.
          }
        };
        for (const entry of performance.getEntriesByType("resource")) add(entry.name);
        // Blocked requests leave no timing entry, but their elements stay.
        for (const element of document.querySelectorAll("[src], link[href]")) {
          add(element.getAttribute("src") ?? element.getAttribute("href"));
        }
        return [...hosts];
      },
    });
    return frames.flatMap((frame) => (Array.isArray(frame.result) ? frame.result : []));
  } catch {
    return [];
  }
}

/**
 * Watches the tab's requests while the popup is open, and reports what the
 * rules did to each (see "the console" in core.ts). Only requests that
 * start from now on count: what came before was read back (readEarlier).
 * Nothing is kept once the popup closes.
 */
function watch(
  tabId: number,
  paramsSource: string,
  onLine: (line: ConsoleLine) => void,
  onNavigate: (url: string) => void,
): void {
  const web = chrome.webRequest;
  const filter: chrome.webRequest.RequestFilter = { urls: ["<all_urls>"], tabId };
  const started = new Set<string>();
  const sending = new Map<string, chrome.webRequest.HttpHeader[]>();
  const receiving = new Map<string, chrome.webRequest.HttpHeader[]>();
  const done = (id: string) => {
    started.delete(id);
    sending.delete(id);
    receiving.delete(id);
  };
  const emit = (lines: (ConsoleLine | null)[]) => {
    for (const line of lines) if (line) onLine(line);
  };
  web.onBeforeRequest.addListener((d) => {
    // A redirect starts the same request again, under the same id.
    if (started.has(d.requestId) || isExtensionUrl(d.url)) return;
    started.add(d.requestId);
    if (d.type === "main_frame") onNavigate(d.url);
    return undefined;
  }, filter);
  web.onBeforeRedirect.addListener((d) => {
    if (started.has(d.requestId)) {
      emit([redirectLine(d.url, d.redirectUrl, d.timeStamp, paramsSource)]);
    }
  }, filter);
  web.onErrorOccurred.addListener((d) => {
    if (started.has(d.requestId)) emit([blockedLine(d.url, d.error, d.timeStamp)]);
    done(d.requestId);
  }, filter);
  web.onCompleted.addListener((d) => done(d.requestId), filter);
  web.onBeforeSendHeaders.addListener(
    (d) => {
      if (started.has(d.requestId)) sending.set(d.requestId, d.requestHeaders ?? []);
      return undefined;
    },
    filter,
    ["requestHeaders", "extraHeaders"],
  );
  web.onSendHeaders.addListener(
    (d) => {
      const before = sending.get(d.requestId);
      if (!before) return;
      sending.delete(d.requestId);
      emit(headerLines(d.url, before, d.requestHeaders ?? [], true, d.timeStamp));
    },
    filter,
    ["requestHeaders", "extraHeaders"],
  );
  web.onHeadersReceived.addListener(
    (d) => {
      if (started.has(d.requestId) && !isExtensionUrl(d.url)) {
        receiving.set(d.requestId, d.responseHeaders ?? []);
      }
      return undefined;
    },
    filter,
    ["responseHeaders", "extraHeaders"],
  );
  web.onResponseStarted.addListener(
    (d) => {
      const before = receiving.get(d.requestId);
      if (!before) return;
      receiving.delete(d.requestId);
      emit(headerLines(d.url, before, d.responseHeaders ?? [], false, d.timeStamp));
    },
    filter,
    ["responseHeaders", "extraHeaders"],
  );
}

// ------------------------------------------------------------- the console

/** Lines kept on screen; the counts go on past them. */
const MAX_LINES = 600;

const screen = {
  /** Everything counted since the page loaded, earlier lines included. */
  total: 0,
  sums: new Map<LogAction, number>(),
  /** False when the earlier matches couldn't be read: the total then starts at opening. */
  exact: true,
  /** The earlier matches were read (or failed to be): until then the total has only live ones. */
  earlierRead: false,
  last: null as { line: ConsoleLine; item: HTMLLIElement } | null,
  /** Lines waiting for the console to start, then for the next draw. */
  queue: [] as ConsoleLine[],
  ready: false,
  /** The page changed since the console started: what was read back is the old page's. */
  navigated: false,
  timer: 0,
  /** Lines added while the reader was scrolled up. */
  unseen: 0,
};

function lineItem(line: ConsoleLine): HTMLLIElement {
  const item = el("li", `line t-${line.action}${line.live ? "" : " earlier"}`);
  const row = el("button", "row");
  row.type = "button";
  row.setAttribute("aria-expanded", "false");
  const time = el("time", "time", clock(line.at));
  time.dateTime = new Date(line.at).toISOString();
  row.append(time, el("span", "tag", CONSOLE_TAGS[line.action]));
  if (line.mark) row.append(el("span", "mark", line.mark));
  row.append(el("span", "msg", line.text));
  const rep = el("span", "rep", String(line.count));
  rep.hidden = line.count <= 1;
  row.append(rep);
  const more = el("div", "more");
  more.append(el("span", "url", line.text));
  const about = [line.detail, line.source].filter((part) => part !== "").join(" · ");
  if (about) more.append(el("span", "", about));
  if (!line.live) {
    more.append(el("span", "", "Before you opened this: what the rule targets, not the address."));
  }
  row.onclick = () => {
    const open = item.classList.toggle("open");
    row.setAttribute("aria-expanded", String(open));
  };
  item.append(row, more);
  return item;
}

function divider(text: string, notice = false): HTMLLIElement {
  return el("li", notice ? "divider notice" : "divider", text);
}

/**
 * Reads what sinkd did before the popup opened, into the log. Not on
 * opening but from the click (or key) that first shows the log: most
 * opens never show it, and the read parses megabytes of rules. And
 * Chrome caps reads at 20 in 10 minutes, but not the ones a click asks
 * for, so a popup opened often no longer comes up with an empty log.
 * `null` once read, or when there is nothing to read.
 */
let loadEarlier: (() => void) | null = null;
/** The log has been shown, maybe before the console started. */
let logShown = false;

/** Where the earlier lines go, before the live ones; empty until they're read. */
const EARLIER_SLOT = "log-earlier";

/**
 * Why the earlier matches are missing, and, when a click can read them
 * (`limited`), a button that does.
 */
function earlierNotice(slot: HTMLElement, text: string, limited: boolean): void {
  slot.className = "divider notice";
  slot.replaceChildren(el("span", "", limited ? `${text} ` : text));
  if (limited) {
    const again = el("button", "again", "Show them");
    again.type = "button";
    again.onclick = () => loadEarlier?.();
    slot.append(again);
  }
  slot.hidden = false;
}

/**
 * `loadEarlier` for a console started at `since`: the earlier lines take
 * the slot's place and count; or the slot says why there are none.
 */
function earlierLoader(state: State, tabId: number, since: number): () => void {
  let reading = false;
  return () => {
    if (reading) return;
    reading = true;
    // getMatchedRules is called before readEarlier's first await, so
    // inside the click that called this.
    readEarlier(state, tabId, since)
      .then((earlier) => {
        if (screen.navigated) return;
        // Gone if more than MAX_LINES came in live meanwhile: then the
        // earlier lines would be off the top, and only count.
        const slot = document.getElementById(EARLIER_SLOT);
        if ("error" in earlier) {
          // A click can read past the cap; nothing helps with the rest.
          if (!earlier.limited || !slot) loadEarlier = null;
          screen.exact = false;
          if (slot) earlierNotice(slot, earlier.error, earlier.limited);
        } else {
          loadEarlier = null;
          const list = $("log-lines");
          const stick = atBottom(list);
          if (slot) slot.replaceWith(...earlier.lines.map(lineItem));
          for (const line of earlier.lines) {
            screen.total += line.count;
            screen.sums.set(line.action, (screen.sums.get(line.action) ?? 0) + line.count);
          }
          screen.exact = true;
          if (stick) list.scrollTop = list.scrollHeight;
        }
        screen.earlierRead = true;
        drawCounts();
      })
      .catch((e) => console.error("sinkd popup:", e))
      .finally(() => {
        reading = false;
      });
  };
}

const atBottom = (list: HTMLElement) =>
  list.scrollHeight - list.scrollTop - list.clientHeight < 12 || list.clientHeight === 0;

/** Draws what's queued: new lines, or one more of the line before. */
function draw(): void {
  screen.timer = 0;
  const list = $("log-lines");
  const stick = atBottom(list);
  let added = 0;
  for (const line of screen.queue) {
    screen.total += line.count;
    screen.sums.set(line.action, (screen.sums.get(line.action) ?? 0) + line.count);
    const last = screen.last;
    if (last && line.live && sameLine(last.line, line)) {
      last.line.count += line.count;
      const rep = last.item.querySelector<HTMLElement>(".rep");
      if (rep) {
        rep.textContent = String(last.line.count);
        rep.hidden = false;
      }
      continue;
    }
    const item = lineItem(line);
    list.append(item);
    screen.last = { line: { ...line }, item };
    added += 1;
  }
  screen.queue = [];
  while (list.childElementCount > MAX_LINES) {
    list.firstElementChild?.remove();
  }
  if (stick) {
    list.scrollTop = list.scrollHeight;
  } else {
    screen.unseen += added;
  }
  const jump = $<HTMLButtonElement>("log-jump");
  jump.hidden = screen.unseen === 0;
  jump.textContent = `↓ ${screen.unseen} new`;
  drawCounts();
}

function drawCounts(): void {
  const pill = $("log-count");
  // Like the badge, which shows nothing at 0; and nothing until it can
  // match the badge, once the earlier matches are in.
  pill.hidden = screen.total === 0 || !screen.earlierRead;
  pill.textContent = screen.total.toLocaleString();
  $("log-total").textContent = screen.total.toLocaleString();
  $("log-caption").textContent = screen.exact
    ? screen.total === 1
      ? "action on this page"
      : "actions on this page"
    : "since you opened this";
  for (const chip of $("log-filters").querySelectorAll<HTMLElement>(".chip")) {
    const action = chip.dataset.action as LogAction;
    const count = screen.sums.get(action) ?? 0;
    const b = chip.querySelector("b");
    if (b) b.textContent = count.toLocaleString();
    // HTTPS upgrades and the odd rule show up only once they happen.
    if (action === "upgraded" || action === "other") chip.hidden = count === 0;
  }
}

function push(line: ConsoleLine): void {
  screen.queue.push(line);
  if (screen.ready && !screen.timer) {
    screen.timer = window.setTimeout(draw, 50);
  }
}

/** A new page in the tab: the badge starts over, and so does the console. */
function startOver(url: string): void {
  screen.total = 0;
  screen.sums.clear();
  screen.exact = true;
  screen.last = null;
  screen.unseen = 0;
  screen.navigated = true;
  // Everything on the new page is seen live.
  screen.earlierRead = true;
  loadEarlier = null;
  // Lines of the old page still waiting are gone with it.
  screen.queue = [];
  $("log-lines").replaceChildren(divider(`navigated · ${url.replace(/^[a-z]+:\/\//, "")}`));
  drawCounts();
}

function setupFilters(): void {
  const list = $("log-lines");
  $("log-filters").replaceChildren(
    ...LOG_ACTIONS.map((a) => {
      const chip = el("button", `chip t-${a.id}`);
      chip.type = "button";
      chip.dataset.action = a.id;
      chip.setAttribute("aria-pressed", "true");
      chip.title = a.name;
      chip.append(CONSOLE_TAGS[a.id], el("b", "", "0"));
      chip.onclick = () => {
        const shown = chip.getAttribute("aria-pressed") !== "true";
        chip.setAttribute("aria-pressed", String(shown));
        list.classList.toggle(`hide-${a.id}`, !shown);
      };
      return chip;
    }),
  );
  // The tooltip closes on Escape, and opens again once the pointer or
  // focus comes back.
  const about = $("log-about");
  about.addEventListener("keydown", (event) => {
    if (event.key === "Escape") about.classList.add("closed");
  });
  for (const type of ["pointerleave", "focusout"]) {
    about.addEventListener(type, () => about.classList.remove("closed"));
  }
  $<HTMLButtonElement>("log-jump").onclick = () => {
    list.scrollTop = list.scrollHeight;
  };
  list.addEventListener("scroll", () => {
    if (screen.unseen > 0 && atBottom(list)) {
      screen.unseen = 0;
      $("log-jump").hidden = true;
    }
  });
}

/** Not watching: a page sinkd doesn't act on. */
function idle(message: string): void {
  $("log-live").classList.add("off");
  $("log-state").textContent = "idle";
  $("log-lines").classList.add("off");
  $("log-lines").replaceChildren(divider(message, true));
}

/** Starts the console: the matches so far, then the live ones. */
async function startConsole(): Promise<void> {
  setupFilters();
  drawCounts();
  const state = current?.state;
  const tabId = current?.tab?.id;
  if (!state || tabId === undefined || state.site === null) {
    idle("sinkd doesn't act on this page.");
    return;
  }
  const since = Date.now();
  const params = state.rulesets.find((r) => r.id === "params")?.name;
  watch(tabId, params ?? "Tracking parameters", push, startOver);
  const list = $("log-lines");
  if (!screen.navigated) {
    const slot = el("li", "");
    slot.id = EARLIER_SLOT;
    slot.hidden = true;
    list.append(slot, divider(`live since ${clock(since)}`));
    loadEarlier = earlierLoader(state, tabId, since);
  }
  if (state.paused) {
    list.append(divider("sinkd is off for this site, so it changes nothing here.", true));
  }
  screen.ready = true;
  draw();
  // The log was shown before the console started: no click to read in
  // now, but the cap is rarely reached, and the notice has a button.
  if (logShown) loadEarlier?.();
}

// ---------------------------------------------------------------- the views

const VIEWS = ["controls", "log"] as const;
type View = (typeof VIEWS)[number];

function show(view: View, focus = false): void {
  for (const name of VIEWS) {
    const tab = $(`tab-${name}`);
    const selected = name === view;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(`view-${name}`).hidden = !selected;
    if (selected && focus) tab.focus();
  }
  if (view === "log") {
    // From the click or key that shows the log, so Chrome doesn't count it.
    logShown = true;
    loadEarlier?.();
    const list = $("log-lines");
    list.scrollTop = list.scrollHeight;
    screen.unseen = 0;
    $("log-jump").hidden = true;
  }
}

for (const name of VIEWS) {
  $(`tab-${name}`).onclick = () => show(name);
}
$("tab-controls").parentElement?.addEventListener("keydown", (event) => {
  const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
  if (step === undefined) return;
  event.preventDefault();
  const at = VIEWS.findIndex((name) => $(`tab-${name}`).getAttribute("aria-selected") === "true");
  show(VIEWS[(at + step + VIEWS.length) % VIEWS.length] ?? "controls", true);
});

// Firefox neither counts on the badge nor says which rules matched, so it
// has no log, and the popup is the one view.
const HAS_LOG = typeof dnr.getMatchedRules === "function" && chrome.webRequest !== undefined;
const tabs = $("tab-controls").parentElement;
if (tabs) tabs.hidden = !HAS_LOG;

// -------------------------------------------------------------- the splash

/** Every input the splash holds back while it is up, so none reaches the controls. */
const SPLASH_INPUTS = [
  "pointerdown",
  "pointerup",
  "mousedown",
  "mouseup",
  "click",
  "dblclick",
  "contextmenu",
  "keydown",
  "keypress",
  "keyup",
  "wheel",
  "touchstart",
  "touchmove",
  "touchend",
] as const;
/** The popup's height when it last opened, so it opens at full height under the splash. */
const HEIGHT_KEY = "sinkd:popup-height";
/** Set once the splash has played: it plays the first time the popup opens, not every time. */
const SPLASH_SEEN_KEY = "sinkd:splash-seen";
const FIRST_HEIGHT = 560;
/** The tallest a popup gets, in Chrome and in Firefox. */
const MOST_HEIGHT = 600;

/**
 * Opens the popup at the height it had last time, not small and then
 * growing as the controls arrive (or under the splash). The returned
 * function lets the popup take its own height again, and remembers it.
 */
function holdHeight(): () => void {
  let height = FIRST_HEIGHT;
  try {
    height = Number(localStorage.getItem(HEIGHT_KEY)) || FIRST_HEIGHT;
  } catch {
    // Storage blocked: the usual height.
  }
  document.body.style.minHeight = `${Math.min(MOST_HEIGHT, height)}px`;
  return () => {
    document.body.style.minHeight = "";
    try {
      localStorage.setItem(HEIGHT_KEY, String(document.documentElement.scrollHeight));
    } catch {
      // Storage blocked: next time opens at the usual height.
    }
  };
}

/**
 * The splash the first time the popup opens after install ("the splash"
 * in core.ts); later opens go straight to the controls. It plays at its
 * own pace whatever the user does, holds every input back from the
 * controls until it is gone, and leaves once it is whole and the controls
 * have rendered (`ready`). Never with reduced motion, and never when
 * storage is blocked, since then it could not tell a first open apart.
 */
function splashScreen(ready: Promise<unknown>): void {
  const splash = document.getElementById("splash");
  if (!splash) return;
  let first = false;
  try {
    first = localStorage.getItem(SPLASH_SEEN_KEY) === null;
    if (first) localStorage.setItem(SPLASH_SEEN_KEY, "1");
  } catch {
    // Storage blocked: no splash.
  }
  const release = holdHeight();
  if (!first || matchMedia("(prefers-reduced-motion: reduce)").matches) {
    splash.remove();
    ready.then(release, release);
    return;
  }
  splash.hidden = false;
  const shapes = [...splash.querySelectorAll<SVGRectElement>("rect")];
  const word = splash.querySelector<HTMLElement>(".splash-word");
  const draw = (t: number) => {
    splashShapes(t).forEach((shape, i) => {
      const rect = shapes[i];
      if (!rect) return;
      const { cx, cy, w, h } = shape;
      rect.setAttribute("x", (cx - w / 2).toFixed(3));
      rect.setAttribute("y", (cy - h / 2).toFixed(3));
      rect.setAttribute("width", w.toFixed(3));
      rect.setAttribute("height", h.toFixed(3));
      rect.setAttribute("rx", shape.rx.toFixed(3));
      rect.setAttribute(
        "transform",
        `rotate(${shape.rot.toFixed(2)} ${cx.toFixed(2)} ${cy.toFixed(2)})`,
      );
      if (shape.strokeWidth) rect.setAttribute("stroke-width", shape.strokeWidth.toFixed(3));
      rect.setAttribute("opacity", shape.opacity.toFixed(3));
    });
    const { opacity, rise } = splashWordmark(t);
    if (word) {
      word.style.opacity = opacity.toFixed(3);
      word.style.transform = `translateY(${rise.toFixed(2)}px)`;
    }
  };

  // No click lands on a switch underneath, no key moves the focus or flips
  // one. Escape still closes the popup, and shortcuts do what they do.
  const take = (event: Event) => {
    event.stopImmediatePropagation();
    const key = event as KeyboardEvent;
    const passes = key.key === "Escape" || key.metaKey || key.ctrlKey || key.altKey;
    if (event.cancelable && !passes) event.preventDefault();
  };
  const options = { capture: true, passive: false } as const;
  for (const type of SPLASH_INPUTS) window.addEventListener(type, take, options);

  let whole = false;
  let rendered = false;
  let leaving = false;
  const leave = () => {
    if (leaving || !whole || !rendered) return;
    leaving = true;
    release();
    splash.animate([{ opacity: 1 }, { opacity: 0 }], {
      duration: SPLASH.fade,
      easing: "ease-out",
      fill: "forwards",
    });
    setTimeout(() => {
      splash.remove();
      for (const type of SPLASH_INPUTS) window.removeEventListener(type, take, options);
    }, SPLASH.fade);
  };
  const settled = () => {
    rendered = true;
    leave();
  };
  ready.then(settled, settled);

  // Its own clock, a frame at a time (a stall counts as one frame), so it
  // never jumps ahead.
  let clock = 0;
  let last = performance.now();
  const tick = (now: number) => {
    clock += Math.min(50, Math.max(0, now - last));
    last = now;
    draw(clock);
    if (clock < SPLASH.hold) requestAnimationFrame(tick);
    else {
      whole = true;
      leave();
    }
  };
  draw(0);
  requestAnimationFrame(tick);
}

const ready = refresh();
splashScreen(ready);
ready
  .then(() => (HAS_LOG ? startConsole() : undefined))
  .catch((e) => console.error("sinkd popup:", e));
