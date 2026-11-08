// The toolbar popup: switch sinkd, or one privacy feature, off for the
// current site; or a kind of protection off everywhere. It only talks to
// the background script, asks for site access back if the user took it
// away (Chrome's site access menu, Firefox's add-on permissions), and
// connects the bridge to the sinkd command line when asked to.

import { browserOf, type Request, type State } from "./core.js";

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

async function send(request: Request): Promise<State | null> {
  return (await chrome.runtime.sendMessage(request)) as State | null;
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

/** A list item with a labeled checkbox. */
function switchItem(
  name: string,
  description: string | null,
  checked: boolean,
  onChange: (checked: boolean) => Promise<void>,
): HTMLLIElement {
  const item = document.createElement("li");
  const label = document.createElement("label");
  label.className = "switch";
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = checked;
  box.onchange = () => {
    onChange(box.checked).catch((e) => console.error("sinkd popup:", e));
  };
  const text = document.createElement("span");
  text.textContent = name;
  if (description) {
    const desc = document.createElement("span");
    desc.className = "desc";
    desc.textContent = description;
    text.append(desc);
  }
  label.append(box, text);
  item.append(label);
  return item;
}

async function reload(tab: chrome.tabs.Tab | undefined): Promise<void> {
  if (tab?.id !== undefined) {
    await chrome.tabs.reload(tab.id);
  }
}

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
    render(state, tab);
  }
}

refresh().catch((e) => console.error("sinkd popup:", e));
