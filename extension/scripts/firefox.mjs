// Playwright's Firefox with the extension, for the end-to-end test and the
// testbed. Playwright loads extensions into Chromium only, so this does
// what about:debugging does: it starts Firefox's remote debugging server
// (on 127.0.0.1, for a throwaway profile) and installs the unpacked
// extension as a temporary add-on, which goes away with the browser. The
// same connection evaluates code in the extension's background page, which
// Playwright can't reach, and in the browser's parent process, where the
// testbed sets DNS answers (aliases included) for the names it tests.

import { randomUUID } from "node:crypto";
import net from "node:net";
import { firefox } from "playwright-core";

import { FIREFOX_ID } from "./build.mjs";

/** A free TCP port on 127.0.0.1. */
async function freePort() {
  const server = net.createServer();
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const { port } = server.address();
  await new Promise((ok) => server.close(ok));
  return port;
}

/**
 * A client for Firefox's remote debugging protocol: JSON packets, each
 * prefixed with its length and a colon. Replies and events come from an
 * actor; `next` takes the first packet from it that passes `filter`,
 * whether it already arrived or not.
 */
async function connect(port) {
  let socket;
  for (let attempt = 0; ; attempt++) {
    try {
      socket = await new Promise((ok, fail) => {
        const s = net.connect(port, "127.0.0.1", () => ok(s));
        s.once("error", fail);
      });
      break;
    } catch (error) {
      if (attempt > 100) throw error;
      await new Promise((ok) => setTimeout(ok, 100));
    }
  }
  let buffer = Buffer.alloc(0);
  const waiting = [];
  const backlog = [];
  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const colon = buffer.indexOf(":");
      if (colon < 0) return;
      const length = Number(buffer.subarray(0, colon).toString());
      if (buffer.length < colon + 1 + length) return;
      const packet = JSON.parse(buffer.subarray(colon + 1, colon + 1 + length).toString());
      buffer = buffer.subarray(colon + 1 + length);
      const i = waiting.findIndex((w) => w.from === packet.from && w.filter(packet));
      if (i >= 0) waiting.splice(i, 1)[0].ok(packet);
      else backlog.push(packet);
    }
  });
  const next = (from, filter = () => true, timeout = 30_000) => {
    const i = backlog.findIndex((p) => p.from === from && filter(p));
    if (i >= 0) return Promise.resolve(backlog.splice(i, 1)[0]);
    return new Promise((ok, fail) => {
      const entry = { from, filter, ok };
      waiting.push(entry);
      setTimeout(() => {
        const j = waiting.indexOf(entry);
        if (j >= 0) {
          waiting.splice(j, 1);
          fail(new Error(`no packet from ${from} in ${timeout} ms`));
        }
      }, timeout).unref();
    });
  };
  /** Sends a request; resolves with its reply (a packet without a type). */
  const request = async (to, type, rest = {}) => {
    const reply = next(to, (p) => p.type === undefined || p.error !== undefined);
    const body = Buffer.from(JSON.stringify({ to, type, ...rest }));
    socket.write(`${body.length}:`);
    socket.write(body);
    const packet = await reply;
    if (packet.error) throw new Error(`${type}: ${packet.error}: ${packet.message ?? ""}`);
    return packet;
  };
  await next("root");
  return { request, next, backlog, close: () => socket.destroy() };
}

/** Evaluates `text` with a console actor; returns the result as JSON. */
async function evaluateWith(rdp, consoleActor, text) {
  const started = await rdp.request(consoleActor, "evaluateJSAsync", {
    text,
    mapped: { await: true },
  });
  const done = await rdp.next(
    consoleActor,
    (p) => p.type === "evaluationResult" && p.resultID === started.resultID,
  );
  if (done.hasException) {
    throw new Error(done.exceptionMessage ?? "evaluation failed");
  }
  let result = done.result;
  if (result?.type === "longString") {
    ({ substring: result } = await rdp.request(result.actor, "substring", {
      start: 0,
      end: result.length,
    }));
  }
  return typeof result === "string" ? JSON.parse(result) : undefined;
}

/** The text that runs `fn(arg)` and hands back its (awaited) value as JSON. */
const invocation = (fn, arg) =>
  `(async () => JSON.stringify(await (${fn})(${JSON.stringify(arg ?? null)})))()`;

/**
 * The text that runs `fn(document, window, arg)` in the popup, loaded in a
 * frame of the background page (Playwright can't open extension pages in
 * Firefox's tabs): fresh when `reload`, else the frame already there.
 */
const inPopup = (fn, arg, reload) => `(async () => {
  let frame = document.getElementById("sinkhole-test-popup");
  if (frame && ${reload}) { frame.remove(); frame = null; }
  if (!frame) {
    frame = document.createElement("iframe");
    frame.id = "sinkhole-test-popup";
    frame.src = "popup.html";
    const loaded = new Promise((ok) => frame.addEventListener("load", ok, { once: true }));
    document.body.append(frame);
    await loaded;
  }
  const value = await (${fn})(frame.contentDocument, frame.contentWindow, ${JSON.stringify(arg ?? null)});
  return JSON.stringify(value);
})()`;

/**
 * Firefox in `profile` with the unpacked extension at `extension`. Options
 * are Playwright's launchPersistentContext options plus `prefs`.
 *
 * Returns the context; `evaluate(fn, arg)`, which runs in the background
 * page (`fn` must be self-contained, as with Playwright's evaluate);
 * `parent(fn, arg)`, the same in the parent process with chrome
 * privileges; `popup(fn, arg, { reload })`, which runs
 * `fn(document, window, arg)` in the popup page; `send(request)`, a message
 * from the popup to the background page; `suspend()`, which ends the
 * background page as Firefox does after it idles; and the extension's
 * moz-extension:// origin.
 */
export async function launchFirefox(extension, profile, { prefs = {}, ...options } = {}) {
  const port = await freePort();
  // The extension's internal UUID, fixed so its pages have a known URL.
  const uuid = randomUUID();
  const context = await firefox.launchPersistentContext(profile, {
    headless: true,
    ...options,
    args: ["-start-debugger-server", String(port), ...(options.args ?? [])],
    firefoxUserPrefs: {
      "devtools.debugger.remote-enabled": true,
      "devtools.debugger.prompt-connection": false,
      "devtools.chrome.enabled": true,
      "extensions.webextensions.uuids": JSON.stringify({ [FIREFOX_ID]: uuid }),
      ...prefs,
    },
  });
  let rdp;
  try {
    rdp = await connect(port);
    const root = await rdp.request("root", "getRoot");
    const { addon } = await rdp.request(root.addonsActor, "installTemporaryAddon", {
      addonPath: extension,
      openDevTools: false,
    });
    const { addons } = await rdp.request("root", "listAddons");
    const descriptor = addons.find((a) => a.id === addon.id);
    const watcher = await rdp.request(descriptor.actor, "getWatcher", {
      isServerTargetSwitchingEnabled: true,
    });
    await rdp.request(watcher.actor, "watchTargets", { targetType: "frame" });

    // The background page's console, followed across restarts: an event
    // page that idled out comes back as a new target.
    let background = null;
    const isBackground = (p) =>
      p.type === "target-available-form" &&
      p.target.url?.endsWith("/_generated_background_page.html");
    const backgroundConsole = async () => {
      for (;;) {
        const gone = rdp.backlog.findIndex(
          (p) =>
            p.from === watcher.actor &&
            p.type === "target-destroyed-form" &&
            p.target.actor === background?.actor,
        );
        if (gone >= 0) {
          rdp.backlog.splice(gone, 1);
          background = null;
        }
        const fresh = rdp.backlog.findIndex((p) => p.from === watcher.actor && isBackground(p));
        if (fresh < 0) break;
        background = rdp.backlog.splice(fresh, 1)[0].target;
      }
      background ??= (await rdp.next(watcher.actor, isBackground)).target;
      return background.consoleActor;
    };

    const parentProcess = await rdp.request("root", "getProcess", { id: 0 });
    const parentTarget = await rdp.request(parentProcess.processDescriptor.actor, "getTarget");
    const parentConsole = (parentTarget.process ?? parentTarget.form).consoleActor;

    const evaluate = async (fn, arg) =>
      evaluateWith(rdp, await backgroundConsole(), invocation(fn, arg));
    const popup = async (fn, arg, { reload = false } = {}) =>
      evaluateWith(rdp, await backgroundConsole(), inPopup(fn, arg, reload));
    return {
      context,
      id: addon.id,
      uuid,
      origin: `moz-extension://${uuid}`,
      evaluate,
      popup,
      send: (request) =>
        popup((_document, window, r) => window.chrome.runtime.sendMessage(r), request),
      parent: (fn, arg) => evaluateWith(rdp, parentConsole, invocation(fn, arg)),
      suspend: async () => {
        await backgroundConsole();
        await rdp.request(descriptor.actor, "terminateBackgroundScript");
        background = null;
      },
      close: async () => {
        rdp.close();
        await context.close();
      },
    };
  } catch (error) {
    rdp?.close();
    await context.close();
    throw error;
  }
}

/**
 * Makes `host` resolve to 127.0.0.1 in this Firefox, with `alias` as its
 * canonical name (CNAME), through the DNS override service Firefox has for
 * its own tests. Only lookups that go to the system resolver see it.
 */
export function overrideDns(browser, host, alias = null) {
  return browser.parent(
    ({ host, alias }) => {
      const service = Components.classes["@mozilla.org/network/native-dns-override;1"].getService(
        Components.interfaces.nsINativeDNSResolverOverride,
      );
      service.addIPOverride(host, "127.0.0.1");
      if (alias) service.setCnameOverride(host, alias);
      Services.dns.clearCache(true);
      return true;
    },
    { host, alias },
  );
}
