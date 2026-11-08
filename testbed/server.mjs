// The testbed's web server: every hostname the browser asks for leads
// here, and pages are served from sites/<hostname>/. Chromium resolves
// every name to it (--host-resolver-rules); Firefox, which can't, uses it
// as its proxy: absolute URLs for HTTP, CONNECT tunnels for HTTPS. Hosts
// without a directory stand in for third parties: ad networks, trackers,
// CDNs. Each request is logged with the headers the privacy checks look
// at, so a test can tell exactly what left the browser.
//
// With `https: true` it also serves HTTPS (third-party cookies need
// `Secure`), with a self-signed certificate made for the run by openssl.
// Only the test's own browsers see it, told to accept it; nothing is
// installed or trusted anywhere else.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { extname, join, normalize, resolve } from "node:path";

const sites = resolve(import.meta.dirname, "sites");

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".gif": "image/gif",
};

const GIF = Buffer.from("R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==", "base64");

// What the real third-party scripts would do, reduced to the API pages
// check for. Without a blocker these load and the detectors stay quiet;
// with one, they must be replaced by surrogates that do the same.
const THIRD_PARTY = {
  "/ads.js": "window.canRunAds = true;",
  "/pagead/js/adsbygoogle.js": `
    window.adsbygoogle = window.adsbygoogle || [];
    window.adsbygoogle.loaded = true;`,
  "/tag/js/gpt.js": `(function () {
    var g = (window.googletag = window.googletag || { cmd: [] });
    var queued = g.cmd || [];
    g.cmd = { push: function (f) { f(); return 1; } };
    g.apiReady = true;
    queued.forEach(function (f) { f(); });
  })();`,
  "/analytics.js": `
    window.ga = function () {
      var last = arguments[arguments.length - 1];
      if (last && typeof last.hitCallback === "function") setTimeout(last.hitCallback, 0);
    };
    window.ga.loaded = true;`,
};

// Hosts that serve another host's pages: the same page on two sites.
const ALIASES = { "fp-b.test": "fp.test" };

const YEARS = 60 * 60 * 24 * 365 * 2;
// Response headers by host and path.
const HEADERS = {
  // A page that asks for full referrers everywhere.
  "ref.test/page.html": { "referrer-policy": "unsafe-url" },
  // First-party cookies set by the server: one tracking, one not.
  "cookie.test/": {
    "set-cookie": [
      `_fbp=fb.1.123.456; Max-Age=${YEARS}; Path=/`,
      `sid=abc; Max-Age=${YEARS}; Path=/`,
    ],
  },
  // A tracker visited directly (first party) sets its cookie; later, as a
  // third party, it would get it back and set another.
  "cookie-tracker.test/set": {
    "set-cookie": `tid=first; Max-Age=3600; Path=/; Secure; SameSite=None`,
  },
  "cookie-tracker.test/allowed.gif": {
    "set-cookie": `tid2=third; Max-Age=3600; Path=/; Secure; SameSite=None`,
  },
};

/** Serves the testbed until `close()`. */
export async function startServer({ generated = {}, https = false } = {}) {
  const log = [];
  // Added before every response, to stand in for a network.
  let latency = 0;
  const handle = (scheme) => async (req, res) => {
    // A proxy request names the whole URL.
    if (/^https?:\/\//.test(req.url ?? "")) {
      const url = new URL(req.url);
      req.url = url.pathname + url.search;
    }
    if (latency) await new Promise((done) => setTimeout(done, latency));
    const host = (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase();
    const [path] = (req.url ?? "/").split("?");
    log.push({
      scheme,
      host,
      url: req.url,
      method: req.method,
      cookie: req.headers.cookie ?? null,
      referer: req.headers.referer ?? null,
      gpc: req.headers["sec-gpc"] ?? null,
    });
    const send = (type, body, status = 200) => {
      res.writeHead(status, {
        "content-type": type,
        "cache-control": "no-store",
        // Probes are cross-origin; without a blocker they must succeed.
        "access-control-allow-origin": "*",
        ...HEADERS[`${host}${path}`],
      });
      res.end(body);
    };
    const page = generated[`${host}${path}`];
    if (page) return send(TYPES[".html"], page());
    const dir = ALIASES[host] ?? host;
    const file = normalize(join(sites, dir, path === "/" ? "index.html" : path));
    if (file.startsWith(join(sites, dir)) && host !== "") {
      try {
        return send(TYPES[extname(file)] ?? "application/octet-stream", await readFile(file));
      } catch {
        // Not a page of this site: a third-party response below.
      }
    }
    if (THIRD_PARTY[path]) return send(TYPES[".js"], THIRD_PARTY[path]);
    if (path.endsWith(".js")) return send(TYPES[".js"], `/* ${host}${path} */`);
    if (path.endsWith(".gif")) return send(TYPES[".gif"], GIF);
    if (path === "/landing") return send(TYPES[".html"], "<!doctype html><title>landing</title>");
    if (path === "/blank") return send(TYPES[".html"], "<!doctype html><title>blank</title>");
    if (path === "/set") return send(TYPES[".html"], "<!doctype html><title>set</title>");
    send("text/plain", "", 204);
  };
  const server = createServer(handle("http"));
  // Idle connections outlive the browser's own keep-alive (Firefox: 115 s),
  // so the server never closes one just as a request goes out on it.
  server.keepAliveTimeout = 120_000;
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  let secure = null;
  // CONNECT, from Firefox: a tunnel to the HTTPS server for port 443, to
  // the HTTP one for anything else (WebSockets). A tunnel's sockets leave
  // the server's keeping, so they are tracked here, and either end closing
  // closes both: a half-closed tunnel would hold the server open.
  const tunnels = new Set();
  server.on("connect", (req, socket, head) => {
    const tls = req.url?.endsWith(":443") && secure;
    const upstream = connect(tls ? secure.address().port : server.address().port, "127.0.0.1");
    const ends = [socket, upstream];
    const destroy = () => {
      for (const end of ends) end.destroy();
    };
    for (const end of ends) {
      tunnels.add(end);
      end.on("error", () => {});
      end.on("end", destroy);
      end.on("close", () => {
        tunnels.delete(end);
        destroy();
      });
    }
    upstream.on("connect", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
  });
  if (https) {
    const dir = mkdtempSync(join(tmpdir(), "sinkd-testbed-tls-"));
    try {
      execFileSync(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "rsa:2048",
          "-nodes",
          "-days",
          "1",
          "-subj",
          "/CN=testbed",
        ].concat(["-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")]),
        { stdio: "ignore" },
      );
      secure = createHttpsServer(
        { key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) },
        handle("https"),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    secure.keepAliveTimeout = 120_000;
    await new Promise((ok) => secure.listen(0, "127.0.0.1", ok));
  }
  return {
    port: server.address().port,
    httpsPort: secure?.address().port ?? null,
    log,
    /** Requests to `host` (and its subdomains) so far. */
    to: (host) => log.filter((r) => r.host === host || r.host.endsWith(`.${host}`)),
    setLatency: (ms) => {
      latency = ms;
    },
    close: () => {
      for (const end of tunnels) end.destroy();
      return Promise.all(
        [server, secure].filter(Boolean).map((s) => {
          const closed = new Promise((ok) => s.close(ok));
          // Kept-alive connections would hold it open.
          s.closeAllConnections();
          return closed;
        }),
      );
    },
  };
}
