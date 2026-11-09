// The landing page's panels, in reading order. Each one makes one point.

import type { ReactNode } from "react";

import { Logo } from "./Logo";

const GITHUB = "https://github.com/nald0422/sinkd";

/** A panel: full height when horizontal, natural height when stacked. */
function Panel({
  id,
  tone = "paper",
  className = "",
  children,
}: {
  id: string;
  tone?: "paper" | "deep" | "ink";
  className?: string;
  children: ReactNode;
}) {
  const tones = {
    paper: "bg-paper text-ink",
    deep: "bg-paper-deep text-ink",
    ink: "bg-ink text-sand",
  };
  return (
    <section
      id={id}
      className={`relative flex shrink-0 flex-col justify-center px-6 py-24 md:h-screen md:px-16 lg:px-24 ${tones[tone]} ${className}`}
    >
      {children}
    </section>
  );
}

function Eyebrow({ children, dark = false }: { children: ReactNode; dark?: boolean }) {
  return (
    <div
      className={`mb-5 text-xs font-semibold uppercase tracking-[0.14em] ${dark ? "text-muted-dark" : "text-muted"}`}
    >
      {children}
    </div>
  );
}

function Dot() {
  return <span aria-hidden className="mt-2.5 inline-block size-2 shrink-0 rounded-full bg-clay" />;
}

export function Hero({ onNext }: { onNext: () => void }) {
  return (
    <Panel id="top" className="md:w-screen">
      <div className="grid items-center gap-16 md:grid-cols-[1.1fr_1fr]">
        <div>
          <Eyebrow>Ad and tracker blocker · browser and every app</Eyebrow>
          <h1 className="text-5xl font-medium leading-[1.04] tracking-tight md:text-6xl lg:text-7xl">
            Ad and tracker blocking that <span className="text-clay">blends in.</span>
          </h1>
          <p className="mt-7 max-w-xl text-lg leading-relaxed text-muted md:text-xl">
            sinkd blocks ads and trackers, strips what is left of tracking and keeps out of sight,
            in your browser and for every app on your computer.
          </p>
          <div className="mt-10 flex flex-wrap items-center gap-4">
            <a
              href={GITHUB}
              className="rounded-full bg-ink px-6 py-3 text-sm font-medium text-paper transition hover:bg-ink-soft"
            >
              View on GitHub
            </a>
            <button
              type="button"
              onClick={onNext}
              className="rounded-full px-6 py-3 text-sm font-medium text-ink ring-1 ring-ink/20 transition hover:ring-ink/50"
            >
              How it works →
            </button>
          </div>
          <p className="mt-6 text-sm text-muted">
            Coming to the Chrome Web Store and Firefox Add-ons.
          </p>
        </div>
        <div className="hidden justify-center md:flex">
          <Logo size={360} bare className="drop-shadow-sm" />
        </div>
      </div>
      <div className="absolute bottom-10 left-16 hidden items-center gap-3 text-sm text-muted md:flex lg:left-24">
        <span>Scroll</span>
        <span aria-hidden className="h-px w-16 bg-muted/50" />
        <span aria-hidden>→</span>
      </div>
    </Panel>
  );
}

export function Idea() {
  return (
    <Panel id="idea" className="md:w-[74vw]">
      <div className="grid max-w-5xl items-center gap-14 md:grid-cols-[auto_1fr]">
        <div
          aria-hidden
          className="font-mono text-5xl tracking-tight text-ink md:text-6xl lg:text-7xl"
        >
          0<span className="text-clay">.</span>0<span className="text-clay">.</span>0
          <span className="text-clay">.</span>0
        </div>
        <div>
          <Eyebrow>The idea</Eyebrow>
          <h2 className="text-4xl font-medium leading-tight tracking-tight md:text-5xl">
            A sinkhole for the web's junk.
          </h2>
          <p className="mt-6 text-lg leading-relaxed text-muted">
            When a page reaches for an ad or a tracker, sinkd answers with nothing,{" "}
            <span className="font-mono text-[0.95em] text-ink">0.0.0.0</span>, and it quietly falls
            away. The page keeps working. The tracking doesn't.
          </p>
          <p className="mt-4 text-lg leading-relaxed text-muted">
            The mark is how maps draw a sinkhole: contour lines closing in on a low point.
          </p>
        </div>
      </div>
    </Panel>
  );
}

export function BeforeAfter() {
  const shots = [
    ["Without sinkd", "page-before.jpg"],
    ["With sinkd", "page-after.jpg"],
  ] as const;
  return (
    <Panel id="pages" tone="deep" className="md:w-screen">
      <Eyebrow>On a page</Eyebrow>
      <h2 className="text-4xl font-medium tracking-tight md:text-5xl">
        Ads gone. <span className="text-clay">The page stays whole.</span>
      </h2>
      <div className="mt-10 grid gap-8 md:grid-cols-2">
        {shots.map(([label, src]) => (
          <figure key={src} className="min-w-0">
            <figcaption className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-muted">
              {label}
            </figcaption>
            <div className="overflow-hidden rounded-xl bg-white shadow-[0_22px_60px_rgba(44,48,44,0.18)]">
              <div className="flex h-8 items-center gap-1.5 bg-[#e4dfd4] px-3">
                {[0, 1, 2].map((i) => (
                  <span key={i} className="size-2.5 rounded-full bg-[#cfc8ba]" />
                ))}
              </div>
              <img
                src={`./${src}`}
                alt={`${label}: a news page`}
                className="block max-h-[52vh] w-full object-cover object-top"
                loading="lazy"
              />
            </div>
          </figure>
        ))}
      </div>
    </Panel>
  );
}

const FEATURES = [
  ["Ads, trackers, malware", "Blocked, with harmless stand-ins for the scripts pages depend on."],
  ["Tracking parameters", "utm_*, fbclid, gclid and more, removed from links."],
  ["Cookies and referrer", "Kept from trackers; analytics cookies expire within a week."],
  ["A fingerprint per site", "Canvas, WebGL and audio noise, stable per site and session."],
  ["Global Privacy Control", "Every site is told not to sell or share your data."],
  ["Local IP address", "WebRTC uses only the public interface."],
] as const;

export function Privacy() {
  return (
    <Panel id="privacy" className="md:w-[86vw]">
      <Eyebrow>Beyond blocking</Eyebrow>
      <h2 className="max-w-2xl text-4xl font-medium tracking-tight md:text-5xl">
        Less to track you with.
      </h2>
      <div className="mt-12 grid gap-x-12 gap-y-9 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map(([title, text]) => (
          <div key={title} className="flex gap-4">
            <Dot />
            <div>
              <div className="text-lg font-medium">{title}</div>
              <p className="mt-1.5 leading-relaxed text-muted">{text}</p>
            </div>
          </div>
        ))}
      </div>
      <p className="mt-12 text-muted">
        Every protection can be switched off on its own, everywhere or for one site. It never
        changes your user agent: blending in beats standing out.
      </p>
    </Panel>
  );
}

// Lines from the real `sinkd check` output.
const TERMINAL = [
  ["cmd", "$ sinkd check ad.doubleclick.net"],
  ["", ""],
  ["", "Resolver (every app; DNS name ad.doubleclick.net):"],
  ["hit", "  BLOCKED by `ad.doubleclick.net` in a blocklist: answered 0.0.0.0 / ::"],
  ["", ""],
  ["", "Extension, network (browser only):"],
  ["hit", "  BLOCKED by `||ad.doubleclick.net^`"],
  ["", '    easylist, line 58629 (ruleset "ads"); the extension applies it'],
] as const;

export function EveryApp() {
  return (
    <Panel id="every-app" tone="ink" className="md:w-[88vw]">
      <div className="grid items-center gap-14 lg:grid-cols-[0.8fr_1.2fr]">
        <div>
          <Eyebrow dark>Optional, for macOS and Linux</Eyebrow>
          <h2 className="text-4xl font-medium leading-tight tracking-tight md:text-5xl">
            Every app, <span className="text-clay">not just the browser.</span>
          </h2>
          <p className="mt-6 text-lg leading-relaxed text-muted-dark">
            The sinkd program becomes your computer's DNS resolver and blocks the same trackers for
            every app, over encrypted DNS. Its allowlist, blocklist and pause reach the extension
            too.
          </p>
          <div className="mt-8 space-y-2 font-mono text-sm">
            <div className="rounded-lg bg-ink-soft px-4 py-3 text-sand">
              <span className="text-muted-dark">$ </span>sudo sinkd install
            </div>
            <div className="px-4 text-muted-dark">Undo it all: sudo sinkd uninstall</div>
          </div>
        </div>
        <div className="overflow-hidden rounded-xl shadow-[0_22px_60px_rgba(0,0,0,0.35)] ring-1 ring-white/5">
          <div className="flex h-8 items-center gap-1.5 bg-ink-soft px-3">
            {[0, 1, 2].map((i) => (
              <span key={i} className="size-2.5 rounded-full bg-[#5c6259]" />
            ))}
          </div>
          <pre className="overflow-x-auto bg-[#252925] px-6 py-5 font-mono text-[12px] leading-relaxed text-sand xl:text-[13px]">
            {TERMINAL.map(([kind, line], i) => (
              <div
                // biome-ignore lint/suspicious/noArrayIndexKey: a fixed list of lines
                key={i}
                className={kind === "cmd" ? "text-paper" : kind === "hit" ? "text-clay" : ""}
              >
                {line || " "}
              </div>
            ))}
          </pre>
        </div>
      </div>
    </Panel>
  );
}

const LIMITS = [
  ["Your IP address", "Use a VPN or Tor."],
  ["Sites you're logged in to", "They know who you are."],
  ["Server-side tracking", "It happens where no blocker can see."],
  ["Behavioral fingerprinting", "How you type and move is yours to vary."],
] as const;

export function Honest() {
  return (
    <Panel id="honest" className="md:w-[66vw]">
      <Eyebrow>Honestly</Eyebrow>
      <h2 className="max-w-xl text-4xl font-medium leading-tight tracking-tight md:text-5xl">
        Untrackable isn't a thing. Harder to track is.
      </h2>
      <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted">
        sinkd defeats third-party tracking and the common fingerprinting and detection tricks,
        without breaking sites. What it can't reach:
      </p>
      <dl className="mt-9 grid max-w-2xl gap-x-10 gap-y-5 sm:grid-cols-2">
        {LIMITS.map(([title, text]) => (
          <div key={title} className="border-t border-ink/15 pt-4">
            <dt className="font-medium">{title}</dt>
            <dd className="mt-1 text-muted">{text}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}

export function Open() {
  const links = [
    ["Source on GitHub", GITHUB],
    ["Privacy policy", `${GITHUB}/blob/main/docs/privacy.md`],
    ["How it's built", `${GITHUB}/blob/main/DESIGN.md`],
  ] as const;
  return (
    <Panel id="open" tone="ink" className="md:w-screen">
      <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
        <Logo size={96} variant="basalt" bare />
        <h2 className="mt-10 text-4xl font-medium leading-tight tracking-tight md:text-6xl">
          Open source. <span className="text-clay">Nothing to phone home to.</span>
        </h2>
        <p className="mt-6 text-lg leading-relaxed text-muted-dark">
          No account, no analytics, no remote code. Everything runs on your device. MIT or Apache
          2.0, your choice.
        </p>
        <nav className="mt-10 flex flex-wrap justify-center gap-3">
          {links.map(([label, href]) => (
            <a
              key={label}
              href={href}
              className="rounded-full px-5 py-2.5 text-sm text-sand ring-1 ring-sand/25 transition hover:ring-sand/60"
            >
              {label}
            </a>
          ))}
        </nav>
      </div>
      <footer className="absolute inset-x-0 bottom-8 text-center text-xs text-muted-dark">
        sinkd · {new Date().getFullYear()}
      </footer>
    </Panel>
  );
}
