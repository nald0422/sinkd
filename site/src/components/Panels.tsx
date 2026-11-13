// The landing page's panels, in reading order. Each one makes one point,
// and each fits one screen, a phone's included: what has more items than a
// phone can show turns sideways in a carousel there.

import type { ReactNode } from "react";

import { Carousel } from "./Carousel";
import { HeroMark } from "./HeroMark";
import { Logo } from "./Logo";
import { PageSweep } from "./PageSweep";

const GITHUB = "https://github.com/nald0422/sinkd";
const CHROME_STORE = "https://chromewebstore.google.com/detail/abgodfdohgofhleaaenojdpjhapecknf";

/** The panels' headings: a phone's size first, then a screen's. */
const H2 =
  "text-[2rem] font-medium leading-[1.12] tracking-tight tiny:text-[1.75rem] md:text-5xl md:leading-tight";

/**
 * A panel: one screen, wide and high, when horizontal (so a step shows
 * exactly one), natural height when stacked. Content is centered in a
 * column of its own, clear of the header and the counter.
 */
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
    paper: "bg-white text-ink",
    deep: "bg-snow text-ink",
    ink: "bg-ink text-mist",
  };
  return (
    <section
      id={id}
      className={`relative flex shrink-0 flex-col justify-center px-6 pt-16 pb-12 stage:h-dvh stage:w-screen md:px-16 md:py-24 lg:px-24 ${tones[tone]} ${className}`}
    >
      <div className="mx-auto w-full max-w-6xl">{children}</div>
    </section>
  );
}

function Eyebrow({ children, dark = false }: { children: ReactNode; dark?: boolean }) {
  return (
    <div
      className={`mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] md:mb-5 md:text-xs ${dark ? "text-silver" : "text-smoke"}`}
    >
      {children}
    </div>
  );
}

function Dot() {
  return <span aria-hidden className="mt-2.5 inline-block size-2 shrink-0 rounded-full bg-ink" />;
}

export function Hero({ onNext }: { onNext: () => void }) {
  return (
    <Panel id="top">
      <div className="grid items-center gap-16 lg:grid-cols-[1.1fr_1fr]">
        <div>
          <Eyebrow>Ad and tracker blocker · browser and every app</Eyebrow>
          <h1 className="text-[2.75rem] font-medium leading-[1.04] tracking-tight tiny:text-[2.4rem] md:text-6xl lg:text-7xl short:text-6xl">
            Ad and tracker blocking that <span className="text-smoke">blends in.</span>
          </h1>
          <p className="mt-5 max-w-xl text-base leading-relaxed text-smoke md:mt-7 md:text-xl short:mt-5">
            sinkd blocks ads and trackers, strips what is left of tracking and keeps out of sight,
            in your browser and for every app on your computer.
          </p>
          <div className="mt-7 flex flex-wrap items-center gap-3 md:mt-10 md:gap-4 short:mt-7">
            <a
              href={CHROME_STORE}
              className="rounded-full bg-ink px-5 py-3 text-sm font-medium text-white transition hover:bg-carbon md:px-6"
            >
              Add to Chrome
            </a>
            <button
              type="button"
              onClick={onNext}
              className="rounded-full px-5 py-3 text-sm font-medium text-ink ring-1 ring-ink/20 transition hover:ring-ink/50 md:px-6"
            >
              How it works →
            </button>
          </div>
          <p className="mt-5 text-sm text-smoke md:mt-6">
            Free and open source, on{" "}
            <a href={GITHUB} className="text-ink underline underline-offset-4 hover:text-smoke">
              GitHub
            </a>
            . Coming to <span className="whitespace-nowrap">Firefox Add-ons.</span>
          </p>
        </div>
        <div className="hidden justify-center lg:flex">
          <HeroMark size={360} className="drop-shadow-sm" />
        </div>
      </div>
      <div className="absolute bottom-4 left-6 flex items-center gap-3 text-sm text-smoke md:bottom-10 md:left-16 lg:left-24">
        <span className="pointer-coarse:hidden">Scroll</span>
        <span className="hidden pointer-coarse:inline">Swipe</span>
        <span aria-hidden className="h-px w-16 bg-smoke/50" />
        <span aria-hidden className="motion-safe:animate-nudge">
          →
        </span>
      </div>
    </Panel>
  );
}

export function Idea() {
  return (
    <Panel id="idea">
      <div className="grid max-w-5xl items-center gap-8 md:grid-cols-[auto_1fr] md:gap-14">
        <div
          aria-hidden
          className="font-mono text-[2.75rem] tracking-tight text-ink md:text-6xl lg:text-7xl"
        >
          0<span className="text-smoke">.</span>0<span className="text-smoke">.</span>0
          <span className="text-smoke">.</span>0
        </div>
        <div>
          <Eyebrow>The idea</Eyebrow>
          <h2 className={H2}>A sinkhole for the web's junk.</h2>
          <p className="mt-4 text-base leading-relaxed text-smoke md:mt-6 md:text-lg">
            When a page reaches for an ad or a tracker, sinkd answers with nothing,{" "}
            <span className="font-mono text-[0.95em] text-ink">0.0.0.0</span>, and it quietly falls
            away. The page keeps working. The tracking doesn't.
          </p>
          <p className="mt-3 text-base leading-relaxed text-smoke tiny:hidden md:mt-4 md:text-lg">
            The mark is how maps draw a sinkhole: contour lines closing in on a low point.
          </p>
        </div>
      </div>
    </Panel>
  );
}

export function BeforeAfter() {
  return (
    <Panel id="pages" tone="deep">
      <div className="grid gap-6 md:gap-10 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,2fr)] lg:items-center lg:gap-14">
        <div>
          <Eyebrow>On a page</Eyebrow>
          <h2 className={H2}>
            Ads gone. <span className="text-smoke">The page stays whole.</span>
          </h2>
          <p className="mt-4 hidden max-w-md text-lg leading-relaxed text-smoke md:block">
            Drag the mark across the page. Where sinkd has been, the ads are gone, the page closes
            up around them, and the log lists each request it blocked.
          </p>
        </div>
        <div className="min-w-0">
          <PageSweep />
          <p className="mt-3 text-xs text-smoke md:hidden tiny:hidden">
            Drag the mark across the page, or tap where to put it.
          </p>
        </div>
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

/** A card on a phone, plain from md up. */
const CARD = "h-full rounded-2xl p-5 tiny:p-4 md:rounded-none md:bg-transparent md:p-0";

export function Privacy() {
  return (
    <Panel id="privacy">
      <Eyebrow>Beyond blocking</Eyebrow>
      <h2 className={`${H2} max-w-2xl`}>Less to track you with.</h2>
      <div className="mt-6 md:mt-12">
        <Carousel
          label="Protections"
          layout="md:grid md:grid-cols-2 md:gap-x-12 md:gap-y-9 lg:grid-cols-3"
        >
          {FEATURES.map(([title, text]) => (
            <div key={title} className={`${CARD} flex gap-4 bg-snow`}>
              <Dot />
              <div>
                <div className="text-lg font-medium">{title}</div>
                <p className="mt-1.5 leading-relaxed text-smoke">{text}</p>
              </div>
            </div>
          ))}
        </Carousel>
      </div>
      <p className="mt-4 text-sm leading-relaxed text-smoke md:mt-12 md:text-base">
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
    <Panel id="every-app" tone="ink">
      <Eyebrow dark>Optional, for macOS and Linux</Eyebrow>
      <h2 className={H2}>
        Every app, <span className="text-pewter">not just the browser.</span>
      </h2>
      <div className="mt-6 md:mt-10">
        <Carousel
          label="The resolver"
          dark
          width="w-[88%]"
          layout="md:block md:space-y-8 lg:grid lg:grid-cols-[0.8fr_1.2fr] lg:items-center lg:gap-8 lg:space-y-0 xl:gap-14"
        >
          <div className={`${CARD} bg-carbon`}>
            <p className="text-base leading-relaxed text-silver tiny:text-sm md:text-lg lg:text-base xl:text-lg">
              The sinkd program becomes your computer's DNS resolver and blocks the same trackers
              for every app, over encrypted DNS. OISD and AdGuard's DNS lists add the ad networks
              and telemetry only apps talk to. Its allowlist, blocklist and pause reach the
              extension too.
            </p>
            <div className="mt-5 space-y-2 font-mono text-sm md:mt-8">
              <div className="rounded-lg bg-ink px-4 py-3 text-mist md:bg-carbon">
                <span className="text-silver">$ </span>sudo sinkd install
              </div>
              <div className="px-4 text-silver">Undo it all: sudo sinkd uninstall</div>
            </div>
          </div>
          <div className="h-full overflow-hidden rounded-xl bg-term shadow-[0_22px_60px_rgba(0,0,0,0.35)] ring-1 ring-white/5 md:h-auto">
            <div className="flex h-8 items-center gap-1.5 bg-term-bar px-3">
              {[0, 1, 2].map((i) => (
                <span key={i} className="size-2.5 rounded-full bg-term-dot" />
              ))}
            </div>
            <pre className="whitespace-pre-wrap px-4 py-4 font-mono text-[11px] leading-relaxed text-term-text [overflow-wrap:anywhere] md:overflow-x-auto md:whitespace-pre md:px-6 md:py-5 md:text-[12px] md:[overflow-wrap:normal] xl:text-[13px]">
              {TERMINAL.map(([kind, line], i) => (
                <div
                  // biome-ignore lint/suspicious/noArrayIndexKey: a fixed list of lines
                  key={i}
                  className={kind === "cmd" ? "text-white" : kind === "hit" ? "text-term-red" : ""}
                >
                  {line || " "}
                </div>
              ))}
            </pre>
          </div>
        </Carousel>
      </div>
    </Panel>
  );
}

// The build pipeline (DESIGN.md, "Shape of the system"), with the numbers
// measured on the public lists, rounded. The resolver's count is a new
// install's: the pipeline's 89k names and the two DNS lists it adds.
const STEPS = [
  [
    "Collect",
    "Public filter lists, EasyList, EasyPrivacy and uBlock Origin's, fetched over HTTPS, checked and cached.",
    "7 lists · 164k lines",
  ],
  [
    "Parse",
    "One parser reads Adblock Plus, uBlock Origin and AdGuard syntax into structured rules.",
    "99.3% understood",
  ],
  [
    "Compile",
    "Each rule is translated for each target, exactly. What a target can't express is reported, never approximated.",
    "120k rules · under 1 s",
  ],
] as const;

const TARGETS = [
  ["Browser extension", "blocks requests", "20k rules"],
  ["Every app", "the resolver, with two DNS lists", "370k domains"],
  ["On the page", "hides what's left", "43k rules"],
] as const;

/**
 * A step's number, and the arrow on to the next step when there is one.
 * On a phone the carousel's own numbered steps take its place.
 */
function StepMark({ n, last = false }: { n: number; last?: boolean }) {
  return (
    <div className="flex items-center max-md:hidden" aria-hidden>
      <span
        className={`grid size-10 shrink-0 place-items-center rounded-full font-mono text-xs ${
          last ? "bg-ink text-white" : "bg-white text-ink ring-1 ring-ink/25"
        }`}
      >
        {String(n).padStart(2, "0")}
      </span>
      {!last && (
        <span className="mx-3 hidden flex-1 items-center lg:flex">
          <span className="h-px flex-1 bg-ink/25" />
          <span className="border-y-[4px] border-l-[7px] border-y-transparent border-l-ink/40" />
        </span>
      )}
    </div>
  );
}

export function Process() {
  const title = "text-xl font-medium md:mt-5 short:mt-3";
  return (
    <Panel id="process" tone="deep">
      <Eyebrow>How it's made</Eyebrow>
      <h2 className={`${H2} short:text-4xl`}>
        One parser. <span className="text-smoke">Every target.</span>
      </h2>
      <p className="mt-4 max-w-2xl text-base leading-relaxed text-smoke tiny:hidden md:mt-5 md:text-lg short:mt-3 md:max-lg:hidden">
        The same public filter lists become rules for your browser, your computer's DNS and the page
        itself, so a rule means the same in all three.
      </p>
      <div className="mt-6 md:mt-12 short:mt-8">
        <Carousel
          label="How sinkd is made"
          indicator="steps"
          layout="md:grid md:grid-cols-2 md:gap-10 short:gap-y-8 lg:grid-cols-[1fr_1fr_1fr_1.15fr] lg:gap-0"
        >
          {[
            ...STEPS.map(([name, text, stat], i) => (
              <div key={name} className={`${CARD} bg-white lg:pr-6`}>
                <StepMark n={i + 1} />
                <h3 className={title}>{name}</h3>
                <p className="mt-2 max-w-xs leading-relaxed text-smoke">{text}</p>
                <div className="mt-4 font-mono text-xs text-ink/70">{stat}</div>
              </div>
            )),
            <div key="run" className={`${CARD} bg-white`}>
              <StepMark n={STEPS.length + 1} last />
              <h3 className={title}>Run</h3>
              <ul className="mt-3 border-l border-ink/25">
                {TARGETS.map(([name, what, stat]) => (
                  <li
                    key={name}
                    className="relative py-2 pl-5 before:absolute before:top-1/2 before:left-0 before:h-px before:w-3 before:bg-ink/25"
                  >
                    <div className="flex items-baseline justify-between gap-4">
                      <span className="font-medium">{name}</span>
                      <span className="shrink-0 font-mono text-xs text-ink/70">{stat}</span>
                    </div>
                    <div className="text-sm text-smoke">{what}</div>
                  </li>
                ))}
              </ul>
            </div>,
          ]}
        </Carousel>
      </div>
      <p className="mt-12 hidden max-w-2xl text-smoke short:mt-8 lg:block">
        Lists are data. They can switch on the scriptlets sinkd ships, never bring code of their
        own, and the store build can be reproduced from the source, byte for byte.
      </p>
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
    <Panel id="open" tone="ink">
      <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
        <Logo size={96} variant="graphite" bare className="size-16 md:size-24" />
        <h2 className="mt-6 text-[2rem] font-medium leading-[1.12] tracking-tight md:mt-10 md:text-6xl md:leading-tight">
          Open source. <span className="text-pewter">Nothing to phone home to.</span>
        </h2>
        <p className="mt-4 text-base leading-relaxed text-silver md:mt-6 md:text-lg">
          No account, no analytics, no remote code. Everything runs on your device. MIT or Apache
          2.0, your choice.
        </p>
        <nav className="mt-7 flex flex-wrap justify-center gap-2.5 md:mt-10 md:gap-3">
          {links.map(([label, href]) => (
            <a
              key={label}
              href={href}
              className="rounded-full px-4 py-2.5 text-sm text-mist ring-1 ring-mist/25 transition hover:ring-mist/60 md:px-5"
            >
              {label}
            </a>
          ))}
        </nav>
      </div>
      <footer className="absolute inset-x-0 bottom-4 text-center text-xs text-silver md:bottom-8">
        sinkd · {new Date().getFullYear()} ·{" "}
        <a href="./licenses.md" className="underline-offset-2 hover:underline">
          Licenses
        </a>
      </footer>
    </Panel>
  );
}
