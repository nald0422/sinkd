// The landing page's panels, in reading order. Each one makes one point,
// and each fits one screen, a phone's included: what has more items than a
// phone can show turns sideways in a carousel there.

import { type ReactNode, useEffect, useRef, useState } from "react";

import { Carousel } from "./Carousel";
import { Logo } from "./Logo";

const GITHUB = "https://github.com/nald0422/sinkd";

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
    paper: "bg-paper text-ink",
    deep: "bg-paper-deep text-ink",
    ink: "bg-ink text-sand",
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
      className={`mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] md:mb-5 md:text-xs ${dark ? "text-muted-dark" : "text-muted"}`}
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
    <Panel id="top">
      <div className="grid items-center gap-16 lg:grid-cols-[1.1fr_1fr]">
        <div>
          <Eyebrow>Ad and tracker blocker · browser and every app</Eyebrow>
          <h1 className="text-[2.75rem] font-medium leading-[1.04] tracking-tight tiny:text-[2.4rem] md:text-6xl lg:text-7xl short:text-6xl">
            Ad and tracker blocking that <span className="text-clay">blends in.</span>
          </h1>
          <p className="mt-5 max-w-xl text-base leading-relaxed text-muted md:mt-7 md:text-xl short:mt-5">
            sinkd blocks ads and trackers, strips what is left of tracking and keeps out of sight,
            in your browser and for every app on your computer.
          </p>
          <div className="mt-7 flex flex-wrap items-center gap-3 md:mt-10 md:gap-4 short:mt-7">
            <a
              href={GITHUB}
              className="rounded-full bg-ink px-5 py-3 text-sm font-medium text-paper transition hover:bg-ink-soft md:px-6"
            >
              View on GitHub
            </a>
            <button
              type="button"
              onClick={onNext}
              className="rounded-full px-5 py-3 text-sm font-medium text-ink ring-1 ring-ink/20 transition hover:ring-ink/50 md:px-6"
            >
              How it works →
            </button>
          </div>
          <p className="mt-5 text-sm text-muted md:mt-6">
            Coming to the Chrome Web Store and{" "}
            <span className="whitespace-nowrap">Firefox Add-ons.</span>
          </p>
        </div>
        <div className="hidden justify-center lg:flex">
          <Logo size={360} bare className="drop-shadow-sm" />
        </div>
      </div>
      <div className="absolute bottom-4 left-6 flex items-center gap-3 text-sm text-muted md:bottom-10 md:left-16 lg:left-24">
        <span className="pointer-coarse:hidden">Scroll</span>
        <span className="hidden pointer-coarse:inline">Swipe</span>
        <span aria-hidden className="h-px w-16 bg-muted/50" />
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
          0<span className="text-clay">.</span>0<span className="text-clay">.</span>0
          <span className="text-clay">.</span>0
        </div>
        <div>
          <Eyebrow>The idea</Eyebrow>
          <h2 className={H2}>A sinkhole for the web's junk.</h2>
          <p className="mt-4 text-base leading-relaxed text-muted md:mt-6 md:text-lg">
            When a page reaches for an ad or a tracker, sinkd answers with nothing,{" "}
            <span className="font-mono text-[0.95em] text-ink">0.0.0.0</span>, and it quietly falls
            away. The page keeps working. The tracking doesn't.
          </p>
          <p className="mt-3 text-base leading-relaxed text-muted tiny:hidden md:mt-4 md:text-lg">
            The mark is how maps draw a sinkhole: contour lines closing in on a low point.
          </p>
        </div>
      </div>
    </Panel>
  );
}

const SHOTS = [
  ["Without sinkd", "page-before.jpg"],
  ["With sinkd", "page-after.jpg"],
] as const;

/** How long each page holds before the blink shows the other. */
const BLINK = 1600;

/**
 * The before and after in one frame, on a phone, flicking between the two
 * like an astronomer's blink comparator: what changes (the ads) jumps out.
 * It blinks while in view, until a tap holds one page.
 */
function Blink() {
  const [shown, setShown] = useState(0);
  const [held, setHeld] = useState(false);
  const frame = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = frame.current;
    if (held || !el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let timer = 0;
    const observer = new IntersectionObserver(
      ([entry]) => {
        window.clearInterval(timer);
        if (entry?.isIntersecting) timer = window.setInterval(() => setShown((s) => 1 - s), BLINK);
      },
      { threshold: 0.6 },
    );
    observer.observe(el);
    return () => {
      observer.disconnect();
      window.clearInterval(timer);
    };
  }, [held]);
  const hold = (i: number) => {
    setHeld(true);
    setShown(i);
  };
  return (
    <div className="mt-6 md:hidden">
      <div className="relative grid grid-cols-2 rounded-full bg-ink/[0.07] p-1 text-sm">
        <span
          aria-hidden
          className="absolute inset-y-1 left-1 w-[calc(50%-4px)] rounded-full bg-paper shadow-sm transition-transform duration-300"
          style={{ transform: `translateX(${shown * 100}%)` }}
        />
        {SHOTS.map(([label], i) => (
          <button
            key={label}
            type="button"
            aria-pressed={held && shown === i}
            onClick={() => hold(i)}
            className={`relative py-2 font-medium transition-colors duration-300 ${shown === i ? "text-ink" : "text-muted"}`}
          >
            {label}
          </button>
        ))}
      </div>
      <div
        ref={frame}
        className="mt-4 overflow-hidden rounded-xl bg-white shadow-[0_18px_44px_rgba(44,48,44,0.18)]"
      >
        <div className="flex h-7 items-center gap-1.5 bg-[#e4dfd4] px-3">
          {[0, 1, 2].map((i) => (
            <span key={i} className="size-2 rounded-full bg-[#cfc8ba]" />
          ))}
          <span className="ml-auto font-mono text-[10px] text-muted">
            {held ? "held" : "blinking"}
          </span>
        </div>
        <div className="relative h-[34svh]">
          {SHOTS.map(([label, src], i) => (
            <img
              key={src}
              src={`./${src}`}
              alt={`${label}: a news page`}
              aria-hidden={shown !== i}
              className={`absolute inset-0 size-full object-cover object-top transition-opacity duration-300 ${shown === i ? "opacity-100" : "opacity-0"}`}
            />
          ))}
        </div>
      </div>
      <p className="mt-3 text-xs text-muted">
        {held ? "Tap the other to compare." : "One page, blinking between the two. Tap to hold."}
      </p>
    </div>
  );
}

export function BeforeAfter() {
  return (
    <Panel id="pages" tone="deep">
      <Eyebrow>On a page</Eyebrow>
      <h2 className={H2}>
        Ads gone. <span className="text-clay">The page stays whole.</span>
      </h2>
      <Blink />
      <div className="mt-10 hidden gap-8 md:grid md:grid-cols-2">
        {SHOTS.map(([label, src]) => (
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
            <div key={title} className={`${CARD} flex gap-4 bg-paper-deep`}>
              <Dot />
              <div>
                <div className="text-lg font-medium">{title}</div>
                <p className="mt-1.5 leading-relaxed text-muted">{text}</p>
              </div>
            </div>
          ))}
        </Carousel>
      </div>
      <p className="mt-4 text-sm leading-relaxed text-muted md:mt-12 md:text-base">
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
        Every app, <span className="text-clay">not just the browser.</span>
      </h2>
      <div className="mt-6 md:mt-10">
        <Carousel
          label="The resolver"
          dark
          width="w-[88%]"
          layout="md:block md:space-y-8 lg:grid lg:grid-cols-[0.8fr_1.2fr] lg:items-center lg:gap-14 lg:space-y-0"
        >
          <div className={`${CARD} bg-ink-soft`}>
            <p className="text-base leading-relaxed text-muted-dark tiny:text-sm md:text-lg">
              The sinkd program becomes your computer's DNS resolver and blocks the same trackers
              for every app, over encrypted DNS. Its allowlist, blocklist and pause reach the
              extension too.
            </p>
            <div className="mt-5 space-y-2 font-mono text-sm md:mt-8">
              <div className="rounded-lg bg-ink px-4 py-3 text-sand md:bg-ink-soft">
                <span className="text-muted-dark">$ </span>sudo sinkd install
              </div>
              <div className="px-4 text-muted-dark">Undo it all: sudo sinkd uninstall</div>
            </div>
          </div>
          <div className="h-full overflow-hidden rounded-xl bg-[#252925] shadow-[0_22px_60px_rgba(0,0,0,0.35)] ring-1 ring-white/5 md:h-auto">
            <div className="flex h-8 items-center gap-1.5 bg-ink-soft px-3">
              {[0, 1, 2].map((i) => (
                <span key={i} className="size-2.5 rounded-full bg-[#5c6259]" />
              ))}
            </div>
            <pre className="whitespace-pre-wrap px-4 py-4 font-mono text-[11px] leading-relaxed text-sand [overflow-wrap:anywhere] md:overflow-x-auto md:whitespace-pre md:px-6 md:py-5 md:text-[12px] md:[overflow-wrap:normal] xl:text-[13px]">
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
        </Carousel>
      </div>
    </Panel>
  );
}

// The build pipeline (DESIGN.md, "Shape of the system"), with the numbers
// measured on the public lists, rounded.
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
  ["Every app", "the DNS resolver", "89k domains"],
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
          last ? "bg-ink text-paper" : "bg-paper text-ink ring-1 ring-ink/25"
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
        One parser. <span className="text-clay">Every target.</span>
      </h2>
      <p className="mt-4 max-w-2xl text-base leading-relaxed text-muted tiny:hidden md:mt-5 md:text-lg short:mt-3 md:max-lg:hidden">
        The same public filter lists become rules for your browser, your computer's DNS and the page
        itself, so the three never disagree.
      </p>
      <div className="mt-6 md:mt-12 short:mt-8">
        <Carousel
          label="How sinkd is made"
          indicator="steps"
          layout="md:grid md:grid-cols-2 md:gap-10 short:gap-y-8 lg:grid-cols-[1fr_1fr_1fr_1.15fr] lg:gap-0"
        >
          {[
            ...STEPS.map(([name, text, stat], i) => (
              <div key={name} className={`${CARD} bg-paper lg:pr-6`}>
                <StepMark n={i + 1} />
                <h3 className={title}>{name}</h3>
                <p className="mt-2 max-w-xs leading-relaxed text-muted">{text}</p>
                <div className="mt-4 font-mono text-xs text-ink/70">{stat}</div>
              </div>
            )),
            <div key="run" className={`${CARD} bg-paper`}>
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
                    <div className="text-sm text-muted">{what}</div>
                  </li>
                ))}
              </ul>
            </div>,
          ]}
        </Carousel>
      </div>
      <p className="mt-12 hidden max-w-2xl text-muted short:mt-8 lg:block">
        Lists are data. They can switch on the scriptlets sinkd ships, never bring code of their
        own, and the store build can be reproduced from the source, byte for byte.
      </p>
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
    <Panel id="honest">
      <Eyebrow>Honestly</Eyebrow>
      <h2 className={`${H2} max-w-xl`}>Untrackable isn't a thing. Harder to track is.</h2>
      <p className="mt-4 max-w-xl text-base leading-relaxed text-muted md:mt-6 md:text-lg">
        sinkd defeats third-party tracking and the common fingerprinting and detection tricks,
        without breaking sites. What it can't reach:
      </p>
      <div className="mt-6 max-w-2xl md:mt-9">
        <Carousel
          label="What sinkd can't reach"
          width="w-[72%]"
          layout="md:grid md:grid-cols-2 md:gap-x-10 md:gap-y-5"
        >
          {LIMITS.map(([title, text]) => (
            <div
              key={title}
              className="h-full rounded-2xl bg-paper-deep p-5 md:rounded-none md:border-t md:border-ink/15 md:bg-transparent md:p-0 md:pt-4"
            >
              <div className="font-medium">{title}</div>
              <div className="mt-1 text-muted">{text}</div>
            </div>
          ))}
        </Carousel>
      </div>
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
        <Logo size={96} variant="basalt" bare className="size-16 md:size-24" />
        <h2 className="mt-6 text-[2rem] font-medium leading-[1.12] tracking-tight md:mt-10 md:text-6xl md:leading-tight">
          Open source. <span className="text-clay">Nothing to phone home to.</span>
        </h2>
        <p className="mt-4 text-base leading-relaxed text-muted-dark md:mt-6 md:text-lg">
          No account, no analytics, no remote code. Everything runs on your device. MIT or Apache
          2.0, your choice.
        </p>
        <nav className="mt-7 flex flex-wrap justify-center gap-2.5 md:mt-10 md:gap-3">
          {links.map(([label, href]) => (
            <a
              key={label}
              href={href}
              className="rounded-full px-4 py-2.5 text-sm text-sand ring-1 ring-sand/25 transition hover:ring-sand/60 md:px-5"
            >
              {label}
            </a>
          ))}
        </nav>
      </div>
      <footer className="absolute inset-x-0 bottom-4 text-center text-xs text-muted-dark md:bottom-8">
        sinkd · {new Date().getFullYear()} ·{" "}
        <a href="./licenses.md" className="underline-offset-2 hover:underline">
          Licenses
        </a>
      </footer>
    </Panel>
  );
}
