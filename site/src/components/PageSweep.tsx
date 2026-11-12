// "On a page": a news page, with and without sinkd, and the mark to drag
// across it. Where the mark has been, sinkd is on: each ad is wiped away
// as the line passes over it, and once it is gone its slot closes and the
// page closes up, as it does in the browser. The page's own log, under it,
// lists each request blocked, as the extension's Log tab does.
//
// It's the page the store screenshots are taken of (The Ledger, in
// extension/scripts/store-images.mjs), built here rather than shown as two
// pictures: the page reflows as the ads go, so two screenshots side by side
// never line up. Laid out at the width it was captured at and scaled to
// fit, so it is sharp at every size.
//
// The first time it comes into view it shows itself off once: the mark
// sweeps all the way and back. Drag it (or tap where to put it), or use
// the arrow keys. With reduced motion it doesn't sweep, and slots close at
// once.

import {
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type PointerEvent as ReactPointerEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import hero from "../ledger/hero.svg";
import leaderboard from "../ledger/leaderboard.svg";
import native from "../ledger/native.svg";
import sidebar from "../ledger/sidebar.svg";
import { Logo } from "./Logo";

/** The width the page is laid out at, in its own pixels. */
const PAGE_WIDTH = 1200;
/**
 * Where the mark rests: in the gutter between the columns, so the article
 * is shown with sinkd (both its ads gone, closed up) and the sidebar
 * without (its ad still there).
 */
const REST = 0.69;
/** How far a key moves it, and a paging key. */
const STEP = 0.05;
const PAGE_STEP = 0.25;
/** How far (px) a touch moves before it counts as a drag or a scroll. */
const SLOP = 6;

/** The page's ads, each served from ad.doubleclick.net, as on the test page. */
const ADS = [
  { id: "leaderboard", path: "/leaderboard.svg" },
  { id: "native", path: "/native.svg" },
  { id: "sidebar", path: "/sidebar.svg" },
] as const;
type AdId = (typeof ADS)[number]["id"];

/** Where an ad's slot sits across the page, in page pixels: once the mark is past its right edge, it closes. */
interface Span {
  left: number;
  width: number;
}

const clamp01 = (t: number) => Math.min(1, Math.max(0, t));
const easeInOut = (t: number) => (t < 0.5 ? 4 * t ** 3 : 1 - (-2 * t + 2) ** 3 / 2);

/**
 * An ad's slot: wiped from the left up to the mark, and closed (height to
 * nothing, margins included) once the mark is past the ad.
 */
function Slot({
  id,
  spans,
  at,
  className,
  children,
  slotRef,
}: {
  id: AdId;
  spans: Partial<Record<AdId, Span>>;
  at: number;
  className: string;
  children: ReactNode;
  slotRef: (el: HTMLDivElement | null) => void;
}) {
  const span = spans[id];
  const wiped = span ? Math.min(span.width, Math.max(0, at - span.left)) : 0;
  const closed = span ? at >= span.left + span.width : false;
  return (
    <div className="ledger-slot" data-closed={closed}>
      <div className="ledger-slot-inner">
        <div
          ref={slotRef}
          data-ad={id}
          className={className}
          style={{ clipPath: `inset(0 0 0 ${wiped.toFixed(1)}px)` }}
        >
          {children}
        </div>
      </div>
    </div>
  );
}

export function PageSweep() {
  const [at, setAt] = useState(REST);
  const [scale, setScale] = useState(0);
  const [spans, setSpans] = useState<Partial<Record<AdId, Span>>>({});
  const [focused, setFocused] = useState(false);
  const [viewWidth, setViewWidth] = useState(0);
  const [labels, setLabels] = useState([0, 0]);
  const withRef = useRef<HTMLSpanElement>(null);
  const withoutRef = useRef<HTMLSpanElement>(null);
  const viewRef = useRef<HTMLDivElement>(null);
  const pageRef = useRef<HTMLDivElement>(null);
  const slots = useRef<Partial<Record<AdId, HTMLDivElement | null>>>({});
  const demo = useRef<{ frame: number; timer: number; done: boolean }>({
    frame: 0,
    timer: 0,
    done: false,
  });

  /** Stops the sweep that shows it off, for good, once the visitor takes over. */
  const takeOver = useCallback(() => {
    cancelAnimationFrame(demo.current.frame);
    window.clearTimeout(demo.current.timer);
    demo.current.done = true;
  }, []);

  // The page's scale, and where the ads sit across it (in page pixels,
  // which no closing slot changes).
  useLayoutEffect(() => {
    const view = viewRef.current;
    const page = pageRef.current;
    if (!view || !page) return;
    const measure = () => {
      const s = view.clientWidth / PAGE_WIDTH;
      setScale(s);
      const origin = page.getBoundingClientRect().left;
      const next: Partial<Record<AdId, Span>> = {};
      for (const { id } of ADS) {
        const box = slots.current[id]?.getBoundingClientRect();
        if (box) next[id] = { left: (box.left - origin) / s, width: box.width / s };
      }
      setLabels([withRef.current?.offsetWidth ?? 0, withoutRef.current?.offsetWidth ?? 0]);
      setViewWidth(view.clientWidth);
      setSpans(next);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(view);
    return () => observer.disconnect();
  }, []);

  // Showing itself off, once, the first time it is in view.
  useEffect(() => {
    const view = viewRef.current;
    if (!view || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const state = demo.current;
    // All the ads back, then sinkd across the whole page, then to rest.
    const legs = [
      { from: REST, to: 0, ms: 1000 },
      { from: 0, to: 0, ms: 450 },
      { from: 0, to: 1, ms: 1900 },
      { from: 1, to: 1, ms: 600 },
      { from: 1, to: REST, ms: 800 },
    ];
    const run = () => {
      let start = performance.now();
      let leg = 0;
      const tick = (now: number) => {
        const current = legs[leg];
        if (!current || state.done) return;
        const p = clamp01((now - start) / current.ms);
        setAt(current.from + (current.to - current.from) * easeInOut(p));
        if (p >= 1) {
          leg += 1;
          start = now;
        }
        if (leg < legs.length) state.frame = requestAnimationFrame(tick);
        else state.done = true;
      };
      state.frame = requestAnimationFrame(tick);
    };
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry?.isIntersecting || state.done) return;
        observer.disconnect();
        // After the panel has slid in.
        state.timer = window.setTimeout(run, 700);
      },
      { threshold: 0.75 },
    );
    observer.observe(view);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(state.frame);
      window.clearTimeout(state.timer);
    };
  }, []);

  // Dragging. A mouse takes hold at once; a touch only once it moves more
  // sideways than up or down (a vertical swipe still turns the panels), and
  // a tap puts the mark where it landed.
  const drag = useRef<{ id: number; x: number; y: number; held: boolean } | null>(null);
  const moveTo = (clientX: number) => {
    const view = viewRef.current;
    if (!view) return;
    const box = view.getBoundingClientRect();
    setAt(clamp01((clientX - box.left) / box.width));
  };
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    takeOver();
    const held = event.pointerType === "mouse";
    drag.current = { id: event.pointerId, x: event.clientX, y: event.clientY, held };
    event.currentTarget.setPointerCapture(event.pointerId);
    if (held) {
      event.preventDefault(); // no text selection while dragging
      moveTo(event.clientX);
    }
  };
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d || d.id !== event.pointerId) return;
    if (!d.held) {
      const dx = event.clientX - d.x;
      const dy = event.clientY - d.y;
      if (Math.hypot(dx, dy) < SLOP) return;
      if (Math.abs(dy) > Math.abs(dx)) {
        drag.current = null; // a scroll or a swipe, not a drag
        return;
      }
      d.held = true;
    }
    moveTo(event.clientX);
  };
  const onPointerUp = (event: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    drag.current = null;
    if (d && d.id === event.pointerId && !d.held) moveTo(event.clientX); // a tap
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    const by: Record<string, number> = {
      ArrowLeft: -STEP,
      ArrowDown: -STEP,
      ArrowRight: STEP,
      ArrowUp: STEP,
      PageDown: -PAGE_STEP,
      PageUp: PAGE_STEP,
    };
    let next: number | undefined;
    if (event.key === "Home") next = 0;
    else if (event.key === "End") next = 1;
    else if (by[event.key] !== undefined) next = clamp01(at + (by[event.key] ?? 0));
    if (next === undefined) return;
    event.preventDefault();
    takeOver();
    setAt(next);
  };

  const x = at * PAGE_WIDTH;
  const right = (id: AdId) => {
    const span = spans[id];
    return span ? span.left + span.width : Number.POSITIVE_INFINITY;
  };
  const blocked = ADS.filter(({ id }) => x >= right(id)).sort((a, b) => right(a.id) - right(b.id));
  // A side's label shows once its side has room for it.
  const INSET = 12;
  const showWith = at * viewWidth >= (labels[0] ?? 0) + 2 * INSET;
  const showWithout = (1 - at) * viewWidth >= (labels[1] ?? 0) + 2 * INSET;
  const percent = Math.round(at * 100);
  const slot = (id: AdId) => (el: HTMLDivElement | null) => {
    slots.current[id] = el;
  };
  const pageStyle: CSSProperties = {
    width: PAGE_WIDTH,
    transform: `scale(${scale})`,
    visibility: scale ? "visible" : "hidden",
  };

  return (
    <div className="overflow-hidden rounded-xl bg-white shadow-[0_22px_60px_rgba(22,22,22,0.18)]">
      {/* The window's top: the address, and sinkd in the toolbar. */}
      <div className="flex h-8 items-center gap-1.5 bg-mist px-3 md:h-9">
        {[0, 1, 2].map((i) => (
          <span key={i} className="size-2 rounded-full bg-silver md:size-2.5" />
        ))}
        <span className="ml-2 flex h-5 min-w-0 flex-1 items-center truncate rounded-md bg-snow px-2.5 font-sans text-[10px] text-smoke md:ml-3 md:h-6 md:text-xs">
          theledger.example/climate/tides
        </span>
        <Logo size={18} variant="graphite" className="ml-1 shrink-0 md:ml-2" />
      </div>

      {/* The page, and the mark. */}
      <div
        ref={viewRef}
        data-drag
        className="ledger-view relative aspect-[3/2] max-h-[44dvh] w-full cursor-ew-resize touch-pan-y select-none overflow-hidden bg-white short:max-h-[40dvh] md:max-h-[50dvh]"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={() => {
          drag.current = null;
        }}
      >
        <div ref={pageRef} aria-hidden className="ledger" style={pageStyle}>
          <header>
            <span className="masthead">The Ledger</span>
            <nav>
              <span>World</span>
              <span>Climate</span>
              <span>Business</span>
              <span>Culture</span>
            </nav>
          </header>
          <main>
            <article>
              <Slot
                id="leaderboard"
                spans={spans}
                at={x}
                className="ad-leaderboard"
                slotRef={slot("leaderboard")}
              >
                <img src={leaderboard} alt="" draggable={false} />
              </Slot>
              <div className="kicker">Climate</div>
              <h1>Coastal towns redraw their maps as the tides creep higher</h1>
              <div className="byline">By Mara Holt · 6 min read</div>
              <img className="hero" src={hero} alt="" draggable={false} />
              <Slot id="native" spans={spans} at={x} className="sponsored" slotRef={slot("native")}>
                <img src={native} alt="" draggable={false} />
                <div>
                  <small>Sponsored</small>
                  Doctors hate this one weird trick for sleeping better
                </div>
              </Slot>
              <p>
                Along the northern shore, harbor towns are quietly moving roads, pumps and power
                lines a few hundred meters inland, betting that slow, early changes cost less than
                emergency repairs.
              </p>
              <p>
                “We used to plan for the storm of the century,” said one town engineer. “Now we plan
                for the Tuesday high tide.”
              </p>
            </article>
            <aside>
              <Slot
                id="sidebar"
                spans={spans}
                at={x}
                className="ad-sidebar"
                slotRef={slot("sidebar")}
              >
                <img src={sidebar} alt="" draggable={false} />
              </Slot>
              <h3>Most read</h3>
              <ol>
                <li>The quiet return of the night train</li>
                <li>What a warmer winter means for maple syrup</li>
                <li>Inside the library that lends out tools</li>
              </ol>
            </aside>
          </main>
        </div>

        {/* Each side's label, at its bottom corner, while its side has room. */}
        <span
          ref={withRef}
          aria-hidden
          className={`pointer-events-none absolute bottom-3 left-3 whitespace-nowrap rounded-full bg-ink px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-white transition-opacity duration-200 md:px-2.5 md:py-1 md:text-[11px] ${showWith ? "opacity-100" : "opacity-0"}`}
        >
          With sinkd
        </span>
        <span
          ref={withoutRef}
          aria-hidden
          className={`pointer-events-none absolute right-3 bottom-3 whitespace-nowrap rounded-full bg-white/90 px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.12em] text-ink ring-1 ring-ink/15 transition-opacity duration-200 md:px-2.5 md:py-1 md:text-[11px] ${showWithout ? "opacity-100" : "opacity-0"}`}
        >
          Without sinkd
        </span>

        {/* For the keyboard and screen readers; the mark shows its focus. */}
        <input
          type="range"
          min={0}
          max={100}
          step={1}
          value={percent}
          aria-label="Drag sinkd across the page"
          aria-valuetext={`sinkd on ${percent}% of the page; ${blocked.length} of ${ADS.length} ads blocked`}
          className="sr-only"
          onKeyDown={onKeyDown}
          onChange={(event) => {
            takeOver();
            setAt(Number(event.target.value) / 100);
          }}
          onFocus={(event) => setFocused(event.target.matches(":focus-visible"))}
          onBlur={() => setFocused(false)}
        />

        {/* The line, and the mark on it. */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-y-0 w-0.5 -translate-x-1/2 bg-ink shadow-[0_0_0_1px_rgba(255,255,255,0.7)]"
          style={{ left: `${at * 100}%` }}
        />
        <div
          aria-hidden
          className="pointer-events-none absolute top-1/2 -translate-x-1/2 -translate-y-1/2"
          style={{ left: `clamp(26px, ${at * 100}%, calc(100% - 26px))` }}
        >
          <div
            className={`relative grid size-10 place-items-center rounded-full bg-white shadow-[0_6px_18px_rgba(22,22,22,0.22)] ring-1 ring-ink/15 transition-shadow md:size-12 ${
              focused ? "outline-2 outline-offset-2 outline-ink" : ""
            }`}
          >
            <Logo size={26} variant="paper" bare className="md:size-[30px]" />
            <span className="absolute top-1/2 -left-2.5 -translate-y-1/2 border-y-[4px] border-r-[5px] border-y-transparent border-r-ink" />
            <span className="absolute top-1/2 -right-2.5 -translate-y-1/2 border-y-[4px] border-l-[5px] border-y-transparent border-l-ink" />
          </div>
        </div>
      </div>

      {/* The page's log, as the extension's Log tab shows it. */}
      <div className="bg-term px-3 py-2 font-mono text-[10px] leading-[18px] text-term-text md:px-4 md:py-2.5 md:text-xs md:leading-5">
        <div className="flex items-center justify-between text-pewter">
          <span>sinkd · log</span>
          <span aria-live="polite">
            <b className="font-medium text-term-text">{blocked.length}</b> blocked
          </span>
        </div>
        <ol className="mt-1 h-[18px] overflow-hidden max-md:[&>li:not(:last-child)]:hidden md:h-[60px]">
          {blocked.length === 0 ? (
            <li className="text-pewter">Nothing blocked yet. Drag the mark across the page.</li>
          ) : (
            blocked.map(({ id, path }) => (
              <li key={id} className="flex min-w-0 gap-3 whitespace-nowrap animate-fade">
                <span className="w-[5ch] shrink-0 font-semibold text-term-red">block</span>
                <span className="truncate">
                  ad.doubleclick.net<span className="text-pewter">{path}</span>
                </span>
              </li>
            ))
          )}
        </ol>
      </div>
    </div>
  );
}
