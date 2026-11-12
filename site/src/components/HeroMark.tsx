// The hero's mark, at work: what sinkd's resolver does, shown. A real
// tracker's domain types itself in under the mark, a clay spark carries it
// down into the low point (each contour flickers as it passes), and the
// answer comes back: → 0.0.0.0. Then the next one.
//
// It starts once the splash has handed over (splash.ts), when the splash's
// mark lands exactly on this one; runs only while the hero is on screen;
// and with reduced motion the mark is simply drawn. Every frame sets the
// shapes' geometry, so nothing blurs.

import { useEffect, useLayoutEffect, useRef } from "react";
import { afterSplash, splashPending } from "../splash";
import { CLAY, DOT, LOW_Y, RADII, ringY, STROKE } from "./Logo";

const INK = "#161616";
/** The line's type, as in the drafts: Geist Mono, then the system's mono. */
const MONO = '"Geist Mono", ui-monospace, "SF Mono", Menlo, monospace';
/** Real trackers, as sinkd's lists name them. */
const DOMAINS = [
  "ads.doubleclick.net",
  "connect.facebook.net",
  "googletagmanager.com",
  "bat.bing.com",
  "cdn.segment.com",
  "pixel.quantserve.com",
];
const TYPE_MS = 45;
const HOLD_MS = 650;
const SINK_MS = 780;
const LAND_MS = 380;
const ANSWER = "0.0.0.0";
const ANSWER_MS = ANSWER.length * 45 + 1200;
const FADE_MS = 380;
const REST_MS = 600;
/** The line under the mark, and where the spark starts from. */
const TEXT_Y = 137;
const SPARK_Y = 130;
/** The drawing: the mark's 128 square, and room under it for the line. */
const HEIGHT = 146;

const clamp01 = (t: number) => Math.min(1, Math.max(0, t));
const easeIn = (t: number) => t * t;
const easeOut = (t: number) => 1 - (1 - t) ** 3;

export function HeroMark({ size, className }: { size: number; className?: string }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const ringsRef = useRef<(SVGCircleElement | null)[]>([]);
  const lowRef = useRef<SVGCircleElement>(null);
  const textRef = useRef<SVGTextElement>(null);
  const domainRef = useRef<SVGTSpanElement>(null);
  const arrowRef = useRef<SVGTSpanElement>(null);
  const sparkRef = useRef<SVGCircleElement>(null);

  // Hidden while the splash is up: its mark becomes this one.
  useLayoutEffect(() => {
    if (splashPending() && svgRef.current) svgRef.current.style.visibility = "hidden";
  }, []);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const rings = ringsRef.current;
    const bottoms = RADII.map((r, i) => ringY(i) + r);
    const line = (domain: string, arrow: string, opacity: number, spacing = 0) => {
      if (domainRef.current) domainRef.current.textContent = domain;
      if (arrowRef.current) arrowRef.current.textContent = arrow;
      textRef.current?.setAttribute("opacity", opacity.toFixed(3));
      textRef.current?.setAttribute("letter-spacing", spacing.toFixed(3));
    };

    let which = 0;
    let start = 0;
    let frame = 0;
    let visible = false;
    let running = false;

    /** One domain's turn, `t` ms in; false when it is over. */
    const turn = (t: number): boolean => {
      const name = DOMAINS[which] ?? "";
      const typing = name.length * TYPE_MS;
      if (t < typing + HOLD_MS) {
        const shown = Math.min(name.length, Math.floor(t / TYPE_MS));
        const caret = shown < name.length || Math.floor(t / 420) % 2 === 0 ? "▍" : " ";
        line(name.slice(0, shown) + caret, "", 1);
        domainRef.current?.setAttribute("fill", INK);
        return true;
      }
      let s = t - typing - HOLD_MS;
      if (s < SINK_MS) {
        const p = clamp01(s / SINK_MS);
        const fall = easeIn(p);
        line(name, "", 1 - easeOut(p), -2.4 * fall);
        const y = SPARK_Y + (LOW_Y - SPARK_Y) * fall;
        sparkRef.current?.setAttribute("cx", (64 + Math.sin(p * Math.PI) * 10).toFixed(3));
        sparkRef.current?.setAttribute("cy", y.toFixed(3));
        sparkRef.current?.setAttribute("opacity", clamp01(p * 6).toFixed(3));
        rings.forEach((ring, i) => {
          const near = 1 - clamp01(Math.abs(y - (bottoms[i] ?? 0)) / 6);
          ring?.setAttribute("stroke-width", (STROKE + 1.1 * near).toFixed(3));
        });
        return true;
      }
      sparkRef.current?.setAttribute("opacity", "0");
      for (const ring of rings) ring?.setAttribute("stroke-width", String(STROKE));
      s -= SINK_MS;
      if (s < LAND_MS) {
        line("", "", 0);
        lowRef.current?.setAttribute(
          "r",
          (DOT + 1.3 * Math.sin(clamp01(s / LAND_MS) * Math.PI)).toFixed(3),
        );
        return true;
      }
      lowRef.current?.setAttribute("r", String(DOT));
      s -= LAND_MS;
      if (s < ANSWER_MS + FADE_MS) {
        const shown = Math.min(ANSWER.length, Math.floor(s / 45));
        line(ANSWER.slice(0, shown), "→ ", s > ANSWER_MS ? 1 - (s - ANSWER_MS) / FADE_MS : 1);
        domainRef.current?.setAttribute("fill", CLAY);
        return true;
      }
      line("", "", 0);
      return s < ANSWER_MS + FADE_MS + REST_MS;
    };

    const tick = (now: number) => {
      frame = 0;
      if (!turn(now - start)) {
        which = (which + 1) % DOMAINS.length;
        start = now;
      }
      wake();
    };
    const wake = () => {
      if (!frame && running && visible && !document.hidden) frame = requestAnimationFrame(tick);
    };
    const sleep = () => {
      cancelAnimationFrame(frame);
      frame = 0;
    };

    const observer = new IntersectionObserver(([entry]) => {
      const was = visible;
      visible = entry?.isIntersecting ?? false;
      // Back on screen: the current domain from the start.
      if (visible && !was) start = performance.now();
      if (visible) wake();
      else sleep();
    });
    observer.observe(svg);
    const onVisibility = () => (document.hidden ? sleep() : wake());
    document.addEventListener("visibilitychange", onVisibility);
    const cancel = afterSplash(() => {
      svg.style.visibility = "";
      if (reduced) return;
      running = true;
      start = performance.now();
      wake();
    });

    return () => {
      cancel();
      sleep();
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  return (
    <svg
      ref={svgRef}
      data-hero-mark
      width={size}
      height={(size * HEIGHT) / 128}
      viewBox={`0 0 128 ${HEIGHT}`}
      className={className}
      role="img"
      aria-label="sinkd"
      overflow="visible"
    >
      {RADII.map((r, i) => (
        <circle
          key={r}
          ref={(el) => {
            ringsRef.current[i] = el;
          }}
          cx="64"
          cy={ringY(i)}
          r={r}
          fill="none"
          stroke={INK}
          strokeWidth={STROKE}
        />
      ))}
      <circle ref={lowRef} cx="64" cy={LOW_Y} r={DOT} fill={CLAY} />
      <circle ref={sparkRef} cx="64" cy={SPARK_Y} r={1.8} fill={CLAY} opacity={0} />
      <text
        ref={textRef}
        x="64"
        y={TEXT_Y}
        fontFamily={MONO}
        fontSize={6.2}
        fontWeight={500}
        textAnchor="middle"
        opacity={0}
      >
        <tspan ref={arrowRef} fill={CLAY} />
        <tspan ref={domainRef} fill={INK} />
      </text>
    </svg>
  );
}
