// The splash: the page opens on the mark putting itself together out of
// the web's junk. Ad frames at their standard sizes (a 970×90 banner, a
// 160×600 skyscraper, a 300×250 rectangle) and a tracking pixel sit
// scattered; they are pulled in and become the contours, and the pixel
// rounds into the clay low point. Then the mark flies to its place in the
// hero as the white falls away, or, where the hero shows no mark, fades.
// It plays the same whatever the visitor does: clicks, keys, scrolls and
// taps are held back from the page and change nothing in the splash. When
// it shows: splash.ts.
//
// Every frame sets the shapes' geometry, so nothing blurs; the flight
// moves and sizes the drawing itself rather than scaling a picture of it.

import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { splashDone } from "../splash";
import { CLAY, DOT, LOW_Y, RADII, ringY, STROKE } from "./Logo";

const INK = "#161616";
const SMOKE = "#6b6b6b";
/** The ad units where they start, labelled with their sizes. */
const FRAMES = [
  { cx: 64, cy: 18, w: 106, h: 20, rot: -4, label: "970×90" },
  { cx: 109, cy: 80, w: 22, h: 72, rot: 6, label: "160×600" },
  { cx: 24, cy: 94, w: 38, h: 32, rot: -8, label: "300×250" },
] as const;
/** The tracking pixel. */
const PIXEL = { cx: 90, cy: 116, size: 4.4, rot: 18 };
const APPEAR_MS = 420;
const MORPH_AT = 700;
const MORPH_MS = 1150;
const STAGGER = 120;
const PIXEL_MS = 900;
/** Assembled, and a beat to see it whole. */
const HOLD_UNTIL = 2550;
const FLY_MS = 720;
/** Every input the splash holds back while it is up, so none reaches the page. */
const INPUTS = [
  "pointerdown",
  "pointerup",
  "click",
  "dblclick",
  "contextmenu",
  "keydown",
  "keyup",
  "wheel",
  "touchstart",
  "touchmove",
  "touchend",
] as const;

const clamp01 = (t: number) => Math.min(1, Math.max(0, t));
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const easeOut = (t: number) => 1 - (1 - t) ** 3;
const easeInOut = (t: number) => (t < 0.5 ? 4 * t ** 3 : 1 - (-2 * t + 2) ** 3 / 2);
/** Past the mark and back: something coming to rest. */
const settle = (t: number) => 1 + 2.4 * (t - 1) ** 3 + 1.4 * (t - 1) ** 2;

/** A rectangle by its centre, size, corner radius and turn. */
function box(
  el: SVGRectElement | null | undefined,
  cx: number,
  cy: number,
  w: number,
  h: number,
  rx: number,
  rot: number,
) {
  if (!el) return;
  el.setAttribute("x", (cx - w / 2).toFixed(3));
  el.setAttribute("y", (cy - h / 2).toFixed(3));
  el.setAttribute("width", w.toFixed(3));
  el.setAttribute("height", h.toFixed(3));
  el.setAttribute("rx", rx.toFixed(3));
  el.setAttribute("transform", `rotate(${rot.toFixed(2)} ${cx.toFixed(2)} ${cy.toFixed(2)})`);
}

export function Splash() {
  const [gone, setGone] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const framesRef = useRef<(SVGRectElement | null)[]>([]);
  const labelsRef = useRef<(SVGTextElement | null)[]>([]);
  const pixelRef = useRef<SVGRectElement>(null);

  /** The splash `t` ms in. */
  const draw = (t: number) => {
    const appear = clamp01(t / APPEAR_MS);
    FRAMES.forEach((f, i) => {
      const p = clamp01((t - MORPH_AT - i * STAGGER) / MORPH_MS);
      const e = settle(p);
      const r = RADII[i] ?? 0;
      // A frame bobs while it waits; once in place it is still.
      const drift = p < 1 ? (1 - p) * Math.sin(t / 380 + i) * 0.8 : 0;
      const cx = lerp(f.cx, 64, e);
      const cy = lerp(f.cy, ringY(i), e) + drift;
      const frame = framesRef.current[i];
      box(
        frame,
        cx,
        cy,
        lerp(f.w, 2 * r, e),
        lerp(f.h, 2 * r, e),
        lerp(1.5, r, easeInOut(p)),
        lerp(f.rot, 0, easeOut(p)),
      );
      frame?.setAttribute("stroke-width", lerp(1.3, STROKE, easeOut(p)).toFixed(3));
      frame?.setAttribute("opacity", appear.toFixed(3));
      const label = labelsRef.current[i];
      label?.setAttribute("x", cx.toFixed(3));
      label?.setAttribute("y", cy.toFixed(3));
      label?.setAttribute("opacity", (appear * (1 - clamp01(p / 0.3))).toFixed(3));
    });
    const q = clamp01((t - MORPH_AT - FRAMES.length * STAGGER) / PIXEL_MS);
    const e = settle(q);
    const size = lerp(PIXEL.size, 2 * DOT, e);
    box(
      pixelRef.current,
      lerp(PIXEL.cx, 64, e),
      lerp(PIXEL.cy, LOW_Y, e),
      size,
      size,
      lerp(0, DOT, easeInOut(q)),
      lerp(PIXEL.rot, 0, easeOut(q)),
    );
    pixelRef.current?.setAttribute("opacity", appear.toFixed(3));
  };

  // The scattered frames, before the first paint.
  // biome-ignore lint/correctness/useExhaustiveDependencies: draw only touches refs
  useLayoutEffect(() => draw(0), []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: draw only touches refs
  useEffect(() => {
    const root = rootRef.current;
    const svg = svgRef.current;
    if (!root || !svg) return;
    let frame = 0;
    let timer = 0;
    let leaving = false;
    // Its own clock, advanced a frame at a time (a long pause, like a tab in
    // the background, counts as one frame), so it never jumps ahead.
    let clock = 0;
    let last = performance.now();

    const leave = () => {
      if (leaving) return;
      leaving = true;
      cancelAnimationFrame(frame);
      draw(HOLD_UNTIL);
      const ms = FLY_MS;
      const easing = "cubic-bezier(0.65, 0, 0.35, 1)";
      // To the hero's mark, if it is on screen: the same drawing, moved and sized.
      const from = svg.getBoundingClientRect();
      const to = document.querySelector("[data-hero-mark]")?.getBoundingClientRect();
      const onScreen =
        to &&
        to.width > 0 &&
        to.right > 0 &&
        to.left < innerWidth &&
        to.bottom > 0 &&
        to.top < innerHeight;
      if (onScreen) {
        svg.style.transform = "none";
        svg.animate(
          [
            {
              left: `${from.left}px`,
              top: `${from.top}px`,
              width: `${from.width}px`,
              height: `${from.height}px`,
            },
            {
              left: `${to.left}px`,
              top: `${to.top}px`,
              width: `${to.width}px`,
              height: `${to.width}px`,
            },
          ],
          { duration: ms, easing, fill: "forwards" },
        );
      } else {
        svg.animate([{ opacity: 1 }, { opacity: 0 }], { duration: ms, easing, fill: "forwards" });
      }
      root.animate(
        [{ backgroundColor: "rgb(255 255 255)" }, { backgroundColor: "rgb(255 255 255 / 0)" }],
        {
          duration: ms,
          easing,
          fill: "forwards",
        },
      );
      timer = window.setTimeout(() => {
        // Handing over: the page takes inputs again. (Gone, the splash
        // renders nothing but stays mounted, so this can't wait for the
        // effect's cleanup.)
        release();
        splashDone();
        setGone(true);
      }, ms);
    };

    const tick = (now: number) => {
      const dt = Math.min(50, now - last);
      last = now;
      clock += dt;
      draw(Math.min(clock, HOLD_UNTIL));
      if (clock >= HOLD_UNTIL) leave();
      else frame = requestAnimationFrame(tick);
    };

    // Until it is gone, the splash holds back every input before the page
    // sees it: no click lands on a button underneath, no key turns the
    // panels, no wheel or swipe scrolls. The splash itself ignores them.
    // Browser shortcuts (with a modifier key) still do what they do.
    const take = (event: Event) => {
      event.stopImmediatePropagation();
      const key = event as KeyboardEvent;
      const shortcut = key.metaKey || key.ctrlKey || key.altKey;
      if (event.cancelable && !shortcut) event.preventDefault();
    };
    const options = { capture: true, passive: false } as const;
    const release = () => {
      for (const type of INPUTS) window.removeEventListener(type, take, options);
    };
    for (const type of INPUTS) window.addEventListener(type, take, options);
    frame = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(frame);
      window.clearTimeout(timer);
      release();
    };
  }, []);

  if (gone) return null;
  return (
    <div ref={rootRef} aria-hidden="true" className="fixed inset-0 z-50 bg-white">
      <svg
        ref={svgRef}
        aria-hidden="true"
        viewBox="0 0 128 128"
        overflow="visible"
        className="drop-shadow-sm"
        style={{
          position: "fixed",
          left: "50%",
          top: "50%",
          width: "min(60vw, 300px)",
          height: "min(60vw, 300px)",
          transform: "translate(-50%, -50%)",
        }}
      >
        {FRAMES.map((f, i) => (
          <rect
            key={f.label}
            ref={(el) => {
              framesRef.current[i] = el;
            }}
            fill="none"
            stroke={INK}
          />
        ))}
        {FRAMES.map((f, i) => (
          <text
            key={f.label}
            ref={(el) => {
              labelsRef.current[i] = el;
            }}
            className="font-mono"
            fontSize={5.2}
            fill={SMOKE}
            textAnchor="middle"
            dominantBaseline="middle"
          >
            {f.label}
          </text>
        ))}
        <rect ref={pixelRef} fill={CLAY} />
      </svg>
    </div>
  );
}
