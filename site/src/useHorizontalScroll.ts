// Vertical scrolling, shown sideways. The section is as tall as the panel
// track is wide (plus one screen); its inner box sticks to the viewport,
// and every pixel scrolled down moves the track one pixel left. So the
// scrollbar, the keyboard and links all keep working as on any page, and
// the browser still owns the scrolling.
//
// Every panel is one screen, and each step moves exactly one whole panel:
// - a wheel or trackpad gesture (momentum included), and the paging keys;
// - on a touch screen, a swipe in any direction. The page itself doesn't
//   pan (`touch-action`), so nothing scrolls halfway. A sideways swipe on a
//   carousel turns its cards instead, and turns the page once it is past
//   the last card (or before the first). One on a control marked
//   `data-drag` (the page sweep) is the control's, as are its keys.
// Scrollbar drags are left to CSS scroll snapping, one point per panel.
//
// Readers who ask for reduced motion get the same panels, without the
// slide. Screens too short for a panel (a phone on its side) get the
// panels stacked, as an ordinary page.

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

/** Tall enough for a panel. Keep in step with the `stage` variant in index.css. */
const QUERY = "(min-height: 480px)";
const REDUCED = "(prefers-reduced-motion: reduce)";

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const list = window.matchMedia(query);
    const onChange = () => setMatches(list.matches);
    list.addEventListener("change", onChange);
    return () => list.removeEventListener("change", onChange);
  }, [query]);
  return matches;
}

/** A pause this long (ms) between wheel events ends a gesture. */
const SETTLE = 180;
/** No new step for this long (ms) after one starts: the slide's length. */
const SLIDE = 650;
/** How far (px) a touch must travel to be a swipe rather than a tap. */
const SWIPE = 40;
/** What each paging key does: a step back or forward, or a jump to an end. */
const KEYS: Record<string, -1 | 1 | "first" | "last"> = {
  ArrowRight: 1,
  ArrowDown: 1,
  PageDown: 1,
  ArrowLeft: -1,
  ArrowUp: -1,
  PageUp: -1,
  Home: "first",
  End: "last",
};

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

const panelsOf = (track: HTMLElement | null) => Array.from(track?.children ?? []) as HTMLElement[];

/** The carousel an event happened in, if any (components/Carousel.tsx). */
const carouselOf = (target: EventTarget | null) =>
  target instanceof Element ? target.closest<HTMLElement>("[data-carousel]") : null;
/** A control that takes sideways drags and the arrow keys for itself (`data-drag`). */
const dragOf = (target: EventTarget | null) =>
  target instanceof Element ? target.closest<HTMLElement>("[data-drag]") : null;

/** Whether a carousel is at its first card, and at its last. */
function edges(carousel: HTMLElement | null) {
  if (!carousel) return { atStart: true, atEnd: true };
  const max = carousel.scrollWidth - carousel.clientWidth;
  return { atStart: carousel.scrollLeft <= 1, atEnd: carousel.scrollLeft >= max - 1 };
}

export function useHorizontalScroll() {
  const sectionRef = useRef<HTMLElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const barRef = useRef<HTMLDivElement>(null);
  const horizontal = useMediaQuery(QUERY);
  const reduced = useMediaQuery(REDUCED);
  const [height, setHeight] = useState<number | null>(null);
  /** Where each panel sits, in pixels scrolled into the section. */
  const [snaps, setSnaps] = useState<number[]>([]);
  const [active, setActive] = useState(0);
  const activeRef = useRef(0);
  // The panel being scrolled to, so a step taken mid-slide counts from it.
  const targetRef = useRef(0);
  // How far the track travels, and where in the page that travel starts.
  const geometry = useRef({ distance: 0, start: 0 });
  // Positions the track for the current scroll; set while horizontal.
  const reposition = useRef<() => void>(() => {});

  useLayoutEffect(() => {
    const track = trackRef.current;
    const section = sectionRef.current;
    if (!horizontal || !track || !section) {
      setHeight(null);
      setSnaps([]);
      return;
    }
    const root = document.documentElement;
    root.style.scrollSnapType = "y mandatory";
    // Touch never pans the page, only steps it (below); zooming still works.
    root.style.touchAction = "pinch-zoom";
    const measure = () => {
      const distance = Math.max(0, track.scrollWidth - window.innerWidth);
      geometry.current = { distance, start: section.offsetTop };
      setHeight(distance + window.innerHeight);
      setSnaps(panelsOf(track).map((p) => Math.min(p.offsetLeft, distance)));
      reposition.current();
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(track);
    window.addEventListener("resize", measure);
    return () => {
      root.style.scrollSnapType = "";
      root.style.touchAction = "";
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [horizontal]);

  /** Scrolls to panel `index`: sideways when horizontal, down otherwise. */
  const goTo = useCallback(
    (index: number, smooth = true) => {
      const list = panelsOf(trackRef.current);
      const to = clamp(index, 0, list.length - 1);
      const panel = list[to];
      if (!panel) return;
      targetRef.current = to;
      const behavior = smooth && !reduced ? "smooth" : "instant";
      if (!horizontal) {
        panel.scrollIntoView({ behavior });
        return;
      }
      const { distance, start } = geometry.current;
      window.scrollTo({ top: start + clamp(panel.offsetLeft, 0, distance), behavior });
    },
    [horizontal, reduced],
  );

  useEffect(() => {
    const track = trackRef.current;
    const bar = barRef.current;
    if (!track) return;
    if (!horizontal) {
      track.style.transform = "";
      if (bar) bar.style.transform = "scaleX(0)";
      return;
    }
    let frame = 0;
    const update = () => {
      frame = 0;
      const { distance, start } = geometry.current;
      const offset = clamp(window.scrollY - start, 0, distance);
      track.style.transform = `translate3d(${-offset}px, 0, 0)`;
      if (bar) bar.style.transform = `scaleX(${distance ? offset / distance : 0})`;
      // The panel under the middle of the screen is the current one.
      const middle = offset + window.innerWidth / 2;
      const index = panelsOf(track).findIndex((p) => middle < p.offsetLeft + p.offsetWidth);
      if (index >= 0 && index !== activeRef.current) {
        activeRef.current = index;
        setActive(index);
      }
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(update);
    };
    const step = (by: number) => goTo(targetRef.current + by);
    // One wheel or trackpad gesture, one panel, down or sideways alike. A
    // gesture arrives as a stream of events (a trackpad's momentum goes on
    // for a second, and often opens with a near-zero delta); a pause of
    // SETTLE ms starts the next one. A gesture steps once, at its first real
    // movement, and not while a slide is under way.
    let lastWheel = 0;
    let armed = true;
    let busyUntil = 0;
    const onWheel = (event: WheelEvent) => {
      if (event.ctrlKey) return; // pinch to zoom
      // Sideways over a carousel that can turn: its cards, not the page.
      const carousel = carouselOf(event.target);
      if (
        carousel &&
        Math.abs(event.deltaX) > Math.abs(event.deltaY) &&
        carousel.scrollWidth > carousel.clientWidth
      ) {
        return;
      }
      event.preventDefault();
      const now = performance.now();
      if (now - lastWheel > SETTLE) armed = true;
      lastWheel = now;
      const delta = Math.abs(event.deltaY) >= Math.abs(event.deltaX) ? event.deltaY : event.deltaX;
      if (!armed || now < busyUntil || Math.abs(delta) < 2) return;
      armed = false;
      busyUntil = now + SLIDE;
      step(Math.sign(delta));
    };
    // A swipe: up or left is forward, down or right is back.
    let touch:
      | ({
          x: number;
          y: number;
          carousel: HTMLElement | null;
          drag: HTMLElement | null;
        } & ReturnType<typeof edges>)
      | null = null;
    const onTouchStart = (event: TouchEvent) => {
      const point = event.touches[0];
      if (event.touches.length !== 1 || !point) {
        touch = null; // a pinch
        return;
      }
      const carousel = carouselOf(event.target);
      const drag = dragOf(event.target);
      touch = { x: point.clientX, y: point.clientY, carousel, drag, ...edges(carousel) };
    };
    const onTouchEnd = (event: TouchEvent) => {
      const start = touch;
      const point = event.changedTouches[0];
      touch = null;
      if (!start || !point) return;
      const dx = point.clientX - start.x;
      const dy = point.clientY - start.y;
      if (Math.max(Math.abs(dx), Math.abs(dy)) < SWIPE) return; // a tap
      // A sideways drag on a control that takes them is that control's.
      if (start.drag && Math.abs(dx) >= Math.abs(dy)) return;
      if (Math.abs(dy) > Math.abs(dx)) {
        step(dy < 0 ? 1 : -1);
        return;
      }
      const by = dx < 0 ? 1 : -1;
      // On a carousel, only once it was already at that end.
      if (start.carousel && !(by > 0 ? start.atEnd : start.atStart)) return;
      step(by);
    };
    const onTouchCancel = () => {
      touch = null;
    };
    // The paging keys, and the arrows, step a panel at a time. Space on a
    // focused button or link still presses it.
    const onKey = (event: KeyboardEvent) => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      if (dragOf(event.target)) return; // its own keys
      const onControl = (event.target as HTMLElement).closest?.("a, button, input, textarea");
      let move = KEYS[event.key];
      if (event.key === " " && !onControl) move = event.shiftKey ? -1 : 1;
      if (move === undefined) return;
      event.preventDefault();
      if (move === "first") goTo(0);
      else if (move === "last") goTo(Number.MAX_SAFE_INTEGER);
      else step(move);
    };
    // After a scrollbar drag, count from where it stopped (measured now:
    // the frame that would have done it may not have run yet).
    const onScrollEnd = () => {
      update();
      targetRef.current = activeRef.current;
    };
    // Tabbing to a link in a panel off screen brings that panel in.
    const onFocus = (event: FocusEvent) => {
      const index = panelsOf(track).findIndex((p) => p.contains(event.target as Node));
      if (index >= 0 && index !== activeRef.current) goTo(index, false);
    };
    reposition.current = update;
    update();
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    window.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("touchstart", onTouchStart, { passive: true });
    window.addEventListener("touchend", onTouchEnd, { passive: true });
    window.addEventListener("touchcancel", onTouchCancel, { passive: true });
    window.addEventListener("scrollend", onScrollEnd);
    window.addEventListener("keydown", onKey);
    document.addEventListener("focusin", onFocus);
    return () => {
      cancelAnimationFrame(frame);
      reposition.current = () => {};
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      window.removeEventListener("wheel", onWheel);
      window.removeEventListener("touchstart", onTouchStart);
      window.removeEventListener("touchend", onTouchEnd);
      window.removeEventListener("touchcancel", onTouchCancel);
      window.removeEventListener("scrollend", onScrollEnd);
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("focusin", onFocus);
    };
  }, [horizontal, goTo]);

  return { sectionRef, trackRef, barRef, horizontal, height, snaps, active, goTo };
}
