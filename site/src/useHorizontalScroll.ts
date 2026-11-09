// Vertical scrolling, shown sideways. The section is as tall as the panel
// track is wide (plus one screen); its inner box sticks to the viewport,
// and every pixel scrolled down moves the track one pixel left. So the
// scrollbar, the keyboard, a trackpad and links all keep working as on any
// page, and the browser still owns the scrolling.
//
// Small screens and readers who ask for reduced motion get the panels
// stacked, as an ordinary page.

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";

const QUERY = "(min-width: 768px) and (prefers-reduced-motion: no-preference)";

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

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

const panelsOf = (track: HTMLElement | null) => Array.from(track?.children ?? []) as HTMLElement[];

export function useHorizontalScroll() {
  const sectionRef = useRef<HTMLElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const barRef = useRef<HTMLDivElement>(null);
  const horizontal = useMediaQuery(QUERY);
  const [height, setHeight] = useState<number | null>(null);
  const [active, setActive] = useState(0);
  const activeRef = useRef(0);
  // How far the track travels, and where in the page that travel starts.
  const geometry = useRef({ distance: 0, start: 0 });
  // Positions the track for the current scroll; set while horizontal.
  const reposition = useRef<() => void>(() => {});

  useLayoutEffect(() => {
    const track = trackRef.current;
    const section = sectionRef.current;
    if (!horizontal || !track || !section) {
      setHeight(null);
      return;
    }
    const measure = () => {
      const distance = Math.max(0, track.scrollWidth - window.innerWidth);
      geometry.current = { distance, start: section.offsetTop };
      setHeight(distance + window.innerHeight);
      reposition.current();
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(track);
    window.addEventListener("resize", measure);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, [horizontal]);

  /** Scrolls to panel `index`: sideways when horizontal, down otherwise. */
  const goTo = useCallback(
    (index: number, smooth = true) => {
      const list = panelsOf(trackRef.current);
      const panel = list[clamp(index, 0, list.length - 1)];
      if (!panel) return;
      const behavior = smooth ? "smooth" : "instant";
      if (!horizontal) {
        panel.scrollIntoView({ behavior });
        return;
      }
      const { distance, start } = geometry.current;
      window.scrollTo({ top: start + clamp(panel.offsetLeft, 0, distance), behavior });
    },
    [horizontal],
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
    // A sideways swipe on a trackpad moves the page too.
    const onWheel = (event: WheelEvent) => {
      if (Math.abs(event.deltaX) > Math.abs(event.deltaY)) {
        window.scrollBy({ top: event.deltaX, behavior: "instant" });
      }
    };
    // Left and right arrows step through the panels.
    const onKey = (event: KeyboardEvent) => {
      if (event.altKey || event.ctrlKey || event.metaKey) return;
      if (event.key === "ArrowRight") goTo(activeRef.current + 1);
      else if (event.key === "ArrowLeft") goTo(activeRef.current - 1);
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
    window.addEventListener("wheel", onWheel, { passive: true });
    window.addEventListener("keydown", onKey);
    document.addEventListener("focusin", onFocus);
    return () => {
      cancelAnimationFrame(frame);
      reposition.current = () => {};
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      window.removeEventListener("wheel", onWheel);
      window.removeEventListener("keydown", onKey);
      document.removeEventListener("focusin", onFocus);
    };
  }, [horizontal, goTo]);

  return { sectionRef, trackRef, barRef, horizontal, height, active, goTo };
}
