// Cards that turn sideways, one at a time, on a phone, and lay out however
// `layout` says from md up (a grid, two columns, a flow). A sideways swipe
// turns the cards; past the last one it turns the page instead
// (useHorizontalScroll looks for `data-carousel`).

import { Children, Fragment, type ReactNode, useRef, useState } from "react";

const pad = (n: number) => String(n).padStart(2, "0");

interface Props {
  /** What the cards are, for screen readers. */
  label: string;
  children: ReactNode;
  /** The container from md up, e.g. "md:grid md:grid-cols-3 md:gap-8". */
  layout: string;
  /** Each card's width on a phone; the next one peeks in beside it. */
  width?: string;
  /** Bars and a count, or numbered steps joined by arrows (a process). */
  indicator?: "bars" | "steps";
  /** On an ink panel. */
  dark?: boolean;
}

export function Carousel({
  label,
  children,
  layout,
  width = "w-[84%]",
  indicator = "bars",
  dark = false,
}: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [index, setIndex] = useState(0);
  const items = Children.toArray(children);
  const count = items.length;

  const cards = () => Array.from(ref.current?.children ?? []) as HTMLElement[];
  const onScroll = () => {
    const el = ref.current;
    const [first, second] = cards();
    if (!el || !first || !second) return;
    const atEnd = el.scrollLeft >= el.scrollWidth - el.clientWidth - 1;
    const step = second.offsetLeft - first.offsetLeft;
    setIndex(atEnd ? count - 1 : Math.round(el.scrollLeft / step));
  };
  const show = (i: number) => {
    const list = cards();
    const [first] = list;
    const card = list[i];
    if (!first || !card) return;
    ref.current?.scrollTo({ left: card.offsetLeft - first.offsetLeft, behavior: "smooth" });
  };

  const steps = (
    <div className="mb-5 flex items-center md:hidden">
      {items.map((_, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: one marker per card, in order
        <Fragment key={i}>
          <button
            type="button"
            onClick={() => show(i)}
            aria-label={`Step ${i + 1} of ${count}`}
            aria-current={i === index ? "step" : undefined}
            className={`grid size-9 shrink-0 place-items-center rounded-full font-mono text-[11px] transition-colors duration-300 ${
              i === index
                ? "bg-ink text-white"
                : i < index
                  ? "bg-smoke text-white"
                  : "bg-white text-ink ring-1 ring-ink/25"
            }`}
          >
            {pad(i + 1)}
          </button>
          {i < count - 1 && (
            <span aria-hidden className="mx-2 flex flex-1 items-center">
              <span
                className={`h-px flex-1 transition-colors duration-300 ${i < index ? "bg-smoke" : "bg-ink/25"}`}
              />
              <span
                className={`border-y-[4px] border-l-[6px] border-y-transparent transition-colors duration-300 ${
                  i < index ? "border-l-smoke" : "border-l-ink/40"
                }`}
              />
            </span>
          )}
        </Fragment>
      ))}
    </div>
  );

  const bars = (
    <div className="mt-3 flex items-center gap-4 md:hidden">
      <div className="flex flex-1 gap-1.5">
        {items.map((_, i) => (
          <button
            // biome-ignore lint/suspicious/noArrayIndexKey: one bar per card, in order
            key={i}
            type="button"
            onClick={() => show(i)}
            aria-label={`Show ${i + 1} of ${count}`}
            className="flex-1 py-3"
          >
            <span
              className={`block h-[3px] rounded-full transition-colors duration-300 ${
                i === index
                  ? dark
                    ? "bg-white"
                    : "bg-ink"
                  : i < index
                    ? dark
                      ? "bg-mist/45"
                      : "bg-ink/40"
                    : dark
                      ? "bg-mist/15"
                      : "bg-ink/15"
              }`}
            />
          </button>
        ))}
      </div>
      <span
        className={`font-mono text-xs tabular-nums ${dark ? "text-silver" : "text-smoke"}`}
        aria-live="polite"
      >
        {pad(index + 1)} / {pad(count)}
      </span>
    </div>
  );

  return (
    <div>
      {indicator === "steps" && steps}
      <section
        ref={ref}
        data-carousel
        aria-roledescription="carousel"
        aria-label={label}
        onScroll={onScroll}
        className={`-mx-6 flex touch-pan-x touch-pinch-zoom snap-x snap-mandatory scroll-px-6 gap-3 overflow-x-auto overscroll-x-contain px-6 [scrollbar-width:none] md:mx-0 md:overflow-visible md:px-0 [&::-webkit-scrollbar]:hidden ${layout}`}
      >
        {items.map((item, i) => (
          <div
            // biome-ignore lint/suspicious/noArrayIndexKey: the cards are a fixed list
            key={i}
            className={`shrink-0 snap-start md:w-auto ${width}`}
          >
            {item}
          </div>
        ))}
      </section>
      {indicator === "bars" && bars}
    </div>
  );
}
