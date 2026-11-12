import { useState } from "react";
import { Logo } from "./components/Logo";
import { BeforeAfter, EveryApp, Hero, Idea, Open, Privacy, Process } from "./components/Panels";
import { Splash } from "./components/Splash";
import { wantSplash } from "./splash";
import { useHorizontalScroll } from "./useHorizontalScroll";

/** Header links, by the index of the panel they go to. */
const NAV = [
  ["The idea", 1],
  ["On a page", 2],
  ["Privacy", 3],
  ["Every app", 4],
  ["How it's made", 5],
  ["Open source", 6],
] as const;
/** Every panel's name, for the header on a phone. */
const NAMES = ["", "The idea", "On a page", "Privacy", "Every app", "How it's made", "Open source"];
const PANELS = NAMES.length;
/** The panels on ink, where the header and counter turn light. */
const DARK: readonly number[] = [4, 6];

export function App() {
  const { sectionRef, trackRef, barRef, horizontal, height, snaps, active, goTo } =
    useHorizontalScroll();
  const dark = DARK.includes(active);
  // Decided once, before the hero's mark asks whether to wait for it.
  const [splash] = useState(wantSplash);

  return (
    <>
      {splash && <Splash />}
      <header
        className={`fixed inset-x-0 top-0 z-20 flex items-center justify-between px-6 py-4 transition-colors duration-500 md:px-16 md:py-5 lg:px-24 ${
          horizontal && dark ? "text-mist" : "text-ink"
        } ${horizontal ? "" : "bg-white/85 backdrop-blur-md"}`}
      >
        <button
          type="button"
          onClick={() => goTo(0)}
          className="flex items-center gap-3 text-lg font-medium tracking-tight"
        >
          <Logo size={30} variant={horizontal && dark ? "paper" : "graphite"} />
          sinkd
        </button>
        {horizontal && (
          <span
            key={active}
            aria-hidden
            className="font-mono text-[11px] uppercase tracking-[0.14em] opacity-70 motion-safe:animate-fade md:hidden"
          >
            {NAMES[active]}
          </span>
        )}
        <nav className="hidden gap-7 text-sm md:flex">
          {NAV.map(([label, index]) => (
            <button
              key={label}
              type="button"
              onClick={() => goTo(index)}
              className={`transition-opacity ${active === index ? "opacity-100" : "opacity-55 hover:opacity-100"}`}
            >
              {label}
            </button>
          ))}
        </nav>
      </header>

      <main
        ref={sectionRef}
        className="relative"
        style={horizontal && height ? { height } : undefined}
      >
        {/* Snap points, one per panel, at the scroll offset that shows it. */}
        {snaps.map((top) => (
          <div
            key={top}
            aria-hidden
            className="pointer-events-none absolute inset-x-0 h-px snap-start snap-always"
            style={{ top }}
          />
        ))}
        <div className={horizontal ? "sticky top-0 h-dvh overflow-hidden" : ""}>
          <div
            ref={trackRef}
            className={horizontal ? "flex h-full w-max will-change-transform" : "flex flex-col"}
          >
            <Hero onNext={() => goTo(1)} />
            <Idea />
            <BeforeAfter />
            <Privacy />
            <EveryApp />
            <Process />
            <Open />
          </div>
        </div>
      </main>

      {horizontal && (
        <div className="pointer-events-none fixed inset-x-0 bottom-0 z-20">
          <div className="flex items-center justify-end px-6 pb-4 font-mono text-xs md:px-16 md:pb-6 lg:px-24">
            <span className={dark ? "text-silver" : "text-smoke"}>
              {String(active + 1).padStart(2, "0")} / {String(PANELS).padStart(2, "0")}
            </span>
          </div>
          <div
            ref={barRef}
            className={`h-0.5 origin-left scale-x-0 ${dark ? "bg-white" : "bg-ink"}`}
          />
        </div>
      )}
    </>
  );
}
