import { Logo } from "./components/Logo";
import { BeforeAfter, EveryApp, Hero, Honest, Idea, Open, Privacy } from "./components/Panels";
import { useHorizontalScroll } from "./useHorizontalScroll";

/** Header links, by the index of the panel they go to. */
const NAV = [
  ["The idea", 1],
  ["On a page", 2],
  ["Privacy", 3],
  ["Every app", 4],
  ["Open source", 6],
] as const;
const PANELS = 7;

export function App() {
  const { sectionRef, trackRef, barRef, horizontal, height, active, goTo } = useHorizontalScroll();
  const dark = active === 4 || active === 6;

  return (
    <>
      <header
        className={`fixed inset-x-0 top-0 z-20 flex items-center justify-between px-6 py-5 transition-colors duration-500 md:px-16 lg:px-24 ${
          horizontal && dark ? "text-sand" : "text-ink"
        } ${horizontal ? "" : "bg-paper/85 backdrop-blur-md"}`}
      >
        <button
          type="button"
          onClick={() => goTo(0)}
          className="flex items-center gap-3 text-lg font-medium tracking-tight"
        >
          <Logo size={30} variant={horizontal && dark ? "basalt" : "stone"} />
          sinkd
        </button>
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
        <div className={horizontal ? "sticky top-0 h-screen overflow-hidden" : ""}>
          <div
            ref={trackRef}
            className={horizontal ? "flex h-full w-max will-change-transform" : "flex flex-col"}
          >
            <Hero onNext={() => goTo(1)} />
            <Idea />
            <BeforeAfter />
            <Privacy />
            <EveryApp />
            <Honest />
            <Open />
          </div>
        </div>
      </main>

      {horizontal && (
        <div className="pointer-events-none fixed inset-x-0 bottom-0 z-20">
          <div className="flex items-center justify-end px-16 pb-6 font-mono text-xs lg:px-24">
            <span className={dark ? "text-muted-dark" : "text-muted"}>
              {String(active + 1).padStart(2, "0")} / {String(PANELS).padStart(2, "0")}
            </span>
          </div>
          <div ref={barRef} className="h-0.5 origin-left scale-x-0 bg-clay" />
        </div>
      )}
    </>
  );
}
