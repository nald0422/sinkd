// When the splash (components/Splash.tsx) shows, and what waits for it:
// the hero's mark starts its loop once the splash has handed over, or at
// once when there is no splash. Once a session, never with reduced motion.

const SEEN = "sinkd:splash";
let wanted: boolean | undefined;
let finished = false;
const waiting = new Set<() => void>();

function decide(): boolean {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return false;
  try {
    if (sessionStorage.getItem(SEEN)) return false;
    sessionStorage.setItem(SEEN, "1");
  } catch {
    // Storage blocked: show it, every visit.
  }
  return true;
}

/** Whether this page load opens on the splash; decided once. */
export function wantSplash(): boolean {
  wanted ??= decide();
  return wanted;
}

/** The splash is showing and has not handed over yet. */
export const splashPending = (): boolean => wantSplash() && !finished;

/** Called by the splash as it hands over. */
export function splashDone(): void {
  if (finished) return;
  finished = true;
  for (const run of waiting) run();
  waiting.clear();
}

/** Runs `run` once the splash has handed over, or now if there is none. */
export function afterSplash(run: () => void): () => void {
  if (!splashPending()) {
    run();
    return () => {};
  }
  waiting.add(run);
  return () => waiting.delete(run);
}
