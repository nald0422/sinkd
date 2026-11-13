// The frame of the site's plain pages (support.html, privacy.html): the
// header back to the landing page, a column of text and the footer.

import type { ReactNode } from "react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { Logo } from "./Logo";

const FOOTER = [
  ["Support", "./support.html"],
  ["Privacy policy", "./privacy.html"],
  ["Licenses", "./licenses.md"],
] as const;

function Page({ children }: { children: ReactNode }) {
  return (
    <>
      <header className="flex items-center justify-between px-6 py-4 md:px-16 md:py-5 lg:px-24">
        <a href="./" className="flex items-center gap-3 text-lg font-medium tracking-tight">
          <Logo size={30} variant="graphite" />
          sinkd
        </a>
        <a href="./" className="text-sm opacity-55 transition-opacity hover:opacity-100">
          Home
        </a>
      </header>
      <main className="mx-auto max-w-2xl px-6 pt-10 pb-20 md:pt-16">{children}</main>
      <footer className="pb-8 text-center text-xs text-smoke">
        sinkd · {new Date().getFullYear()}
        {FOOTER.map(([label, href]) => (
          <span key={label}>
            {" · "}
            <a href={href} className="underline-offset-2 hover:underline">
              {label}
            </a>
          </span>
        ))}
      </footer>
    </>
  );
}

/** Renders a plain page into #root. */
export function mount(children: ReactNode) {
  const root = document.getElementById("root");
  if (root) {
    createRoot(root).render(
      <StrictMode>
        <Page>{children}</Page>
      </StrictMode>,
    );
  }
}
