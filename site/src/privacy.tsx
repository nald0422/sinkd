// The privacy policy page (privacy.html), which the store listings link to.
// Its text is docs/privacy.md, read at build time, so the page and the
// repository's copy can't drift apart. The renderer below knows only what
// that file uses: headings, paragraphs, bullet lists, **bold**, *italic*,
// `code` and <links>. It builds elements, never HTML from the text.

import type { ReactNode } from "react";

import policy from "../../docs/privacy.md?raw";
import { mount } from "./components/Page";
import "./index.css";

const LINK = "underline underline-offset-2 break-words";

/** One line of inline markdown, as React nodes. */
function inline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  const pattern = /\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|<((?:https?:\/\/|[^\s@<>]+@)[^\s<>]+)>/g;
  let last = 0;
  for (const m of text.matchAll(pattern)) {
    const at = m.index ?? 0;
    if (at > last) out.push(text.slice(last, at));
    const key = `${at}`;
    if (m[1] !== undefined) out.push(<strong key={key}>{inline(m[1])}</strong>);
    else if (m[2] !== undefined) out.push(<em key={key}>{inline(m[2])}</em>);
    else if (m[3] !== undefined)
      out.push(
        <code key={key} className="rounded bg-snow px-1.5 py-0.5 font-mono text-[0.9em]">
          {m[3]}
        </code>,
      );
    else if (m[4] !== undefined) {
      const href = m[4].includes("@") && !m[4].includes("://") ? `mailto:${m[4]}` : m[4];
      out.push(
        <a key={key} href={href} className={LINK}>
          {m[4]}
        </a>,
      );
    }
    last = at + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/** The file's blocks: runs of lines between blank lines. */
function blocks(markdown: string): ReactNode[] {
  return markdown
    .trim()
    .split(/\n\s*\n/)
    .map((block, i) => {
      const key = `b${i}`;
      const text = block.trim();
      if (text.startsWith("## ")) {
        return (
          <h2 key={key} className="mt-12 text-xl font-medium tracking-tight md:text-2xl">
            {inline(text.slice(3))}
          </h2>
        );
      }
      if (text.startsWith("# ")) {
        return (
          <h1
            key={key}
            className="text-[2rem] font-medium leading-[1.12] tracking-tight md:text-5xl md:leading-tight"
          >
            {inline(text.slice(2))}
          </h1>
        );
      }
      if (text.startsWith("- ")) {
        const items = text.split(/\n(?=- )/).map((item) => item.slice(2).replace(/\s*\n\s*/g, " "));
        return (
          <ul key={key} className="mt-5 space-y-3">
            {items.map((item) => (
              <li key={item} className="flex gap-3 leading-relaxed text-carbon">
                <span
                  aria-hidden
                  className="mt-2.5 inline-block size-1.5 shrink-0 rounded-full bg-ink"
                />
                <span>{inline(item)}</span>
              </li>
            ))}
          </ul>
        );
      }
      const line = text.replace(/\s*\n\s*/g, " ");
      // The "version, last updated" line under the title.
      if (/^\*[^*].*\*$/.test(line)) {
        return (
          <p key={key} className="mt-3 text-sm text-smoke">
            {line.slice(1, -1)}
          </p>
        );
      }
      return (
        <p key={key} className="mt-5 leading-relaxed text-carbon">
          {inline(line)}
        </p>
      );
    });
}

mount(
  <article>
    <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-smoke md:text-xs">
      Privacy
    </div>
    {blocks(policy)}
  </article>,
);
