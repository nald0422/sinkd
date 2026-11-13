// The support page (support.html): fixes for the common problems first,
// then the email address. The store listing links here as its support
// site. Plain and vertical; none of the landing page's panels.

import type { ReactNode } from "react";
import { useState } from "react";

import { mount } from "./components/Page";
import "./index.css";

const GITHUB = "https://github.com/nald0422/sinkd";
/** Put together here, so the address isn't one string in the page's script. */
const EMAIL = ["bill22.db", "gmail.com"].join("@");

/** A first draft of the email, with what we'd ask for anyway. */
const BODY = [
  "What happened:",
  "",
  "",
  "The page's address (if it's about a site):",
  "",
  "Browser and version:",
  "sinkd version (on chrome://extensions):",
].join("\n");
const MAILTO = `mailto:${EMAIL}?subject=${encodeURIComponent("sinkd support")}&body=${encodeURIComponent(BODY)}`;

const FIXES: readonly [string, ReactNode][] = [
  [
    "A site looks broken or won't load",
    <>
      Open the sinkd popup on that site and turn off <b>On for this site</b>, then reload. If that
      fixes it, email us the page's address so we can fix it for everyone.
    </>,
  ],
  [
    "An ad got through",
    <>
      Some ads come from the site itself and can't be told apart from its content. Email us the
      page's address and where on the page the ad was.
    </>,
  ],
  [
    "The Log tab is empty while the icon shows a count",
    <>
      Update to the latest version (0.1.4 or later reads the log when you click the tab). Chrome
      shows the log only for the tab you opened the popup on, and Firefox has no log at all.
    </>,
  ],
  [
    "The DNS resolver blocks something it shouldn't",
    <>
      Run <Code>sinkd allow add example.com</Code> with the site's address, or{" "}
      <Code>sinkd pause</Code> to stop blocking for a while. <Code>sudo sinkd uninstall</Code> puts
      your DNS settings back exactly as they were.
    </>,
  ],
  [
    "Removing sinkd",
    <>
      In the browser, remove it from <Code>chrome://extensions</Code> (or Firefox's Add-ons page).
      It keeps nothing anywhere else.
    </>,
  ],
];

function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-snow px-1.5 py-0.5 font-mono text-[0.9em]">{children}</code>;
}

function CopyAddress() {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(EMAIL).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1600);
      },
      () => {},
    );
  };
  return (
    <button
      type="button"
      onClick={copy}
      className="rounded-full px-5 py-3 text-sm text-ink ring-1 ring-ink/20 transition hover:ring-ink/50"
    >
      <span aria-live="polite">{copied ? "Copied" : "Copy address"}</span>
    </button>
  );
}

function Support() {
  return (
    <>
      <div className="mb-3 text-[11px] font-semibold uppercase tracking-[0.14em] text-smoke md:text-xs">
        Support
      </div>
      <h1 className="text-[2rem] font-medium leading-[1.12] tracking-tight md:text-5xl md:leading-tight">
        How can we help?
      </h1>
      <p className="mt-4 text-base leading-relaxed text-smoke md:text-lg">
        Most problems have a quick fix below. If yours doesn't, write to us and we'll get back to
        you.
      </p>

      <section aria-labelledby="fixes" className="mt-12">
        <h2 id="fixes" className="text-xl font-medium tracking-tight">
          Quick fixes
        </h2>
        <div className="mt-4 divide-y divide-mist border-y border-mist">
          {FIXES.map(([question, answer]) => (
            <details key={question} className="group py-1">
              <summary className="flex cursor-pointer list-none items-center justify-between gap-4 py-3 font-medium [&::-webkit-details-marker]:hidden">
                {question}
                <span
                  aria-hidden
                  className="text-xl leading-none text-pewter transition-transform group-open:rotate-45"
                >
                  +
                </span>
              </summary>
              <p className="pb-4 leading-relaxed text-smoke">{answer}</p>
            </details>
          ))}
        </div>
      </section>

      <section aria-labelledby="contact" className="mt-14 rounded-2xl bg-snow p-6 md:p-8">
        <h2 id="contact" className="text-xl font-medium tracking-tight">
          Email us
        </h2>
        <p className="mt-2 leading-relaxed text-smoke">
          Tell us what happened, and the page's address if it's about a site. The email opens with
          those questions filled in.
        </p>
        <p className="mt-4 break-all font-mono text-base md:text-lg">{EMAIL}</p>
        <div className="mt-5 flex flex-wrap gap-3">
          <a
            href={MAILTO}
            className="rounded-full bg-ink px-5 py-3 text-sm text-white transition hover:bg-carbon"
          >
            Write an email
          </a>
          <CopyAddress />
        </div>
        <p className="mt-5 text-sm leading-relaxed text-smoke">
          sinkd never sends anything by itself; we only see what you put in the email. Bugs and
          ideas can also go to{" "}
          <a href={`${GITHUB}/issues`} className="underline underline-offset-2">
            GitHub issues
          </a>
          .
        </p>
      </section>
    </>
  );
}

mount(<Support />);
