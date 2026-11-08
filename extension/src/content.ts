// The content script, in the extension's ISOLATED world: nothing here is
// visible to page scripts, and it adds no nodes, attributes or styles of
// its own to the page. (Procedural rules change the elements they target,
// and only those.)
//
// It does two things the service worker can't do from outside the page:
//
// 1. Generic hiding by token. Generic rules (`##.ad-banner`) are keyed by
//    their rightmost class or id, so this script reports the classes and
//    ids the page actually uses and the worker inserts only the rules that
//    can match. The worker's CSS goes in with insertCSS at the user origin,
//    which pages can't see in document.styleSheets.
// 2. Procedural rules (`:has-text()`, `:upward()`, `:remove()`, …), which
//    CSS can't express. The worker sends this site's rules; they run here
//    when the page loads and again when it changes.
//
// It also relays the fingerprint-noise seed to farble.js in the page's
// main world (see that file for the handshake).
//
// The worker decides what applies; this script never sees a filter list.
// A script, not a module (content scripts can't import), hence the IIFE.

(() => {
  /** Tokens sent per message, and in all: a page with more is generating them. */
  const BATCH = 1000;
  const MAX_TOKENS = 20000;
  /** Wait after a change before looking at the page again. */
  const SETTLE_MS = 100;

  interface PageReply {
    procedural: unknown[];
    generic: boolean;
  }

  type Step = { kind: "css"; value: string } | { kind: "op"; value: Op };
  interface Selector {
    steps: Step[];
  }
  type Op =
    | { op: "has-text" | "matches-attr" | "matches-path" | "matches-prop"; arg: string }
    | { op: "matches-media" | "xpath" | "watch-attr"; arg: string }
    | { op: "has" | "not"; arg: Selector }
    | { op: "matches-css"; arg: { pseudo: string | null; arg: string } }
    | { op: "min-text-length"; arg: number }
    | { op: "upward"; arg: { kind: "levels"; value: number } | { kind: "selector"; value: string } }
    | { op: "others" };
  type Action =
    | { kind: "hide" | "remove" }
    | { kind: "style" | "remove_attr" | "remove_class"; value: string };
  interface Rule {
    selector: Selector;
    action: Action;
  }

  const send = (message: object): Promise<unknown> =>
    chrome.runtime.sendMessage(message).catch(() => null);

  // ------------------------------------------------------- fingerprint seed

  const HELLO = "dd5a2b-h";
  const READY = "dd5a2b-r";
  const SEED = "dd5a2b-s";
  let token: string | null = null;
  addEventListener(
    HELLO,
    (event) => {
      const detail: unknown = (event as CustomEvent).detail;
      // farble.js's token arrives before any page script runs, so the
      // first one is genuine. Later ones are swallowed only if they repeat
      // it (a page must not see it); anything else is left alone, so a page
      // can't tell this listener exists.
      if (typeof detail !== "string" || !/^[0-9a-f]{32}$/.test(detail)) return;
      if (token !== null && detail !== token) return;
      event.stopImmediatePropagation();
      if (token !== null) return;
      token = detail;
      void send({ type: "seed" }).then((reply) => {
        const seed = (reply as { seed?: unknown } | null)?.seed;
        const value = typeof seed === "string" && /^[0-9a-f]{64}$/.test(seed) ? seed : "off";
        dispatchEvent(new CustomEvent(SEED, { detail: `${token}:${value}` }));
      });
    },
    true,
  );
  // In case farble.js ran first and its token went unheard.
  dispatchEvent(new Event(READY));

  // ---------------------------------------------------------------- tokens

  const sent = new Set<string>();
  let pending: string[] = [];
  let first = true;

  function collect(element: Element): void {
    if (sent.size >= MAX_TOKENS) {
      return;
    }
    const id = element.id;
    if (id && !/\s/.test(id) && !sent.has(`#${id}`)) {
      sent.add(`#${id}`);
      pending.push(`#${id}`);
    }
    for (const name of element.classList) {
      if (!sent.has(`.${name}`)) {
        sent.add(`.${name}`);
        pending.push(`.${name}`);
      }
    }
  }

  function flushTokens(): void {
    while (pending.length > 0 || first) {
      const tokens = pending.slice(0, BATCH);
      pending = pending.slice(BATCH);
      // The first message also asks for the generic rules that have no
      // token, so it goes out even when the page has no classes or ids.
      void send({ type: "generic", tokens, always: first });
      first = false;
    }
  }

  function survey(root: ParentNode): void {
    if (root instanceof Element) {
      collect(root);
    }
    for (const element of root.querySelectorAll("[id],[class]")) {
      collect(element);
    }
  }

  // ------------------------------------------------------------ procedural

  /** uBO's argument convention: `/re/flags` is a regex, anything else literal. */
  function pattern(arg: string): (text: string) => boolean {
    const re = /^\/(.+)\/([dgimsuy]*)$/.exec(arg);
    if (re) {
      try {
        const regex = new RegExp(re[1] ?? "", (re[2] ?? "").replace("g", ""));
        return (text) => regex.test(text);
      } catch {
        return () => false;
      }
    }
    return (text) => text.includes(arg);
  }

  /** Like `pattern`, but a literal must match the whole text. */
  function exact(arg: string): (text: string) => boolean {
    return arg.startsWith("/") ? pattern(arg) : (text) => text === arg;
  }

  function unquote(s: string): string {
    const t = s.trim();
    return /^(["']).*\1$/.test(t) ? t.slice(1, -1) : t;
  }

  /** Splits `name=value` at the first `=` outside a `/regex/`. */
  function nameValue(arg: string): [string, string | null] {
    let inRegex = false;
    for (let i = 0; i < arg.length; i++) {
      const c = arg[i];
      if (c === "\\") {
        i++;
      } else if (c === "/") {
        inRegex = !inRegex;
      } else if (c === "=" && !inRegex) {
        return [unquote(arg.slice(0, i)), unquote(arg.slice(i + 1))];
      }
    }
    return [unquote(arg), null];
  }

  function query(root: ParentNode, css: string): Element[] {
    try {
      return [...root.querySelectorAll(css)];
    } catch {
      return [];
    }
  }

  /**
   * CSS that starts at `element`: `> .child`, `.descendant`, or a sibling
   * (`+ .next`, `~ .later`). Siblings are outside the element, so those
   * are found from its parent, anchored by the element's position.
   */
  function within(element: Element, css: string): Element[] {
    const text = css.trim();
    if (!/^[+~]/.test(text)) {
      return query(element, `:scope ${text}`);
    }
    const parent = element.parentElement;
    if (!parent) {
      return [];
    }
    const position = [...parent.children].indexOf(element) + 1;
    return query(parent, `:scope > :nth-child(${position}) ${text}`);
  }

  /** CSS after an operator, applied to each element found so far. */
  function relative(elements: Element[], css: string): Element[] {
    const out = new Set<Element>();
    const combinator = /^(\s|[>+~])/.test(css);
    for (const element of elements) {
      if (combinator) {
        for (const match of within(element, css)) out.add(match);
      } else {
        // No combinator: more conditions on the same element.
        try {
          if (element.matches(css)) out.add(element);
        } catch {
          // An invalid selector matches nothing.
        }
      }
    }
    return [...out];
  }

  /**
   * Runs `selector` from `start`, as uBO does: leading CSS searches from
   * `start` (the whole document when it is null); a leading operator
   * tests `start` itself.
   */
  function evaluate(selector: Selector, start: Element | null): Element[] {
    let elements: Element[] = [];
    selector.steps.forEach((step, i) => {
      if (step.kind === "css") {
        if (i > 0) {
          elements = relative(elements, step.value);
        } else {
          elements = start ? within(start, step.value) : query(document, step.value);
        }
      } else if (i > 0) {
        elements = apply(step.value, elements);
      } else if (step.value.op === "xpath") {
        elements = xpath(step.value.arg, [start ?? document]);
      } else {
        elements = apply(step.value, start ? [start] : query(document, "body *"));
      }
    });
    return elements;
  }

  function xpath(expression: string, contexts: Node[]): Element[] {
    const out = new Set<Element>();
    for (const context of contexts) {
      let result: XPathResult;
      try {
        result = document.evaluate(
          expression,
          context,
          null,
          XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
          null,
        );
      } catch {
        return [];
      }
      for (let i = 0; i < result.snapshotLength; i++) {
        const node = result.snapshotItem(i);
        if (node instanceof Element) out.add(node);
      }
    }
    return [...out];
  }

  function apply(op: Op, elements: Element[]): Element[] {
    switch (op.op) {
      case "has-text": {
        const test = pattern(op.arg);
        return elements.filter((e) => test(e.textContent ?? ""));
      }
      case "has":
        return elements.filter((e) => evaluate(op.arg, e).length > 0);
      case "not":
        return elements.filter((e) => evaluate(op.arg, e).length === 0);
      case "matches-css": {
        const [name, value] = nameValue(op.arg.arg);
        if (value === null) {
          return [];
        }
        const test = exact(value);
        const pseudo = op.arg.pseudo ? `::${op.arg.pseudo}` : null;
        return elements.filter((e) => test(getComputedStyle(e, pseudo).getPropertyValue(name)));
      }
      case "matches-attr": {
        const [name, value] = nameValue(op.arg);
        const testName = exact(name);
        const testValue = value === null ? () => true : exact(value);
        return elements.filter((e) =>
          [...e.attributes].some((a) => testName(a.name) && testValue(a.value)),
        );
      }
      case "matches-path":
        return pattern(op.arg)(location.pathname + location.search) ? elements : [];
      case "matches-media":
        return matchMedia(op.arg).matches ? elements : [];
      case "matches-prop": {
        // Only the DOM's own properties: what page scripts set on an
        // element is in the page's world, not visible here.
        const [chain, value] = nameValue(op.arg);
        const test = value === null ? () => true : exact(value);
        return elements.filter((e) => {
          let v: unknown = e;
          for (const key of chain.split(".")) {
            if (v === null || v === undefined) return false;
            v = (v as Record<string, unknown>)[key];
          }
          return v !== undefined && test(String(v));
        });
      }
      case "min-text-length":
        return elements.filter((e) => (e.textContent ?? "").length >= op.arg);
      case "upward": {
        const up = op.arg;
        const out = new Set<Element>();
        for (const e of elements) {
          let target: Element | null = null;
          if (up.kind === "levels") {
            target = e;
            for (let n = 0; n < up.value && target; n++) {
              target = target.parentElement;
            }
          } else {
            try {
              target = e.parentElement?.closest(up.value) ?? null;
            } catch {
              target = null;
            }
          }
          if (target && target !== document.documentElement && target !== document.body) {
            out.add(target);
          }
        }
        return [...out];
      }
      case "xpath":
        return xpath(op.arg, elements);
      case "watch-attr":
        return elements;
      case "others": {
        // Everything except the subjects, their ancestors and descendants.
        const keep = new Set<Element>();
        for (const e of elements) {
          for (let a: Element | null = e; a; a = a.parentElement) keep.add(a);
          for (const d of e.querySelectorAll("*")) keep.add(d);
        }
        if (keep.size === 0) {
          return [];
        }
        return query(document, "body *").filter(
          (e) => !keep.has(e) && !/^(SCRIPT|STYLE|LINK|META|NOSCRIPT)$/.test(e.tagName),
        );
      }
    }
  }

  const done = new WeakMap<Rule, WeakSet<Element>>();

  function act(rule: Rule, element: Element): void {
    const style = (element as HTMLElement).style;
    const action = rule.action;
    switch (action.kind) {
      case "hide":
        style?.setProperty("display", "none", "important");
        break;
      case "remove":
        element.remove();
        break;
      case "style":
        for (const declaration of action.value.split(";")) {
          const colon = declaration.indexOf(":");
          if (colon > 0) {
            const value = declaration.slice(colon + 1).replace(/!\s*important\s*$/i, "");
            style?.setProperty(declaration.slice(0, colon).trim(), value.trim(), "important");
          }
        }
        break;
      case "remove_attr": {
        const test = exact(action.value);
        for (const a of [...element.attributes]) {
          if (test(a.name)) element.removeAttribute(a.name);
        }
        break;
      }
      case "remove_class": {
        const test = exact(action.value);
        for (const name of [...element.classList]) {
          if (test(name)) element.classList.remove(name);
        }
        break;
      }
    }
  }

  function runRules(rules: Rule[]): void {
    for (const rule of rules) {
      let seen = done.get(rule);
      if (!seen) {
        seen = new WeakSet();
        done.set(rule, seen);
      }
      for (const element of evaluate(rule.selector, null)) {
        // remove-attr and remove-class run again on elements the page
        // changes back; the rest act once.
        const repeat = rule.action.kind === "remove_attr" || rule.action.kind === "remove_class";
        if (repeat || !seen.has(element)) {
          seen.add(element);
          act(rule, element);
        }
      }
    }
  }

  function watchedAttributes(rules: Rule[]): string[] {
    const names = new Set(["id", "class"]);
    const visit = (selector: Selector): void => {
      for (const step of selector.steps) {
        if (step.kind !== "op") continue;
        const op = step.value;
        if (op.op === "watch-attr") {
          for (const name of op.arg.split(",")) if (name.trim()) names.add(name.trim());
        } else if (op.op === "has" || op.op === "not") {
          visit(op.arg);
        }
      }
    };
    for (const rule of rules) visit(rule.selector);
    return [...names];
  }

  // ----------------------------------------------------------------- start

  function start(reply: PageReply): void {
    const rules = (Array.isArray(reply.procedural) ? reply.procedural : []).filter(
      (r): r is Rule => typeof r === "object" && r !== null && "selector" in r && "action" in r,
    );
    if (!reply.generic && rules.length === 0) {
      return;
    }
    const added: Element[] = [];
    let scheduled = false;

    const settle = (): void => {
      scheduled = false;
      if (reply.generic) {
        for (const element of added.splice(0)) survey(element);
        flushTokens();
      }
      if (rules.length > 0) runRules(rules);
    };
    const later = (): void => {
      if (!scheduled) {
        scheduled = true;
        setTimeout(settle, SETTLE_MS);
      }
    };

    const observer = new MutationObserver((records) => {
      for (const record of records) {
        if (record.type === "attributes") {
          if (record.target instanceof Element) added.push(record.target);
        } else {
          for (const node of record.addedNodes) {
            if (node instanceof Element) added.push(node);
          }
        }
      }
      later();
    });
    const begin = (): void => {
      if (reply.generic) survey(document);
      settle();
      observer.observe(document, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: watchedAttributes(rules),
      });
    };
    // At document_start there is no body yet. Survey what exists now, so
    // the first rules arrive early, and the whole page once it is parsed.
    if (reply.generic && document.documentElement) {
      survey(document);
      flushTokens();
    }
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", begin, { once: true });
    } else {
      begin();
    }
  }

  void send({ type: "page" }).then((reply) => {
    if (reply && typeof reply === "object") {
      start(reply as PageReply);
    }
  });
})();
