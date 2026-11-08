// Scriptlets: original implementations, MIT OR Apache-2.0. Argument
// conventions follow uBlock Origin's documentation so community lists work
// unchanged; no code is taken from uBO or AdGuard.
//
// The compiler drops this header, wraps the rest in a function together
// with a table of which calls run on which sites, and the extension
// registers the result as a content script in the page's MAIN world at
// document_start, before any page script. Nothing below may name the
// extension: a page can read script sources.
//
// Rules for the code below:
// - Every built-in it relies on is captured at load, before page scripts
//   can replace it, and called through Reflect.apply.
// - Nothing is added to the page's globals except what a scriptlet is asked
//   to set. Everything lives in this closure.
// - Replaced functions are Proxies of the originals, so name and length
//   survive, and Function.prototype.toString reports the original's source
//   for them. Property descriptors keep their flags.
// - Errors thrown on purpose (abort-*) have this script's frames removed
//   from their stack before they are thrown.

'use strict';

const win = self;
const doc = win.document;
const ObjectCreate = Object.create;
const ObjectDefineProperty = Object.defineProperty;
const ObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const ObjectGetPrototypeOf = Object.getPrototypeOf;
const ObjectHasOwn = Object.prototype.hasOwnProperty;
const ObjectKeys = Object.keys;
const ReflectApply = Reflect.apply;
const ProxyCtor = Proxy;
const RegExpCtor = RegExp;
const RegExpTest = RegExp.prototype.test;
const RegExpExec = RegExp.prototype.exec;
const StringSplit = String.prototype.split;
const StringReplace = String.prototype.replace;
const StringTrim = String.prototype.trim;
const StringToLower = String.prototype.toLowerCase;
const StringIncludes = String.prototype.includes;
const StringStartsWith = String.prototype.startsWith;
const StringSlice = String.prototype.slice;
const StringIndexOf = String.prototype.indexOf;
const StringToUpper = String.prototype.toUpperCase;
const ArrayJoin = Array.prototype.join;
const ArrayFilter = Array.prototype.filter;
const ArrayMap = Array.prototype.map;
const ArrayIsArray = Array.isArray;
const JSONParse = JSON.parse;
const NumberCtor = Number;
const MathAbs = Math.abs;
const MathMin = Math.min;
const MathMax = Math.max;
const ErrorCtor = Error;
const ReferenceErrorCtor = ReferenceError;
const PromiseResolve = Promise.resolve.bind(Promise);
const PromiseThen = Promise.prototype.then;
const WeakMapCtor = WeakMap;
const WeakMapGet = WeakMap.prototype.get;
const WeakMapSet = WeakMap.prototype.set;
const WeakMapHas = WeakMap.prototype.has;
const SetCtor = Set;
const nativeToString = Function.prototype.toString;
const addListener = EventTarget.prototype.addEventListener;
const MutationObserverCtor = win.MutationObserver;
const ResponseCtor = win.Response;
const URLCtor = URL;
const EventCtor = Event;
const dispatch = EventTarget.prototype.dispatchEvent;
const setTimeoutNative = win.setTimeout;
const querySelectorAll = Document.prototype.querySelectorAll;
const cookieDescriptor = ObjectGetOwnPropertyDescriptor(Document.prototype, 'cookie');
const cssEscape = win.CSS && win.CSS.escape;
const localStorageGetter = (() => {
  try {
    return ObjectGetOwnPropertyDescriptor(win, 'localStorage').get;
  } catch (e) {
    return undefined;
  }
})();

const call = (fn, self, ...args) => ReflectApply(fn, self, args);
const split = (s, sep) => call(StringSplit, String(s), sep);
const trim = (s) => call(StringTrim, String(s));
const includes = (s, sub) => call(StringIncludes, String(s), sub);
const startsWith = (s, sub) => call(StringStartsWith, String(s), sub);
const lower = (s) => call(StringToLower, String(s));
const upper = (s) => call(StringToUpper, String(s));
const slice = (s, a, b) => call(StringSlice, String(s), a, b);
const indexOf = (s, sub) => call(StringIndexOf, String(s), sub);
const join = (a, sep) => call(ArrayJoin, a, sep);
const filter = (a, fn) => call(ArrayFilter, a, fn);
const map = (a, fn) => call(ArrayMap, a, fn);
const has = (o, k) => call(ObjectHasOwn, o, k);
const later = (fn) => call(setTimeoutNative, win, fn, 0);

// ---- Looking native ------------------------------------------------------

// Replacement → the function whose source it reports.
const masks = new WeakMapCtor();
// A native function with no name: what an accessor we define reports.
const anonymousNative = function () {}.bind();
let toStringPatched = false;

function mask(replacement, original) {
  call(WeakMapSet, masks, replacement, original || anonymousNative);
  if (!toStringPatched) {
    toStringPatched = true;
    const patched = new ProxyCtor(nativeToString, {
      apply(target, self, args) {
        const shown = call(WeakMapHas, masks, self) ? call(WeakMapGet, masks, self) : self;
        try {
          return ReflectApply(target, shown, args);
        } catch (error) {
          // toString on a non-function throws; not with this frame in it.
          throw scrub(error);
        }
      },
    });
    call(WeakMapSet, masks, patched, nativeToString);
    const descriptor = ObjectGetOwnPropertyDescriptor(Function.prototype, 'toString');
    descriptor.value = patched;
    ObjectDefineProperty(Function.prototype, 'toString', descriptor);
  }
  return replacement;
}

/** Replaces `owner[prop]`, a function, with a Proxy of it. */
function wrap(owner, prop, handler) {
  if (!owner) {
    return;
  }
  const descriptor = ObjectGetOwnPropertyDescriptor(owner, prop);
  if (!descriptor || typeof descriptor.value !== 'function') {
    return;
  }
  if (!descriptor.writable && !descriptor.configurable) {
    return;
  }
  const original = descriptor.value;
  // An error raised inside a trap (the original throwing, say JSON.parse on
  // bad input) would carry this script's frame in its stack; scrub it on
  // the way out.
  const guarded = ObjectCreate(null);
  for (const trap of ObjectKeys(handler)) {
    const fn = handler[trap];
    guarded[trap] = function () {
      try {
        return ReflectApply(fn, handler, arguments);
      } catch (error) {
        throw scrub(error);
      }
    };
  }
  descriptor.value = mask(new ProxyCtor(original, guarded), original);
  ObjectDefineProperty(owner, prop, descriptor);
}

/** An accessor function that stringifies like a native one. */
const accessor = (fn) => mask(fn);

function scrub(error) {
  try {
    const lines = split(error.stack, '\n');
    error.stack = join(
      filter(lines, (line) => !includes(line, '-extension://')),
      '\n',
    );
  } catch (e) {
    // A frozen error keeps its stack.
  }
  return error;
}

function abort(prop) {
  throw scrub(new ReferenceErrorCtor(`${prop} is not defined`));
}

// ---- Patterns ------------------------------------------------------------

const matchAll = /^/;
const matchNothing = /(?!)/;

/** `/regex/flags`, or a literal; empty matches everything. */
function pattern(arg) {
  if (arg === undefined || arg === '') {
    return matchAll;
  }
  const regex = call(RegExpExec, /^\/(.+)\/([dgimsuy]*)$/, String(arg));
  if (regex) {
    try {
      return new RegExpCtor(regex[1], regex[2]);
    } catch (e) {
      return matchNothing;
    }
  }
  return new RegExpCtor(call(StringReplace, String(arg), /[.*+?^${}()|[\]\\]/g, '\\$&'));
}

/** A pattern that may start with `!` to invert it. */
function negatable(arg) {
  const text = arg === undefined ? '' : String(arg);
  return startsWith(text, '!')
    ? { re: pattern(slice(text, 1)), not: true }
    : { re: pattern(text), not: false };
}

const test = (re, s) => {
  re.lastIndex = 0;
  return call(RegExpTest, re, String(s));
};
const hit = (p, s) => test(p.re, s) !== p.not;

function sourceOf(fn) {
  if (typeof fn === 'function') {
    try {
      return call(nativeToString, fn);
    } catch (e) {
      return '';
    }
  }
  return fn === undefined || fn === null ? '' : String(fn);
}

/**
 * The current stack, for `stack` arguments: this script's frames dropped,
 * frames from the page itself named `inlineScript`, frames with no source
 * named `injectedScript`.
 */
function stackMatches(needle) {
  const re = pattern(needle);
  const page = split(win.location.href, '#')[0];
  const frames = [];
  for (const line of split(new ErrorCtor().stack, '\n')) {
    if (includes(line, '-extension://') || !includes(line, ' at ')) {
      continue;
    }
    if (includes(line, page)) {
      frames.push(call(StringReplace, line, page, 'inlineScript'));
    } else if (includes(line, '<anonymous>')) {
      frames.push(call(StringReplace, line, '<anonymous>', 'injectedScript'));
    } else {
      frames.push(line);
    }
  }
  return test(re, join(frames, '\n'));
}

// ---- Property chains -----------------------------------------------------

/**
 * Calls `onLast(owner, prop)` once the object owning the last link of
 * `chain` exists: now, or when the page assigns the missing links.
 */
function onChain(chain, onLast) {
  const links = split(chain, '.');
  const walk = (owner, i) => {
    const prop = links[i];
    if (i === links.length - 1) {
      onLast(owner, prop);
      return;
    }
    let value;
    try {
      value = owner[prop];
    } catch (e) {
      return;
    }
    if ((typeof value === 'object' && value !== null) || typeof value === 'function') {
      walk(value, i + 1);
      return;
    }
    const descriptor = ObjectGetOwnPropertyDescriptor(owner, prop);
    if (descriptor && !descriptor.configurable) {
      return;
    }
    // A native getter that has nothing to return yet (document.body before
    // <body> is parsed) must not be shadowed by a trap: the page would
    // never see the real value.
    if (!descriptor && inheritedAccessor(owner, prop)) {
      return;
    }
    ObjectDefineProperty(owner, prop, {
      configurable: true,
      enumerable: true,
      get: accessor(() => value),
      set: accessor((next) => {
        value = next;
        if ((typeof next === 'object' && next !== null) || typeof next === 'function') {
          walk(next, i + 1);
        }
      }),
    });
  };
  walk(win, 0);
}

/** Whether `prop` comes from a getter on `owner`'s prototype chain. */
function inheritedAccessor(owner, prop) {
  for (let proto = ObjectGetPrototypeOf(owner); proto; proto = ObjectGetPrototypeOf(proto)) {
    const descriptor = ObjectGetOwnPropertyDescriptor(proto, prop);
    if (descriptor) {
      return !has(descriptor, 'value');
    }
  }
  return false;
}

function currentValue(owner, prop) {
  const descriptor = ObjectGetOwnPropertyDescriptor(owner, prop);
  if (!descriptor) {
    return { value: undefined, ok: true };
  }
  if (!descriptor.configurable) {
    return { ok: false };
  }
  if (has(descriptor, 'value')) {
    return { value: descriptor.value, ok: true, enumerable: descriptor.enumerable };
  }
  try {
    return { value: owner[prop], ok: true, enumerable: descriptor.enumerable };
  } catch (e) {
    return { value: undefined, ok: true, enumerable: descriptor.enumerable };
  }
}

const INVALID = {};

/** The values `set-constant` and friends accept. */
function constant(raw) {
  const noop = mask(() => {});
  switch (raw) {
    case 'undefined':
      return undefined;
    case 'false':
      return false;
    case 'true':
      return true;
    case 'null':
      return null;
    case '':
    case "''":
    case 'emptyStr':
      return '';
    case 'noopFunc':
      return noop;
    case 'trueFunc':
      return mask(() => true);
    case 'falseFunc':
      return mask(() => false);
    case 'throwFunc':
      return mask(() => {
        throw scrub(new ErrorCtor());
      });
    case 'noopCallbackFunc':
      return mask(() => noop);
    case 'noopPromiseResolve':
      return mask(() => PromiseResolve());
    case '[]':
    case 'emptyArr':
      return [];
    case '{}':
    case 'emptyObj':
      return {};
    default: {
      if (test(/^-?\d+(\.\d+)?$/, raw)) {
        const n = NumberCtor(raw);
        if (MathAbs(n) <= 0x7fff) {
          return n;
        }
      }
      return INVALID;
    }
  }
}

// ---- DOM helpers ---------------------------------------------------------

/**
 * Runs `task` on elements matching `selector` when the document is ready
 * (`complete`: when it has loaded), and on new ones too with `stay`.
 */
function domTask(selector, behavior, task) {
  const run = () => {
    let found;
    try {
      found = call(querySelectorAll, doc, selector);
    } catch (e) {
      return;
    }
    for (const element of found) {
      try {
        task(element);
      } catch (e) {
        // One bad element does not stop the rest.
      }
    }
  };
  const when = String(behavior || '');
  if (includes(when, 'complete')) {
    if (doc.readyState === 'complete') {
      run();
    } else {
      call(addListener, win, 'load', run, { capture: true, once: true });
    }
  } else if (doc.readyState === 'loading') {
    call(addListener, doc, 'DOMContentLoaded', run, { capture: true, once: true });
  } else {
    run();
  }
  if (includes(when, 'stay') && MutationObserverCtor) {
    let queued = false;
    const observer = new MutationObserverCtor(() => {
      if (!queued) {
        queued = true;
        later(() => {
          queued = false;
          run();
        });
      }
    });
    observer.observe(doc, { attributes: true, childList: true, subtree: true });
  }
}

// ---- Requests ------------------------------------------------------------

/**
 * `url:/ads/ method:POST` or a bare URL pattern; `*` matches everything,
 * an empty string nothing (it only logs, in uBO).
 */
function requestFilter(props) {
  const text = trim(props || '');
  if (text === '') {
    return null;
  }
  if (text === '*') {
    return [];
  }
  const filters = [];
  for (const token of split(text, /\s+/)) {
    const colon = indexOf(token, ':');
    const named = colon > 0 && test(/^[a-zA-Z]+$/, slice(token, 0, colon));
    const key = named ? slice(token, 0, colon) : 'url';
    const value = named ? slice(token, colon + 1) : token;
    filters.push({ key, re: pattern(value) });
  }
  return filters;
}

function requestMatches(filters, details) {
  if (filters === null) {
    return false;
  }
  for (const f of filters) {
    if (!has(details, f.key) || !test(f.re, details[f.key])) {
      return false;
    }
  }
  return true;
}

function responseText(body) {
  switch (body) {
    case undefined:
    case '':
    case 'emptyStr':
      return '';
    case 'emptyObj':
    case '{}':
      return '{}';
    case 'emptyArr':
    case '[]':
      return '[]';
    case 'true':
    case 'false':
      return body;
    default:
      return '';
  }
}

// ---- JSON paths ----------------------------------------------------------

/** Objects reached by `path` (`a.b`, `a.[].b`, `a.*.b`), with the last key. */
function reach(root, path) {
  const links = split(path, '.');
  let owners = [root];
  for (let i = 0; i < links.length - 1; i++) {
    const next = [];
    for (const owner of owners) {
      if (owner === null || typeof owner !== 'object') {
        continue;
      }
      const link = links[i];
      if (link === '[]' || link === '*') {
        const keys = ArrayIsArray(owner) && link === '[]' ? owner.keys() : ObjectKeys(owner);
        for (const k of keys) {
          next.push(owner[k]);
        }
      } else if (has(owner, link)) {
        next.push(owner[link]);
      }
    }
    owners = next;
  }
  const last = links[links.length - 1];
  return { owners: filter(owners, (o) => o !== null && typeof o === 'object'), last };
}

function pathExists(root, path) {
  const { owners, last } = reach(root, path);
  for (const owner of owners) {
    if (last === '*' ? ObjectKeys(owner).length > 0 : has(owner, last)) {
      return true;
    }
  }
  return false;
}

function prune(root, path) {
  const { owners, last } = reach(root, path);
  for (const owner of owners) {
    if (last === '*' || last === '[]') {
      for (const k of ObjectKeys(owner)) {
        delete owner[k];
      }
    } else if (has(owner, last)) {
      delete owner[last];
    }
  }
}

// ---- The scriptlets ------------------------------------------------------
//
// Each takes (args, dialect): the arguments as the list wrote them, and
// 'u', 'a' or 'b' for uBO, AdGuard or ABP syntax.

function timerDefuser(name) {
  return ([needle, delay]) => {
    const text = negatable(needle);
    const delayText = delay === undefined ? '' : String(delay);
    const delayNot = startsWith(delayText, '!');
    const delayValue = NumberCtor(delayNot ? slice(delayText, 1) : delayText);
    wrap(win, name, {
      apply(target, self, args) {
        const [fn, ms] = args;
        const delayHit = delayText === '' || (NumberCtor(ms || 0) === delayValue) !== delayNot;
        if (hit(text, sourceOf(fn)) && delayHit) {
          args[0] = mask(() => {});
        }
        return ReflectApply(target, self, args);
      },
    });
  };
}

function timerBooster(name) {
  return ([needle, delay, boost]) => {
    const re = pattern(needle);
    const want = delay === '*' ? NaN : NumberCtor(delay || 1000) || 1000;
    let factor = NumberCtor(boost === undefined || boost === '' ? 0.05 : boost);
    factor = factor > 0 ? MathMin(50, MathMax(0.001, factor)) : 0.05;
    wrap(win, name, {
      apply(target, self, args) {
        const [fn, ms] = args;
        if ((want !== want || NumberCtor(ms) === want) && test(re, sourceOf(fn))) {
          args[1] = NumberCtor(ms) * factor;
        }
        return ReflectApply(target, self, args);
      },
    });
  };
}

const scriptlets = {
  'set-constant'([chain, raw, stack]) {
    const value = constant(raw);
    if (value === INVALID || !chain) {
      return;
    }
    const applies = stack ? () => stackMatches(stack) : () => true;
    onChain(chain, (owner, prop) => {
      const current = currentValue(owner, prop);
      if (!current.ok) {
        return;
      }
      let real = current.value;
      ObjectDefineProperty(owner, prop, {
        configurable: false,
        enumerable: current.enumerable !== false,
        get: accessor(() => (applies() ? value : real)),
        set: accessor((next) => {
          if (!applies()) {
            real = next;
          }
        }),
      });
    });
  },

  'abort-on-property-read'([chain]) {
    if (!chain) {
      return;
    }
    onChain(chain, (owner, prop) => {
      if (!currentValue(owner, prop).ok) {
        return;
      }
      ObjectDefineProperty(owner, prop, {
        configurable: true,
        get: accessor(() => abort(prop)),
        set: accessor(() => {}),
      });
    });
  },

  'abort-on-property-write'([chain]) {
    if (!chain) {
      return;
    }
    onChain(chain, (owner, prop) => {
      const current = currentValue(owner, prop);
      if (!current.ok) {
        return;
      }
      const value = current.value;
      ObjectDefineProperty(owner, prop, {
        configurable: true,
        get: accessor(() => value),
        set: accessor(() => abort(prop)),
      });
    });
  },

  'abort-current-script'([chain, needle, context], dialect) {
    if (!chain) {
      return;
    }
    const re = pattern(needle);
    const contextRe = context ? pattern(context) : null;
    // AdGuard's abort-current-inline-script looks at inline scripts only.
    const inlineOnly = dialect === 'a';
    const check = () => {
      const script = doc.currentScript;
      if (!script || script.tagName !== 'SCRIPT') {
        return;
      }
      if (script.src && inlineOnly) {
        return;
      }
      if (contextRe && !test(contextRe, script.src || '')) {
        return;
      }
      let text = script.src ? '' : script.text;
      if (startsWith(script.src, 'data:')) {
        try {
          const comma = indexOf(script.src, ',');
          const data = slice(script.src, comma + 1);
          text = includes(slice(script.src, 0, comma), ';base64') ? win.atob(data) : decodeURIComponent(data);
        } catch (e) {
          text = '';
        }
      }
      if (test(re, text)) {
        abort(split(chain, '.').pop());
      }
    };
    onChain(chain, (owner, prop) => {
      const current = currentValue(owner, prop);
      if (!current.ok) {
        return;
      }
      let value = current.value;
      ObjectDefineProperty(owner, prop, {
        configurable: true,
        enumerable: current.enumerable !== false,
        get: accessor(() => {
          check();
          return value;
        }),
        set: accessor((next) => {
          check();
          value = next;
        }),
      });
    });
  },

  'abort-on-stack-trace'([chain, needle]) {
    if (!chain || !needle) {
      return;
    }
    onChain(chain, (owner, prop) => {
      const current = currentValue(owner, prop);
      if (!current.ok) {
        return;
      }
      let value = current.value;
      const check = () => {
        if (stackMatches(needle)) {
          abort(prop);
        }
      };
      ObjectDefineProperty(owner, prop, {
        configurable: true,
        enumerable: current.enumerable !== false,
        get: accessor(() => {
          check();
          return value;
        }),
        set: accessor((next) => {
          check();
          value = next;
        }),
      });
    });
  },

  'prevent-setTimeout': timerDefuser('setTimeout'),
  'prevent-setInterval': timerDefuser('setInterval'),
  'nano-setTimeout-booster': timerBooster('setTimeout'),
  'nano-setInterval-booster': timerBooster('setInterval'),

  'prevent-fetch'([props, body, type]) {
    const filters = requestFilter(props);
    if (filters === null || typeof ResponseCtor !== 'function') {
      return;
    }
    wrap(win, 'fetch', {
      apply(target, self, args) {
        const [resource, init] = args;
        const details = { url: '', method: 'GET' };
        try {
          if (resource && typeof resource === 'object' && 'url' in resource) {
            details.url = String(resource.url);
            details.method = String(resource.method || 'GET');
          } else {
            details.url = String(resource);
          }
          if (init && typeof init === 'object') {
            for (const key of ['method', 'mode', 'credentials', 'body']) {
              if (init[key] !== undefined) {
                details[key] = String(init[key]);
              }
            }
          }
        } catch (e) {
          return ReflectApply(target, self, args);
        }
        details.method = upper(details.method);
        if (!requestMatches(filters, details)) {
          return ReflectApply(target, self, args);
        }
        // A plausible empty success, not a network error: a failed request
        // is what detection scripts look for.
        const response = new ResponseCtor(responseText(body), { status: 200, statusText: 'OK' });
        try {
          ObjectDefineProperty(response, 'url', { value: new URLCtor(details.url, win.location.href).href });
          if (type === 'opaque') {
            ObjectDefineProperty(response, 'type', { value: 'opaque' });
          }
        } catch (e) {
          // A relative URL that does not resolve keeps the default.
        }
        return PromiseResolve(response);
      },
    });
  },

  'prevent-xhr'([props, body]) {
    const filters = requestFilter(props);
    const XHR = win.XMLHttpRequest;
    if (filters === null || typeof XHR !== 'function') {
      return;
    }
    const pending = new WeakMapCtor();
    wrap(XHR.prototype, 'open', {
      apply(target, xhr, args) {
        const details = {
          method: upper(args[0] || 'GET'),
          url: String(args[1]),
        };
        if (requestMatches(filters, details)) {
          call(WeakMapSet, pending, xhr, details);
        } else {
          call(WeakMapSet, pending, xhr, null);
        }
        return ReflectApply(target, xhr, args);
      },
    });
    wrap(XHR.prototype, 'send', {
      apply(target, xhr, args) {
        const details = call(WeakMapGet, pending, xhr);
        if (!details) {
          return ReflectApply(target, xhr, args);
        }
        // Complete the request without the network, as a 200.
        const text = responseText(body);
        let response = text;
        if (xhr.responseType === 'json') {
          try {
            response = call(JSONParse, JSON, text || 'null');
          } catch (e) {
            response = null;
          }
        }
        const values = {
          readyState: 4,
          status: 200,
          statusText: 'OK',
          responseText: text,
          response,
          responseURL: details.url,
        };
        for (const key of ObjectKeys(values)) {
          ObjectDefineProperty(xhr, key, { configurable: true, value: values[key] });
        }
        later(() => {
          for (const type of ['readystatechange', 'load', 'loadend']) {
            call(dispatch, xhr, new EventCtor(type));
          }
        });
        return undefined;
      },
    });
  },

  'json-prune'([remove, required, stack]) {
    const removePaths = filter(split(remove || '', /\s+/), Boolean);
    const requiredPaths = filter(split(required || '', /\s+/), Boolean);
    if (removePaths.length === 0) {
      return;
    }
    const apply = (result) => {
      if (result === null || typeof result !== 'object') {
        return result;
      }
      if (stack && !stackMatches(stack)) {
        return result;
      }
      for (const path of requiredPaths) {
        if (!pathExists(result, path)) {
          return result;
        }
      }
      for (const path of removePaths) {
        prune(result, path);
      }
      return result;
    };
    wrap(JSON, 'parse', {
      apply(target, self, args) {
        return apply(ReflectApply(target, self, args));
      },
    });
    if (ResponseCtor) {
      wrap(ResponseCtor.prototype, 'json', {
        apply(target, self, args) {
          return call(PromiseThen, ReflectApply(target, self, args), apply);
        },
      });
    }
  },

  'remove-class'([classes, selector, behavior]) {
    const names = filter(map(split(classes || '', '|'), trim), Boolean);
    if (names.length === 0 || !cssEscape) {
      return;
    }
    const target = selector || join(map(names, (n) => `.${cssEscape(n)}`), ',');
    domTask(target, behavior, (element) => element.classList.remove(...names));
  },

  'remove-attr'([attrs, selector, behavior]) {
    const names = filter(map(split(attrs || '', '|'), trim), Boolean);
    if (names.length === 0 || !cssEscape) {
      return;
    }
    const target = selector || join(map(names, (n) => `[${cssEscape(n)}]`), ',');
    domTask(target, behavior, (element) => {
      for (const name of names) {
        element.removeAttribute(name);
      }
    });
  },

  'no-window-open-if'([needle, , decoy]) {
    const url = negatable(needle);
    wrap(win, 'open', {
      apply(target, self, args) {
        if (!hit(url, args.length > 0 ? String(args[0]) : '')) {
          return ReflectApply(target, self, args);
        }
        if (decoy === 'obj' || decoy === 'blank') {
          const noop = mask(() => {});
          return {
            closed: false,
            opener: win,
            close: mask(function () {
              this.closed = true;
            }),
            focus: noop,
            blur: noop,
            postMessage: noop,
            location: { href: 'about:blank' },
          };
        }
        // What a blocked popup gives.
        return null;
      },
    });
  },

  'addEventListener-defuser'([type, needle]) {
    const typeRe = pattern(type);
    const needleRe = pattern(needle);
    wrap(EventTarget.prototype, 'addEventListener', {
      apply(target, self, args) {
        const [eventType, handler] = args;
        let source = '';
        if (typeof handler === 'function') {
          source = sourceOf(handler);
        } else if (handler && typeof handler.handleEvent === 'function') {
          source = sourceOf(handler.handleEvent);
        }
        if (test(typeRe, eventType) && test(needleRe, source)) {
          return undefined;
        }
        return ReflectApply(target, self, args);
      },
    });
  },

  'href-sanitizer'([selector, source]) {
    if (!selector) {
      return;
    }
    const from = source || 'text';
    domTask(selector, 'stay', (anchor) => {
      if (anchor.tagName !== 'A') {
        return;
      }
      let candidate = null;
      if (from === 'text') {
        candidate = trim(anchor.textContent);
      } else if (startsWith(from, '?')) {
        candidate = new URLCtor(anchor.href).searchParams.get(slice(from, 1));
      } else if (startsWith(from, '[') && from.endsWith(']')) {
        candidate = anchor.getAttribute(slice(from, 1, -1));
      }
      if (!candidate) {
        return;
      }
      const url = new URLCtor(candidate, win.location.href);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        if (anchor.getAttribute('href') !== url.href) {
          anchor.setAttribute('href', url.href);
        }
      }
    });
  },

  'set-local-storage-item'([key, raw]) {
    if (!key || !localStorageGetter) {
      return;
    }
    let storage;
    try {
      storage = call(localStorageGetter, win);
    } catch (e) {
      return;
    }
    const allowed = {
      undefined: 'undefined',
      false: 'false',
      true: 'true',
      null: 'null',
      emptyArr: '[]',
      emptyObj: '{}',
      '': '',
      "''": '',
      yes: 'yes',
      no: 'no',
      on: 'on',
      off: 'off',
    };
    try {
      if (raw === '$remove$') {
        const re = startsWith(key, '/') ? pattern(key) : null;
        if (re) {
          for (let i = storage.length - 1; i >= 0; i--) {
            const name = storage.key(i);
            if (test(re, name)) {
              storage.removeItem(name);
            }
          }
        } else {
          storage.removeItem(key);
        }
        return;
      }
      let value;
      if (has(allowed, raw)) {
        value = allowed[raw];
      } else if (test(/^\d+$/, raw) && NumberCtor(raw) <= 0x7fff) {
        value = raw;
      } else {
        return;
      }
      storage.setItem(key, value);
    } catch (e) {
      // Storage disabled or full.
    }
  },

  'remove-node-text'([nodeName, condition]) {
    if (!nodeName || !MutationObserverCtor) {
      return;
    }
    const nameRe = startsWith(nodeName, '/') ? pattern(nodeName) : new RegExpCtor(`^${pattern(lower(nodeName)).source}$`);
    const textRe = pattern(condition);
    const handle = (node) => {
      if (!test(nameRe, lower(node.nodeName))) {
        return;
      }
      if (test(textRe, node.textContent)) {
        node.textContent = '';
      }
    };
    const walk = (root) => {
      handle(root);
      for (let child = root.firstChild; child; child = child.nextSibling) {
        walk(child);
      }
    };
    if (doc.documentElement) {
      walk(doc.documentElement);
    }
    // Inline scripts reach observers before they run: the parser checks
    // microtasks before executing one.
    new MutationObserverCtor((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          walk(node);
        }
      }
    }).observe(doc, { childList: true, subtree: true });
  },

  'remove-cookie'([needle]) {
    if (!cookieDescriptor) {
      return;
    }
    const re = pattern(needle);
    const remove = () => {
      let cookies;
      try {
        cookies = call(cookieDescriptor.get, doc);
      } catch (e) {
        return;
      }
      for (const part of split(cookies, ';')) {
        const name = trim(split(part, '=')[0]);
        if (name === '' || !test(re, name)) {
          continue;
        }
        const gone = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
        const labels = split(win.location.hostname, '.');
        const variants = [gone, `${gone}; path=/`];
        for (let i = 0; i < labels.length - 1; i++) {
          variants.push(`${gone}; path=/; domain=.${join(labels.slice(i), '.')}`);
        }
        for (const v of variants) {
          call(cookieDescriptor.set, doc, v);
        }
      }
    };
    remove();
    call(addListener, win, 'beforeunload', remove, { capture: true });
    call(addListener, doc, 'visibilitychange', remove, { capture: true });
  },

  nowebrtc() {
    const noop = mask(() => {});
    const resolved = mask(() => PromiseResolve());
    for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection']) {
      const Native = win[name];
      if (typeof Native !== 'function') {
        continue;
      }
      const fake = new ProxyCtor(Native, {
        construct() {
          const pc = ObjectCreate(Native.prototype);
          const props = {
            close: noop,
            addEventListener: noop,
            removeEventListener: noop,
            dispatchEvent: mask(() => true),
            createDataChannel: mask(() => ({ close: noop, send: noop, addEventListener: noop })),
            createOffer: mask(() => PromiseResolve({ type: 'offer', sdp: '' })),
            createAnswer: mask(() => PromiseResolve({ type: 'answer', sdp: '' })),
            setLocalDescription: resolved,
            setRemoteDescription: resolved,
            addIceCandidate: resolved,
            getStats: mask(() => PromiseResolve(new Map())),
            getSenders: mask(() => []),
            getReceivers: mask(() => []),
            getTransceivers: mask(() => []),
            getConfiguration: mask(() => ({})),
            localDescription: null,
            remoteDescription: null,
            signalingState: 'closed',
            iceGatheringState: 'complete',
            iceConnectionState: 'closed',
            connectionState: 'closed',
          };
          for (const key of ObjectKeys(props)) {
            ObjectDefineProperty(pc, key, { configurable: true, writable: true, value: props[key] });
          }
          return pc;
        },
      });
      mask(fake, Native);
      const descriptor = ObjectGetOwnPropertyDescriptor(win, name);
      if (descriptor && (descriptor.writable || descriptor.configurable)) {
        descriptor.value = fake;
        ObjectDefineProperty(win, name, descriptor);
      }
    }
  },

  noeval() {
    wrap(win, 'eval', {
      apply() {
        return undefined;
      },
    });
  },
};

// ---- Which calls run here ------------------------------------------------

/**
 * `data`: `calls` ([name, dialect, ...args]), `hosts` (key → call indexes)
 * and `except` (key → call indexes, or "*" for every call). `keys`: the
 * page's host keys, from the prelude.
 */
function run(data, keys) {
  const picked = new SetCtor();
  const excepted = new SetCtor();
  for (const key of keys) {
    if (has(data.except, key)) {
      if (data.except[key] === '*') {
        return;
      }
      for (const id of data.except[key]) {
        excepted.add(id);
      }
    }
    if (has(data.hosts, key)) {
      for (const id of data.hosts[key]) {
        picked.add(id);
      }
    }
  }
  for (const id of picked) {
    if (excepted.has(id)) {
      continue;
    }
    const [name, dialect, ...args] = data.calls[id];
    if (!has(scriptlets, name)) {
      continue;
    }
    try {
      scriptlets[name](args, dialect);
    } catch (e) {
      // A scriptlet that fails must not stop the others.
    }
  }
}
