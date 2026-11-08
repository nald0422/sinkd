// Fingerprint noise ("farbling", after Brave), in the page's main world at
// document_start, before any page script.
//
// Readback APIs that fingerprinters hash get a small, deterministic change:
// canvas pixels (toDataURL, toBlob, getImageData, OffscreenCanvas), WebGL
// readPixels, and audio samples. The change comes from a seed that is
// HMAC(per-session key, site), computed by the service worker: the same
// site sees the same values all session (nothing breaks, nothing looks
// random), another site or another session sees different ones, so the
// hashes can't link them. The WebGL renderer string and the CPU and memory
// figures are bucketed into a few common values instead. The user agent
// and platform are left alone.
//
// The seed arrives a few milliseconds after this script starts, from the
// isolated-world content script (which can ask the worker; this world
// can't). The handshake: this script sends a fresh random token in a DOM
// event that only the content script, listening since before any page
// script, receives; the seed comes back in an event that carries the token
// and that this script stops before any page listener sees it. Until then,
// readbacks are noised with a random per-load seed: stable afterwards,
// never the true values.
//
// Stealth rules as in the scriptlet library: built-ins are captured at load
// and called through Reflect.apply; replaced functions are Proxies of the
// originals and Function.prototype.toString reports the originals' source;
// descriptors keep their flags; errors thrown through a wrapper lose this
// script's frames; no globals, no DOM nodes.
//
// A script, not a module (content scripts can't import), hence the IIFE.

(() => {
  const HELLO = "dd5a2b-h";
  const READY = "dd5a2b-r";
  const SEED = "dd5a2b-s";

  // ---- built-ins, captured before page scripts can replace them --------
  const win = window;
  const ReflectApply = Reflect.apply;
  const ObjectDefineProperty = Object.defineProperty;
  const ObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const ObjectKeys = Object.keys;
  const ObjectCreate = Object.create;
  const ProxyCtor = Proxy;
  const WeakMapCtor = WeakMap;
  const WeakMapGet = WeakMap.prototype.get;
  const WeakMapSet = WeakMap.prototype.set;
  const WeakMapHas = WeakMap.prototype.has;
  const SetCtor = Set;
  const SetHas = Set.prototype.has;
  const SetAdd = Set.prototype.add;
  const ObjectIsPrototypeOf = Object.prototype.isPrototypeOf;
  const ObjectGetPrototypeOf = Object.getPrototypeOf;
  const MathImul = Math.imul;
  const nativeToString = Function.prototype.toString;
  const getRandomValues = Crypto.prototype.getRandomValues;
  const cryptoObject = win.crypto;
  const addListener = EventTarget.prototype.addEventListener;
  const removeListener = EventTarget.prototype.removeEventListener;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const stopImmediately = Event.prototype.stopImmediatePropagation;
  const CustomEventCtor = CustomEvent;
  const detailOf = getter(CustomEvent.prototype, "detail");
  const StringSlice = String.prototype.slice;
  const StringIndexOf = String.prototype.indexOf;
  const StringSplit = String.prototype.split;
  const ArrayFilter = Array.prototype.filter;
  const ArrayJoin = Array.prototype.join;
  const StringIncludes = String.prototype.includes;
  const NumberParseInt = Number.parseInt;
  const Uint32ArrayCtor = Uint32Array;
  const Uint8ArrayCtor = Uint8Array;
  const typedArrayProto = Object.getPrototypeOf(Uint8Array.prototype) as object;
  const typedLength = getter(typedArrayProto, "length");
  const subarray = (typedArrayProto as Uint8Array).subarray;
  const doc = document;
  const createElement = Document.prototype.createElement;
  const canvasProto = HTMLCanvasElement.prototype;
  const getContext = canvasProto.getContext;
  const canvasWidth = getter(canvasProto, "width");
  const canvasHeight = getter(canvasProto, "height");
  const setCanvasWidth = setter(canvasProto, "width");
  const setCanvasHeight = setter(canvasProto, "height");
  const ctx2d = CanvasRenderingContext2D.prototype;
  const getImageData = ctx2d.getImageData;
  const putImageData = ctx2d.putImageData;
  const drawImage = ctx2d.drawImage;
  const ctxCanvas = getter(ctx2d, "canvas");
  const imageDataData = getter(ImageData.prototype, "data");
  const imageDataWidth = getter(ImageData.prototype, "width");
  const imageDataHeight = getter(ImageData.prototype, "height");
  const OffscreenCanvasCtor = win.OffscreenCanvas;
  const offscreenProto = OffscreenCanvasCtor?.prototype;
  const offscreenGetContext = offscreenProto?.getContext;
  const offscreenWidth = offscreenProto && getter(offscreenProto, "width");
  const offscreenHeight = offscreenProto && getter(offscreenProto, "height");
  const offscreenCtx = win.OffscreenCanvasRenderingContext2D?.prototype;
  const offscreenCtxCanvas = offscreenCtx && getter(offscreenCtx, "canvas");
  // Prototype checks rather than instanceof, which a page can redirect
  // through Symbol.hasInstance.
  const isA = (value: unknown, proto: object | undefined): boolean =>
    proto !== undefined &&
    typeof value === "object" &&
    value !== null &&
    (call(ObjectIsPrototypeOf, proto, value) as boolean);

  function getter(proto: object, name: string): ((this: unknown) => unknown) | undefined {
    return ObjectGetOwnPropertyDescriptor(proto, name)?.get;
  }
  function setter(proto: object, name: string): ((this: unknown, v: unknown) => void) | undefined {
    return ObjectGetOwnPropertyDescriptor(proto, name)?.set;
  }
  const call = <T>(fn: ((...a: never[]) => T) | undefined, self: unknown, ...args: unknown[]): T =>
    ReflectApply(fn as (...a: unknown[]) => T, self, args);

  // ---- looking native --------------------------------------------------
  // Replacement → the function whose source it reports.
  const masks = new WeakMapCtor<object, object>();
  const shownFor = (self: unknown): unknown =>
    call(WeakMapHas, masks, self) ? call(WeakMapGet, masks, self) : self;
  let toStringPatched = false;

  function scrub(error: unknown): unknown {
    try {
      const e = error as { stack?: string };
      const lines = call(StringSplit, e.stack, "\n") as string[];
      e.stack = call(
        ArrayJoin,
        call(ArrayFilter, lines, (line: string) => !call(StringIncludes, line, "-extension://")),
        "\n",
      );
    } catch {
      // A frozen error, or not an error: thrown as it is.
    }
    return error;
  }

  function mask<T extends object>(replacement: T, original: object): T {
    call(WeakMapSet, masks, replacement, original);
    if (!toStringPatched) {
      toStringPatched = true;
      const patched = new ProxyCtor(nativeToString, {
        apply(target, self, args) {
          try {
            return ReflectApply(target, shownFor(self), args);
          } catch (error) {
            throw scrub(error);
          }
        },
      });
      call(WeakMapSet, masks, patched, nativeToString);
      const descriptor = ObjectGetOwnPropertyDescriptor(Function.prototype, "toString");
      if (descriptor) {
        descriptor.value = patched;
        ObjectDefineProperty(Function.prototype, "toString", descriptor);
      }
    }
    return replacement;
  }

  /** A Proxy of `original` with `handler`'s traps, errors scrubbed. */
  function proxy<T extends object>(original: T, handler: ProxyHandler<T>): T {
    const guarded = ObjectCreate(null) as ProxyHandler<T>;
    for (const trap of ObjectKeys(handler) as (keyof ProxyHandler<T>)[]) {
      const fn = handler[trap] as (...a: unknown[]) => unknown;
      (guarded as Record<string, unknown>)[trap] = (...args: unknown[]) => {
        try {
          return ReflectApply(fn, handler, args);
        } catch (error) {
          throw scrub(error);
        }
      };
    }
    return mask(new ProxyCtor(original, guarded), original);
  }

  /** Replaces the method `owner[name]`, keeping its descriptor. */
  function wrapMethod(
    owner: object | undefined,
    name: string,
    apply: (target: (...a: unknown[]) => unknown, self: unknown, args: unknown[]) => unknown,
  ): void {
    const descriptor = owner && ObjectGetOwnPropertyDescriptor(owner, name);
    if (!owner || !descriptor || typeof descriptor.value !== "function") {
      return;
    }
    descriptor.value = proxy(descriptor.value, { apply });
    ObjectDefineProperty(owner, name, descriptor);
  }

  /** Replaces the getter of `owner[name]`, keeping its descriptor. */
  function wrapGetter(owner: object, name: string, change: (value: unknown) => unknown): void {
    const descriptor = ObjectGetOwnPropertyDescriptor(owner, name);
    if (!descriptor?.get) {
      return;
    }
    descriptor.get = proxy(descriptor.get, {
      apply(target, self, args) {
        const value = ReflectApply(target, self, args);
        return off ? value : change(value);
      },
    });
    ObjectDefineProperty(owner, name, descriptor);
  }

  // ---- the seed ----------------------------------------------------------
  const randomWords = (n: number): Uint32Array => {
    const words = new Uint32ArrayCtor(n);
    call(getRandomValues, cryptoObject, words);
    return words;
  };
  // Until the worker's seed arrives: random, so never the true values.
  let key = randomWords(8);
  let off = false;

  const token = (() => {
    const bytes = new Uint8ArrayCtor(16);
    call(getRandomValues, cryptoObject, bytes);
    let hex = "";
    for (const b of bytes) hex += (b < 16 ? "0" : "") + b.toString(16);
    return hex;
  })();

  const onSeed = (event: Event): void => {
    const detail = call(detailOf, event);
    if (typeof detail !== "string" || call(StringIndexOf, detail, `${token}:`) !== 0) {
      // Not ours: leave it alone, so a page can't tell we listen.
      return;
    }
    call(stopImmediately, event);
    call(removeListener, win, SEED, onSeed, true);
    const value = call(StringSlice, detail, token.length + 1) as string;
    if (value === "off") {
      off = true;
      return;
    }
    const words = new Uint32ArrayCtor(8);
    for (let i = 0; i < 8; i++) {
      words[i] = NumberParseInt(call(StringSlice, value, i * 8, i * 8 + 8) as string, 16) >>> 0;
    }
    key = words;
  };
  call(addListener, win, SEED, onSeed, true);
  const hello = (): boolean => call(dispatch, win, new CustomEventCtor(HELLO, { detail: token }));
  // Whichever of this script and the content script runs second starts the
  // handshake; READY means the content script is listening now.
  let answered = false;
  call(
    addListener,
    win,
    READY,
    () => {
      if (!answered) {
        answered = true;
        hello();
      }
    },
    true,
  );
  hello();

  // ---- deterministic noise -----------------------------------------------
  /** A 32-bit hash of (position, purpose) under the key. */
  function noise(position: number, purpose: number): number {
    let h = (position ^ (key[purpose & 7] ?? 0)) >>> 0;
    h = MathImul(h ^ (h >>> 16), 0x85ebca6b);
    h = MathImul(h ^ (h >>> 13), 0xc2b2ae35);
    h ^= h >>> 16;
    h = MathImul(h ^ (key[(purpose + 3) & 7] ?? 0), 0x9e3779b1);
    return (h ^ (h >>> 15)) >>> 0;
  }

  const CANVAS = 1;
  const WEBGL = 2;
  const AUDIO = 4;

  /**
   * Noise in RGBA pixels: about one pixel in sixteen that is not fully
   * transparent gets the low bit of one channel set from the hash. Keyed
   * by the pixel's position in the whole canvas, so a part read on its own
   * matches the whole, and setting (not flipping) the bit means reading
   * twice, or reading what was written back, gives the same result. Blank
   * canvases stay blank.
   */
  function noisePixels(
    data: Uint8ClampedArray | Uint8Array,
    stride: number,
    x0: number,
    y0: number,
    width: number,
    height: number,
    purpose: number,
  ): void {
    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const i = (y * width + x) * 4;
        if (data[i + 3] === 0) continue;
        const h = noise((y0 + y) * stride + x0 + x, purpose);
        if ((h & 15) !== 0) continue;
        const channel = i + ((h >>> 4) % 3);
        data[channel] = ((data[channel] ?? 0) & 0xfe) | ((h >>> 8) & 1);
      }
    }
  }

  function noiseImageData(image: ImageData, stride: number, x0: number, y0: number): void {
    const data = call(imageDataData, image) as Uint8ClampedArray;
    noisePixels(
      data,
      stride,
      x0,
      y0,
      call(imageDataWidth, image) as number,
      call(imageDataHeight, image) as number,
      CANVAS,
    );
  }

  // ---- canvas ------------------------------------------------------------
  /** A noised copy of a canvas, to export instead of it; null if empty. */
  function noisedCopy(source: HTMLCanvasElement): HTMLCanvasElement | null {
    const width = call(canvasWidth, source) as number;
    const height = call(canvasHeight, source) as number;
    if (!width || !height) return null;
    const copy = call(createElement, doc, "canvas") as HTMLCanvasElement;
    call(setCanvasWidth, copy, width);
    call(setCanvasHeight, copy, height);
    const ctx = call(getContext, copy, "2d") as CanvasRenderingContext2D;
    call(drawImage, ctx, source, 0, 0);
    const image = call(getImageData, ctx, 0, 0, width, height) as ImageData;
    noiseImageData(image, width, 0, 0);
    call(putImageData, ctx, image, 0, 0);
    return copy;
  }

  for (const name of ["toDataURL", "toBlob"]) {
    wrapMethod(canvasProto, name, (target, self, args) => {
      if (off || !isA(self, canvasProto)) return ReflectApply(target, self, args);
      // A tainted canvas throws in getImageData; the original throws too.
      let copy: HTMLCanvasElement | null = null;
      try {
        copy = noisedCopy(self as HTMLCanvasElement);
      } catch {
        copy = null;
      }
      return ReflectApply(target, copy ?? self, args);
    });
  }

  /** Where a getImageData(sx, sy, sw, sh) read starts (sw, sh may be negative). */
  const readOrigin = (args: unknown[]): [number, number] => {
    const [sx = 0, sy = 0, sw = 0, sh = 0] = args as number[];
    return [sw < 0 ? sx + sw : sx, sh < 0 ? sy + sh : sy];
  };

  wrapMethod(ctx2d, "getImageData", (target, self, args) => {
    const image = ReflectApply(target, self, args) as ImageData;
    if (!off) {
      const canvas = call(ctxCanvas, self) as HTMLCanvasElement;
      const [x0, y0] = readOrigin(args);
      noiseImageData(image, call(canvasWidth, canvas) as number, x0 | 0, y0 | 0);
    }
    return image;
  });

  if (offscreenProto && OffscreenCanvasCtor && offscreenCtx) {
    const offGetImageData = offscreenCtx.getImageData;
    const offPutImageData = offscreenCtx.putImageData;
    const offDrawImage = offscreenCtx.drawImage;
    wrapMethod(offscreenCtx, "getImageData", (target, self, args) => {
      const image = ReflectApply(target, self, args) as ImageData;
      if (!off) {
        const canvas = call(offscreenCtxCanvas, self) as OffscreenCanvas;
        const [x0, y0] = readOrigin(args);
        noiseImageData(image, call(offscreenWidth, canvas) as number, x0 | 0, y0 | 0);
      }
      return image;
    });
    wrapMethod(offscreenProto, "convertToBlob", (target, self, args) => {
      if (off) return ReflectApply(target, self, args);
      let copy: OffscreenCanvas | null = null;
      try {
        const width = call(offscreenWidth, self) as number;
        const height = call(offscreenHeight, self) as number;
        if (width && height) {
          copy = new OffscreenCanvasCtor(width, height);
          const ctx = call(offscreenGetContext, copy, "2d") as OffscreenCanvasRenderingContext2D;
          call(offDrawImage, ctx, self, 0, 0);
          const image = call(offGetImageData, ctx, 0, 0, width, height) as ImageData;
          noiseImageData(image, width, 0, 0);
          call(offPutImageData, ctx, image, 0, 0);
        }
      } catch {
        copy = null;
      }
      return ReflectApply(target, copy ?? self, args);
    });
  }

  // ---- WebGL -------------------------------------------------------------
  const RGBA = 0x1908;
  const UNSIGNED_BYTE = 0x1401;
  const UNMASKED_RENDERER = 0x9246;

  /**
   * The renderer, bucketed: one common string per GPU maker and graphics
   * API, so the exact model no longer narrows down the machine. Software
   * renderers and anything unrecognized pass through.
   */
  function bucketRenderer(renderer: unknown): unknown {
    if (typeof renderer !== "string") return renderer;
    const has = (s: string) => call(StringIncludes, renderer, s) as boolean;
    // Firefox reports a coarse name already ("Apple M1, or similar"), in
    // its own format; a Chrome-style one would stand out there.
    if (has("SwiftShader") || has("llvmpipe") || has(", or similar")) return renderer;
    if (has("Apple")) return "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)";
    const d3d = has("Direct3D") || has("D3D11");
    if (has("NVIDIA")) {
      return d3d
        ? "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)"
        : "ANGLE (NVIDIA Corporation, NVIDIA GeForce GTX 1650/PCIe/SSE2, OpenGL 4.5.0)";
    }
    if (has("AMD") || has("Radeon")) {
      return d3d
        ? "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
        : "ANGLE (AMD, AMD Radeon Graphics (radeonsi), OpenGL 4.6)";
    }
    if (has("Intel")) {
      return d3d
        ? "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)"
        : "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)";
    }
    return renderer;
  }

  // WebGL is patched lazily: building the WebGL interfaces costs a page
  // about 1.4 ms, and most pages never use them. A WebGL context only
  // comes from getContext, so its prototype is patched there, before the
  // page gets the context; any left over are patched at the first idle
  // moment after load. (A script that copies readPixels off the prototype
  // before either can call the copy unnoised: see DESIGN.md.)
  const patchedWebgl = new WeakMapCtor<object, boolean>();
  function patchWebgl(proto: WebGLRenderingContext | undefined): void {
    if (!proto || call(WeakMapHas, patchedWebgl, proto)) return;
    if (!ObjectGetOwnPropertyDescriptor(proto, "readPixels")) return;
    call(WeakMapSet, patchedWebgl, proto, true);
    const bufferWidth = getter(proto, "drawingBufferWidth");
    wrapMethod(proto, "readPixels", (target, self, args) => {
      const result = ReflectApply(target, self, args);
      const [x, y, width, height, format, type, pixels, offset] = args as [
        number,
        number,
        number,
        number,
        number,
        number,
        unknown,
        number?,
      ];
      if (
        !off &&
        format === RGBA &&
        type === UNSIGNED_BYTE &&
        isA(pixels, Uint8ArrayCtor.prototype)
      ) {
        const view = pixels as Uint8Array;
        const start = (offset ?? 0) | 0;
        const data = start ? (call(subarray, view, start) as Uint8Array) : view;
        noisePixels(
          data,
          call(bufferWidth, self) as number,
          x | 0,
          y | 0,
          width | 0,
          height | 0,
          WEBGL,
        );
      }
      return result;
    });
    wrapMethod(proto, "getParameter", (target, self, args) => {
      const value = ReflectApply(target, self, args);
      return !off && args[0] === UNMASKED_RENDERER ? bucketRenderer(value) : value;
    });
  }
  const patchFromContext = (
    target: (...a: unknown[]) => unknown,
    self: unknown,
    args: unknown[],
  ) => {
    const context = ReflectApply(target, self, args);
    if (context !== null && typeof context === "object") {
      patchWebgl(ObjectGetPrototypeOf(context) as WebGLRenderingContext);
    }
    return context;
  };
  wrapMethod(canvasProto, "getContext", patchFromContext);
  wrapMethod(offscreenProto, "getContext", patchFromContext);
  const idle = win.requestIdleCallback ?? ((fn: () => void) => win.setTimeout(fn, 1));
  call(
    addListener,
    win,
    "load",
    () => {
      ReflectApply(idle, win, [
        () => {
          patchWebgl(win.WebGLRenderingContext?.prototype);
          patchWebgl(win.WebGL2RenderingContext?.prototype);
        },
        { timeout: 2000 },
      ]);
    },
    { once: true },
  );

  // ---- audio -------------------------------------------------------------
  // Each channel of a buffer is noised once, in place, so reading it again
  // (or copying it out) gives the same samples.
  const noised = new WeakMapCtor<object, Set<number>>();

  function noiseSamples(data: Float32Array, start: number, purpose: number): void {
    const length = call(typedLength, data) as number;
    for (let i = 0; i < length; i++) {
      const v = data[i] ?? 0;
      if (v === 0) continue;
      // Below -120 dB: inaudible, but enough to change a hash of samples.
      data[i] = v + ((noise(start + i, purpose) & 0xffff) / 0xffff - 0.5) * 2e-7;
    }
  }

  const audioProto = win.AudioBuffer?.prototype;
  if (audioProto) {
    const getChannelData = audioProto.getChannelData;
    const noiseChannel = (buffer: AudioBuffer, channel: number): void => {
      let done = call(WeakMapGet, noised, buffer) as Set<number> | undefined;
      if (!done) {
        done = new SetCtor();
        call(WeakMapSet, noised, buffer, done);
      }
      if (call(SetHas, done, channel)) return;
      call(SetAdd, done, channel);
      noiseSamples(call(getChannelData, buffer, channel) as Float32Array, 0, AUDIO + channel);
    };
    wrapMethod(audioProto, "getChannelData", (target, self, args) => {
      if (!off) noiseChannel(self as AudioBuffer, (args[0] as number) | 0);
      return ReflectApply(target, self, args);
    });
    wrapMethod(audioProto, "copyFromChannel", (target, self, args) => {
      if (!off) noiseChannel(self as AudioBuffer, (args[1] as number) | 0);
      return ReflectApply(target, self, args);
    });
  }
  const analyserProto = win.AnalyserNode?.prototype;
  const float32Proto = Float32Array.prototype;
  for (const name of ["getFloatFrequencyData", "getFloatTimeDomainData"]) {
    wrapMethod(analyserProto, name, (target, self, args) => {
      const result = ReflectApply(target, self, args);
      if (!off && isA(args[0], float32Proto)) noiseSamples(args[0] as Float32Array, 0, AUDIO + 7);
      return result;
    });
  }

  // ---- hardware figures ----------------------------------------------------
  // Bucketed to 2, 4 or 8: common values that say less about the machine.
  const bucket = (value: unknown): unknown =>
    typeof value === "number" && value > 0 ? (value >= 8 ? 8 : value >= 4 ? 4 : 2) : value;
  wrapGetter(Navigator.prototype, "hardwareConcurrency", bucket);
  wrapGetter(Navigator.prototype, "deviceMemory", bucket);
})();
