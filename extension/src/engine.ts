// The page engine: cosmetic lookups by hostname, answered by the Rust
// index (crates/core/src/page.rs) compiled to wasm32
// (crates/engine-wasm). This file only moves bytes across the boundary;
// the matching is all in Rust.
//
// The module has no imports. Its five exports: input(len) reserves room
// for input and returns its address; load() reads the index from the
// input; page(mask) and generic(mask, always) answer for the input and
// return the answer's length; output() returns the answer's address.

/** What a page gets: CSS for insertCSS, procedural rules for the content script. */
export interface PageAnswer {
  css: string;
  /** Procedural rules as the compiler wrote them (selector + action). */
  procedural: unknown[];
  /** Whether generic hiding applies (no $generichide / $elemhide). */
  generic: boolean;
}

interface Exports {
  memory: WebAssembly.Memory;
  input(len: number): number;
  output(): number;
  load(): number;
  page(mask: number): number;
  generic(mask: number, always: number): number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class Engine {
  private constructor(private readonly exports: Exports) {}

  /** Instantiates the module and loads an index. Throws if either is bad. */
  static async load(wasm: BufferSource, index: Uint8Array): Promise<Engine> {
    const { instance } = await WebAssembly.instantiate(wasm, {});
    const engine = new Engine(instance.exports as unknown as Exports);
    engine.write(index);
    if (engine.exports.load() !== 1) {
      throw new Error("page index is not readable");
    }
    return engine;
  }

  /** CSS and procedural rules for a hostname, for the rulesets in `mask`. */
  page(hostname: string, mask: number): PageAnswer {
    this.write(encoder.encode(hostname));
    const answer = JSON.parse(this.read(this.exports.page(mask))) as PageAnswer;
    return answer;
  }

  /**
   * Generic hiding CSS for the class and id tokens (`.ad`, `#banner`) seen
   * on a page. `always`: also the generic rules no token can select by.
   */
  generic(hostname: string, mask: number, tokens: string[], always: boolean): string {
    this.write(encoder.encode([hostname, ...tokens].join("\n")));
    return this.read(this.exports.generic(mask, always ? 1 : 0));
  }

  private write(bytes: Uint8Array): void {
    const at = this.exports.input(bytes.length);
    // Views go stale when memory grows, so take a new one each time.
    new Uint8Array(this.exports.memory.buffer, at, bytes.length).set(bytes);
  }

  private read(length: number): string {
    const at = this.exports.output();
    return decoder.decode(new Uint8Array(this.exports.memory.buffer, at, length));
  }
}
