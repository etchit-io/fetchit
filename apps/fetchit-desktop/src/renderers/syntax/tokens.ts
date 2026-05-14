// Regex-based syntax-highlighting framework. Ported from
// `apps/fetchit-android/.../syntax/Syntax.kt` — same palette, same per-language
// regex passes, same later-wins priority. Each language is a tiny token
// emitter; this module owns the registry-agnostic plumbing.

export type TokenColor = "keyword" | "literal" | "string" | "number" | "comment";

export interface Token {
  start: number;
  end: number;
  color: TokenColor;
}

export type Tokenizer = (text: string) => Token[];

// Push one token per match of `pattern` into `out`. Clones the regex with the
// `g` flag so iteration is stateful regardless of how the caller declared it.
export function colorRule(
  out: Token[],
  text: string,
  pattern: RegExp,
  color: TokenColor,
): void {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const re = new RegExp(pattern.source, flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    out.push({ start: m.index, end: m.index + m[0].length, color });
  }
}

// Apply tokens to `host` by appending text nodes for uncolored runs and
// `<span class="tok-...">` for colored runs. Resolves overlap by later-wins
// (mirrors the Android applyTokens priority — token list order).
// No innerHTML: spans get textContent, so untrusted source bytes can never
// escape into markup.
export function applyTokensInto(host: HTMLElement, text: string, tokens: Token[]): void {
  if (text.length === 0) return;
  if (tokens.length === 0) {
    host.appendChild(document.createTextNode(text));
    return;
  }
  const colors: (TokenColor | null)[] = new Array(text.length).fill(null);
  for (const t of tokens) {
    const start = Math.max(0, t.start);
    const end = Math.min(t.end, text.length);
    for (let i = start; i < end; i++) colors[i] = t.color;
  }
  const frag = document.createDocumentFragment();
  let i = 0;
  while (i < text.length) {
    const c = colors[i];
    let j = i + 1;
    while (j < text.length && colors[j] === c) j++;
    const slice = text.slice(i, j);
    if (c === null) {
      frag.appendChild(document.createTextNode(slice));
    } else {
      const span = document.createElement("span");
      span.className = `tok-${c}`;
      span.textContent = slice;
      frag.appendChild(span);
    }
    i = j;
  }
  host.appendChild(frag);
}

// For HTML's `<style>...</style>` and `<script>...</script>` blocks: tokenize
// the body with a different language and merge those tokens back into the
// outer pass, after dropping any outer tokens that fall entirely inside the
// body. Uses the `d` flag so capture-group indices come back in `m.indices`.
export function embedSubLanguage(
  out: Token[],
  text: string,
  outerPattern: RegExp,
  inner: Tokenizer,
): void {
  let flags = outerPattern.flags;
  if (!flags.includes("g")) flags += "g";
  if (!flags.includes("d")) flags += "d";
  const re = new RegExp(outerPattern.source, flags);
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    const indices = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices;
    const bodyRange = indices?.[1];
    if (!bodyRange) continue;
    const [bodyStart, bodyEnd] = bodyRange;
    for (let i = out.length - 1; i >= 0; i--) {
      if (out[i].start >= bodyStart && out[i].end <= bodyEnd) out.splice(i, 1);
    }
    const body = text.slice(bodyStart, bodyEnd);
    for (const t of inner(body)) {
      out.push({ start: t.start + bodyStart, end: t.end + bodyStart, color: t.color });
    }
  }
}
