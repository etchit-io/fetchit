// Safe inline-markdown for chat message bodies. Parses a tiny subset --
// bold, italic, inline code, strikethrough -- and appends the result as
// DOM text and element nodes. It never builds HTML from the input string
// (no innerHTML), so any HTML in an untrusted body stays inert literal
// text. Block constructs, links and images are out of scope; links are
// handled by the bubble's own URL tokenizer.

// One pass, ordered by precedence so a code span wins over emphasis and
// `**` wins over `*`. Each span's inner class excludes its own delimiter
// and newlines, so a span never crosses a line or nests.
const INLINE_RE
  = /`([^`\n]+)`|\*\*([^*\n]+)\*\*|~~([^~\n]+)~~|\*([^*\n]+)\*|_([^_\n]+)_/g;

/// Parse the safe inline-markdown subset in `text` and append the
/// resulting text + `<strong>`/`<em>`/`<code>`/`<del>` nodes to `parent`.
/// Drop-in replacement for `parent.appendChild(createTextNode(text))`.
export function appendInlineMarkdown(parent: Node, text: string): void {
  let cursor = 0;
  for (const m of text.matchAll(INLINE_RE)) {
    const start = m.index ?? 0;
    if (start > cursor) {
      parent.appendChild(document.createTextNode(text.slice(cursor, start)));
    }
    parent.appendChild(spanFor(m));
    cursor = start + m[0].length;
  }
  if (cursor < text.length) {
    parent.appendChild(document.createTextNode(text.slice(cursor)));
  }
}

function spanFor(m: RegExpMatchArray): HTMLElement {
  let tag: "code" | "strong" | "del" | "em";
  let inner: string;
  if (m[1] !== undefined) {
    tag = "code";
    inner = m[1];
  } else if (m[2] !== undefined) {
    tag = "strong";
    inner = m[2];
  } else if (m[3] !== undefined) {
    tag = "del";
    inner = m[3];
  } else {
    tag = "em";
    inner = m[4] ?? m[5] ?? "";
  }
  const el = document.createElement(tag);
  el.textContent = inner;
  return el;
}
