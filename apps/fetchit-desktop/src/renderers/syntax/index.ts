// Public API for the syntax module: highlight a text body into a host element.
// If no language can be chosen (explicit tag or content heuristic), the host
// receives a plain text node — same shape as plain rendering, so callers can
// always use this entry point.

import { applyTokensInto } from "./tokens";
import { chooseTokenizer } from "./detect";

export { tokenizerByName, detectByContent, chooseTokenizer } from "./detect";
export type { Tokenizer, Token, TokenColor } from "./tokens";

export function highlightInto(
  host: HTMLElement,
  text: string,
  language: string | null | undefined,
): void {
  const tokenizer = chooseTokenizer(language, text);
  if (!tokenizer) {
    host.appendChild(document.createTextNode(text));
    return;
  }
  applyTokensInto(host, text, tokenizer(text));
}
