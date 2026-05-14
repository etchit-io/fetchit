import { colorRule, embedSubLanguage, type Token, type Tokenizer } from "./tokens";
import { css } from "./css";
import { jsts } from "./jsts";

const commentRe = /<!--[\s\S]*?-->/;
const stringRe = /"[^"]*"|'[^']*'/;
const tagRe = /<\/?[A-Za-z][\w-]*|>|\/>/;
const attrRe = /\b[A-Za-z-]+(?==)/;
// Capture only the body so the sub-language tokens cover the contents, not
// the surrounding tags themselves.
const styleBlockRe = /<style[^>]*>([\s\S]*?)<\/style>/i;
const scriptBlockRe = /<script[^>]*>([\s\S]*?)<\/script>/i;

export const html: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, attrRe, "literal");
  colorRule(out, text, tagRe, "keyword");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentRe, "comment");
  embedSubLanguage(out, text, styleBlockRe, css);
  embedSubLanguage(out, text, scriptBlockRe, jsts);
  return out;
};
