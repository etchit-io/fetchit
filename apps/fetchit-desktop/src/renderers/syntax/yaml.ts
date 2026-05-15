import { colorRule, type Token, type Tokenizer } from "./tokens";

const commentRe = /#.*$/m;
const stringRe = /"[^"]*"|'[^']*'/;
const keyRe = /^\s*[\w-]+(?=\s*:)/m;
const listMarkerRe = /^\s*-(?=\s)/m;
const literalRe = /\b(true|false|null|yes|no|~)\b/;
const numberRe = /(?<![A-Za-z_])-?\d+(?:\.\d+)?\b/;

export const yaml: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, keyRe, "keyword");
  colorRule(out, text, listMarkerRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentRe, "comment");
  return out;
};
