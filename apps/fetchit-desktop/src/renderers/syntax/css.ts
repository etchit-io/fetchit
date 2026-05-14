import { colorRule, type Token, type Tokenizer } from "./tokens";

const commentRe = /\/\*[\s\S]*?\*\//;
const stringRe = /"[^"]*"|'[^']*'/;
const propertyRe = /[a-z-]+(?=\s*:)/;
const hexColorRe = /#[0-9a-fA-F]{3,8}\b/;
const numberRe = /(?<![A-Za-z_])-?\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|s|ms|deg|fr)?/;
const atRuleRe = /@[a-z-]+/;

export const css: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, hexColorRe, "literal");
  colorRule(out, text, propertyRe, "literal");
  colorRule(out, text, atRuleRe, "keyword");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentRe, "comment");
  return out;
};
