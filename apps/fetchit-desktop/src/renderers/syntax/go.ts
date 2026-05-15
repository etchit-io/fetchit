import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "func", "var", "const", "type", "struct", "interface", "map", "chan",
  "range", "return", "if", "else", "for", "switch", "case", "default", "select",
  "break", "continue", "fallthrough", "goto", "defer", "go", "package", "import",
];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`);
const literalRe = /\b(true|false|nil|iota)\b/;
const commentLineRe = /\/\/.*$/m;
const commentBlockRe = /\/\*[\s\S]*?\*\//;
const stringRe = /"(?:[^"\\]|\\.)*"|`[^`]*`/;
const numberRe = /(?<![A-Za-z_])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/;

export const go: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentBlockRe, "comment");
  colorRule(out, text, commentLineRe, "comment");
  return out;
};
