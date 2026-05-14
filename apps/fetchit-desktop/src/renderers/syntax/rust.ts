import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "fn", "let", "mut", "const", "static", "struct", "enum", "impl", "trait",
  "use", "mod", "pub", "crate", "self", "Self",
  "return", "if", "else", "match", "for", "while", "loop", "break", "continue",
  "in", "where", "as", "ref", "move", "async", "await", "dyn", "unsafe", "extern",
  "type", "union",
];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`);
const literalRe = /\b(true|false|None|Some|Ok|Err)\b/;
const commentLineRe = /\/\/.*$/m;
const commentBlockRe = /\/\*[\s\S]*?\*\//;
const stringRe = /"(?:[^"\\]|\\.)*"/;
const attributeRe = /#!?\[[^\]]*\]/m;
const numberRe =
  /(?<![A-Za-z_])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?:[ui](?:8|16|32|64|128|size)|[fF](?:32|64))?/;

export const rust: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, attributeRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentBlockRe, "comment");
  colorRule(out, text, commentLineRe, "comment");
  return out;
};
