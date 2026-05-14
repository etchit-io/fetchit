import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "fun", "val", "var", "class", "object", "interface", "enum", "data", "sealed",
  "abstract", "open", "override", "private", "public", "protected", "internal",
  "inline", "suspend", "infix", "operator", "external", "tailrec", "reified",
  "companion", "init", "constructor",
  "return", "yield", "if", "else", "when", "is", "in", "for", "while", "do",
  "try", "catch", "finally", "throw", "break", "continue",
  "import", "package", "as", "this", "super", "by",
];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`);
const literalRe = /\b(true|false|null)\b/;
const commentLineRe = /\/\/.*$/m;
const commentBlockRe = /\/\*[\s\S]*?\*\//;
const tripleStringRe = /"""[\s\S]*?"""/;
const stringRe = /"(?:[^"\\\n]|\\.)*"/;
const annotationRe = /@\w+(?:\.\w+)*/;
const numberRe = /(?<![A-Za-z_])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[fFlL]?/;

export const kotlin: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, annotationRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, tripleStringRe, "string");
  colorRule(out, text, commentBlockRe, "comment");
  colorRule(out, text, commentLineRe, "comment");
  return out;
};
