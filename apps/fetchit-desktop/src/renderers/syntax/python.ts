import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "def", "class", "lambda", "return", "yield",
  "if", "elif", "else", "for", "while",
  "try", "except", "finally", "raise",
  "import", "from", "as", "with",
  "in", "not", "and", "or", "is",
  "pass", "break", "continue", "del", "global", "nonlocal",
  "assert", "async", "await",
];
const literals = ["None", "True", "False"];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`);
const literalRe = new RegExp(`\\b(${literals.join("|")})\\b`);
const commentRe = /#.*$/m;
const tripleStringRe = /(?:'''[\s\S]*?'''|"""[\s\S]*?""")/;
const stringRe =
  /[fFrRbB]{0,2}'(?:[^'\\\n]|\\.)*'|[fFrRbB]{0,2}"(?:[^"\\\n]|\\.)*"/;
const numberRe = /(?<![A-Za-z_])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/;
const decoratorRe = /^\s*@\w+(?:\.\w+)*/m;

export const python: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, decoratorRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, tripleStringRe, "string");
  colorRule(out, text, commentRe, "comment");
  return out;
};
