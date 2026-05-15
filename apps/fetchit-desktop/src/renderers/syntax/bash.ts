import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "if", "then", "else", "elif", "fi",
  "for", "while", "until", "do", "done",
  "function", "case", "esac", "in", "select",
  "return", "exit", "break", "continue",
  "set", "unset", "export", "local", "readonly", "declare", "typeset",
  "alias", "unalias", "trap", "shift", "source",
];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`);
const commentRe = /#.*$/m;
const dqStringRe = /"(?:[^"\\]|\\.)*"/;
const sqStringRe = /'[^'\n]*'/;
const varRe = /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/;
const numberRe = /(?<![A-Za-z_])\d+\b/;

export const bash: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, varRe, "literal");
  colorRule(out, text, dqStringRe, "string");
  colorRule(out, text, sqStringRe, "string");
  colorRule(out, text, commentRe, "comment");
  return out;
};
