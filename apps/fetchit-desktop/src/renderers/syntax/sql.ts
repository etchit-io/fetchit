import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "select", "from", "where", "insert", "into", "values", "update", "set", "delete",
  "create", "table", "index", "view", "drop", "alter",
  "join", "left", "right", "inner", "outer", "cross", "on",
  "and", "or", "not", "in", "is", "null", "like", "between", "exists",
  "order", "by", "group", "having", "limit", "offset", "distinct",
  "case", "when", "then", "else", "end", "as",
  "union", "all", "intersect", "except",
  "primary", "key", "foreign", "references", "default", "unique", "check", "constraint",
  "begin", "commit", "rollback", "transaction",
];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`, "i");
const literalRe = /\b(true|false|null)\b/i;
const commentLineRe = /--.*$/m;
const commentBlockRe = /\/\*[\s\S]*?\*\//;
const stringRe = /'(?:[^'\\]|\\.)*'/;
const numberRe = /(?<![A-Za-z_])\d+(?:\.\d+)?\b/;

export const sql: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentBlockRe, "comment");
  colorRule(out, text, commentLineRe, "comment");
  return out;
};
