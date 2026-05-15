import { colorRule, type Token, type Tokenizer } from "./tokens";

const keywords = [
  "var", "let", "const", "function", "class", "extends", "new", "this", "super",
  "return", "yield", "async", "await",
  "if", "else", "for", "while", "do", "switch", "case", "default",
  "break", "continue", "try", "catch", "finally", "throw",
  "typeof", "instanceof", "in", "of",
  "import", "from", "export", "as",
  "interface", "type", "enum", "implements",
  "public", "private", "protected", "static", "readonly", "abstract",
  "namespace", "declare", "module",
];

const builtins = [
  "document", "window", "globalThis", "self", "console", "navigator", "location",
  "history", "screen", "alert", "confirm", "prompt",
  "fetch", "Request", "Response", "Headers", "URL", "URLSearchParams",
  "setTimeout", "setInterval", "clearTimeout", "clearInterval",
  "requestAnimationFrame", "cancelAnimationFrame",
  "Math", "JSON", "Date", "Promise", "Symbol",
  "Array", "Object", "Number", "String", "Boolean", "BigInt",
  "Map", "Set", "WeakMap", "WeakSet",
  "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError",
  "RegExp", "Function", "Reflect", "Proxy",
  "Uint8Array", "Int8Array", "Uint16Array", "Int16Array",
  "Uint32Array", "Int32Array", "Float32Array", "Float64Array",
  "ArrayBuffer", "DataView",
];

const keywordRe = new RegExp(`\\b(${keywords.join("|")})\\b`);
const builtinRe = new RegExp(`\\b(${builtins.join("|")})\\b`);
const literalRe = /\b(true|false|null|undefined|NaN|Infinity)\b/;
const commentLineRe = /\/\/.*$/m;
const commentBlockRe = /\/\*[\s\S]*?\*\//;
const stringRe =
  /"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`/;
const numberRe = /(?<![A-Za-z_])\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/;

export const jsts: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, builtinRe, "literal");
  colorRule(out, text, keywordRe, "keyword");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, stringRe, "string");
  colorRule(out, text, commentBlockRe, "comment");
  colorRule(out, text, commentLineRe, "comment");
  return out;
};
