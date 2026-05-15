import { colorRule, type Token, type Tokenizer } from "./tokens";

const stringRe = /"(?:[^"\\]|\\.)*"/;
const keyRe = /("(?:[^"\\]|\\.)*")\s*:/;
const numberRe = /(?<![A-Za-z_])-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/;
const literalRe = /\b(true|false|null)\b/;

export const json: Tokenizer = (text) => {
  const out: Token[] = [];
  colorRule(out, text, numberRe, "number");
  colorRule(out, text, literalRe, "literal");
  colorRule(out, text, stringRe, "string");

  // Keys (string + ":") need to override the generic string color; iterate
  // with capture-group indices so we only re-color the key, not the colon.
  const keyG = new RegExp(keyRe.source, "gd");
  let m: RegExpExecArray | null;
  while ((m = keyG.exec(text)) !== null) {
    if (m[0].length === 0) {
      keyG.lastIndex++;
      continue;
    }
    const indices = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices;
    const k = indices?.[1];
    if (!k) continue;
    out.push({ start: k[0], end: k[1], color: "keyword" });
  }
  return out;
};
