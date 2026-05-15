// Language detection — explicit tag first, then content-based heuristic.
// Ported from `apps/fetchit-android/.../syntax/LanguageDetector.kt`.

import type { Tokenizer } from "./tokens";
import { bash } from "./bash";
import { css } from "./css";
import { go } from "./go";
import { html } from "./html";
import { json } from "./json";
import { jsts } from "./jsts";
import { kotlin } from "./kotlin";
import { python } from "./python";
import { rust } from "./rust";
import { sql } from "./sql";
import { yaml } from "./yaml";

// Look up a tokenizer by an explicit language tag — typically from a
// rendition's `language` field. Aliases follow the Android map.
export function tokenizerByName(name: string | null | undefined): Tokenizer | null {
  if (!name) return null;
  switch (name.toLowerCase()) {
    case "":
    case "plain":
    case "text":
      return null;
    case "json":
    case "jsonc":
      return json;
    case "bash":
    case "sh":
    case "shell":
    case "zsh":
      return bash;
    case "python":
    case "py":
      return python;
    case "javascript":
    case "js":
    case "jsx":
    case "typescript":
    case "ts":
    case "tsx":
      return jsts;
    case "kotlin":
    case "kt":
    case "kts":
      return kotlin;
    case "rust":
    case "rs":
      return rust;
    case "go":
    case "golang":
      return go;
    case "html":
    case "xml":
    case "svg":
      return html;
    case "css":
    case "scss":
      return css;
    case "yaml":
    case "yml":
      return yaml;
    case "sql":
      return sql;
    default:
      return null;
  }
}

// Best-effort content-based detection — first-line heuristics + a couple
// of whole-buffer shape checks.
export function detectByContent(text: string): Tokenizer | null {
  const sample = text.slice(0, 2000);
  if (sample.trim().length === 0) return null;
  const firstLine = sample.split("\n").find((l) => l.trim().length > 0)?.trim() ?? "";
  const lower = firstLine.toLowerCase();

  if (firstLine.startsWith("#!")) {
    if (lower.includes("python")) return python;
    if (lower.includes("node") || lower.includes("deno")) return jsts;
    return bash;
  }

  if (lower.startsWith("<!doctype") || lower.startsWith("<html") || lower.startsWith("<?xml")) {
    return html;
  }

  const trimmed = text.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    if (/"[\w-]+"\s*:/.test(trimmed.slice(0, 500))) return json;
  }

  if (/^(def |class |import |from |if __name__|@\w+)/.test(firstLine)) return python;

  if (/^(fun |val |var |package |object |class \w+(\s*:|\s*\())/.test(firstLine)) {
    return kotlin;
  }

  if (/^(import|export|const|let|var|function|class|interface|type|async function|require\()/.test(firstLine)) {
    return jsts;
  }

  if (/^(fn |use |mod |struct |enum |impl |pub |#!?\[)/.test(firstLine)) return rust;
  if (/^(package |import |func )/.test(firstLine)) return go;

  if (/^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH|BEGIN)\b/i.test(firstLine)) {
    return sql;
  }

  if (/^([.#]?[A-Za-z][\w-]*|::?[\w-]+|@\w+)[\w\s.,#:>-]*\{/m.test(sample.slice(0, 800))) {
    return css;
  }

  if (/^[\w-]+:\s+\S/m.test(sample.slice(0, 500))) return yaml;

  return null;
}

// Single entry point: explicit name wins, then content. Returns null when
// nothing is a confident match — caller falls back to plain rendering.
export function chooseTokenizer(language: string | null | undefined, text: string): Tokenizer | null {
  return tokenizerByName(language) ?? detectByContent(text);
}
