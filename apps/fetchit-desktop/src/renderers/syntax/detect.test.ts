import { describe, expect, it } from "vitest";
import { tokenizerByName, detectByContent, chooseTokenizer } from "./detect";
import { rust } from "./rust";
import { python } from "./python";
import { jsts } from "./jsts";
import { json } from "./json";
import { bash } from "./bash";
import { go } from "./go";
import { sql } from "./sql";
import { yaml } from "./yaml";
import { html } from "./html";
import { kotlin } from "./kotlin";
import { css } from "./css";

describe("tokenizerByName", () => {
  it.each([
    ["rust", rust], ["rs", rust],
    ["python", python], ["py", python],
    ["javascript", jsts], ["js", jsts], ["typescript", jsts], ["ts", jsts],
    ["json", json], ["jsonc", json],
    ["bash", bash], ["sh", bash], ["zsh", bash],
    ["go", go], ["golang", go],
    ["sql", sql],
    ["yaml", yaml], ["yml", yaml],
    ["html", html], ["xml", html], ["svg", html],
    ["kotlin", kotlin], ["kt", kotlin],
    ["css", css], ["scss", css],
  ])("maps %s to its tokenizer", (name, expected) => {
    expect(tokenizerByName(name)).toBe(expected);
  });

  it("normalises case", () => {
    expect(tokenizerByName("RUST")).toBe(rust);
  });

  it("returns null for plain/text/empty/null/unknown", () => {
    expect(tokenizerByName(null)).toBeNull();
    expect(tokenizerByName(undefined)).toBeNull();
    expect(tokenizerByName("")).toBeNull();
    expect(tokenizerByName("plain")).toBeNull();
    expect(tokenizerByName("text")).toBeNull();
    expect(tokenizerByName("brainfuck")).toBeNull();
  });
});

describe("detectByContent", () => {
  it.each([
    ["#!/usr/bin/env python3\nprint('x')", python],
    ["#!/usr/bin/env node\nconsole.log(1)", jsts],
    ["#!/bin/bash\necho hi", bash],
    ["<!doctype html><html></html>", html],
    ['{"name": "fetchit"}', json],
    ["def foo():\n    pass", python],
    ["fun main() = println(\"hi\")", kotlin],
    ["const x = 42;", jsts],
    ["fn main() {}", rust],
    ["func main() {}", go],
    ["SELECT * FROM users;", sql],
    ["select 1;", sql],
    ["name: fetchit\nversion: 0.1", yaml],
  ])("detects %s", (sample, expected) => {
    expect(detectByContent(sample)).toBe(expected);
  });

  it("detects CSS by rule-block shape", () => {
    expect(detectByContent(".foo { color: red; }")).toBe(css);
  });

  it("returns null on blank input", () => {
    expect(detectByContent("")).toBeNull();
    expect(detectByContent("   \n\n  ")).toBeNull();
  });

  it("returns null when nothing matches confidently", () => {
    expect(detectByContent("just some plain prose, nothing structured here at all.")).toBeNull();
  });
});

describe("chooseTokenizer", () => {
  it("prefers an explicit name over content detection", () => {
    // Content looks like Rust, but explicit `python` overrides.
    expect(chooseTokenizer("python", "fn main() {}")).toBe(python);
  });

  it("falls back to content detection when name is null/unknown", () => {
    expect(chooseTokenizer(null, "fn main() {}")).toBe(rust);
    expect(chooseTokenizer("brainfuck", "fn main() {}")).toBe(rust);
  });

  it("returns null when both fail", () => {
    expect(chooseTokenizer(null, "")).toBeNull();
  });
});
