//! Heuristic language detection for plain-text content.
//!
//! Mirrors the Android-side `detectLanguageFromContent` etchit ships
//! in its `SyntaxHighlighters.kt`. Living here means CLI consumers,
//! WASM viewers, and any future renderer get the same auto-detection
//! without re-implementing — `Rendition::Text { language: ... }`
//! carries the answer across the FFI.
//!
//! Returns a stable language identifier matching what UI shells use
//! to pick a syntax highlighter (e.g. `"rust"`, `"python"`, `"json"`).
//! `None` means "no confident match — render plain".

use once_cell::sync::Lazy;
use regex::Regex;

static SHEBANG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^#!").unwrap());
static JSON_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#""[\w-]+"\s*:"#).unwrap());
static PYTHON_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(def |class |import |from |if __name__|@\w+)").unwrap());
static KOTLIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(fun |val |var |package |object |class \w+(\s*:|\s*\())").unwrap()
});
static JS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(import|export|const|let|var|function|class|interface|type|async function|require\()").unwrap()
});
static RUST_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(fn |use |mod |struct |enum |impl |pub |#!?\[)").unwrap());
static GO_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(package |import |func )").unwrap());
static SQL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH|BEGIN)\b").unwrap()
});
static CSS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^([.#]?[A-Za-z][\w-]*|::?[\w-]+|@\w+)[\w\s.,#:>-]*\{").unwrap()
});
static YAML_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?m)^[\w-]+:\s+\S").unwrap());

/// Best-guess language tag. `None` if nothing matches confidently.
pub fn detect(text: &str) -> Option<&'static str> {
    let sample = &text[..text.len().min(2000)];
    if sample.trim().is_empty() {
        return None;
    }
    let first_line = sample.lines().find(|l| !l.trim().is_empty())?.trim();
    let lower = first_line.to_lowercase();

    // Shebang
    if SHEBANG_RE.is_match(first_line) {
        return Some(if lower.contains("python") {
            "python"
        } else if lower.contains("node") || lower.contains("deno") {
            "javascript"
        } else {
            "bash"
        });
    }

    // JSON — whole-text shape
    let trimmed = text.trim();
    if (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'))
    {
        let head_500 = &trimmed[..trimmed.len().min(500)];
        if JSON_KEY_RE.is_match(head_500) {
            return Some("json");
        }
    }

    if PYTHON_RE.is_match(first_line) {
        return Some("python");
    }
    if KOTLIN_RE.is_match(first_line) {
        return Some("kotlin");
    }
    if JS_RE.is_match(first_line) {
        return Some("javascript");
    }
    if RUST_RE.is_match(first_line) {
        return Some("rust");
    }
    if GO_RE.is_match(first_line) {
        return Some("go");
    }
    if SQL_RE.is_match(first_line) {
        return Some("sql");
    }
    if CSS_RE.is_match(&sample[..sample.len().min(800)]) {
        return Some("css");
    }
    if YAML_RE.is_match(&sample[..sample.len().min(500)]) {
        return Some("yaml");
    }

    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn detects_rust_from_fn() {
        assert_eq!(detect("fn main() {}\n"), Some("rust"));
    }

    #[test]
    fn detects_rust_from_use() {
        assert_eq!(detect("use std::io;\nfn main() {}\n"), Some("rust"));
    }

    #[test]
    fn detects_python_from_def() {
        assert_eq!(detect("def foo():\n    pass\n"), Some("python"));
    }

    #[test]
    fn detects_kotlin_from_fun() {
        assert_eq!(detect("fun main() = println(\"hi\")\n"), Some("kotlin"));
    }

    #[test]
    fn detects_js_from_const() {
        assert_eq!(detect("const x = 42;\n"), Some("javascript"));
    }

    #[test]
    fn detects_go_from_func() {
        // `package main` alone matches Kotlin's regex first (it allows
        // `package ` too) — same precedence etchit uses. Go-specific
        // detection fires on the `func ` keyword.
        assert_eq!(detect("func main() {}\n"), Some("go"));
    }

    #[test]
    fn detects_sql_case_insensitive() {
        assert_eq!(detect("SELECT * FROM users;\n"), Some("sql"));
        assert_eq!(detect("select 1;\n"), Some("sql"));
    }

    #[test]
    fn detects_yaml() {
        assert_eq!(detect("name: fetchit\nversion: 0.1\n"), Some("yaml"));
    }

    #[test]
    fn detects_python_shebang() {
        assert_eq!(detect("#!/usr/bin/env python3\nprint('hi')\n"), Some("python"));
    }

    #[test]
    fn detects_bash_shebang() {
        assert_eq!(detect("#!/bin/bash\necho hi\n"), Some("bash"));
    }

    #[test]
    fn detects_node_shebang() {
        assert_eq!(detect("#!/usr/bin/env node\n"), Some("javascript"));
    }

    #[test]
    fn no_match_for_plain_prose() {
        assert_eq!(
            detect("Just some prose, nothing fancy here at all.\n"),
            None,
        );
    }

    #[test]
    fn no_match_for_empty() {
        assert_eq!(detect(""), None);
        assert_eq!(detect("   \n  \n"), None);
    }
}
