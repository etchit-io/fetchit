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

// The static regex initialisers below `.unwrap()` on `Regex::new` against
// compile-time-known literal patterns. A failure here is a developer error
// caught the first time anything in the module is touched, not a runtime
// concern. Allowing the lint at module scope avoids decorating every static.
#![allow(clippy::unwrap_used)]

use regex::Regex;
use std::sync::LazyLock;

static SHEBANG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^#!").unwrap());
static JSON_KEY_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""[\w-]+"\s*:"#).unwrap());
static PYTHON_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(def |class |import |from |if __name__|@\w+)").unwrap());
static KOTLIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(fun |val |var |package |object |class \w+(\s*:|\s*\())").unwrap()
});
static JS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(import|export|const|let|var|function|class|interface|type|async function|require\()",
    )
    .unwrap()
});
static RUST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(fn |use |mod |struct |enum |impl |pub |#!?\[)").unwrap());
static GO_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(package |import |func )").unwrap());
static SQL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WITH|BEGIN)\b").unwrap()
});
static CSS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^([.#]?[A-Za-z][\w-]*|::?[\w-]+|@\w+)[\w\s.,#:>-]*\{").unwrap()
});
static YAML_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^[\w-]+:\s+\S").unwrap());

/// A byte prefix of `s` no longer than `max` bytes, clamped DOWN to the
/// nearest UTF-8 char boundary so the result is always a valid `&str`.
///
/// `str` indexing panics when the index is not on a char boundary; these
/// detection slices cap by byte length, so a multibyte character
/// straddling the cap would otherwise crash on perfectly valid UTF-8.
/// `floor_char_boundary` is still unstable, so this does the walk-back
/// by hand. For ASCII (the common code-detection case) `max` is already
/// a boundary and this returns the same slice as a raw index.
fn prefix_on_boundary(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Best-guess language tag. `None` if nothing matches confidently.
pub fn detect(text: &str) -> Option<&'static str> {
    let sample = prefix_on_boundary(text, 2000);
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
        let head_500 = prefix_on_boundary(trimmed, 500);
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
    if CSS_RE.is_match(prefix_on_boundary(sample, 800)) {
        return Some("css");
    }
    if YAML_RE.is_match(prefix_on_boundary(sample, 500)) {
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
        assert_eq!(
            detect("#!/usr/bin/env python3\nprint('hi')\n"),
            Some("python")
        );
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

    #[test]
    fn prefix_on_boundary_clamps_inside_multibyte_char() {
        // 'é' is 2 bytes (0xC3 0xA9). Capping at byte 1 lands inside it;
        // the prefix must clamp back to byte 0, never panic.
        let s = "é";
        assert_eq!(s.len(), 2);
        assert_eq!(prefix_on_boundary(s, 1), "");
        assert_eq!(prefix_on_boundary(s, 2), "é");
    }

    #[test]
    fn prefix_on_boundary_is_exact_for_ascii() {
        assert_eq!(prefix_on_boundary("abcdef", 3), "abc");
        assert_eq!(prefix_on_boundary("abc", 10), "abc");
        assert_eq!(prefix_on_boundary("", 5), "");
    }

    #[test]
    fn detect_does_not_panic_on_multibyte_straddling_cap() {
        // Regression: detect() sliced `text[..min(2000)]` by raw byte
        // index, which panicked when a multibyte char straddled byte
        // 2000. Build exactly that: 1999 ASCII bytes + a 2-byte char
        // spanning bytes 1999..2001. Must return cleanly, not panic.
        let mut s = "a".repeat(1999);
        s.push('é');
        s.push_str("tail");
        assert!(s.len() > 2000);
        // 'a'*1999 is plain prose -> no language match, but the call
        // itself must not crash.
        let _ = detect(&s);
    }
}
