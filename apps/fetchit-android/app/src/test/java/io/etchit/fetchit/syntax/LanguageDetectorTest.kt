package io.etchit.fetchit.syntax

import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** Unit tests for the language-detection entry points in LanguageDetector.kt. */
class LanguageDetectorTest {

    @Test
    fun maps_explicit_language_tags_to_highlighters() {
        assertSame(JsonHighlighter, highlighterForLanguage("json"))
        assertSame(PythonHighlighter, highlighterForLanguage("py"))
        assertSame(JsTsHighlighter, highlighterForLanguage("typescript"))
        assertSame(KotlinHighlighter, highlighterForLanguage("kt"))
        assertSame(RustHighlighter, highlighterForLanguage("rust"))
        assertSame(GoHighlighter, highlighterForLanguage("golang"))
        assertSame(HtmlHighlighter, highlighterForLanguage("xml"))
        assertSame(CssHighlighter, highlighterForLanguage("scss"))
        assertSame(YamlHighlighter, highlighterForLanguage("yml"))
        assertSame(SqlHighlighter, highlighterForLanguage("sql"))
        assertSame(BashHighlighter, highlighterForLanguage("shell"))
    }

    @Test
    fun unknown_or_plain_tag_is_null() {
        assertNull(highlighterForLanguage(null))
        assertNull(highlighterForLanguage(""))
        assertNull(highlighterForLanguage("plain"))
        assertNull(highlighterForLanguage("text"))
        assertNull(highlighterForLanguage("brainfuck"))
    }

    @Test
    fun tag_match_is_case_insensitive() {
        assertSame(JsonHighlighter, highlighterForLanguage("JSON"))
        assertSame(RustHighlighter, highlighterForLanguage("Rust"))
    }

    @Test
    fun detects_shebang_lines() {
        assertSame(PythonHighlighter, detectLanguageFromContent("#!/usr/bin/python3\nprint(1)"))
        assertSame(JsTsHighlighter, detectLanguageFromContent("#!/usr/bin/env node\nx()"))
        assertSame(BashHighlighter, detectLanguageFromContent("#!/bin/bash\necho hi"))
    }

    @Test
    fun detects_html_and_json_by_shape() {
        assertSame(HtmlHighlighter, detectLanguageFromContent("<!DOCTYPE html>\n<html></html>"))
        assertSame(JsonHighlighter, detectLanguageFromContent("""{"key": "value"}"""))
    }

    @Test
    fun detects_languages_by_first_line() {
        assertSame(PythonHighlighter, detectLanguageFromContent("def main():\n    pass"))
        assertSame(KotlinHighlighter, detectLanguageFromContent("fun main() {}"))
        assertSame(RustHighlighter, detectLanguageFromContent("fn main() {}"))
        assertSame(GoHighlighter, detectLanguageFromContent("func main() {}"))
        assertSame(SqlHighlighter, detectLanguageFromContent("SELECT * FROM users"))
    }

    @Test
    fun returns_null_when_nothing_matches() {
        assertNull(detectLanguageFromContent(""))
        assertNull(detectLanguageFromContent("   \n   \n"))
        assertNull(detectLanguageFromContent("just some ordinary english prose"))
    }

    @Test
    fun explicit_tag_wins_over_content_detection() {
        // Body looks like Python; the explicit tag must take precedence.
        assertSame(JsonHighlighter, highlighterFor("json", "def f():\n    pass"))
    }

    @Test
    fun content_detection_runs_when_no_tag_given() {
        assertSame(PythonHighlighter, highlighterFor(null, "def f():\n    pass"))
    }
}
