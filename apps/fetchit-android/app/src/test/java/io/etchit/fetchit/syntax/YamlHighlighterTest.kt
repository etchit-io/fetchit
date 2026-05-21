package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [YamlHighlighter.tokenize]. */
class YamlHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return YamlHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keys_literals_numbers_strings_and_comments() {
        val code = "name: bob # person\nage: 42\nactive: true\nlabel: \"vip\""
        assertTrue("key name", colored(code, "name", SyntaxColors.KEYWORD))
        assertTrue("key age", colored(code, "age", SyntaxColors.KEYWORD))
        assertTrue("comment", colored(code, "# person", SyntaxColors.COMMENT))
        assertTrue("number", colored(code, "42", SyntaxColors.NUMBER))
        assertTrue("literal true", colored(code, "true", SyntaxColors.LITERAL))
        assertTrue("string", colored(code, "\"vip\"", SyntaxColors.STRING))
    }

    @Test
    fun colors_list_marker_and_negative_number() {
        // listMarkerRe is `^\s*-(?=\s)` — leading indent is part of the match,
        // so a column-0 marker yields a token covering exactly "-".
        val code = "- item\nnudge: -7\n"
        assertTrue("list marker", colored(code, "-", SyntaxColors.LITERAL))
        assertTrue("negative number", colored(code, "-7", SyntaxColors.NUMBER))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(YamlHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        YamlHighlighter.tokenize("\"".repeat(4000))
        YamlHighlighter.tokenize("{".repeat(4000))
        YamlHighlighter.tokenize("\\".repeat(4000))
        YamlHighlighter.tokenize("\"unterminated string")
    }
}
