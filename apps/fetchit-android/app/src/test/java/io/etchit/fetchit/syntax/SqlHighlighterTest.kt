package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [SqlHighlighter.tokenize]. */
class SqlHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return SqlHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_strings_numbers_and_comments() {
        val code = "SELECT name FROM users WHERE age = 30 -- adults\nAND tag = 'vip'"
        assertTrue("keyword SELECT", colored(code, "SELECT", SyntaxColors.KEYWORD))
        assertTrue("keyword FROM", colored(code, "FROM", SyntaxColors.KEYWORD))
        assertTrue("keyword WHERE", colored(code, "WHERE", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "30", SyntaxColors.NUMBER))
        assertTrue("line comment", colored(code, "-- adults", SyntaxColors.COMMENT))
        assertTrue("string", colored(code, "'vip'", SyntaxColors.STRING))
    }

    @Test
    fun keywords_are_case_insensitive() {
        val code = "select * from t /* note */ where x is null"
        assertTrue("lowercase keyword", colored(code, "select", SyntaxColors.KEYWORD))
        assertTrue("block comment", colored(code, "/* note */", SyntaxColors.COMMENT))
        assertTrue("literal null", colored(code, "null", SyntaxColors.LITERAL))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(SqlHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        SqlHighlighter.tokenize("'".repeat(4000))
        SqlHighlighter.tokenize("{".repeat(4000))
        SqlHighlighter.tokenize("\\".repeat(4000))
        SqlHighlighter.tokenize("'unterminated string")
    }
}
