package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [JsonHighlighter.tokenize]. */
class JsonHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return JsonHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keys_numbers_literals_and_strings() {
        val code = """{"name": "bob", "age": 42, "active": true, "note": null}"""
        assertTrue("key", colored(code, "\"name\"", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "42", SyntaxColors.NUMBER))
        assertTrue("literal true", colored(code, "true", SyntaxColors.LITERAL))
        assertTrue("literal null", colored(code, "null", SyntaxColors.LITERAL))
        assertTrue("value string", colored(code, "\"bob\"", SyntaxColors.STRING))
    }

    @Test
    fun tokenizes_negative_and_scientific_numbers() {
        val code = """{"t": -3.5e2}"""
        assertTrue(colored(code, "-3.5e2", SyntaxColors.NUMBER))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(JsonHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        // Unbalanced quotes / braces / backslashes must terminate cleanly.
        JsonHighlighter.tokenize("\"".repeat(4000))
        JsonHighlighter.tokenize("{".repeat(4000))
        JsonHighlighter.tokenize("\\".repeat(4000))
        JsonHighlighter.tokenize("\"unterminated string")
    }
}
