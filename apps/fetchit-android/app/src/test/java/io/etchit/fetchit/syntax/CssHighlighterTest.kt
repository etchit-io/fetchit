package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [CssHighlighter.tokenize]. */
class CssHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return CssHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_properties_numbers_colors_atrules_strings_and_comments() {
        val code = "/* main */ @media all { color: #fff; width: 12px; content: \"x\"; }"
        assertTrue("comment", colored(code, "/* main */", SyntaxColors.COMMENT))
        assertTrue("at-rule", colored(code, "@media", SyntaxColors.KEYWORD))
        assertTrue("property color", colored(code, "color", SyntaxColors.LITERAL))
        assertTrue("property width", colored(code, "width", SyntaxColors.LITERAL))
        assertTrue("hex color", colored(code, "#fff", SyntaxColors.LITERAL))
        assertTrue("number with unit", colored(code, "12px", SyntaxColors.NUMBER))
        assertTrue("string", colored(code, "\"x\"", SyntaxColors.STRING))
    }

    @Test
    fun colors_negative_and_percentage_numbers() {
        val code = "a { margin: -5%; }"
        assertTrue(colored(code, "-5%", SyntaxColors.NUMBER))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(CssHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        CssHighlighter.tokenize("\"".repeat(4000))
        CssHighlighter.tokenize("{".repeat(4000))
        CssHighlighter.tokenize("\\".repeat(4000))
        CssHighlighter.tokenize("/* unterminated comment")
    }
}
