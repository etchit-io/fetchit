package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [BashHighlighter.tokenize]. */
class BashHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return BashHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_strings_vars_numbers_and_comments() {
        val code = "for i in 1 2 3; do echo \"\$HOME\" 'lit'; done # loop"
        assertTrue("keyword for", colored(code, "for", SyntaxColors.KEYWORD))
        assertTrue("keyword in", colored(code, "in", SyntaxColors.KEYWORD))
        assertTrue("keyword do", colored(code, "do", SyntaxColors.KEYWORD))
        assertTrue("keyword done", colored(code, "done", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "2", SyntaxColors.NUMBER))
        assertTrue("variable", colored(code, "\$HOME", SyntaxColors.LITERAL))
        assertTrue("double-quoted string", colored(code, "\"\$HOME\"", SyntaxColors.STRING))
        assertTrue("single-quoted string", colored(code, "'lit'", SyntaxColors.STRING))
        assertTrue("comment", colored(code, "# loop", SyntaxColors.COMMENT))
    }

    @Test
    fun colors_braced_variable() {
        val code = "echo \${PATH}"
        assertTrue(colored(code, "\${PATH}", SyntaxColors.LITERAL))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(BashHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        BashHighlighter.tokenize("\"".repeat(4000))
        BashHighlighter.tokenize("{".repeat(4000))
        BashHighlighter.tokenize("\\".repeat(4000))
        BashHighlighter.tokenize("\"unterminated string")
    }
}
