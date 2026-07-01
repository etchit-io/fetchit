package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [PythonHighlighter.tokenize]. */
class PythonHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return PythonHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_literals_strings_numbers_and_comments() {
        val code = "def f(x):\n    return 42  # answer\n    s = 'hi'\n    ok = True"
        assertTrue("keyword def", colored(code, "def", SyntaxColors.KEYWORD))
        assertTrue("keyword return", colored(code, "return", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "42", SyntaxColors.NUMBER))
        assertTrue("comment", colored(code, "# answer", SyntaxColors.COMMENT))
        assertTrue("string", colored(code, "'hi'", SyntaxColors.STRING))
        assertTrue("literal True", colored(code, "True", SyntaxColors.LITERAL))
    }

    @Test
    fun colors_decorator_and_triple_string() {
        val code = "@staticmethod\ndef g():\n    return '''doc'''"
        assertTrue("decorator", colored(code, "@staticmethod", SyntaxColors.LITERAL))
        assertTrue("triple string", colored(code, "'''doc'''", SyntaxColors.STRING))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(PythonHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        PythonHighlighter.tokenize("\"".repeat(4000))
        PythonHighlighter.tokenize("{".repeat(4000))
        PythonHighlighter.tokenize("\\".repeat(4000))
        PythonHighlighter.tokenize("'''unterminated triple string")
    }
}
