package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [GoHighlighter.tokenize]. */
class GoHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return GoHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_literals_strings_numbers_and_comments() {
        val code = "func main() { var x = 3.14 // pi\n s := \"hi\"; ok := true }"
        assertTrue("keyword func", colored(code, "func", SyntaxColors.KEYWORD))
        assertTrue("keyword var", colored(code, "var", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "3.14", SyntaxColors.NUMBER))
        assertTrue("line comment", colored(code, "// pi", SyntaxColors.COMMENT))
        assertTrue("string", colored(code, "\"hi\"", SyntaxColors.STRING))
        assertTrue("literal true", colored(code, "true", SyntaxColors.LITERAL))
    }

    @Test
    fun colors_block_comment_and_raw_string() {
        val code = "/* doc */ x := `raw` "
        assertTrue("block comment", colored(code, "/* doc */", SyntaxColors.COMMENT))
        assertTrue("raw string", colored(code, "`raw`", SyntaxColors.STRING))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(GoHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        GoHighlighter.tokenize("\"".repeat(4000))
        GoHighlighter.tokenize("{".repeat(4000))
        GoHighlighter.tokenize("\\".repeat(4000))
        GoHighlighter.tokenize("\"unterminated string")
    }
}
