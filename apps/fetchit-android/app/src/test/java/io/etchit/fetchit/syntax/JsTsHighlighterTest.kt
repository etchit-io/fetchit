package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [JsTsHighlighter.tokenize]. */
class JsTsHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return JsTsHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_builtins_literals_strings_numbers_and_comments() {
        val code = "const x = 42; // note\n console.log('hi'); let ok = true;"
        assertTrue("keyword const", colored(code, "const", SyntaxColors.KEYWORD))
        assertTrue("keyword let", colored(code, "let", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "42", SyntaxColors.NUMBER))
        assertTrue("line comment", colored(code, "// note", SyntaxColors.COMMENT))
        assertTrue("builtin console", colored(code, "console", SyntaxColors.LITERAL))
        assertTrue("string", colored(code, "'hi'", SyntaxColors.STRING))
        assertTrue("literal true", colored(code, "true", SyntaxColors.LITERAL))
    }

    @Test
    fun colors_block_comment_and_template_string() {
        val code = "/* doc */ const t = `tpl`;"
        assertTrue("block comment", colored(code, "/* doc */", SyntaxColors.COMMENT))
        assertTrue("template string", colored(code, "`tpl`", SyntaxColors.STRING))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(JsTsHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        JsTsHighlighter.tokenize("\"".repeat(4000))
        JsTsHighlighter.tokenize("{".repeat(4000))
        JsTsHighlighter.tokenize("\\".repeat(4000))
        JsTsHighlighter.tokenize("`unterminated template")
    }
}
