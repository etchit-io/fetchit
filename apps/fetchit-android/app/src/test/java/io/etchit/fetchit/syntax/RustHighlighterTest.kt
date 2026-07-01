package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [RustHighlighter.tokenize]. */
class RustHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return RustHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_literals_strings_numbers_and_comments() {
        val code = "fn main() { let x = 9; // c\n let s = \"hi\"; let o = Some(1); }"
        assertTrue("keyword fn", colored(code, "fn", SyntaxColors.KEYWORD))
        assertTrue("keyword let", colored(code, "let", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "9", SyntaxColors.NUMBER))
        assertTrue("line comment", colored(code, "// c", SyntaxColors.COMMENT))
        assertTrue("string", colored(code, "\"hi\"", SyntaxColors.STRING))
        assertTrue("literal Some", colored(code, "Some", SyntaxColors.LITERAL))
    }

    @Test
    fun colors_attribute_block_comment_and_typed_number() {
        val code = "#[derive(Debug)] /* doc */ let n = 5u32;"
        assertTrue("attribute", colored(code, "#[derive(Debug)]", SyntaxColors.LITERAL))
        assertTrue("block comment", colored(code, "/* doc */", SyntaxColors.COMMENT))
        assertTrue("typed number", colored(code, "5u32", SyntaxColors.NUMBER))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(RustHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        RustHighlighter.tokenize("\"".repeat(4000))
        RustHighlighter.tokenize("{".repeat(4000))
        RustHighlighter.tokenize("\\".repeat(4000))
        RustHighlighter.tokenize("\"unterminated string")
    }
}
