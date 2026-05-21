package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [KotlinHighlighter.tokenize]. */
class KotlinHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return KotlinHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_keywords_literals_strings_numbers_and_comments() {
        val code = "fun main() { val x = 7 // c\n var s = \"hi\"; val ok = true }"
        assertTrue("keyword fun", colored(code, "fun", SyntaxColors.KEYWORD))
        assertTrue("keyword val", colored(code, "val", SyntaxColors.KEYWORD))
        assertTrue("keyword var", colored(code, "var", SyntaxColors.KEYWORD))
        assertTrue("number", colored(code, "7", SyntaxColors.NUMBER))
        assertTrue("line comment", colored(code, "// c", SyntaxColors.COMMENT))
        assertTrue("string", colored(code, "\"hi\"", SyntaxColors.STRING))
        assertTrue("literal true", colored(code, "true", SyntaxColors.LITERAL))
    }

    @Test
    fun colors_annotation_block_comment_and_triple_string() {
        val code = "@JvmStatic /* doc */ val raw = \"\"\"text\"\"\""
        assertTrue("annotation", colored(code, "@JvmStatic", SyntaxColors.LITERAL))
        assertTrue("block comment", colored(code, "/* doc */", SyntaxColors.COMMENT))
        assertTrue("triple string", colored(code, "\"\"\"text\"\"\"", SyntaxColors.STRING))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(KotlinHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        KotlinHighlighter.tokenize("\"".repeat(4000))
        KotlinHighlighter.tokenize("{".repeat(4000))
        KotlinHighlighter.tokenize("\\".repeat(4000))
        KotlinHighlighter.tokenize("\"\"\"unterminated triple string")
    }
}
