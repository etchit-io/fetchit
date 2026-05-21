package io.etchit.fetchit.syntax

import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [HtmlHighlighter.tokenize]. */
class HtmlHighlighterTest {

    /** True if some token covers exactly [sub]'s span in [code] with [color]. */
    private fun colored(code: String, sub: String, color: Int): Boolean {
        val i = code.indexOf(sub)
        require(i >= 0) { "test bug: '$sub' not found in code" }
        return HtmlHighlighter.tokenize(code)
            .any { it.start == i && it.end == i + sub.length && it.color == color }
    }

    @Test
    fun colors_tags_attributes_strings_and_comments() {
        val code = "<!-- hi --><a href=\"x\">link</a>"
        assertTrue("comment", colored(code, "<!-- hi -->", SyntaxColors.COMMENT))
        assertTrue("open tag", colored(code, "<a", SyntaxColors.KEYWORD))
        assertTrue("close tag", colored(code, "</a", SyntaxColors.KEYWORD))
        assertTrue("attribute", colored(code, "href", SyntaxColors.LITERAL))
        assertTrue("attr-value string", colored(code, "\"x\"", SyntaxColors.STRING))
    }

    @Test
    fun embeds_css_sub_language_in_style_block() {
        val code = "<style>.a{color:#fff;}</style>"
        // color is a CSS property -> LITERAL; #fff is a CSS hex color -> LITERAL.
        assertTrue("embedded css property", colored(code, "color", SyntaxColors.LITERAL))
        assertTrue("embedded css hex", colored(code, "#fff", SyntaxColors.LITERAL))
    }

    @Test
    fun embeds_js_sub_language_in_script_block() {
        val code = "<script>const n = 42;</script>"
        // const is a JS keyword; 42 is a JS number.
        assertTrue("embedded js keyword", colored(code, "const", SyntaxColors.KEYWORD))
        assertTrue("embedded js number", colored(code, "42", SyntaxColors.NUMBER))
    }

    @Test
    fun empty_input_yields_no_tokens() {
        assertTrue(HtmlHighlighter.tokenize("").isEmpty())
    }

    @Test
    fun pathological_input_returns_without_hanging_or_throwing() {
        HtmlHighlighter.tokenize("\"".repeat(4000))
        HtmlHighlighter.tokenize("<".repeat(4000))
        HtmlHighlighter.tokenize("\\".repeat(4000))
        HtmlHighlighter.tokenize("<!-- unterminated comment")
    }
}
