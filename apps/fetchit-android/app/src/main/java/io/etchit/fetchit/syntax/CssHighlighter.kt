package io.etchit.fetchit.syntax

object CssHighlighter : SyntaxHighlighter {
    override val displayName = "CSS"

    private val commentRe = Regex("(?s)/\\*.*?\\*/")
    private val stringRe = Regex("\"[^\"]*\"|'[^']*'")
    private val propertyRe = Regex("[a-z-]+(?=\\s*:)")
    private val hexColorRe = Regex("#[0-9a-fA-F]{3,8}\\b")
    private val numberRe = Regex(
        "(?<![A-Za-z_])-?\\d+(?:\\.\\d+)?(?:px|em|rem|%|vh|vw|s|ms|deg|fr)?",
    )
    private val atRuleRe = Regex("@[a-z-]+")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, hexColorRe, SyntaxColors.LITERAL)
        colorRule(out, s, propertyRe, SyntaxColors.LITERAL)
        colorRule(out, s, atRuleRe, SyntaxColors.KEYWORD)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, commentRe, SyntaxColors.COMMENT)
        return out
    }
}
