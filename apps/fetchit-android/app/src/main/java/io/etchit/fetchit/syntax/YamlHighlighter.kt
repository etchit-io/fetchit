package io.etchit.fetchit.syntax

object YamlHighlighter : SyntaxHighlighter {
    override val displayName = "YAML"

    private val commentRe = Regex("(?m)#.*$")
    private val stringRe = Regex("\"[^\"]*\"|'[^']*'")
    private val keyRe = Regex("(?m)^\\s*[\\w-]+(?=\\s*:)")
    private val listMarkerRe = Regex("(?m)^\\s*-(?=\\s)")
    private val literalRe = Regex("\\b(true|false|null|yes|no|~)\\b")
    private val numberRe = Regex("(?<![A-Za-z_])-?\\d+(?:\\.\\d+)?\\b")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, keyRe, SyntaxColors.KEYWORD)
        colorRule(out, s, listMarkerRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, commentRe, SyntaxColors.COMMENT)
        return out
    }
}
