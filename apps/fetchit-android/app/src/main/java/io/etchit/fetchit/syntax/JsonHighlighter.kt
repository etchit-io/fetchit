package io.etchit.fetchit.syntax

object JsonHighlighter : SyntaxHighlighter {
    override val displayName = "JSON"

    private val stringRe = Regex("\"(?:[^\"\\\\]|\\\\.)*\"")
    private val keyRe = Regex("(\"(?:[^\"\\\\]|\\\\.)*\")\\s*:")
    private val numberRe = Regex("(?<![A-Za-z_])-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?")
    private val literalRe = Regex("\\b(true|false|null)\\b")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        for (m in keyRe.findAll(s)) {
            val k = m.groups[1] ?: continue
            out += HighlightToken(k.range.first, k.range.last + 1, color = SyntaxColors.KEYWORD)
        }
        return out
    }
}
