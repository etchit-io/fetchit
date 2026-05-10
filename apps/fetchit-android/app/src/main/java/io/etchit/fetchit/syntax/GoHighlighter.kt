package io.etchit.fetchit.syntax

object GoHighlighter : SyntaxHighlighter {
    override val displayName = "Go"

    private val keywords = setOf(
        "func", "var", "const", "type", "struct", "interface", "map", "chan",
        "range", "return", "if", "else", "for", "switch", "case", "default", "select",
        "break", "continue", "fallthrough", "goto", "defer", "go", "package", "import",
    )
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b")
    private val literalRe = Regex("\\b(true|false|nil|iota)\\b")
    private val commentLineRe = Regex("(?m)//.*$")
    private val commentBlockRe = Regex("(?s)/\\*.*?\\*/")
    private val stringRe = Regex("\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`")
    private val numberRe = Regex("(?<![A-Za-z_])\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, keywordRe, SyntaxColors.KEYWORD)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, commentBlockRe, SyntaxColors.COMMENT)
        colorRule(out, s, commentLineRe, SyntaxColors.COMMENT)
        return out
    }
}
