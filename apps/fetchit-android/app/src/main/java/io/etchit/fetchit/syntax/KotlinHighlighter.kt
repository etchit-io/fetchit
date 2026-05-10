package io.etchit.fetchit.syntax

object KotlinHighlighter : SyntaxHighlighter {
    override val displayName = "Kotlin"

    private val keywords = setOf(
        "fun", "val", "var", "class", "object", "interface", "enum", "data", "sealed",
        "abstract", "open", "override", "private", "public", "protected", "internal",
        "inline", "suspend", "infix", "operator", "external", "tailrec", "reified",
        "companion", "init", "constructor",
        "return", "yield", "if", "else", "when", "is", "in", "for", "while", "do",
        "try", "catch", "finally", "throw", "break", "continue",
        "import", "package", "as", "this", "super", "by",
    )
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b")
    private val literalRe = Regex("\\b(true|false|null)\\b")
    private val commentLineRe = Regex("(?m)//.*$")
    private val commentBlockRe = Regex("(?s)/\\*.*?\\*/")
    private val tripleStringRe = Regex("(?s)\"\"\".*?\"\"\"")
    private val stringRe = Regex("\"(?:[^\"\\\\\\n]|\\\\.)*\"")
    private val annotationRe = Regex("@\\w+(?:\\.\\w+)*")
    private val numberRe = Regex("(?<![A-Za-z_])\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?[fFlL]?")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, keywordRe, SyntaxColors.KEYWORD)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, annotationRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, tripleStringRe, SyntaxColors.STRING)
        colorRule(out, s, commentBlockRe, SyntaxColors.COMMENT)
        colorRule(out, s, commentLineRe, SyntaxColors.COMMENT)
        return out
    }
}
