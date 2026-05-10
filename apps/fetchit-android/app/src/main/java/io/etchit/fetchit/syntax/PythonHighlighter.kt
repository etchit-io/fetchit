package io.etchit.fetchit.syntax

object PythonHighlighter : SyntaxHighlighter {
    override val displayName = "Python"

    private val keywords = setOf(
        "def", "class", "lambda", "return", "yield",
        "if", "elif", "else", "for", "while",
        "try", "except", "finally", "raise",
        "import", "from", "as", "with",
        "in", "not", "and", "or", "is",
        "pass", "break", "continue", "del", "global", "nonlocal",
        "assert", "async", "await",
    )
    private val literals = setOf("None", "True", "False")
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b")
    private val literalRe = Regex("\\b(${literals.joinToString("|")})\\b")
    private val commentRe = Regex("(?m)#.*$")
    // Triple-quoted first (must have priority over single-line strings).
    private val tripleStringRe = Regex("(?s)(?:'''.*?'''|\"\"\".*?\"\"\")")
    private val stringRe = Regex(
        "[fFrRbB]{0,2}'(?:[^'\\\\\\n]|\\\\.)*'|[fFrRbB]{0,2}\"(?:[^\"\\\\\\n]|\\\\.)*\"",
    )
    private val numberRe = Regex("(?<![A-Za-z_])\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?")
    private val decoratorRe = Regex("(?m)^\\s*@\\w+(?:\\.\\w+)*")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, keywordRe, SyntaxColors.KEYWORD)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, decoratorRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, tripleStringRe, SyntaxColors.STRING)
        colorRule(out, s, commentRe, SyntaxColors.COMMENT)
        return out
    }
}
