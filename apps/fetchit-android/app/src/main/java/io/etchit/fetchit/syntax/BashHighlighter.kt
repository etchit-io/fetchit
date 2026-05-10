package io.etchit.fetchit.syntax

object BashHighlighter : SyntaxHighlighter {
    override val displayName = "Bash"

    private val keywords = setOf(
        "if", "then", "else", "elif", "fi",
        "for", "while", "until", "do", "done",
        "function", "case", "esac", "in", "select",
        "return", "exit", "break", "continue",
        "set", "unset", "export", "local", "readonly", "declare", "typeset",
        "alias", "unalias", "trap", "shift", "source",
    )
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b")
    private val commentRe = Regex("(?m)#.*$")
    private val dqStringRe = Regex("\"(?:[^\"\\\\]|\\\\.)*\"")
    private val sqStringRe = Regex("'[^'\\n]*'")
    private val varRe = Regex("\\$\\{?[A-Za-z_][A-Za-z0-9_]*\\}?")
    private val numberRe = Regex("(?<![A-Za-z_])\\d+\\b")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, keywordRe, SyntaxColors.KEYWORD)
        colorRule(out, s, varRe, SyntaxColors.LITERAL)
        colorRule(out, s, dqStringRe, SyntaxColors.STRING)
        colorRule(out, s, sqStringRe, SyntaxColors.STRING)
        colorRule(out, s, commentRe, SyntaxColors.COMMENT)
        return out
    }
}
