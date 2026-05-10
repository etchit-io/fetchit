package io.etchit.fetchit.syntax

object SqlHighlighter : SyntaxHighlighter {
    override val displayName = "SQL"

    private val keywords = setOf(
        "select", "from", "where", "insert", "into", "values", "update", "set", "delete",
        "create", "table", "index", "view", "drop", "alter",
        "join", "left", "right", "inner", "outer", "cross", "on",
        "and", "or", "not", "in", "is", "null", "like", "between", "exists",
        "order", "by", "group", "having", "limit", "offset", "distinct",
        "case", "when", "then", "else", "end", "as",
        "union", "all", "intersect", "except",
        "primary", "key", "foreign", "references", "default", "unique", "check", "constraint",
        "begin", "commit", "rollback", "transaction",
    )
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b", RegexOption.IGNORE_CASE)
    private val literalRe = Regex("\\b(true|false|null)\\b", RegexOption.IGNORE_CASE)
    private val commentLineRe = Regex("(?m)--.*$")
    private val commentBlockRe = Regex("(?s)/\\*.*?\\*/")
    private val stringRe = Regex("'(?:[^'\\\\]|\\\\.)*'")
    private val numberRe = Regex("(?<![A-Za-z_])\\d+(?:\\.\\d+)?\\b")

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
