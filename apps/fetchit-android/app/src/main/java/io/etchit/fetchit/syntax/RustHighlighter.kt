package io.etchit.fetchit.syntax

object RustHighlighter : SyntaxHighlighter {
    override val displayName = "Rust"

    private val keywords = setOf(
        "fn", "let", "mut", "const", "static", "struct", "enum", "impl", "trait",
        "use", "mod", "pub", "crate", "self", "Self",
        "return", "if", "else", "match", "for", "while", "loop", "break", "continue",
        "in", "where", "as", "ref", "move", "async", "await", "dyn", "unsafe", "extern",
        "type", "union",
    )
    private val keywordRe = Regex("\\b(${keywords.joinToString("|")})\\b")
    private val literalRe = Regex("\\b(true|false|None|Some|Ok|Err)\\b")
    private val commentLineRe = Regex("(?m)//.*$")
    private val commentBlockRe = Regex("(?s)/\\*.*?\\*/")
    private val stringRe = Regex("\"(?:[^\"\\\\]|\\\\.)*\"")
    private val attributeRe = Regex("(?m)#!?\\[[^\\]]*\\]")
    private val numberRe = Regex(
        "(?<![A-Za-z_])\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?(?:[ui](?:8|16|32|64|128|size)|[fF](?:32|64))?",
    )

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, numberRe, SyntaxColors.NUMBER)
        colorRule(out, s, keywordRe, SyntaxColors.KEYWORD)
        colorRule(out, s, literalRe, SyntaxColors.LITERAL)
        colorRule(out, s, attributeRe, SyntaxColors.LITERAL)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, commentBlockRe, SyntaxColors.COMMENT)
        colorRule(out, s, commentLineRe, SyntaxColors.COMMENT)
        return out
    }
}
