package io.etchit.fetchit.syntax

object HtmlHighlighter : SyntaxHighlighter {
    override val displayName = "HTML"

    private val commentRe = Regex("(?s)<!--.*?-->")
    private val stringRe = Regex("\"[^\"]*\"|'[^']*'")
    private val tagRe = Regex("</?[A-Za-z][\\w-]*|>|/>")
    private val attrRe = Regex("\\b[A-Za-z-]+(?==)")
    // Capture only the content between opening/closing tags so the
    // sub-language tokens cover styles/script bodies, not the wrapper.
    private val styleBlockRe = Regex("(?si)<style[^>]*>(.*?)</style>")
    private val scriptBlockRe = Regex("(?si)<script[^>]*>(.*?)</script>")

    override fun tokenize(text: CharSequence): List<HighlightToken> {
        val s = text.toString()
        val out = mutableListOf<HighlightToken>()
        colorRule(out, s, attrRe, SyntaxColors.LITERAL)
        colorRule(out, s, tagRe, SyntaxColors.KEYWORD)
        colorRule(out, s, stringRe, SyntaxColors.STRING)
        colorRule(out, s, commentRe, SyntaxColors.COMMENT)
        embedSubLanguage(out, s, styleBlockRe, CssHighlighter)
        embedSubLanguage(out, s, scriptBlockRe, JsTsHighlighter)
        return out
    }
}

/**
 * For each match of [outerRe] in [s], tokenize its first capture group
 * with [inner] and merge the results back into [out] at the original
 * offsets. Drops any outer tokens that fall fully inside the body
 * first — without that, HTML's `\b\w+(?==)` attr regex mis-paints JS
 * `x = 5` because there's no JS token for bare identifiers.
 */
private fun embedSubLanguage(
    out: MutableList<HighlightToken>,
    s: String,
    outerRe: Regex,
    inner: SyntaxHighlighter,
) {
    for (m in outerRe.findAll(s)) {
        val body = m.groups[1] ?: continue
        val bodyStart = body.range.first
        val bodyEnd = body.range.last + 1
        out.removeAll { it.start >= bodyStart && it.end <= bodyEnd }
        val sub = s.substring(bodyStart, bodyEnd)
        for (t in inner.tokenize(sub)) {
            out += HighlightToken(t.start + bodyStart, t.end + bodyStart, t.color, t.style)
        }
    }
}
