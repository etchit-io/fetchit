package io.etchit.fetchit.chat

/**
 * Bounded `<title>` extraction for an address card's HTML preview.
 *
 * Never a WebView and never a full parse: fetched HTML is untrusted, and a
 * card preview must not execute or lay anything out. Only the first
 * [SCAN_LIMIT_CHARS] of the document are examined (a real `<title>` lives in
 * the head), the search is plain index scanning rather than a backtracking
 * regex over attacker-supplied bytes, and the result is entity-decoded for the
 * handful of entities that actually appear in titles, whitespace-collapsed,
 * and capped at [MAX_TITLE_CHARS].
 */
object HtmlTitle {

    /** How much of the document is searched at all. */
    const val SCAN_LIMIT_CHARS: Int = 16 * 1024

    /** Longest title the card will carry, ellipsis included. */
    const val MAX_TITLE_CHARS: Int = 120

    private const val OPEN_TAG = "<title"
    private const val CLOSE_TAG = "</title"

    private val WHITESPACE_RUN = Regex("\\s+")

    /** The document's title, or `null` when it has none worth showing. */
    fun extract(html: String): String? {
        val head = if (html.length > SCAN_LIMIT_CHARS) html.substring(0, SCAN_LIMIT_CHARS) else html
        var from = 0
        while (true) {
            val open = head.indexOf(OPEN_TAG, from, ignoreCase = true)
            if (open < 0) return null
            val afterName = open + OPEN_TAG.length
            if (afterName >= head.length) return null
            val next = head[afterName]
            // The tag name has to end here — `<titlebar>` is not `<title>`.
            if (next != '>' && next != '/' && !next.isWhitespace()) {
                from = afterName
                continue
            }
            val gt = head.indexOf('>', afterName)
            if (gt < 0) return null
            val close = head.indexOf(CLOSE_TAG, gt + 1, ignoreCase = true)
            if (close < 0) return null
            return clean(head.substring(gt + 1, close))
        }
    }

    private fun clean(raw: String): String? {
        val collapsed = decodeEntities(raw).replace(WHITESPACE_RUN, " ").trim()
        if (collapsed.isEmpty()) return null
        if (collapsed.length <= MAX_TITLE_CHARS) return collapsed
        return collapsed.take(MAX_TITLE_CHARS - 1).trimEnd() + "…"
    }

    /** `&amp;` decodes last, so `&amp;lt;` yields `&lt;` and not `<`. */
    private fun decodeEntities(s: String): String = s
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}
