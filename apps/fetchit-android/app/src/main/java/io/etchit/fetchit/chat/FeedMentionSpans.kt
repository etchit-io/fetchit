package io.etchit.fetchit.chat

/** One resolved mention occurrence in a post body: `[start, endExclusive)`. */
data class MentionSpan(val start: Int, val endExclusive: Int, val mention: FeedMention)

/** Mention spans drawn on one post. Matches the engine's per-post cap. */
const val MAX_MENTION_SPANS = 32

/**
 * Locate each of [mentions] inside [body], returning the character ranges
 * to make tappable.
 *
 * The body is PLAIN TEXT — the engine reduced the post's HTML before it
 * ever reached the shell — so the anchor that carried the mention's link
 * is gone and the visible text has to be matched back to the tag. Two
 * forms are tried, in order, and the first that hits wins:
 *
 * 1. the full handle (`@alice@mastodon.example`), and
 * 2. the local part alone (`@alice`) — what a Mastodon-family server's
 *    markup reduces to, since it renders the domain in a hidden span.
 *
 * Matching is case-insensitive (handles are), bounded by [MAX_MENTION_SPANS],
 * and refuses any range that touches one already claimed — including the
 * [blocked] ranges a caller passes for spans it has already placed
 * (autonomi:// links), so two ClickableSpans can never fight over the
 * same characters.
 *
 * A match must not run into surrounding handle characters, so `@alice`
 * does not light up inside `@alicia` and an ordinary email address in
 * prose is not mistaken for its own mention.
 */
fun mentionRanges(
    body: String,
    mentions: List<FeedMention>,
    blocked: List<IntRange> = emptyList(),
): List<MentionSpan> {
    if (body.isEmpty() || mentions.isEmpty()) return emptyList()
    val lower = body.lowercase()
    val taken = blocked.mapTo(ArrayList()) { it.first to it.last + 1 }
    val out = ArrayList<MentionSpan>()

    for (m in mentions) {
        if (out.size >= MAX_MENTION_SPANS) break
        if (m.name.isBlank() || m.href.isBlank()) continue
        for (form in candidateForms(m.name)) {
            val hits = occurrences(lower, form, taken)
            if (hits.isEmpty()) continue
            for ((start, end) in hits) {
                if (out.size >= MAX_MENTION_SPANS) break
                out.add(MentionSpan(start, end, m))
                taken.add(start to end)
            }
            break
        }
    }
    return out.sortedBy { it.start }
}

/** `@user@host` then `@user`, both lowercased, duplicates dropped. */
private fun candidateForms(name: String): List<String> {
    val at = name.trim().let { if (it.startsWith("@")) it else "@$it" }.lowercase()
    val local = "@" + at.drop(1).substringBefore('@')
    return if (local == at) listOf(at) else listOf(at, local)
}

private fun occurrences(
    lower: String,
    form: String,
    taken: List<Pair<Int, Int>>,
): List<Pair<Int, Int>> {
    if (form.length < 2) return emptyList()
    val out = ArrayList<Pair<Int, Int>>()
    var i = lower.indexOf(form)
    while (i >= 0) {
        val end = i + form.length
        val boundedStart = !isHandleChar(lower.getOrNull(i - 1))
        val boundedEnd = !isHandleChar(lower.getOrNull(end))
        val free = taken.none { (s, e) -> i < e && s < end }
        if (boundedStart && boundedEnd && free) out.add(i to end)
        i = lower.indexOf(form, i + 1)
    }
    return out
}

/** Characters that can legally sit inside a handle, so a match that
 *  abuts one is part of a longer name and not this mention. */
private fun isHandleChar(c: Char?): Boolean =
    c != null && (c.isLetterOrDigit() || c == '_' || c == '-' || c == '.' || c == '@')
