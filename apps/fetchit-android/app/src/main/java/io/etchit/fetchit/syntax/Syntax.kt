package io.etchit.fetchit.syntax

import android.text.Editable
import android.text.Spannable
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan

/**
 * Token-coloring framework. Ported from etchit-android's
 * `SyntaxHighlighters.kt` (single 653-line file there) and split per
 * language under this package per fetch>it's no-bloat rule.
 *
 * Each language is a regex-based pass that walks the buffer, emits
 * tokens, and lets [`applyTokens`] stamp spans on the destination
 * `Editable`. Not a parser — pathological inputs (escaped quotes
 * inside escaped quotes, triple-quoted Python strings spanning
 * megabytes) gracefully fall back to plain text rather than mis-color.
 *
 * Same color values etchit uses, so the family looks consistent
 * across viewers and the editor.
 */

/**
 * A token produced by [`SyntaxHighlighter.tokenize`]: the [start, end)
 * range plus either a foreground colour, a style flag (Typeface.BOLD /
 * ITALIC), or both. `-1` means "no colour" / "no style".
 */
data class HighlightToken(
    val start: Int,
    val end: Int,
    val color: Int = -1,
    val style: Int = -1,
)

interface SyntaxHighlighter {
    /** Human-readable name for picker UI / logs. */
    val displayName: String

    /** Pure tokenization pass — no `Spannable` allocations. */
    fun tokenize(text: CharSequence): List<HighlightToken>
}

/** Strict brand palette — every colour is from etchit's spec. */
object SyntaxColors {
    const val DEFAULT = 0xFFf5f2eb.toInt() // bone — left implicit
    const val KEYWORD = 0xFFc9732b.toInt() // copper
    const val LITERAL = 0xFFe58a3f.toInt() // copper-bright
    const val STRING = 0xFFd6cfc0.toInt()  // bone-dim
    const val NUMBER = 0xFF6ab04c.toInt()  // signal-ok (deliberately
    // distinct from the `status_green` #9ece6a used elsewhere)
    const val COMMENT = 0xFF8a8a8a.toInt() // ash
}

/** Strip every span we may have added on a previous pass. */
fun clearSyntaxSpans(e: Editable) {
    for (span in e.getSpans(0, e.length, ForegroundColorSpan::class.java)) e.removeSpan(span)
    for (span in e.getSpans(0, e.length, StyleSpan::class.java)) e.removeSpan(span)
}

/** Append every match of [re] to [out] as a coloured token. */
internal fun colorRule(out: MutableList<HighlightToken>, s: String, re: Regex, c: Int) {
    for (m in re.findAll(s)) out += HighlightToken(m.range.first, m.range.last + 1, color = c)
}

/** Append every match of [re] to [out] as a styled (bold/italic) token. */
internal fun styleRule(out: MutableList<HighlightToken>, s: String, re: Regex, styleFlag: Int) {
    for (m in re.findAll(s)) out += HighlightToken(m.range.first, m.range.last + 1, style = styleFlag)
}

/**
 * Apply [tokens] within `[rangeStart, rangeEnd)` to [editable].
 *
 * Pre-merges tokens by priority into one span per contiguous run of
 * identical (colour, style). Without this merge, later-applied spans
 * (strings, comments) get dropped first when Android's Spannable cliff
 * (~5–7K spans) hits. Priority follows token list order; tokens later
 * in the list win for colour and style independently.
 */
fun SyntaxHighlighter.applyTokens(
    editable: Editable, tokens: List<HighlightToken>, rangeStart: Int, rangeEnd: Int,
) {
    clearSyntaxSpans(editable)
    if (tokens.isEmpty()) return
    val len = editable.length
    if (len == 0) return
    val rs = rangeStart.coerceAtLeast(0)
    val re = rangeEnd.coerceAtMost(len)
    if (rs >= re) return

    val winnerColor = IntArray(len) { -1 }
    val winnerStyle = IntArray(len) { -1 }
    val winnerPriority = IntArray(len) { -1 }
    for ((i, t) in tokens.withIndex()) {
        val s = t.start.coerceAtLeast(0)
        val e = t.end.coerceAtMost(len)
        if (e <= s) continue
        for (p in s until e) {
            if (i >= winnerPriority[p]) {
                winnerPriority[p] = i
                if (t.color != -1) winnerColor[p] = t.color
                if (t.style != -1) winnerStyle[p] = t.style
            }
        }
    }

    var p = rs
    while (p < re) {
        val c = winnerColor[p]
        val st = winnerStyle[p]
        if (c == -1 && st == -1) { p++; continue }
        var q = p + 1
        while (q < re && winnerColor[q] == c && winnerStyle[q] == st) q++
        if (c != -1) editable.setSpan(
            ForegroundColorSpan(c), p, q, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
        )
        if (st != -1) editable.setSpan(
            StyleSpan(st), p, q, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
        )
        p = q
    }
}

/** Whole-doc apply convenience — tokenize + applyTokens with full range. */
fun SyntaxHighlighter.apply(editable: Editable, rangeStart: Int = 0, rangeEnd: Int = editable.length) {
    applyTokens(editable, tokenize(editable), rangeStart, rangeEnd)
}
