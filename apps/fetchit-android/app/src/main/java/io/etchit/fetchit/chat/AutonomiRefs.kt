package io.etchit.fetchit.chat

/**
 * Extraction of Autonomi content addresses from free text — message bodies
 * and fediverse post bodies — so each one can grow a content card.
 *
 * Strictness matches the reader's own validator
 * ([io.etchit.fetchit.isValidAutonomiAddress]): exactly 64 hex characters,
 * either case. Both the `autonomi://<addr>` URI form and the bare form count,
 * with an optional `0x` prefix (the Autonomi app prefixes public addresses
 * with it). A hex run of any other length, or one glued to surrounding word
 * characters, is never a match — a 63/65-char paste or a long identifier
 * inside a word must not sprout a card.
 */
object AutonomiRefs {

    /**
     * One address token. The word-boundary lookaround pins the run to exactly
     * 64 free-standing hex characters; the optional scheme and `0x` prefixes
     * sit inside that boundary so `autonomi://<addr>` reads as one token
     * rather than a prefix plus a bare hit.
     */
    private val ADDRESS = Regex(
        "(?<![0-9A-Za-z_])(?:autonomi://)?(?:0x)?([0-9a-fA-F]{64})(?![0-9A-Za-z_])",
        RegexOption.IGNORE_CASE,
    )

    /**
     * Every address referenced in [text] — lowercased, deduplicated, in
     * encounter order. Empty when the text carries none.
     */
    fun addresses(text: String): List<String> {
        val seen = LinkedHashSet<String>()
        ADDRESS.findAll(text).forEach { seen.add(it.groupValues[1].lowercase()) }
        return seen.toList()
    }
}
