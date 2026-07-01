package io.etchit.fetchit.chat

/**
 * Pure helpers for the `x0x://pair/` URI scheme and `autonomi://` link
 * extraction. All functions are stateless and have no Android or FFI
 * dependencies so they are JVM-testable without Robolectric.
 */
object ChatUris {

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

    /** Matches `autonomi://` followed by exactly 64 lowercase hex chars.
     *  The negative lookahead (?![0-9a-f]) prevents matching the first 64
     *  chars of a longer hex run (truncated or false link). */
    private val AUTONOMI_LINK = Regex("autonomi://([0-9a-f]{64})(?![0-9a-f])")

    /**
     * Extract every `autonomi://<64-hex>` address embedded in [text].
     * Returns the address hex strings (without the scheme prefix),
     * deduplicated in encounter order. Returns an empty list when none
     * are found. Only lowercase hex is matched — callers normalise before
     * storing so addresses coming off the wire are already lowercase.
     */
    fun autonomiAddresses(text: String): List<String> {
        val seen = LinkedHashSet<String>()
        AUTONOMI_LINK.findAll(text).forEach { seen.add(it.groupValues[1]) }
        return seen.toList()
    }

    /**
     * Extract the 64-hex agent id from an `x0x://pair/<64hex>` URI.
     *
     * Returns the lowercase hex string when the URI is well-formed, or
     * `null` if the scheme is wrong, the path is absent, or the first
     * path segment is not 64 hex characters.
     */
    fun pairUriAgentId(uri: String): String? {
        // Normalize once at entry so a hand-typed uppercase scheme or hex
        // segment parses the same as the lowercase form the FFI emits;
        // removePrefix is case-sensitive, so it must see the normalized form.
        val normalized = uri.lowercase()
        if (!normalized.startsWith("x0x://pair/")) return null
        // Strip query / fragment then isolate the first path segment.
        val afterScheme = normalized.removePrefix("x0x://pair/")
        val segment = afterScheme.substringBefore('?').substringBefore('#').trim()
        if (!segment.matches(HEX64)) return null
        return segment
    }

    /**
     * Return `true` if [uri] is a well-formed `x0x://pair/` URI.
     * Convenience wrapper over [pairUriAgentId].
     */
    fun isPairUri(uri: String): Boolean = pairUriAgentId(uri) != null

    /**
     * Return `true` if [uri] is a `x0x://invite/<blob>` group-invite link
     * with a non-empty body.
     *
     * Unlike a pair URI, the invite body is an opaque MLS Welcome blob -- not
     * a fixed 64-hex shape -- so only the scheme + path prefix is validated
     * (case-insensitively) and the body is required to be non-blank. The
     * engine rejects a structurally-invalid blob on join; this is just the
     * client-side gate so an obvious paste-mistake fails fast in the dialog.
     */
    fun isInviteUri(uri: String): Boolean {
        val trimmed = uri.trim()
        // Lowercase only for the prefix check: the base64 body is
        // case-sensitive and must reach the engine untouched.
        val prefix = "x0x://invite/"
        if (trimmed.length <= prefix.length) return false
        if (!trimmed.take(prefix.length).lowercase().startsWith(prefix)) return false
        return trimmed.substring(prefix.length).isNotBlank()
    }
}
