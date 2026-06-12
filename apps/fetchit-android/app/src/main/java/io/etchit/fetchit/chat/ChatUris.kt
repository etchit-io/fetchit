package io.etchit.fetchit.chat

/**
 * Pure helpers for the `x0x://pair/` URI scheme and `autonomi://` link
 * extraction. All functions are stateless and have no Android or FFI
 * dependencies so they are JVM-testable without Robolectric.
 */
object ChatUris {

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

    /** Matches `autonomi://` followed by exactly 64 lowercase hex chars. */
    private val AUTONOMI_LINK = Regex("autonomi://([0-9a-f]{64})")

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
        if (!uri.startsWith("x0x://pair/", ignoreCase = true)) return null
        // Strip query / fragment then isolate the first path segment.
        val afterScheme = uri.removePrefix("x0x://pair/")
        val segment = afterScheme.substringBefore('?').substringBefore('#').trim()
        if (!segment.matches(HEX64)) return null
        return segment.lowercase()
    }

    /**
     * Return `true` if [uri] is a well-formed `x0x://pair/` URI.
     * Convenience wrapper over [pairUriAgentId].
     */
    fun isPairUri(uri: String): Boolean = pairUriAgentId(uri) != null
}
