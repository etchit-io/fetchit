package io.etchit.fetchit.chat

/**
 * Pure helpers for the `x0x://pair/` URI scheme.
 *
 * All functions are stateless and have no Android or FFI dependencies
 * so they are JVM-testable without Robolectric.
 */
object ChatUris {

    private val HEX64 = Regex("^[0-9a-fA-F]{64}$")

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
