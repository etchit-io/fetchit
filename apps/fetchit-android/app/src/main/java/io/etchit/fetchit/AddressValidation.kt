package io.etchit.fetchit

/**
 * Cheap pre-check that a user-supplied string looks like an Autonomi
 * address. Identical shape to the Rust [`fetchit_core::Address`] parser
 * (64 lowercase-or-uppercase hex characters, no whitespace) — the
 * native code does its own validation, this is just a courtesy for
 * fast feedback before standing up the network client.
 */
fun isValidAutonomiAddress(s: String): Boolean {
    if (s.length != 64) return false
    return s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
}

/**
 * A parsed Autonomi input: the bare 64-hex address and its optional
 * query string (`?…`, or `""` when absent).
 */
data class AutonomiUrl(val address: String, val query: String)

/**
 * Parse whatever the user pasted into a bare 64-hex address and its
 * optional query string. Accepts a leading `autonomi://` scheme or `0x`
 * prefix, surrounding whitespace, and a trailing path / `#fragment`.
 * The query (with its leading `?`) is preserved so it can be carried
 * into a rendered SPA. Returns `null` when the leading segment is not
 * a 64-hex address.
 */
fun parseAutonomiUrl(raw: String): AutonomiUrl? {
    val trimmed = raw.trim()
    val withoutScheme = trimmed.removePrefix("autonomi://")
    // Tolerate a leading `0x` — the Autonomi app prefixes public
    // addresses with it; the address itself is bare 64-hex.
    val bare =
        if (withoutScheme.startsWith("0x", ignoreCase = true)) withoutScheme.substring(2)
        else withoutScheme
    val address = bare.substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
        .trim()
    if (!isValidAutonomiAddress(address)) return null
    return AutonomiUrl(address, queryOf(bare))
}

/**
 * Normalise whatever the user pasted into a bare 64-hex address, or
 * `null`. Drops any query / fragment.
 */
fun parseAutonomiInput(raw: String): String? = parseAutonomiUrl(raw)?.address

/**
 * Extract the query string (with its leading `?`) from a
 * scheme-stripped input, or `""`. A `?` only opens a query when it
 * precedes any `#`.
 */
private fun queryOf(s: String): String {
    val hash = s.indexOf('#')
    val q = s.indexOf('?')
    if (q < 0 || (hash in 0 until q)) return ""
    return if (hash < 0) s.substring(q) else s.substring(q, hash)
}
