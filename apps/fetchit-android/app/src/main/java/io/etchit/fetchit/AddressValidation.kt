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
 * Normalise whatever the user pasted into a bare 64-hex address.
 * Accepts a leading `autonomi://` scheme or `0x` prefix, surrounding
 * whitespace, and a trailing query / fragment. Returns the address if
 * it parses, `null` otherwise.
 */
fun parseAutonomiInput(raw: String): String? {
    val trimmed = raw.trim()
    val withoutScheme = trimmed.removePrefix("autonomi://")
    // Tolerate a leading `0x` — the Autonomi app prefixes public
    // addresses with it; the address itself is bare 64-hex.
    val bare =
        if (withoutScheme.startsWith("0x", ignoreCase = true)) withoutScheme.substring(2)
        else withoutScheme
    val withoutPath = bare.substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
        .trim()
    return if (isValidAutonomiAddress(withoutPath)) withoutPath else null
}
