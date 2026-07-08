package io.etchit.fetchit.chat

/** Why a fediverse @handle is rejected at mint time; `null` means acceptable. */
enum class FediHandleError { EMPTY, TOO_LONG, INVALID_CHARS }

/**
 * Validate a fediverse @handle for minting, mirroring desktop's rule: 1–64
 * ASCII letters/digits/`-`/`_`. Returns the first failing reason, or `null`
 * when the handle is acceptable.
 *
 * Leading/trailing whitespace is trimmed first, so a blank field reports
 * [FediHandleError.EMPTY] (not INVALID_CHARS); an internal space or any
 * non-ASCII/symbol character reports [FediHandleError.INVALID_CHARS].
 */
fun fediHandleError(handle: String): FediHandleError? {
    val h = handle.trim()
    if (h.isEmpty()) return FediHandleError.EMPTY
    if (h.length > 64) return FediHandleError.TOO_LONG
    val ok = h.all { c ->
        c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' || c == '_'
    }
    return if (ok) null else FediHandleError.INVALID_CHARS
}
