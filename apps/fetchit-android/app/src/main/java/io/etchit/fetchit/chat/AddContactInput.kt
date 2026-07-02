package io.etchit.fetchit.chat

/**
 * Home fediverse instance. A bare name typed into "add someone" resolves here,
 * because a fetch>it handle minted on this app is bound to `@name@etchit.io`
 * (see the mint flow). So "alice" finds `@alice@etchit.io` without the user
 * having to know what an instance is.
 */
const val HOME_INSTANCE = "etchit.io"

/**
 * What the single "add someone" box turned out to hold. One field, two intents:
 * a pasted invite link imports a contact directly; a typed name is a fediverse
 * handle we look up first (so the user can find someone and *then* choose to
 * message them privately).
 */
sealed interface AddContactInput {
    /** A pasted `x0x://…` / share link — hand straight to the import path. */
    data class PairUri(val raw: String) : AddContactInput

    /** A fediverse handle to resolve, already normalized to `local@instance`. */
    data class FediHandle(val handle: String) : AddContactInput

    /** Nothing usable was typed. */
    object Empty : AddContactInput
}

/**
 * Classify what someone typed into the "add someone" box.
 *
 * - Anything containing a URL scheme (`://`) is a link to import verbatim.
 * - Otherwise it's treated as a fediverse handle: a leading `@` is dropped and
 *   the whole thing lowercased (handles are case-insensitive), and a bare name
 *   with no instance gets [HOME_INSTANCE] appended so "alice" becomes
 *   `alice@etchit.io`.
 *
 * The returned [AddContactInput.FediHandle.handle] is in the `local@instance`
 * form the engine's lookup expects; malformed handles still surface as a
 * friendly "no one found" at lookup time rather than being rejected here.
 */
fun classifyAddContactInput(raw: String): AddContactInput {
    val trimmed = raw.trim()
    if (trimmed.isEmpty()) return AddContactInput.Empty
    if (trimmed.contains("://")) return AddContactInput.PairUri(trimmed)
    val body = trimmed.removePrefix("@").lowercase()
    if (body.isEmpty()) return AddContactInput.Empty
    val handle = if (body.contains('@')) body else "$body@$HOME_INSTANCE"
    return AddContactInput.FediHandle(handle)
}

/**
 * Friendly local contact name for someone found by fediverse handle. From a
 * canonical `@local@instance` handle (or `local@instance`), take the local part
 * so "@alice@etchit.io" becomes "alice" — the name the user typed. Falls back to
 * the whole handle if there's no local part to extract.
 */
fun contactNameFromHandle(handle: String): String =
    handle.removePrefix("@").substringBefore('@').ifEmpty { handle }
