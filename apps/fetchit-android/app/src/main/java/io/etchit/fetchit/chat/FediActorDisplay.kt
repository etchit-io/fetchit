package io.etchit.fetchit.chat

/**
 * Format a relay-verified fediverse actor URL as a readable `@user@domain`
 * handle for feed attribution.
 *
 * The input is always the relay-**verified** actor URL (never a body-asserted
 * one), so the derived handle is exactly as trustworthy as the URL — this is
 * presentation only, not a new trust claim. Handles the two common actor-URL
 * shapes:
 *
 * ```
 * https://mastodon.social/@alice   ->  @alice@mastodon.social
 * https://example.com/users/bob    ->  @bob@example.com
 * ```
 *
 * Falls back to the bare host (or the raw input) when the shape is
 * unrecognised, so an odd URL is never rendered as a broken handle.
 */
fun fediActorDisplay(actorUrl: String): String {
    val trimmed = actorUrl.trim()
    val noScheme = trimmed.substringAfter("://", trimmed)
    val host = noScheme.substringBefore('/').lowercase()
    if (host.isEmpty()) return trimmed
    val user = noScheme.substringAfter('/', "")
        .trimEnd('/')
        .substringAfterLast('/')
        .removePrefix("@")
    return if (user.isEmpty()) host else "@$user@$host"
}
