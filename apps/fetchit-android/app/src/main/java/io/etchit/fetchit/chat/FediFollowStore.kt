package io.etchit.fetchit.chat

import android.content.Context
import android.content.SharedPreferences

/**
 * Canonical storage form of a fediverse handle: trimmed, lowercased,
 * leading `@` dropped. Handles are case-insensitive identifiers and
 * arrive both as `@user@host` (lookup cards) and `user@host` (feed
 * author labels); one form keeps follow/block state stable everywhere.
 */
fun canonicalFediHandle(handle: String): String =
    handle.trim().removePrefix("@").lowercase()

/**
 * Remembers which fediverse accounts this device has successfully sent a
 * `Follow` to, so the lookup card can show a persistent "following" state
 * instead of a snackbar the user may have missed.
 *
 * Device-local optimism, not ground truth: the remote side's Accept (and
 * any later unfollow from another surface) is not tracked here — M7's
 * inbound feed seam owns that. Plain `SharedPreferences` (same reasoning
 * as [io.etchit.fetchit.BookmarkStore]): handles are public identifiers.
 */
class FediFollowStore(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Record a successfully-sent follow of [handle]. */
    fun recordFollow(handle: String) {
        val next = handles() + canonicalFediHandle(handle)
        prefs.edit().putStringSet(KEY, next).apply()
    }

    /** Whether a follow of [handle] was sent from this device. */
    fun isFollowing(handle: String): Boolean = canonicalFediHandle(handle) in handles()

    /** Drop [handle] after an unfollow so cards stop showing "following". */
    fun forget(handle: String) {
        prefs.edit().putStringSet(KEY, handles() - canonicalFediHandle(handle)).apply()
    }

    /** All followed handles, sorted for stable display. */
    fun following(): List<String> = handles().sorted()

    // getStringSet's returned instance must never be mutated (Android
    // caches it); copy defensively — and re-canonicalize on read so
    // entries persisted under an older canonical form stay matchable.
    private fun handles(): Set<String> =
        prefs.getStringSet(KEY, emptySet()).orEmpty().mapTo(HashSet(), ::canonicalFediHandle)

    companion object {
        private const val PREFS_NAME = "fedi_follow_store"
        private const val KEY = "following_v1"
    }
}
