package io.etchit.fetchit.chat

import android.content.Context
import android.content.SharedPreferences

/**
 * Canonical storage form of a fediverse handle: trimmed + lowercased.
 * Handles are case-insensitive identifiers; storing one form keeps the
 * "following" state stable however the user typed the lookup.
 */
fun canonicalFediHandle(handle: String): String = handle.trim().lowercase()

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

    /** All followed handles, sorted for stable display. */
    fun following(): List<String> = handles().sorted()

    // getStringSet's returned instance must never be mutated (Android
    // caches it); copy defensively before use.
    private fun handles(): Set<String> = prefs.getStringSet(KEY, emptySet()).orEmpty().toSet()

    companion object {
        private const val PREFS_NAME = "fedi_follow_store"
        private const val KEY = "following_v1"
    }
}
