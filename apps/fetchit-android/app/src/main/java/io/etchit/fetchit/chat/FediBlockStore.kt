package io.etchit.fetchit.chat

import android.content.Context
import android.content.SharedPreferences

/**
 * Device-local block list for fediverse accounts, keyed on the canonical
 * `@user@host` handle (see [canonicalFediHandle]). Blocking here hides
 * the account's posts from the pulled feed and disables follow/message
 * actions on its card — an honest "this device wants nothing from them",
 * not a network-level ban (no `Block` activity is delivered; most
 * servers treat one as advisory anyway).
 *
 * Plain `SharedPreferences` (the [io.etchit.fetchit.BookmarkStore]
 * idiom): handles are public identifiers.
 */
class FediBlockStore(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Block [handle]. */
    fun block(handle: String) {
        prefs.edit().putStringSet(KEY, handles() + canonicalFediHandle(handle)).apply()
    }

    /** Unblock [handle]. */
    fun unblock(handle: String) {
        prefs.edit().putStringSet(KEY, handles() - canonicalFediHandle(handle)).apply()
    }

    /** Whether [handle] is blocked on this device. */
    fun isBlocked(handle: String): Boolean = canonicalFediHandle(handle) in handles()

    /**
     * Whether ANY of [candidates] is blocked, skipping blanks.
     *
     * A blocked account can reach a surface under more than one name:
     * a feed row knows the author both as a `user@host` label and as an
     * actor URL, and entries already on this device were stored under
     * whichever form the blocking surface happened to hold. Matching on
     * a single field would silently orphan those entries and let a
     * blocked account's posts reappear, so every form a caller has goes
     * through the same check.
     */
    fun isAnyBlocked(vararg candidates: String): Boolean =
        candidates.any { it.isNotBlank() && isBlocked(it) }

    /** All blocked handles, sorted for stable display. */
    fun blocked(): List<String> = handles().sorted()

    // getStringSet's returned instance must never be mutated (Android
    // caches it); copy defensively, re-canonicalizing on read.
    private fun handles(): Set<String> =
        prefs.getStringSet(KEY, emptySet()).orEmpty().mapTo(HashSet(), ::canonicalFediHandle)

    private companion object {
        const val PREFS_NAME = "fedi_block_store"
        const val KEY = "blocked_v1"
    }
}
