package io.etchit.fetchit

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists [`Bookmark`]s in `SharedPreferences` as a single JSON-encoded
 * key (`bookmarks_v1`).
 *
 * Plain `SharedPreferences`, not `EncryptedSharedPreferences` — Autonomi
 * addresses are public, the labels are user-chosen, and the
 * encryption-at-rest cost (Keystore handshake on every read) isn't worth
 * the marginal threat-model improvement (spec §3a).
 *
 * Single-process — fetch/it has no service or background worker, so
 * there's no inter-process synchronisation concern.
 */
class BookmarkStore(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _bookmarks = MutableStateFlow(load())

    /** Current state of the bookmark list, observable for UI updates. */
    val bookmarks: StateFlow<List<Bookmark>> = _bookmarks.asStateFlow()

    /** Add a new bookmark. Newest first. */
    fun add(bookmark: Bookmark) {
        write(listOf(bookmark) + _bookmarks.value)
    }

    /** Replace the bookmark with `id`. No-op if not found. */
    fun update(id: String, transform: (Bookmark) -> Bookmark) {
        write(_bookmarks.value.map { if (it.id == id) transform(it) else it })
    }

    /** Remove the bookmark with `id`. No-op if not found. */
    fun delete(id: String) {
        write(_bookmarks.value.filter { it.id != id })
    }

    /** Replace the whole list — used by import. Prepends imports. */
    fun mergeImport(imported: List<Bookmark>) {
        // De-duplicate by address; existing bookmarks win on conflict
        // so the user's chosen labels aren't clobbered by an import.
        val existingAddresses = _bookmarks.value.map { it.address }.toSet()
        val newOnes = imported.filter { it.address !in existingAddresses }
        write(newOnes + _bookmarks.value)
    }

    private fun load(): List<Bookmark> = BookmarkSerde.decodeStorage(prefs.getString(KEY, null))

    private fun write(list: List<Bookmark>) {
        prefs.edit().putString(KEY, BookmarkSerde.encodeStorage(list)).apply()
        _bookmarks.value = list
    }

    private companion object {
        const val PREFS_NAME = "fetchit_bookmarks"
        const val KEY = "bookmarks_v1"
    }
}
