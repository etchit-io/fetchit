package io.etchit.fetchit

import android.content.Context
import android.content.SharedPreferences
import uniffi.fetchit_ffi.defaultPeers

/**
 * Persists user-overridden bootstrap peers. Stored as newline-separated
 * text, matching etchit's `ConnectionManager` shape.
 *
 * When unset, [`peers`] returns the bundled production defaults from
 * the FFI (`fetchit_net::DEFAULT_PEERS`). This keeps the default list
 * in one source of truth (Rust) — no risk of the Android side drifting.
 */
class SettingsStore(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Current peer list. User override if set, otherwise the FFI defaults. */
    fun peers(): List<String> {
        val saved = prefs.getString(KEY_PEERS, null)
        if (saved.isNullOrBlank()) return defaultPeers()
        return saved.lines().map { it.trim() }.filter { it.isNotEmpty() }
    }

    /**
     * Save `peers` (one entry per line) or clear the override if empty
     * — clearing falls back to the FFI defaults next time [`peers`] is
     * called.
     */
    fun savePeers(peers: List<String>) {
        val cleaned = peers.map { it.trim() }.filter { it.isNotEmpty() }
        prefs.edit().apply {
            if (cleaned.isEmpty()) remove(KEY_PEERS) else putString(KEY_PEERS, cleaned.joinToString("\n"))
            apply()
        }
    }

    /** `true` if the user has overridden the defaults. */
    fun hasOverride(): Boolean = prefs.contains(KEY_PEERS)

    private companion object {
        const val PREFS_NAME = "fetchit_settings"
        const val KEY_PEERS = "bootstrap_peers"
    }
}
