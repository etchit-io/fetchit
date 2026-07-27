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

    private val appContext: Context = context.applicationContext

    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

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

    /** Persisted theme choice. Defaults to [Theme.Dark] when unset. */
    fun theme(): Theme {
        val name = prefs.getString(KEY_THEME, null) ?: return Theme.Dark
        return Theme.fromId(name) ?: Theme.Dark
    }

    /** Persist [theme]. Caller is responsible for triggering an
     *  `Activity.recreate()` so the new style takes effect. */
    fun saveTheme(theme: Theme) {
        prefs.edit().putString(KEY_THEME, theme.id).apply()
    }

    /**
     * User-chosen display name sent with outgoing DMs.
     * Empty string means unset — callers should fall back to a
     * synthesised default (e.g. "agent-" + first 6 hex of the agent id).
     */
    fun chatDisplayName(): String = prefs.getString(KEY_CHAT_DISPLAY_NAME, "").orEmpty()

    /** Persist [name]. Pass an empty string to clear the override. */
    fun saveChatDisplayName(name: String) {
        prefs.edit().putString(KEY_CHAT_DISPLAY_NAME, name.trim()).apply()
    }

    /**
     * Whether the chat client keeps its connection while the app is
     * backgrounded. Defaults to `true`.
     *
     * Chat holds a relay/QUIC connection that is slow to re-establish on
     * mobile networks; dropping it on every idle period forces a costly
     * reconnect on return and briefly fails sends mid-reconnect. Keeping it
     * warm across app switches and screen-off is the default so messaging
     * stays instant. The reader/browse client is unaffected — it always
     * idle-disconnects, since its reconnect is a cheap per-fetch bootstrap.
     *
     * Set `false` to save battery: chat also disconnects after the idle
     * grace period, at the cost of a slow reconnect on the next foreground.
     */
    fun chatKeepConnected(): Boolean = prefs.getBoolean(KEY_CHAT_KEEP_CONNECTED, true)

    /** Whether the one-time battery-optimization exemption prompt ran. */
    fun batteryPromptShown(): Boolean = prefs.getBoolean(KEY_BATTERY_PROMPT_SHOWN, false)

    /** Record the battery-exemption prompt as shown (never re-prompts). */
    fun saveBatteryPromptShown() {
        prefs.edit().putBoolean(KEY_BATTERY_PROMPT_SHOWN, true).apply()
    }

    /** Persist the chat keep-connected preference. */
    fun saveChatKeepConnected(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_CHAT_KEEP_CONNECTED, enabled).apply()
    }

    /**
     * Last-used mode to restore on next launch.
     *
     * Default rule (exact): returns "chat" ONLY when the pref is absent
     * AND [BookmarkStore](context).bookmarks.value.isEmpty() — i.e. a true
     * first run with no saved bookmarks.  The chat empty-state is the
     * intended onboarding screen on first launch.
     *
     * In all other cases (pref present, or pref absent but bookmarks exist)
     * this returns "browse", so existing users wake in browse.
     */
    fun lastMode(): String {
        if (prefs.contains(KEY_MODE)) return prefs.getString(KEY_MODE, MODE_BROWSE) ?: MODE_BROWSE
        // Pref absent: first run — check bookmarks to distinguish a genuine
        // first run (no bookmarks) from a pref-cleared reinstall that
        // somehow retained data (bookmarks present).
        val hasBookmarks = BookmarkStore(appContext).bookmarks.value.isNotEmpty()
        return if (hasBookmarks) MODE_BROWSE else MODE_CHAT
    }

    /** Persist [mode]. Values are [MODE_BROWSE] or [MODE_CHAT]. */
    fun saveLastMode(mode: String) {
        prefs.edit().putString(KEY_MODE, mode).apply()
    }

    /** Last-selected messaging tab ("chats" | "people" | "feed"); defaults to "chats". */
    fun lastChatTab(): String =
        prefs.getString(KEY_LAST_CHAT_TAB, "chats").orEmpty().ifEmpty { "chats" }

    /** Persist the last-selected messaging tab so re-entry restores it. */
    /**
     * Group ids this device has deleted (terminal withdrawal). x0xd's
     * `GET /groups` still returns a withdrawn group as a keyless tombstone and
     * exposes no `withdrawn` field, so a deleted group would otherwise keep its
     * row forever. The delete itself is real and server-side -- this only
     * suppresses the tombstone in the list.
     */
    fun deletedGroupIds(): Set<String> =
        prefs.getStringSet(KEY_DELETED_GROUPS, emptySet()).orEmpty()

    /** Record [groupId] as deleted, so its tombstone stops listing. */
    fun addDeletedGroup(groupId: String) {
        prefs.edit()
            .putStringSet(KEY_DELETED_GROUPS, deletedGroupIds() + groupId)
            .apply()
    }

    fun saveLastChatTab(tab: String) {
        prefs.edit().putString(KEY_LAST_CHAT_TAB, tab).apply()
    }

    private companion object {
        const val PREFS_NAME = "fetchit_settings"
        const val KEY_PEERS = "bootstrap_peers"
        const val KEY_THEME = "theme"
        const val KEY_CHAT_DISPLAY_NAME = "chat_display_name"
        const val KEY_CHAT_KEEP_CONNECTED = "chat_keep_connected"
        const val KEY_BATTERY_PROMPT_SHOWN = "battery_prompt_shown"
        const val KEY_MODE = "mode"
        const val KEY_LAST_CHAT_TAB = "last_chat_tab"
        const val KEY_DELETED_GROUPS = "deleted_group_ids"
        const val MODE_BROWSE = "browse"
        const val MODE_CHAT = "chat"
    }
}
