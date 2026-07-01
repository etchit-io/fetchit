package io.etchit.fetchit

import android.app.Application
import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Unit tests for [SettingsStore]. Robolectric-run for a real
 * `SharedPreferences`.
 *
 * `application = Application::class` keeps Robolectric from instantiating
 * the manifest's `FetchitApplication`, whose `onCreate` calls into the
 * `fetchit_ffi` native library — absent on the host JVM test classpath.
 *
 * For the same reason these tests never exercise `peers()` on the
 * absent-key branch: that branch returns `defaultPeers()` from the FFI,
 * which would hit the missing native library. Coverage here is the
 * SharedPreferences-backed behaviour — the override and theme branches.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class SettingsStoreTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("fetchit_settings", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    // ── peers: override flag ──────────────────────────────────────────

    @Test
    fun hasOverride_is_false_when_unset() {
        assertFalse(SettingsStore(context).hasOverride())
    }

    // ── peers: save / load round-trip ─────────────────────────────────

    @Test
    fun savePeers_then_peers_round_trips() {
        val store = SettingsStore(context)
        val peers = listOf("/ip4/1.2.3.4/udp/1/quic-v1", "/ip4/5.6.7.8/udp/2/quic-v1")
        store.savePeers(peers)
        assertEquals(peers, store.peers())
    }

    @Test
    fun saved_peers_survive_a_fresh_instance() {
        val peers = listOf("/ip4/9.9.9.9/udp/3/quic-v1")
        SettingsStore(context).savePeers(peers)
        // Fresh instance over the same Context — must load from prefs.
        assertEquals(peers, SettingsStore(context).peers())
    }

    @Test
    fun savePeers_sets_the_override_flag() {
        val store = SettingsStore(context)
        store.savePeers(listOf("/ip4/1.1.1.1/udp/1/quic-v1"))
        assertTrue(store.hasOverride())
    }

    @Test
    fun savePeers_trims_whitespace_and_drops_blank_lines() {
        val store = SettingsStore(context)
        store.savePeers(listOf("  /ip4/1.1.1.1/udp/1/quic-v1  ", "", "   "))
        assertEquals(listOf("/ip4/1.1.1.1/udp/1/quic-v1"), store.peers())
    }

    @Test
    fun savePeers_with_an_all_blank_list_clears_the_override() {
        val store = SettingsStore(context)
        store.savePeers(listOf("/ip4/1.1.1.1/udp/1/quic-v1"))
        store.savePeers(listOf("", "   "))
        // The override key is removed — next peers() would fall back to
        // the FFI defaults (not asserted here; see the class doc).
        assertFalse(store.hasOverride())
    }

    @Test
    fun savePeers_with_an_empty_list_clears_the_override() {
        val store = SettingsStore(context)
        store.savePeers(listOf("/ip4/1.1.1.1/udp/1/quic-v1"))
        store.savePeers(emptyList())
        assertFalse(store.hasOverride())
    }

    @Test
    fun a_cleared_override_does_not_survive_a_fresh_instance() {
        SettingsStore(context).savePeers(listOf("/ip4/1.1.1.1/udp/1/quic-v1"))
        SettingsStore(context).savePeers(emptyList())
        assertFalse(SettingsStore(context).hasOverride())
    }

    // ── theme: defaults ───────────────────────────────────────────────

    @Test
    fun theme_defaults_to_dark_when_unset() {
        assertEquals(Theme.Dark, SettingsStore(context).theme())
    }

    // ── theme: save / load round-trip ─────────────────────────────────

    @Test
    fun saveTheme_then_theme_round_trips_for_every_theme() {
        for (theme in Theme.entries) {
            val store = SettingsStore(context)
            store.saveTheme(theme)
            assertEquals(theme, store.theme())
        }
    }

    @Test
    fun saved_theme_survives_a_fresh_instance() {
        SettingsStore(context).saveTheme(Theme.Light)
        assertEquals(Theme.Light, SettingsStore(context).theme())
    }

    @Test
    fun theme_falls_back_to_dark_when_the_stored_id_is_unrecognised() {
        // Simulate a corrupt / future value persisted under the theme key.
        context.getSharedPreferences("fetchit_settings", Context.MODE_PRIVATE)
            .edit().putString("theme", "neon").commit()
        assertEquals(Theme.Dark, SettingsStore(context).theme())
    }

    // ── chatDisplayName ───────────────────────────────────────────────

    @Test
    fun chatDisplayName_returns_empty_string_when_unset() {
        assertEquals("", SettingsStore(context).chatDisplayName())
    }

    @Test
    fun saveChatDisplayName_then_chatDisplayName_round_trips() {
        val store = SettingsStore(context)
        store.saveChatDisplayName("alice")
        assertEquals("alice", store.chatDisplayName())
    }

    @Test
    fun saveChatDisplayName_trims_whitespace() {
        val store = SettingsStore(context)
        store.saveChatDisplayName("  bob  ")
        assertEquals("bob", store.chatDisplayName())
    }

    @Test
    fun saveChatDisplayName_empty_string_clears_override() {
        val store = SettingsStore(context)
        store.saveChatDisplayName("carol")
        store.saveChatDisplayName("")
        assertEquals("", store.chatDisplayName())
    }

    // ── chatKeepConnected ─────────────────────────────────────────────

    /**
     * Default is ON: a fresh install keeps chat connected across
     * backgrounding so messages send instantly, without the user first
     * discovering the setting.
     */
    @Test
    fun chatKeepConnected_defaults_to_true_when_unset() {
        assertTrue(SettingsStore(context).chatKeepConnected())
    }

    @Test
    fun saveChatKeepConnected_false_then_reads_false() {
        val store = SettingsStore(context)
        store.saveChatKeepConnected(false)
        assertFalse(store.chatKeepConnected())
    }

    @Test
    fun saveChatKeepConnected_round_trips_across_a_fresh_instance() {
        SettingsStore(context).saveChatKeepConnected(false)
        assertFalse(SettingsStore(context).chatKeepConnected())
        SettingsStore(context).saveChatKeepConnected(true)
        assertTrue(SettingsStore(context).chatKeepConnected())
    }

    // ── lastMode: default rule ─────────────────────────────────────────

    /**
     * True first run: no "mode" pref and no bookmarks.
     * Default must be "chat" so the onboarding empty-state is shown.
     */
    @Test
    fun lastModeDefaultsToChatOnTrueFirstRun() {
        // No mode pref set, no bookmarks in BookmarkStore.
        context.getSharedPreferences("fetchit_bookmarks", Context.MODE_PRIVATE)
            .edit().clear().commit()
        assertEquals("chat", SettingsStore(context).lastMode())
    }

    /**
     * No mode pref but bookmarks exist — existing user whose prefs were
     * somehow cleared.  Must default to "browse" to avoid surprising them.
     */
    @Test
    fun lastModeDefaultsToBrowseWhenBookmarksExist() {
        context.getSharedPreferences("fetchit_bookmarks", Context.MODE_PRIVATE)
            .edit().clear().commit()
        // Add one bookmark via BookmarkStore so the pref is populated.
        BookmarkStore(context).add(
            Bookmark(id = "id-1", label = "A site", address = "a".repeat(64), addedAt = 1L, kind = null),
        )
        // No mode pref set — should fall back to browse because bookmarks exist.
        assertEquals("browse", SettingsStore(context).lastMode())
    }

    /** Saving "chat" then reading it back must return "chat". */
    @Test
    fun lastModeRoundTrips() {
        val store = SettingsStore(context)
        store.saveLastMode("chat")
        assertEquals("chat", SettingsStore(context).lastMode())
        store.saveLastMode("browse")
        assertEquals("browse", SettingsStore(context).lastMode())
    }
}
