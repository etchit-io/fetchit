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
}
