package io.etchit.fetchit.chat

import android.app.Application
import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Unit tests for [displayNameOrDefault].
 *
 * `application = Application::class` avoids loading `FetchitApplication`
 * and its native FFI init (absent on the host JVM test classpath).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class ChatNamesTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("fetchit_settings", Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun stored_name_wins_over_fallback() {
        context.getSharedPreferences("fetchit_settings", Context.MODE_PRIVATE)
            .edit().putString("chat_display_name", "alice").commit()
        assertEquals("alice", displayNameOrDefault(context, "a".repeat(64)))
    }

    @Test
    fun blank_stored_name_falls_back_to_agent_prefix() {
        // chatDisplayName() returns "" when unset — must produce "agent-<first6>"
        val agentId = "abcdef1234567890" + "0".repeat(48)
        assertEquals("agent-abcdef", displayNameOrDefault(context, agentId))
    }

    @Test
    fun fallback_uses_first_six_hex_chars_of_agent_id() {
        val agentId = "cafebabe" + "0".repeat(56)
        assertEquals("agent-cafeba", displayNameOrDefault(context, agentId))
    }

    // ── groupSenderLabel: inbound group-sender attribution ───────────────

    @Test
    fun group_sender_label_prefers_sender_name() {
        // The name that rode the encrypted message wins (desktop notify.ts parity).
        assertEquals("Alice", groupSenderLabel("Alice", "Mum", "abcdef".repeat(10) + "abcd"))
    }

    @Test
    fun group_sender_label_sender_name_beats_contact() {
        // Both present -> sender_name still wins, matching desktop.
        assertEquals("Alice", groupSenderLabel("Alice", "Mum", "ab".repeat(32)))
    }

    @Test
    fun group_sender_label_falls_back_to_contact_when_sender_name_blank() {
        assertEquals("Mum", groupSenderLabel(null, "Mum", "ab".repeat(32)))
        assertEquals("Mum", groupSenderLabel("   ", "Mum", "ab".repeat(32)))
    }

    @Test
    fun group_sender_label_falls_back_to_agent_prefix_when_all_blank() {
        val agentId = "abcdef1234567890" + "0".repeat(48)
        assertEquals("agent-abcdef", groupSenderLabel(null, null, agentId))
        assertEquals("agent-abcdef", groupSenderLabel("  ", "", agentId))
    }

    // ── disambiguateMemberLabels: same-name collision suffixing ──────────

    @Test
    fun disambiguate_suffixes_both_members_sharing_a_name() {
        // Two "Bob" rows -> each gets its OWN short-id suffix.
        val out = disambiguateMemberLabels(
            listOf(
                "aaaaaa" + "0".repeat(58) to "Bob",
                "bbbbbb" + "0".repeat(58) to "Bob",
            ),
        )
        assertEquals(listOf("Bob · aaaaaa", "Bob · bbbbbb"), out)
    }

    @Test
    fun disambiguate_leaves_unique_names_unchanged() {
        val out = disambiguateMemberLabels(
            listOf(
                "aaaaaa" + "0".repeat(58) to "Alice",
                "bbbbbb" + "0".repeat(58) to "Bob",
            ),
        )
        assertEquals(listOf("Alice", "Bob"), out)
    }

    @Test
    fun disambiguate_suffixes_all_three_on_a_three_way_collision() {
        val out = disambiguateMemberLabels(
            listOf(
                "aaaaaa" + "0".repeat(58) to "Bob",
                "bbbbbb" + "0".repeat(58) to "Bob",
                "cccccc" + "0".repeat(58) to "Bob",
            ),
        )
        assertEquals(listOf("Bob · aaaaaa", "Bob · bbbbbb", "Bob · cccccc"), out)
    }

    @Test
    fun disambiguate_mixes_collisions_and_uniques_in_order() {
        // Order is preserved; only the colliding "Bob" rows are suffixed.
        val out = disambiguateMemberLabels(
            listOf(
                "aaaaaa" + "0".repeat(58) to "Bob",
                "dddddd" + "0".repeat(58) to "Carol",
                "bbbbbb" + "0".repeat(58) to "Bob",
            ),
        )
        assertEquals(listOf("Bob · aaaaaa", "Carol", "Bob · bbbbbb"), out)
    }

    @Test
    fun disambiguate_lowercases_the_short_id_prefix() {
        val out = disambiguateMemberLabels(
            listOf(
                "ABCDEF" + "0".repeat(58) to "Bob",
                "FEDCBA" + "0".repeat(58) to "Bob",
            ),
        )
        assertEquals(listOf("Bob · abcdef", "Bob · fedcba"), out)
    }

    @Test
    fun disambiguate_empty_list_is_empty() {
        assertEquals(emptyList<String>(), disambiguateMemberLabels(emptyList()))
    }
}
