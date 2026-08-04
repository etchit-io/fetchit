package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.fetchit_ffi.FediThreadSummaryFfi
import uniffi.fetchit_ffi.GroupFfi

class ChatRowModelTest {

    private fun fedi(label: String, atMs: Long, unread: UInt = 0u) =
        FediThreadSummaryFfi(
            label = label,
            lastBody = "hi $label",
            lastAtMs = atMs,
            lastOutbound = false,
            unread = unread,
        )

    private fun group(id: String, name: String) =
        GroupFfi(
            groupId = id,
            name = name,
            memberCount = 3uL,
            isOwner = false,
            isPrivate = true,
        )

    @Test
    fun rowsAreSortedNewestFirstAcrossAllKinds() {
        val contacts = listOf(ChatContact(agentIdHex = "a".repeat(64), displayName = "Mum", addedAtMs = 0L))
        val fedi = listOf(fedi("happyborg@fosstodon.org", 300))
        // Contact "Mum" last spoke at 500 -> should sort above the fedi thread at 300.
        val rows = buildChatRows(
            contacts = contacts,
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { key -> if (key.contains("a".repeat(64))) "see you sunday" to 500L else null },
            fediThreads = fedi,
        )
        assertEquals(2, rows.size)
        assertEquals("Mum", (rows[0] as ChatRow.Contact).contact.displayName)
        assertEquals("happyborg@fosstodon.org", (rows[1] as ChatRow.Fedi).summary.label)
    }

    @Test
    fun aLinkedFediThreadIsSuppressedInFavorOfItsContactRow() {
        val contacts = listOf(ChatContact(agentIdHex = "c".repeat(64), displayName = "Happy", addedAtMs = 0L))
        val fedi = listOf(fedi("happyborg@fosstodon.org", 300))
        val rows = buildChatRows(
            contacts = contacts,
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { _ -> "let's talk" to 400L },
            fediThreads = fedi,
            linkedFediLabels = setOf("happyborg@fosstodon.org"),
        )
        assertEquals(1, rows.size)
        assertEquals("Happy", (rows[0] as ChatRow.Contact).contact.displayName)
    }

    @Test
    fun anUnreadFirstContactKeepsItsCountOnTheRow() {
        // The engine's unread count must survive into the row that renders
        // the badge — it is the only signal a never-seen correspondent gets.
        val rows = buildChatRows(
            contacts = emptyList(),
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { null },
            fediThreads = listOf(fedi("stranger@mas.to", 100, unread = 3u)),
        )
        assertEquals(3u, (rows[0] as ChatRow.Fedi).summary.unread)
    }

    @Test
    fun contactAndGroupRowsCarryTheirEngineUnreadCounts() {
        // Private DMs and groups badge from the engine's read marks, keyed by
        // the same conversation keys the previews resolve against.
        val peer = "a".repeat(64)
        val gid = "b".repeat(64)
        val rows = buildChatRows(
            contacts = listOf(ChatContact(agentIdHex = peer, displayName = "Mum", addedAtMs = 0L)),
            groups = listOf(group(gid, "Book club")),
            groupPreview = { "welcome" to 200L },
            contactPreview = { "see you sunday" to 100L },
            fediThreads = emptyList(),
            litUnread = mapOf(
                ConversationStore.convKeyDm(peer) to 2,
                ConversationStore.convKeyGroup(gid) to 7,
            ),
        )
        assertEquals(7, rows.filterIsInstance<ChatRow.Group>().single().unread)
        assertEquals(2, rows.filterIsInstance<ChatRow.Contact>().single().unread)
    }

    @Test
    fun aConversationWithNoKnownCountRendersNoBadge() {
        // An absent key is "not yet read from the engine", which must show
        // nothing rather than guess a count from the in-memory thread.
        val peer = "a".repeat(64)
        val rows = buildChatRows(
            contacts = listOf(ChatContact(agentIdHex = peer, displayName = "Mum", addedAtMs = 0L)),
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { "hi" to 100L },
            fediThreads = emptyList(),
            litUnread = emptyMap(),
        )
        assertEquals(0, (rows[0] as ChatRow.Contact).unread)
    }

    @Test
    fun aGroupKeyNeverBleedsIntoTheDmOfTheSameHex() {
        // Group keys are `g:`-prefixed precisely so a group id that equals a
        // peer's hex cannot silence (or inherit) that peer's badge.
        val hex = "a".repeat(64)
        val rows = buildChatRows(
            contacts = listOf(ChatContact(agentIdHex = hex, displayName = "Mum", addedAtMs = 0L)),
            groups = listOf(group(hex, "Book club")),
            groupPreview = { "welcome" to 200L },
            contactPreview = { "hi" to 100L },
            fediThreads = emptyList(),
            litUnread = mapOf(ConversationStore.convKeyGroup(hex) to 5),
        )
        assertEquals(5, rows.filterIsInstance<ChatRow.Group>().single().unread)
        assertEquals(0, rows.filterIsInstance<ChatRow.Contact>().single().unread)
    }

    @Test
    fun aFediThreadWithNoContactsStillProducesARow() {
        // The unseen-correspondent gap: a fedi thread must appear even with
        // zero private contacts and zero groups.
        val rows = buildChatRows(
            contacts = emptyList(),
            groups = emptyList(),
            groupPreview = { null },
            contactPreview = { null },
            fediThreads = listOf(fedi("stranger@mas.to", 100)),
        )
        assertEquals(1, rows.size)
        assertEquals("stranger@mas.to", (rows[0] as ChatRow.Fedi).summary.label)
    }
}
