package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.fetchit_ffi.FediThreadSummaryFfi

class ChatRowModelTest {

    private fun fedi(label: String, atMs: Long, unread: UInt = 0u) =
        FediThreadSummaryFfi(
            label = label,
            lastBody = "hi $label",
            lastAtMs = atMs,
            lastOutbound = false,
            unread = unread,
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
