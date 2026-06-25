package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConversationStoreTest {
    @Test
    fun appendThenReadBack() {
        val s = ConversationStore()
        s.append("a".repeat(64), ChatMessage(outbound = false, body = "hi", sentAtMs = 1L, messageId = "m1"))
        assertEquals("hi", s.messagesFor("a".repeat(64)).value.single().body)
    }

    @Test
    fun receiptMarksOutboundDelivered() {
        val s = ConversationStore()
        val peer = "b".repeat(64)
        s.append(peer, ChatMessage(outbound = true, body = "yo", sentAtMs = 1L, messageId = "m2"))
        s.markDelivered("m2")
        assertTrue(s.messagesFor(peer).value.single().delivered)
    }

    @Test
    fun unknownReceiptIsNoop() {
        val s = ConversationStore()
        s.markDelivered("nope")
    }

    @Test
    fun groupAndDmWithSameHexDoNotCollide() {
        val s = ConversationStore()
        val hex = "e".repeat(64)
        // A DM thread keyed by bare hex and a group thread whose id is the same
        // hex must be independent conversations.
        s.append(ConversationStore.convKeyDm(hex), ChatMessage(outbound = false, body = "dm", sentAtMs = 1L, messageId = "d1"))
        s.append(ConversationStore.convKeyGroup(hex), ChatMessage(outbound = false, body = "group", sentAtMs = 2L, messageId = "g1"))
        assertEquals("dm", s.messagesFor(ConversationStore.convKeyDm(hex)).value.single().body)
        assertEquals("group", s.messagesFor(ConversationStore.convKeyGroup(hex)).value.single().body)
        assertEquals("g:$hex", ConversationStore.convKeyGroup(hex))
        assertEquals(hex, ConversationStore.convKeyDm(hex))
    }

    @Test
    fun mergeHistoryDedupsByIdAndSortsByTimestamp() {
        val s = ConversationStore()
        val key = "a".repeat(64)
        // A live message (m1) is already shown.
        s.append(key, ChatMessage(outbound = false, body = "live one", sentAtMs = 100L, messageId = "m1"))
        // Hydrate a transcript: an older m0, the duplicate m1, and a newer m2.
        s.mergeHistory(
            key,
            listOf(
                ChatMessage(outbound = false, body = "persisted zero", sentAtMs = 50L, messageId = "m0"),
                ChatMessage(outbound = false, body = "persisted one", sentAtMs = 100L, messageId = "m1"),
                ChatMessage(outbound = true, body = "persisted two", sentAtMs = 150L, messageId = "m2"),
            ),
        )
        val msgs = s.messagesFor(key).value
        // m1 is not doubled; result is m0, m1, m2 in timestamp order.
        assertEquals(listOf("m0", "m1", "m2"), msgs.map { it.messageId })
        // The pre-existing live copy of m1 is the one kept.
        assertEquals("live one", msgs.first { it.messageId == "m1" }.body)
    }

    @Test
    fun mergeHistoryKeepsIdlessLegacyEntries() {
        val s = ConversationStore()
        val key = "a".repeat(64)
        // Two id-less (legacy pre-id) entries cannot be matched, so both survive
        // even though neither carries a message id.
        s.mergeHistory(
            key,
            listOf(
                ChatMessage(outbound = false, body = "legacy a", sentAtMs = 1L, messageId = null),
                ChatMessage(outbound = false, body = "legacy b", sentAtMs = 2L, messageId = ""),
            ),
        )
        assertEquals(2, s.messagesFor(key).value.size)
    }

    @Test
    fun mergeHistoryEmptyIsNoop() {
        val s = ConversationStore()
        val key = "a".repeat(64)
        s.append(key, ChatMessage(outbound = false, body = "x", sentAtMs = 1L, messageId = "m1"))
        s.mergeHistory(key, emptyList())
        assertEquals(1, s.messagesFor(key).value.size)
    }
}
