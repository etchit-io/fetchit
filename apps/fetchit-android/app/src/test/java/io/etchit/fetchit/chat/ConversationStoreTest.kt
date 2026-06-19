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
}
