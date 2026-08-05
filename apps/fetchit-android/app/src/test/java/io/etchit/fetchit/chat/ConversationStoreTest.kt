package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    // ── staged outbound images ────────────────────────────────────────
    // The staged queue is a pure optimistic-render accelerator: it stands
    // in only while no durable image is available. These are the rules it
    // obeys when the bubble brings nothing of its own.

    private fun attachment(tag: Byte) =
        ChatAttachment("image/jpeg", 4, 3, ByteArray(2) { tag })

    private fun upsert(
        s: ConversationStore,
        peer: String,
        id: String,
        delivered: Boolean = false,
        messageId: String? = null,
        attachment: ChatAttachment? = null,
        attachmentDropped: Boolean = false,
    ) =
        s.upsertOutbox(
            peerAgentIdHex = peer,
            outboxId = id,
            body = "",
            sentAtMs = 1L,
            messageId = messageId,
            delivered = delivered,
            failed = false,
            lastError = null,
            attachment = attachment,
            attachmentDropped = attachmentDropped,
        )

    @Test
    fun theFirstBubbleClaimsTheStagedImage() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val att = attachment(1)
        s.stageOutboundAttachment(peer, att)
        upsert(s, peer, "b1")
        assertEquals(att, s.messagesFor(peer).value.single().attachment)
    }

    @Test
    fun aLaterStateOfTheSameBubbleKeepsItsImage() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val att = attachment(1)
        s.stageOutboundAttachment(peer, att)
        upsert(s, peer, "b1")
        // Delivered transition: same bubble, nothing left staged to claim.
        upsert(s, peer, "b1", delivered = true)
        val msg = s.messagesFor(peer).value.single()
        assertTrue(msg.delivered)
        assertEquals(att, msg.attachment)
    }

    @Test
    fun stagedImagesLineUpWithTheirOwnSends() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val first = attachment(1)
        val second = attachment(2)
        s.stageOutboundAttachment(peer, first)
        s.stageOutboundAttachment(peer, second)
        upsert(s, peer, "b1")
        upsert(s, peer, "b2")
        val msgs = s.messagesFor(peer).value
        assertEquals(first, msgs[0].attachment)
        assertEquals(second, msgs[1].attachment)
    }

    @Test
    fun aTextOnlySendAfterAnImageSendGetsNoImage() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val att = attachment(1)
        s.stageOutboundAttachment(peer, att)
        upsert(s, peer, "b1")
        upsert(s, peer, "b2")
        val msgs = s.messagesFor(peer).value
        assertEquals(att, msgs[0].attachment)
        assertNull(msgs[1].attachment)
    }

    @Test
    fun discardingAStagedImageKeepsItOffTheNextMessage() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        // A send that failed before the engine echoed: no bubble will ever
        // arrive to claim this, and it must not attach itself to the next.
        val token = s.stageOutboundAttachment(peer, attachment(1))
        s.discardStagedAttachment(peer, token)
        upsert(s, peer, "b1")
        assertNull(s.messagesFor(peer).value.single().attachment)
    }

    @Test
    fun discardingOneStagedImageLeavesTheOthers() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val kept = attachment(1)
        val orphan = attachment(2)
        s.stageOutboundAttachment(peer, kept)
        val token = s.stageOutboundAttachment(peer, orphan)
        s.discardStagedAttachment(peer, token)
        upsert(s, peer, "b1")
        assertEquals(kept, s.messagesFor(peer).value.single().attachment)
    }

    @Test
    fun aStagedImageNeverCrossesToAnotherPeer() {
        val s = ConversationStore()
        val alice = "a".repeat(64)
        val bob = "b".repeat(64)
        val att = attachment(1)
        s.stageOutboundAttachment(alice, att)
        upsert(s, bob, "b1")
        assertNull(s.messagesFor(bob).value.single().attachment)
        upsert(s, alice, "b2")
        assertEquals(att, s.messagesFor(alice).value.single().attachment)
    }

    // ── the durable image beats the in-memory one ─────────────────────
    // The engine's outbox bubble now carries the picture itself, and the
    // persisted transcript carries it for anything that was actually
    // sent. Both survive a process death; the staged queue does not.

    @Test
    fun theBubblesOwnImageWinsOverTheStagedOne() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val durable = attachment(1)
        val stale = attachment(2)
        s.stageOutboundAttachment(peer, stale)
        upsert(s, peer, "b1", attachment = durable)
        assertEquals(durable, s.messagesFor(peer).value.single().attachment)
        // The staged entry was still consumed: leaving it queued would
        // hand this message's picture to the next send to this peer.
        upsert(s, peer, "b2")
        assertNull(s.messagesFor(peer).value[1].attachment)
    }

    @Test
    fun aBubbleWithNoImageOfItsOwnStillFallsBackToTheStagedOne() {
        // Back-compat: a bubble written by an older build carries no
        // attachment, so the accelerator must still cover it.
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val att = attachment(1)
        s.stageOutboundAttachment(peer, att)
        upsert(s, peer, "b1", attachment = null)
        assertEquals(att, s.messagesFor(peer).value.single().attachment)
    }

    @Test
    fun aColdStartRendersTheSentPhotoFromTheDurableBubble() {
        // The restart case, as the controller drives it: nothing is
        // staged (that queue died with the process), the outbox snapshot
        // projects first, then the transcript is merged in.
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val att = attachment(1)
        upsert(s, peer, "b1", messageId = "m1", attachment = att)
        s.mergeHistory(
            peer,
            listOf(ChatMessage(outbound = true, body = "", sentAtMs = 1L, messageId = "m1", attachment = att)),
        )
        val msgs = s.messagesFor(peer).value
        assertEquals(1, msgs.size)
        assertEquals(att, msgs.single().attachment)
    }

    @Test
    fun aColdStartRecoversTheImageFromTheTranscriptWhenTheBubbleLostIt() {
        // The reported bug, exactly: an image-only DM whose bubble no
        // longer carries the picture (an old vault entry, or bytes the
        // engine released once the message was delivered). The bubble
        // projects first on connect; the transcript entry carrying the
        // photo used to be discarded as "already shown", leaving a bubble
        // with nothing in it but a timestamp.
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val att = attachment(1)
        upsert(s, peer, "b1", messageId = "m1", delivered = true, attachment = null)
        assertNull(s.messagesFor(peer).value.single().attachment)
        s.mergeHistory(
            peer,
            listOf(ChatMessage(outbound = true, body = "", sentAtMs = 1L, messageId = "m1", attachment = att)),
        )
        val msgs = s.messagesFor(peer).value
        assertEquals("still de-duped to one message", 1, msgs.size)
        assertEquals("the vault's copy is restored", att, msgs.single().attachment)
        assertTrue("and the live send state is untouched", msgs.single().delivered)
    }

    @Test
    fun aShownImageIsNeverOverwrittenByTheTranscript() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        val shown = attachment(1)
        upsert(s, peer, "b1", messageId = "m1", attachment = shown)
        s.mergeHistory(
            peer,
            listOf(
                ChatMessage(
                    outbound = true,
                    body = "",
                    sentAtMs = 1L,
                    messageId = "m1",
                    attachment = attachment(2),
                ),
            ),
        )
        assertEquals(shown, s.messagesFor(peer).value.single().attachment)
    }

    @Test
    fun aReleasedImageIsMarkedSoTheUiCanSaySo() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        upsert(s, peer, "b1", attachment = null, attachmentDropped = true)
        val msg = s.messagesFor(peer).value.single()
        assertNull(msg.attachment)
        assertTrue(msg.attachmentDropped)
        // Sticky: a later state of the same bubble does not un-lose it.
        upsert(s, peer, "b1", attachment = null, attachmentDropped = false)
        assertTrue(s.messagesFor(peer).value.single().attachmentDropped)
    }

    @Test
    fun anOrdinaryMessageIsNeverMarkedAsHavingLostAnImage() {
        val s = ConversationStore()
        val peer = "a".repeat(64)
        upsert(s, peer, "b1")
        assertFalse(s.messagesFor(peer).value.single().attachmentDropped)
    }
}
