package io.etchit.fetchit.chat

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.fetchit_ffi.ChatEventFfi
import uniffi.fetchit_ffi.OutboxBubbleFfi
import uniffi.fetchit_ffi.OutboxStatusFfi

/** Regex-based HTML stripper used in place of [android.text.Html.fromHtml] so these tests run on the plain JVM. */
private fun stripHtml(html: String): String =
    html.replace(Regex("<[^>]+>"), "").trim()

class FakeGateway : ChatGateway {
    val events = Channel<ChatEventFfi?>(capacity = 8)
    val enqueued = mutableListOf<Triple<String, String, String>>()
    var startedOutbox: String? = null
    var retried = 0
    var snapshot: List<OutboxBubbleFfi> = emptyList()
    override fun agentIdHex() = "f".repeat(64)
    override suspend fun pairShareUri() = "x0x://pair/${"f".repeat(64)}?r=relay"
    override suspend fun importPairUri(uri: String) {}
    override suspend fun enqueueDm(to: String, body: String, senderName: String): String {
        enqueued += Triple(to, body, senderName); return "outbox-${enqueued.size}"
    }
    override fun startOutbox(displayName: String) { startedOutbox = displayName }
    override suspend fun outboxSnapshot(): List<OutboxBubbleFfi> = snapshot
    override fun retryOutbox() { retried++ }
    override suspend fun nextEvent(): ChatEventFfi? = events.receive()
    override fun disconnect() { events.trySend(null) }
}

class ChatControllerTest {
    @Test
    fun inboundDmLandsInConversation() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Dm("a".repeat(64), "hello", "m9"))
        gw.events.send(null) // pump exits on null
        pump.join()
        assertEquals("hello", convo.messagesFor("a".repeat(64)).value.single().body)
    }

    @Test
    fun receiptMarksDelivered() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        convo.append("a".repeat(64), ChatMessage(outbound = true, body = "x", sentAtMs = 1L, messageId = "m1"))
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Receipt("m1"))
        gw.events.send(null)
        pump.join()
        assertTrue(convo.messagesFor("a".repeat(64)).value.single().delivered)
    }

    @Test
    fun publicPostLandsInFeedAsPlainText() = runTest {
        val gw = FakeGateway()
        val feed = FeedStore()
        val pump = ChatController.pumpEvents(gw, ConversationStore(), feed, scope = this, htmlStripper = ::stripHtml)
        val activity = """{"object":{"content":"<p>hi <b>there</b></p>"}}""".toByteArray()
        gw.events.send(ChatEventFfi.PublicPost("https://m.example/u/x", activity))
        gw.events.send(null)
        pump.join()
        val post = feed.posts.value.single()
        assertEquals("hi there", post.body)
        assertEquals("https://m.example/u/x", post.actorUrl)
    }

    @Test
    fun pumpReportsErrorStop() = runTest {
        val throwingGateway = object : ChatGateway {
            override fun agentIdHex() = "f".repeat(64)
            override suspend fun pairShareUri() = ""
            override suspend fun importPairUri(uri: String) {}
            override suspend fun enqueueDm(to: String, body: String, senderName: String): String = ""
            override fun startOutbox(displayName: String) {}
            override suspend fun outboxSnapshot(): List<OutboxBubbleFfi> = emptyList()
            override fun retryOutbox() {}
            override suspend fun nextEvent(): ChatEventFfi? = throw RuntimeException("boom")
            override fun disconnect() {}
        }
        var stopped: Boolean? = null
        val pump = ChatController.pumpEvents(
            throwingGateway,
            ConversationStore(),
            FeedStore(),
            scope = this,
            htmlStripper = ::stripHtml,
            onStopped = { stopped = it },
            logWarn = { _, _ -> },
        )
        pump.join()
        assertEquals(true, stopped)
    }

    @Test
    fun pumpReportsCleanStop() = runTest {
        val gw = FakeGateway()
        var stopped: Boolean? = null
        val pump = ChatController.pumpEvents(
            gw,
            ConversationStore(),
            FeedStore(),
            scope = this,
            htmlStripper = ::stripHtml,
            onStopped = { stopped = it },
            logWarn = { _, _ -> },
        )
        gw.events.send(null)
        pump.join()
        assertEquals(false, stopped)
    }

    @Test
    fun outboxSendingEventCreatesOutboundBubble() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = OutboxStatusFfi.SENDING)))
        gw.events.send(null)
        pump.join()
        val msg = convo.messagesFor("a".repeat(64)).value.single()
        assertTrue(msg.outbound)
        assertEquals("ob-1", msg.outboxId)
        assertEquals(false, msg.delivered)
        assertEquals(false, msg.failed)
    }

    @Test
    fun outboxDeliveredUpsertsSameBubbleWithoutDuplicating() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = OutboxStatusFfi.SENDING)))
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = OutboxStatusFfi.DELIVERED, messageId = "m1")))
        gw.events.send(null)
        pump.join()
        val msgs = convo.messagesFor("a".repeat(64)).value
        assertEquals(1, msgs.size)
        assertTrue(msgs.single().delivered)
        assertEquals("m1", msgs.single().messageId)
    }

    @Test
    fun outboxFailedEventMarksFailedWithError() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val pump = ChatController.pumpEvents(gw, convo, feed = FeedStore(), scope = this, htmlStripper = ::stripHtml)
        gw.events.send(ChatEventFfi.Outbox(bubble("ob-1", status = OutboxStatusFfi.FAILED, lastError = "no route")))
        gw.events.send(null)
        pump.join()
        val msg = convo.messagesFor("a".repeat(64)).value.single()
        assertTrue(msg.failed)
        assertEquals("no route", msg.lastError)
    }

    @Test
    fun upsertOutboxKeyedByIdSeparatesDistinctBubbles() {
        val convo = ConversationStore()
        convo.upsertOutbox("a".repeat(64), "ob-1", "one", 1L, null, delivered = false, failed = false, lastError = null)
        convo.upsertOutbox("a".repeat(64), "ob-2", "two", 2L, null, delivered = false, failed = false, lastError = null)
        convo.upsertOutbox("a".repeat(64), "ob-1", "one", 1L, "m1", delivered = true, failed = false, lastError = null)
        val msgs = convo.messagesFor("a".repeat(64)).value
        assertEquals(2, msgs.size)
        assertTrue(msgs.first { it.outboxId == "ob-1" }.delivered)
    }

    @Test
    fun upsertOutboxNeverDowngradesDelivered() {
        val convo = ConversationStore()
        convo.upsertOutbox("a".repeat(64), "ob-1", "hi", 1L, "m1", delivered = true, failed = false, lastError = null)
        // A late or reordered Sending for the same bubble must not un-deliver it.
        convo.upsertOutbox("a".repeat(64), "ob-1", "hi", 1L, null, delivered = false, failed = false, lastError = null)
        val msg = convo.messagesFor("a".repeat(64)).value.single()
        assertTrue(msg.delivered)
        assertEquals("m1", msg.messageId)
    }

    private fun bubble(
        id: String,
        peer: String = "a".repeat(64),
        body: String = "hi",
        status: OutboxStatusFfi = OutboxStatusFfi.SENDING,
        messageId: String? = null,
        lastError: String? = null,
    ) = OutboxBubbleFfi(
        id = id,
        peerAgentIdHex = peer,
        body = body,
        status = status,
        messageId = messageId,
        enqueuedAtMs = 1uL,
        lastError = lastError,
    )
}
