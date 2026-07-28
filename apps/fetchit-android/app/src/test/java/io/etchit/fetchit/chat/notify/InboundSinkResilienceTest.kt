package io.etchit.fetchit.chat.notify

import io.etchit.fetchit.chat.ChatController
import io.etchit.fetchit.chat.ConversationStore
import io.etchit.fetchit.chat.FakeGateway
import io.etchit.fetchit.chat.FeedStore
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.fetchit_ffi.ChatEventFfi

/**
 * The notification sink is a BYSTANDER on the delivery path. A throwing sink
 * (notifications revoked, a NotificationManager fault, a bad resource) must
 * never stop message delivery: the pump is the only thing feeding the
 * conversation stores, so an exception escaping into the pump coroutine kills
 * inbound chat until the app restarts, silently. The first notifications
 * build shipped exactly that hole (2026-07-26) and messages stopped arriving
 * on device.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InboundSinkResilienceTest {

    @Test
    fun `a throwing inbound sink does not stop later dms`() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val peer = "a".repeat(64)
        val pump = ChatController.pumpEvents(
            gw,
            convo,
            feed = FeedStore(),
            scope = this,
            htmlStripper = { it },
            onInbound = { error("notifier blew up") },
        )
        gw.events.send(ChatEventFfi.Dm(peer, "first", "m1"))
        gw.events.send(ChatEventFfi.Dm(peer, "second", "m2"))
        gw.events.send(null)
        pump.join()

        assertEquals(
            listOf("first", "second"),
            convo.messagesFor(peer).value.map { it.body },
        )
    }

    @Test
    fun `a throwing inbound sink does not stop later group messages`() = runTest {
        val gw = FakeGateway()
        val convo = ConversationStore()
        val gid = "c".repeat(64)
        val pump = ChatController.pumpEvents(
            gw,
            convo,
            feed = FeedStore(),
            scope = this,
            htmlStripper = { it },
            onInbound = { throw RuntimeException("notifier blew up") },
        )
        repeat(2) { i ->
            gw.events.send(
                ChatEventFfi.GroupMessage(
                    groupId = gid,
                    fromAgentIdHex = "a".repeat(64),
                    senderName = "alice",
                    body = "g$i",
                    messageId = "gm$i",
                ),
            )
        }
        gw.events.send(null)
        pump.join()

        assertEquals(
            listOf("g0", "g1"),
            convo.messagesFor(ConversationStore.convKeyGroup(gid)).value.map { it.body },
        )
    }
}
