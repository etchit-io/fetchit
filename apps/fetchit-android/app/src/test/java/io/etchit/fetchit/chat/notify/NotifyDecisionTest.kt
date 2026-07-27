package io.etchit.fetchit.chat.notify

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotifyDecisionTest {
    private val self = "11".repeat(32)
    private val other = "22".repeat(32)

    private fun dm(sender: String) = InboundNotify(
        convKey = "dm:$sender",
        kind = InboundKind.DM,
        senderAgentIdHex = sender,
        senderLabel = null,
        body = "hello",
        messageId = "m1",
    )

    private fun group(sender: String) = InboundNotify(
        convKey = "group:abc",
        kind = InboundKind.GROUP,
        senderAgentIdHex = sender,
        senderLabel = "josh",
        body = "hi all",
        messageId = "m2",
    )

    @Test
    fun `inbound dm from another agent notifies`() {
        assertTrue(shouldNotify(dm(other), self, visibleConvKey = null))
    }

    @Test
    fun `group message from another agent notifies`() {
        assertTrue(shouldNotify(group(other), self, visibleConvKey = null))
    }

    @Test
    fun `own message never notifies`() {
        // Echoes of self-authored messages (multi-device fanout, group echo)
        // must not raise a notification for the author.
        assertFalse(shouldNotify(dm(self), self, visibleConvKey = null))
        assertFalse(shouldNotify(group(self), self, visibleConvKey = null))
    }

    @Test
    fun `conversation on screen never notifies`() {
        // The user is already reading it; a heads-up would double-signal.
        assertFalse(shouldNotify(dm(other), self, visibleConvKey = "dm:$other"))
        assertFalse(shouldNotify(group(other), self, visibleConvKey = "group:abc"))
    }

    @Test
    fun `a different visible conversation still notifies`() {
        assertTrue(shouldNotify(group(other), self, visibleConvKey = "dm:$other"))
    }

    @Test
    fun `sender case differences do not defeat the self check`() {
        assertFalse(shouldNotify(dm(self.uppercase()), self, visibleConvKey = null))
    }
}
