package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The address-card state machine: address-only → previewing →
 * previewed / failed. Kept free of any view so the no-fetch-on-bind
 * guarantee and the no-refetch-on-rebind guarantee are testable.
 */
class AddressCardStateTest {

    private val addr = "a".repeat(64)
    private val other = "b".repeat(64)
    private val preview = AddressPreview(AddressKind.WEB, sizeBytes = 2048, title = "A page")

    @Test
    fun unseenAddressIsAddressOnly() {
        assertEquals(AddressCardState.AddressOnly, AddressCardStates().stateOf(addr))
    }

    @Test
    fun beginPreviewMovesToPreviewing() {
        val states = AddressCardStates()
        assertTrue(states.beginPreview(addr))
        assertEquals(AddressCardState.Previewing, states.stateOf(addr))
    }

    @Test
    fun secondBeginWhileInFlightIsRejected() {
        val states = AddressCardStates()
        states.beginPreview(addr)
        assertFalse(states.beginPreview(addr))
    }

    @Test
    fun previewedStoresTheFacts() {
        val states = AddressCardStates()
        states.beginPreview(addr)
        states.onPreviewed(addr, preview)
        assertEquals(AddressCardState.Previewed(preview), states.stateOf(addr))
    }

    @Test
    fun rebindOfAPreviewedAddressDoesNotRefetch() {
        val states = AddressCardStates()
        states.beginPreview(addr)
        states.onPreviewed(addr, preview)
        assertFalse(states.beginPreview(addr))
        assertEquals(AddressCardState.Previewed(preview), states.stateOf(addr))
    }

    @Test
    fun failureMovesToFailed() {
        val states = AddressCardStates()
        states.beginPreview(addr)
        states.onFailed(addr)
        assertEquals(AddressCardState.Failed, states.stateOf(addr))
    }

    @Test
    fun failedAddressCanRetry() {
        val states = AddressCardStates()
        states.beginPreview(addr)
        states.onFailed(addr)
        assertTrue(states.beginPreview(addr))
        assertEquals(AddressCardState.Previewing, states.stateOf(addr))
    }

    @Test
    fun addressesAreIndependent() {
        val states = AddressCardStates()
        states.beginPreview(addr)
        states.onPreviewed(addr, preview)
        assertEquals(AddressCardState.AddressOnly, states.stateOf(other))
    }

    @Test
    fun oldestEntriesEvictedBeyondCapacity() {
        val states = AddressCardStates(capacity = 2)
        val a = "a".repeat(64)
        val b = "b".repeat(64)
        val c = "c".repeat(64)
        listOf(a, b, c).forEach {
            states.beginPreview(it)
            states.onPreviewed(it, preview)
        }
        assertEquals(AddressCardState.AddressOnly, states.stateOf(a))
        assertEquals(AddressCardState.Previewed(preview), states.stateOf(b))
        assertEquals(AddressCardState.Previewed(preview), states.stateOf(c))
    }

    @Test
    fun recentlyReadEntrySurvivesEviction() {
        val states = AddressCardStates(capacity = 2)
        val a = "a".repeat(64)
        val b = "b".repeat(64)
        val c = "c".repeat(64)
        states.onPreviewed(a, preview)
        states.onPreviewed(b, preview)
        // Reading `a` makes it the most recent, so `b` is the one evicted.
        states.stateOf(a)
        states.onPreviewed(c, preview)
        assertEquals(AddressCardState.Previewed(preview), states.stateOf(a))
        assertEquals(AddressCardState.AddressOnly, states.stateOf(b))
    }

    @Test
    fun sizesRenderCompactly() {
        assertEquals("512 B", formatCardSize(512))
        assertEquals("1.0 KB", formatCardSize(1024))
        assertEquals("1.5 MB", formatCardSize(1024L * 1536))
        assertEquals("2.0 GB", formatCardSize(2L * 1024 * 1024 * 1024))
    }
}
