package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ChatUrisTest {

    private val validHex = "a".repeat(64)

    @Test
    fun validPairUriReturnsLowercaseAgentId() {
        val uri = "x0x://pair/$validHex?r=relay"
        assertEquals(validHex, ChatUris.pairUriAgentId(uri))
    }

    @Test
    fun validPairUriNoQueryReturnsAgentId() {
        val uri = "x0x://pair/$validHex"
        assertEquals(validHex, ChatUris.pairUriAgentId(uri))
    }

    @Test
    fun wrongSchemeReturnsNull() {
        assertNull(ChatUris.pairUriAgentId("autonomi://pair/$validHex"))
    }

    @Test
    fun shortHexReturnsNull() {
        assertNull(ChatUris.pairUriAgentId("x0x://pair/abcd1234"))
    }

    @Test
    fun nonHexSegmentReturnsNull() {
        assertNull(ChatUris.pairUriAgentId("x0x://pair/${"g".repeat(64)}"))
    }

    @Test
    fun uppercasePairUriIsNormalizedToLowercase() {
        val upper = "A".repeat(64)
        val uri = "x0x://pair/$upper?r=relay"
        assertEquals(upper.lowercase(), ChatUris.pairUriAgentId(uri))
    }
}
