package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    // ── group invite uris ─────────────────────────────────────────────
    // The invite body is an opaque MLS Welcome blob (not a fixed 64-hex
    // shape), so the Join-group dialog validates only the scheme + path
    // prefix and a non-empty body -- the engine rejects a malformed blob.

    @Test
    fun validInviteUriAccepted() {
        assertTrue(ChatUris.isInviteUri("x0x://invite/AAAAbbbbCCCC=="))
    }

    @Test
    fun inviteUriWithSurroundingWhitespaceAccepted() {
        assertTrue(ChatUris.isInviteUri("  x0x://invite/blob  "))
    }

    @Test
    fun inviteSchemeIsCaseInsensitive() {
        // A hand-typed or pasted uri may carry an uppercase scheme; only the
        // scheme+path is normalised (the opaque base64 body is left intact).
        assertTrue(ChatUris.isInviteUri("X0X://INVITE/SomeBlob"))
    }

    @Test
    fun pairUriIsNotAnInviteUri() {
        assertFalse(ChatUris.isInviteUri("x0x://pair/$validHex"))
    }

    @Test
    fun wrongSchemeIsNotAnInviteUri() {
        assertFalse(ChatUris.isInviteUri("https://invite/blob"))
    }

    @Test
    fun emptyInviteBodyRejected() {
        assertFalse(ChatUris.isInviteUri("x0x://invite/"))
        assertFalse(ChatUris.isInviteUri("x0x://invite/   "))
    }

    @Test
    fun blankStringIsNotAnInviteUri() {
        assertFalse(ChatUris.isInviteUri(""))
    }

    // ── isLinkUri (device-link offers) ─────────────────────────────────
    // Like an invite, the body is an opaque relay pointer, so only the
    // scheme+host+version prefix is validated and the body must be non-empty.

    @Test
    fun validLinkUriAccepted() {
        assertTrue(ChatUris.isLinkUri("fetchit://link/v1/AAAAbbbbCCCC=="))
    }

    @Test
    fun linkUriWithSurroundingWhitespaceAccepted() {
        assertTrue(ChatUris.isLinkUri("  fetchit://link/v1/pointer  "))
    }

    @Test
    fun linkSchemeIsCaseInsensitive() {
        // A hand-typed or pasted uri may carry an uppercase scheme/host; only
        // the prefix is normalised (the case-sensitive pointer body is intact).
        assertTrue(ChatUris.isLinkUri("FETCHIT://LINK/V1/SomePointer"))
    }

    @Test
    fun pairAndInviteUrisAreNotLinkUris() {
        assertFalse(ChatUris.isLinkUri("x0x://pair/$validHex"))
        assertFalse(ChatUris.isLinkUri("x0x://invite/blob"))
    }

    @Test
    fun wrongSchemeIsNotALinkUri() {
        assertFalse(ChatUris.isLinkUri("https://link/v1/pointer"))
    }

    @Test
    fun bookmarkImportIsNotALinkUri() {
        // Shares the fetchit:// scheme but a different host — must not match.
        assertFalse(ChatUris.isLinkUri("fetchit://import?v=1&data=abc"))
    }

    @Test
    fun emptyLinkBodyRejected() {
        assertFalse(ChatUris.isLinkUri("fetchit://link/v1/"))
        assertFalse(ChatUris.isLinkUri("fetchit://link/v1/   "))
    }

    @Test
    fun blankStringIsNotALinkUri() {
        assertFalse(ChatUris.isLinkUri(""))
    }

    // ── autonomiAddresses ─────────────────────────────────────────────

    private val addr1 = "a".repeat(64)
    private val addr2 = "b".repeat(64)

    @Test
    fun noLinksReturnsEmptyList() {
        assertTrue(ChatUris.autonomiAddresses("hello world").isEmpty())
    }

    @Test
    fun singleLinkExtracted() {
        val text = "check this out autonomi://$addr1 cool"
        assertEquals(listOf(addr1), ChatUris.autonomiAddresses(text))
    }

    @Test
    fun multipleLinksExtractedInOrder() {
        val text = "autonomi://$addr1 and autonomi://$addr2"
        assertEquals(listOf(addr1, addr2), ChatUris.autonomiAddresses(text))
    }

    @Test
    fun duplicateLinksDeduplicatedKeepingFirstEncounter() {
        val text = "autonomi://$addr1 again autonomi://$addr1"
        assertEquals(listOf(addr1), ChatUris.autonomiAddresses(text))
    }

    @Test
    fun uppercaseHexNotMatchedLinkifyIsLowercaseOnly() {
        // The regex only matches lowercase hex; uppercase addresses coming
        // off the wire are normalised before storage so never appear in text.
        val upper = "A".repeat(64)
        assertTrue(ChatUris.autonomiAddresses("autonomi://$upper").isEmpty())
    }

    @Test
    fun hexRunLongerThan64IsNotMatched() {
        // A 65-char hex run must not match — prevents truncated false links.
        val longHex = "a".repeat(65)
        assertTrue(ChatUris.autonomiAddresses("autonomi://$longHex").isEmpty())
    }
}
