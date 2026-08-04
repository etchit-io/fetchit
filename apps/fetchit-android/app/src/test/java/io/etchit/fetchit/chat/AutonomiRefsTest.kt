package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Address extraction feeding the in-bubble / in-post content cards. */
class AutonomiRefsTest {

    private val addr1 = "a".repeat(64)
    private val addr2 = "0123456789abcdef".repeat(4)

    @Test
    fun noAddressesReturnsEmpty() {
        assertTrue(AutonomiRefs.addresses("just a normal sentence").isEmpty())
    }

    @Test
    fun uriFormExtracted() {
        assertEquals(listOf(addr1), AutonomiRefs.addresses("look at autonomi://$addr1 today"))
    }

    @Test
    fun bareFormExtracted() {
        assertEquals(listOf(addr1), AutonomiRefs.addresses("look at $addr1 today"))
    }

    @Test
    fun bareAddressAloneExtracted() {
        assertEquals(listOf(addr2), AutonomiRefs.addresses(addr2))
    }

    @Test
    fun uppercaseHexNormalisedToLowercase() {
        val upper = addr2.uppercase()
        assertEquals(listOf(addr2), AutonomiRefs.addresses("autonomi://$upper"))
        assertEquals(listOf(addr2), AutonomiRefs.addresses(upper))
    }

    @Test
    fun zeroXPrefixTolerated() {
        assertEquals(listOf(addr1), AutonomiRefs.addresses("0x$addr1"))
    }

    @Test
    fun rejectsSixtyThreeHex() {
        assertTrue(AutonomiRefs.addresses("a".repeat(63)).isEmpty())
    }

    @Test
    fun rejectsSixtyFiveHex() {
        assertTrue(AutonomiRefs.addresses("a".repeat(65)).isEmpty())
        assertTrue(AutonomiRefs.addresses("autonomi://${"a".repeat(65)}").isEmpty())
    }

    @Test
    fun rejectsHexInsideLongerWord() {
        assertTrue(AutonomiRefs.addresses("prefix${addr1}").isEmpty())
        assertTrue(AutonomiRefs.addresses("${addr1}suffix").isEmpty())
        assertTrue(AutonomiRefs.addresses("build_${addr1}_id").isEmpty())
    }

    @Test
    fun rejectsNonHexRunOfSixtyFour() {
        assertTrue(AutonomiRefs.addresses("g".repeat(64)).isEmpty())
    }

    @Test
    fun multipleAddressesInOneMessageKeepEncounterOrder() {
        val text = "first autonomi://$addr1 then $addr2 done"
        assertEquals(listOf(addr1, addr2), AutonomiRefs.addresses(text))
    }

    @Test
    fun duplicatesDeduplicatedKeepingFirstEncounter() {
        val text = "autonomi://$addr2 and again $addr2"
        assertEquals(listOf(addr2), AutonomiRefs.addresses(text))
    }

    @Test
    fun punctuationBoundariesAccepted() {
        assertEquals(listOf(addr1), AutonomiRefs.addresses("(autonomi://$addr1)."))
        assertEquals(listOf(addr1), AutonomiRefs.addresses("here: $addr1, nice"))
    }

    @Test
    fun newlineSeparatedAddressesBothFound() {
        assertEquals(listOf(addr1, addr2), AutonomiRefs.addresses("$addr1\n$addr2"))
    }
}
