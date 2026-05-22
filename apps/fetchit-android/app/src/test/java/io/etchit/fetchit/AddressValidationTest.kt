package io.etchit.fetchit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Unit tests for [isValidAutonomiAddress] and [parseAutonomiInput]. */
class AddressValidationTest {

    /** A canonical 64-char lowercase-hex address, reused across cases. */
    private val addr = "c2b0285930b0a2c3df3928d0a4706b4e6d71e84ebeb4f7805c83ffbb63d0ab61"

    // ── isValidAutonomiAddress ────────────────────────────────────────

    @Test
    fun accepts_64_char_lowercase_hex() {
        assertTrue(isValidAutonomiAddress(addr))
    }

    @Test
    fun accepts_uppercase_and_mixed_case_hex() {
        assertTrue(isValidAutonomiAddress(addr.uppercase()))
        assertTrue(isValidAutonomiAddress("ABCDEF0123456789".repeat(4)))
    }

    @Test
    fun rejects_wrong_length() {
        assertFalse(isValidAutonomiAddress(""))
        assertFalse(isValidAutonomiAddress(addr.dropLast(1)))  // 63 chars
        assertFalse(isValidAutonomiAddress(addr + "a"))        // 65 chars
    }

    @Test
    fun rejects_non_hex_characters() {
        assertFalse(isValidAutonomiAddress("g" + addr.drop(1)))      // 'g' not hex
        assertFalse(isValidAutonomiAddress(addr.dropLast(1) + " "))  // trailing space
        assertFalse(isValidAutonomiAddress(addr.dropLast(1) + "!"))  // punctuation
    }

    // ── parseAutonomiInput ────────────────────────────────────────────

    @Test
    fun parses_bare_address() {
        assertEquals(addr, parseAutonomiInput(addr))
    }

    @Test
    fun strips_autonomi_scheme() {
        assertEquals(addr, parseAutonomiInput("autonomi://$addr"))
    }

    @Test
    fun strips_leading_0x_prefix() {
        assertEquals(addr, parseAutonomiInput("0x$addr"))
        assertEquals(addr, parseAutonomiInput("0X$addr"))
    }

    @Test
    fun trims_surrounding_whitespace() {
        assertEquals(addr, parseAutonomiInput("  $addr  "))
        assertEquals(addr, parseAutonomiInput("\t autonomi://$addr \n"))
    }

    @Test
    fun strips_trailing_path_query_and_fragment() {
        assertEquals(addr, parseAutonomiInput("$addr/some/path"))
        assertEquals(addr, parseAutonomiInput("$addr?foo=bar"))
        assertEquals(addr, parseAutonomiInput("$addr#section"))
        assertEquals(addr, parseAutonomiInput("autonomi://$addr/path?q=1#frag"))
    }

    @Test
    fun returns_null_for_invalid_input() {
        assertNull(parseAutonomiInput(""))
        assertNull(parseAutonomiInput("not an address"))
        assertNull(parseAutonomiInput(addr.dropLast(1)))                 // too short
        assertNull(parseAutonomiInput("autonomi://" + "z".repeat(64)))   // non-hex
        assertNull(parseAutonomiInput("https://example.com/$addr"))      // wrong scheme
    }

    @Test
    fun preserves_case_does_not_normalize() {
        // parseAutonomiInput validates the shape but does not lowercase.
        assertEquals(addr.uppercase(), parseAutonomiInput(addr.uppercase()))
    }
}
