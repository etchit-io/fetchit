package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [IdentityColor] — the "who-is-who" identity palette. Pure
 * JVM (no Android framework), so no Robolectric runner needed.
 *
 * The index derivation mirrors the desktop `identityIndex` (and its
 * avatarColor.test.ts cases), and the mix outputs pin the dark-theme bubble
 * tint / sender-name color so the two shells stay pixel-for-pixel.
 */
class IdentityColorTest {

    @Test
    fun index_maps_first_byte_modulo_eight() {
        // Mirrors desktop avatarColor.test.ts: first byte (two hex), % 8.
        assertEquals(0, IdentityColor.identityIndex("00" + "11".repeat(31)))
        assertEquals(7, IdentityColor.identityIndex("07" + "11".repeat(31)))
        assertEquals(7, IdentityColor.identityIndex("0f" + "11".repeat(31)))
        assertEquals(0, IdentityColor.identityIndex("10" + "11".repeat(31)))
    }

    @Test
    fun index_falls_back_to_zero_on_malformed_input() {
        assertEquals(0, IdentityColor.identityIndex(""))
        assertEquals(0, IdentityColor.identityIndex("zz"))
    }

    @Test
    fun index_is_deterministic() {
        val id = "ab".repeat(32)
        assertEquals(IdentityColor.identityIndex(id), IdentityColor.identityIndex(id))
    }

    @Test
    fun stripe_color_is_the_full_strength_oxidation_hue() {
        // The eight desktop hues, in index order, ARGB-opaque.
        val expected = intArrayOf(
            0xFFC9732B.toInt(), 0xFFD9A440.toInt(), 0xFF56B292.toInt(), 0xFFC2553E.toInt(),
            0xFFA8743A.toInt(), 0xFF8A5A62.toInt(), 0xFF8FAE56.toInt(), 0xFF6E86A8.toInt(),
        )
        for (i in 0..7) {
            val id = "0$i" + "11".repeat(31)
            assertEquals(expected[i], IdentityColor.stripeColor(id))
        }
    }

    @Test
    fun bubble_tint_mixes_hue_over_ink2_pixel_for_pixel() {
        // color-mix(in srgb, HUE 10%, #141414) for id0; 12% for id7.
        assertEquals(0xFF261E16.toInt(), IdentityColor.bubbleTint("00" + "11".repeat(31)))
        assertEquals(0xFF1F2226.toInt(), IdentityColor.bubbleTint("07" + "11".repeat(31)))
    }

    @Test
    fun sender_name_mixes_hue_over_bone_pixel_for_pixel() {
        // color-mix(in srgb, HUE 78%, #f5f2eb).
        assertEquals(0xFFD38F55.toInt(), IdentityColor.senderNameColor("00" + "11".repeat(31)))
        assertEquals(0xFF8C9EB7.toInt(), IdentityColor.senderNameColor("07" + "11".repeat(31)))
    }
}
