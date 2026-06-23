package io.etchit.fetchit.chat

import androidx.annotation.ColorInt

/**
 * Per-identity "who-is-who" coloring for group chat, mirrored from the desktop
 * shell (`apps/fetchit-desktop/src/chat/avatarColor.ts` + `styles.css`). A
 * person's identity index is derived deterministically from their agent id, so
 * the same agent reads as the same hue across both shells — pixel-for-pixel.
 *
 * The eight hues are the desktop oxidation identity palette (the same colors
 * baked into the avatar gradients and the inbound-bubble stripe/sender-name).
 * Self (outbound) messages keep copper and never use this — they are the
 * out-bubble, not a "who".
 */
object IdentityColor {

    /**
     * Deterministic identity index (0..7) for an agent id. Matches desktop's
     * `identityIndex`: the first byte (two hex chars) of the agent id, modulo 8.
     * Non-hex / short ids fall back to 0, as desktop does.
     */
    fun identityIndex(agentIdHex: String): Int =
        agentIdHex.take(2).toIntOrNull(16)?.rem(8) ?: 0

    // The eight oxidation hues, in index order, exactly as the desktop palette
    // (.chat-avatar--g0..7 / .chat-bubble--id0..7 / .chat-sender--id0..7):
    //   0 copper, 1 gold, 2 verdigris, 3 rust-red, 4 bronze,
    //   5 mauve-patina, 6 olive-verd, 7 steel-blue.
    private val HUES = intArrayOf(
        0xFFC9732B.toInt(), // id0 copper
        0xFFD9A440.toInt(), // id1 gold
        0xFF56B292.toInt(), // id2 verdigris
        0xFFC2553E.toInt(), // id3 rust-red
        0xFFA8743A.toInt(), // id4 bronze
        0xFF8A5A62.toInt(), // id5 mauve-patina
        0xFF8FAE56.toInt(), // id6 olive-verd
        0xFF6E86A8.toInt(), // id7 steel-blue
    )

    // The dark-theme surfaces the desktop bubble/sender rules mix against:
    //   --ink-2 = #141414 (bubble tint base), --bone = #f5f2eb (sender-name base).
    // Android ships the dark theme (values/colors.xml ink_2 / bone match).
    private const val INK_2 = 0xFF141414.toInt()
    private const val BONE = 0xFFF5F2EB.toInt()

    // Desktop tints the inbound bubble fill at 10% hue over --ink-2, except id5
    // and id7 (the cooler/muted hues) which use 12% so they stay visible.
    private val TINT_PCT = intArrayOf(10, 10, 10, 10, 10, 12, 10, 12)

    /** The full-strength identity hue (the left-stripe color). */
    @ColorInt
    fun stripeColor(agentIdHex: String): Int = HUES[identityIndex(agentIdHex)]

    /**
     * Inbound-bubble fill tint: the identity hue mixed over `--ink-2` at the
     * desktop per-id percentage. Mirrors
     * `color-mix(in srgb, HUE X%, var(--ink-2))`.
     */
    @ColorInt
    fun bubbleTint(agentIdHex: String): Int {
        val i = identityIndex(agentIdHex)
        return mix(HUES[i], INK_2, TINT_PCT[i])
    }

    /**
     * Group sender-name label color: the identity hue lightened toward the
     * foreground so small text stays legible on the dark surface. Mirrors
     * `color-mix(in srgb, HUE 78%, var(--bone))`.
     */
    @ColorInt
    fun senderNameColor(agentIdHex: String): Int =
        mix(HUES[identityIndex(agentIdHex)], BONE, 78)

    // sRGB linear channel mix: `pct`% of `fg` over `(100-pct)`% of `bg`. CSS
    // color-mix in the srgb space is a straight per-channel weighted average,
    // which is what we reproduce here. Alpha is opaque on both inputs.
    @ColorInt
    private fun mix(@ColorInt fg: Int, @ColorInt bg: Int, pct: Int): Int {
        val w = pct / 100.0
        fun ch(shift: Int): Int {
            val f = (fg ushr shift) and 0xFF
            val b = (bg ushr shift) and 0xFF
            return Math.round(f * w + b * (1 - w)).toInt().coerceIn(0, 255)
        }
        return (0xFF shl 24) or (ch(16) shl 16) or (ch(8) shl 8) or ch(0)
    }
}
