package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The sizing arithmetic and rung-walking behind an inline chat photo.
 * The decode/encode itself is device work; everything it decides is here.
 */
class ChatImageAttachmentTest {

    @Test
    fun `the cap mirrors the engine's attachment limit`() {
        // fetchit_chat::attachment::MAX_ATTACHMENT_BYTES. If the engine's
        // cap moves, this is the copy that must move with it.
        assertEquals(256 * 1024, ChatImageAttachment.MAX_BYTES)
    }

    @Test
    fun `a landscape source keeps its aspect ratio`() {
        // 4000x3000 (4:3) into a 1600 box -> 1600x1200, still 4:3.
        val s = ChatImageAttachment.scaledSize(4000, 3000, 1600)!!
        assertEquals(1600, s.width)
        assertEquals(1200, s.height)
        assertEquals(4000.0 / 3000.0, s.width.toDouble() / s.height.toDouble(), 0.01)
    }

    @Test
    fun `a portrait source keeps its aspect ratio`() {
        val s = ChatImageAttachment.scaledSize(3000, 4000, 1600)!!
        assertEquals(1200, s.width)
        assertEquals(1600, s.height)
        assertEquals(3000.0 / 4000.0, s.width.toDouble() / s.height.toDouble(), 0.01)
    }

    @Test
    fun `a square source stays square`() {
        val s = ChatImageAttachment.scaledSize(2048, 2048, 1024)!!
        assertEquals(1024, s.width)
        assertEquals(1024, s.height)
    }

    @Test
    fun `nothing is ever cropped`() {
        // The whole point of NOT reusing the avatar path: a shared photo is
        // the content, so both dimensions scale by the same factor and no
        // pixels are discarded.
        val s = ChatImageAttachment.scaledSize(3000, 1000, 1500)!!
        assertEquals(1500, s.width)
        assertEquals(500, s.height)
    }

    @Test
    fun `a small source is never scaled up`() {
        val s = ChatImageAttachment.scaledSize(320, 240, 1600)!!
        assertEquals(320, s.width)
        assertEquals(240, s.height)
    }

    @Test
    fun `an extreme panorama keeps a visible short edge`() {
        // 20000x10 into 1600 would round the height to 1 (0.8 rounds up to
        // 1 here, but the clamp is what guarantees it): a zero-height
        // bitmap cannot be encoded at all.
        val s = ChatImageAttachment.scaledSize(20000, 10, 1600)!!
        assertEquals(1600, s.width)
        assertTrue("short edge must stay at least 1px", s.height >= 1)
    }

    @Test
    fun `a degenerate source has no size`() {
        assertNull(ChatImageAttachment.scaledSize(0, 100, 1600))
        assertNull(ChatImageAttachment.scaledSize(100, 0, 1600))
        assertNull(ChatImageAttachment.scaledSize(100, 100, 0))
    }

    @Test
    fun `the ladder tries every quality at an edge before shrinking`() {
        val rungs = ChatImageAttachment.ladder()
        val firstEdge = ChatImageAttachment.EDGE_LADDER.first()
        val qualities = ChatImageAttachment.QUALITY_LADDER.size
        assertEquals(
            ChatImageAttachment.EDGE_LADDER.size * qualities,
            rungs.size,
        )
        // Resolution is preferred over compression quality: every rung at
        // the largest edge comes before the first rung at the next one.
        assertTrue(rungs.take(qualities).all { it.first == firstEdge })
        assertEquals(firstEdge to ChatImageAttachment.QUALITY_LADDER.first(), rungs.first())
        // Within an edge, quality only ever goes down.
        assertEquals(
            ChatImageAttachment.QUALITY_LADDER.toList(),
            rungs.take(qualities).map { it.second },
        )
    }

    @Test
    fun `the first rung that fits wins`() {
        val tried = mutableListOf<Pair<Int, Int>>()
        // Models an encoder whose output shrinks with edge and quality:
        // only the third rung lands under the cap.
        val out = ChatImageAttachment.chooseEncoding { edge, quality ->
            tried += edge to quality
            val size = if (tried.size < 3) {
                ChatImageAttachment.MAX_BYTES + 1
            } else {
                ChatImageAttachment.MAX_BYTES
            }
            ByteArray(size)
        }
        assertEquals(ChatImageAttachment.MAX_BYTES, out!!.size)
        assertEquals(3, tried.size)
        // It stopped at the first fit rather than walking the whole ladder.
        assertTrue(tried.size < ChatImageAttachment.ladder().size)
    }

    @Test
    fun `an image that never fits is refused rather than truncated`() {
        var calls = 0
        val out = ChatImageAttachment.chooseEncoding { _, _ ->
            calls++
            ByteArray(ChatImageAttachment.MAX_BYTES + 1)
        }
        assertNull("no rung fits -> no attachment", out)
        assertEquals(ChatImageAttachment.ladder().size, calls)
    }

    @Test
    fun `a rung that fails to encode is skipped, not fatal`() {
        var calls = 0
        val out = ChatImageAttachment.chooseEncoding { _, _ ->
            calls++
            if (calls == 1) null else ByteArray(16)
        }
        assertEquals(16, out!!.size)
        assertEquals(2, calls)
    }

    @Test
    fun `preparing empty bytes reads as unreadable, not as too large`() {
        // The one prepare() arm that needs no decoder. The distinction is
        // what the user is told: "try another picture" vs "share it as an
        // autonomi:// link".
        assertEquals(
            ChatImageAttachment.Prepared.Unreadable,
            ChatImageAttachment.prepare(ByteArray(0)),
        )
    }

    @Test
    fun `the display decode target is under the avatar bomb guard`() {
        // decodeForDisplay routes through FediAvatars.decodeBounded with the
        // DEFAULT source bound, so a received image is still refused on its
        // declared dimensions.
        assertTrue(ChatImageAttachment.DISPLAY_PX < FediAvatars.MAX_SOURCE_PX)
    }
}
