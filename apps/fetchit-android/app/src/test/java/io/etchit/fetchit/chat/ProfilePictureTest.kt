package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The framing + sizing arithmetic behind a published profile picture.
 * The decode/encode itself is device work; everything it decides is here.
 */
class ProfilePictureTest {

    @Test
    fun `a square source is taken whole`() {
        val box = ProfilePicture.cropBox(800, 800)!!
        assertEquals(0, box.x)
        assertEquals(0, box.y)
        assertEquals(800, box.size)
    }

    @Test
    fun `a landscape source keeps its middle`() {
        // 1200x800 -> the 800px square starting 200px in, so the surplus
        // is split evenly and the centre of the picture survives.
        val box = ProfilePicture.cropBox(1200, 800)!!
        assertEquals(200, box.x)
        assertEquals(0, box.y)
        assertEquals(800, box.size)
        assertEquals(1200, box.x * 2 + box.size)
    }

    @Test
    fun `a portrait source keeps its middle`() {
        val box = ProfilePicture.cropBox(900, 1600)!!
        assertEquals(0, box.x)
        assertEquals(350, box.y)
        assertEquals(900, box.size)
        assertEquals(1600, box.y * 2 + box.size)
    }

    @Test
    fun `an odd surplus never runs off the edge`() {
        // Integer division must round the offset DOWN, or the crop would
        // read one pixel past the source.
        val box = ProfilePicture.cropBox(101, 100)!!
        assertEquals(0, box.x)
        assertTrue(box.x + box.size <= 101)
        assertTrue(box.y + box.size <= 100)
    }

    @Test
    fun `a degenerate source has no crop`() {
        assertNull(ProfilePicture.cropBox(0, 100))
        assertNull(ProfilePicture.cropBox(100, 0))
        assertNull(ProfilePicture.cropBox(-4, -4))
    }

    @Test
    fun `oversized crops scale down to the cap`() {
        assertEquals(ProfilePicture.MAX_EDGE_PX, ProfilePicture.scaledEdge(4000))
        assertEquals(ProfilePicture.MAX_EDGE_PX, ProfilePicture.scaledEdge(513))
        assertEquals(ProfilePicture.MAX_EDGE_PX, ProfilePicture.scaledEdge(512))
    }

    @Test
    fun `a small picture is never enlarged`() {
        // Upscaling would spend bytes on detail that is not there.
        assertEquals(96, ProfilePicture.scaledEdge(96))
        assertEquals(1, ProfilePicture.scaledEdge(1))
    }

    @Test
    fun `the quality ladder only ever steps down and starts high`() {
        val ladder = ProfilePicture.QUALITY_LADDER
        assertTrue(ladder.isNotEmpty())
        assertTrue("first rung should be a good-looking quality", ladder.first() >= 80)
        for (i in 1 until ladder.size) {
            assertTrue("ladder must descend", ladder[i] < ladder[i - 1])
        }
        assertTrue("never below a recognisable face", ladder.last() >= 30)
    }

    @Test
    fun `a source within the bound is read whole`() {
        val src = ByteArray(200_000) { (it % 251).toByte() }
        val got = ProfilePicture.readBounded(src.inputStream(), max = 200_000)
        assertTrue(src.contentEquals(got))
    }

    @Test
    fun `an oversized source is refused rather than truncated`() {
        // Truncating would decode to something the user did not pick.
        val src = ByteArray(1_001)
        assertNull(ProfilePicture.readBounded(src.inputStream(), max = 1_000))
    }

    @Test
    fun `an empty source reads as empty, not null`() {
        assertEquals(0, ProfilePicture.readBounded(ByteArray(0).inputStream())!!.size)
    }

    @Test
    fun `the byte cap matches the one the engine and bridge enforce`() {
        // A picture that passes here and fails there would waste the
        // user's upload; these two numbers must not drift.
        assertEquals(512 * 1024, ProfilePicture.MAX_BYTES)
        assertEquals("image/jpeg", ProfilePicture.CONTENT_TYPE)
    }
}
