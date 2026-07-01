package io.etchit.fetchit

import android.app.Application
import android.graphics.Bitmap
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for [QrBitmap]. Robolectric-run because the renderer uses
 * `Bitmap`, `Canvas` and `Paint`, all Android-framework stubs on the
 * plain JVM classpath.
 *
 * `application = Application::class` keeps Robolectric from instantiating
 * the manifest's `FetchitApplication`, whose `onCreate` calls into the
 * `fetchit_ffi` native library — absent on the host JVM test classpath.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class QrBitmapTest {

    private val payload = "autonomi://" + "a".repeat(64)

    // ── happy path ────────────────────────────────────────────────────

    @Test
    fun a_valid_payload_renders_a_non_null_bitmap() {
        assertNotNull(QrBitmap.renderQrWithLogo(payload))
    }

    @Test
    fun the_bitmap_matches_the_requested_default_size() {
        val bmp = QrBitmap.renderQrWithLogo(payload)!!
        assertEquals(720, bmp.width)
        assertEquals(720, bmp.height)
    }

    @Test
    fun the_bitmap_matches_an_explicit_size() {
        val bmp = QrBitmap.renderQrWithLogo(payload, sizePx = 256)!!
        assertEquals(256, bmp.width)
        assertEquals(256, bmp.height)
    }

    @Test
    fun the_bitmap_is_a_square_with_sane_dimensions() {
        val bmp = QrBitmap.renderQrWithLogo(payload, sizePx = 480)!!
        assertEquals(bmp.width, bmp.height)
        assertTrue("dimensions should be positive", bmp.width > 0)
    }

    @Test
    fun the_bitmap_is_mutable_so_the_centre_logo_can_be_drawn() {
        // The renderer deliberately builds a mutable bitmap so Canvas can
        // stamp the `>` glyph — an immutable one would have thrown.
        assertTrue(QrBitmap.renderQrWithLogo(payload)!!.isMutable)
    }

    @Test
    fun the_bitmap_uses_argb_8888() {
        assertEquals(Bitmap.Config.ARGB_8888, QrBitmap.renderQrWithLogo(payload)!!.config)
    }

    // ── error / empty path ────────────────────────────────────────────

    @Test
    fun an_empty_payload_returns_null() {
        // zxing's Encoder throws WriterException("Found empty contents")
        // for an empty string; the catch in renderQrWithLogo maps any
        // exception to null rather than propagating it to the caller.
        assertNull(QrBitmap.renderQrWithLogo(""))
    }
}
