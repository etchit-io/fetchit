package io.etchit.fetchit

import android.app.Application
import android.graphics.Bitmap
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Unit tests for [QrShare]. Robolectric-run because the renderer uses
 * `Bitmap`, `Canvas`, and `Paint`, which are Android-framework stubs on
 * the plain JVM classpath.
 *
 * `application = Application::class` keeps Robolectric from instantiating
 * the manifest's `FetchitApplication`, whose `onCreate` calls into the
 * `fetchit_ffi` native library — absent on the host JVM test classpath.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class QrShareTest {

    private val validAgentId = "a".repeat(64)
    private val validPairUri = "x0x://pair/$validAgentId"
    private val validPairUriWithQuery = "x0x://pair/$validAgentId?r=relay.example.com"

    // ── renderCardForUri — acceptance ─────────────────────────────────

    @Test
    fun renderCardForUriAcceptsPairUri() {
        assertNotNull(QrShare.renderCardForUri(validPairUri))
    }

    @Test
    fun renderCardForUriAcceptsPairUriWithQueryParam() {
        assertNotNull(QrShare.renderCardForUri(validPairUriWithQuery))
    }

    @Test
    fun renderCardForUriAcceptsPairUriWithLabel() {
        assertNotNull(QrShare.renderCardForUri(validPairUri, label = "fetch>it chat"))
    }

    // ── renderCardForUri — rejection ─────────────────────────────────

    @Test
    fun renderCardForUriRejectsAutonomiScheme() {
        // autonomi:// URIs are Autonomi addresses, not pair codes; the
        // card must never be issued for them via this entry point.
        assertNull(QrShare.renderCardForUri("autonomi://$validAgentId"))
    }

    @Test
    fun renderCardForUriRejectsArbitraryString() {
        assertNull(QrShare.renderCardForUri("https://example.com"))
    }

    @Test
    fun renderCardForUriRejectsEmptyString() {
        assertNull(QrShare.renderCardForUri(""))
    }

    @Test
    fun renderCardForUriRejectsShortHex() {
        assertNull(QrShare.renderCardForUri("x0x://pair/abcd1234"))
    }

    @Test
    fun renderCardForUriRejectsNonHexSegment() {
        assertNull(QrShare.renderCardForUri("x0x://pair/${"g".repeat(64)}"))
    }

    // ── dimensions match address card ─────────────────────────────────

    @Test
    fun pairCardMatchesAddressCardDimensions() {
        val addressCard = QrShare.renderCardFor("a".repeat(64)) ?: return
        val pairCard = QrShare.renderCardForUri(validPairUri) ?: return
        // Width is fixed (CARD_W = QR_PX + PAD*2 = 560). Height varies with
        // content but the layout path is identical so both cards should be
        // the same size when neither has a label.
        assertEquals(addressCard.width, pairCard.width)
        assertEquals(addressCard.height, pairCard.height)
    }

    @Test
    fun pairCardHasSaneDimensions() {
        val card = QrShare.renderCardForUri(validPairUri)!!
        assertEquals(Bitmap.Config.ARGB_8888, card.config)
        assertEquals(560, card.width)
        // Height must be taller than the QR alone (480 px) to include the footer.
        assert(card.height > 480) { "card height ${card.height} should exceed QR height 480" }
    }

    // ── address card path is unchanged ───────────────────────────────

    @Test
    fun renderCardForRejectsNonHexInput() {
        assertNull(QrShare.renderCardFor("not-an-address"))
    }

    @Test
    fun renderCardForRejectsShortHex() {
        assertNull(QrShare.renderCardFor("abcd1234"))
    }

    @Test
    fun renderCardForAcceptsValidAddress() {
        assertNotNull(QrShare.renderCardFor("a".repeat(64)))
    }
}
