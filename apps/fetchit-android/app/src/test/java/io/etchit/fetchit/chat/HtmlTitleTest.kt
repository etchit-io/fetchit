package io.etchit.fetchit.chat

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Bounded, WebView-free `<title>` extraction for the address-card preview. */
class HtmlTitleTest {

    @Test
    fun extractsSimpleTitle() {
        assertEquals("Hello", HtmlTitle.extract("<html><head><title>Hello</title></head></html>"))
    }

    @Test
    fun tagMatchIsCaseInsensitive() {
        assertEquals("Hello", HtmlTitle.extract("<HEAD><TITLE>Hello</TITLE></HEAD>"))
    }

    @Test
    fun titleWithAttributesMatched() {
        assertEquals("Hello", HtmlTitle.extract("""<title lang="en" dir="ltr">Hello</title>"""))
    }

    @Test
    fun titleBarTagIsNotATitle() {
        assertNull(HtmlTitle.extract("<titlebar>Hello</titlebar>"))
    }

    @Test
    fun titleAfterATitleBarTagStillFound() {
        assertEquals("Real", HtmlTitle.extract("<titlebar>x</titlebar><title>Real</title>"))
    }

    @Test
    fun missingTitleReturnsNull() {
        assertNull(HtmlTitle.extract("<html><body><h1>no head here</h1></body></html>"))
    }

    @Test
    fun unterminatedTitleReturnsNull() {
        assertNull(HtmlTitle.extract("<html><head><title>never closed"))
    }

    @Test
    fun emptyTitleReturnsNull() {
        assertNull(HtmlTitle.extract("<title></title>"))
        assertNull(HtmlTitle.extract("<title>   </title>"))
    }

    @Test
    fun whitespaceCollapsedAndTrimmed() {
        assertEquals("a b c", HtmlTitle.extract("<title>\n  a   b\tc \n</title>"))
    }

    @Test
    fun decodesMinimalEntities() {
        assertEquals(
            """Tom & "Jerry" <it's> ok""",
            HtmlTitle.extract("<title>Tom &amp; &quot;Jerry&quot; &lt;it&#39;s&gt; ok</title>"),
        )
    }

    @Test
    fun nbspBecomesSpace() {
        assertEquals("a b", HtmlTitle.extract("<title>a&nbsp;b</title>"))
    }

    @Test
    fun ampersandEntityIsNotDoubleDecoded() {
        assertEquals("&lt;", HtmlTitle.extract("<title>&amp;lt;</title>"))
    }

    @Test
    fun overlongTitleIsTruncatedWithEllipsis() {
        val title = HtmlTitle.extract("<title>${"a".repeat(400)}</title>")!!
        assertEquals(HtmlTitle.MAX_TITLE_CHARS, title.length)
        assertTrue(title.endsWith("…"))
    }

    @Test
    fun titleBeyondScanLimitIsIgnored() {
        val padding = "<!--${"p".repeat(HtmlTitle.SCAN_LIMIT_CHARS)}-->"
        assertNull(HtmlTitle.extract("$padding<title>too late</title>"))
    }

    @Test
    fun titleWithinScanLimitOfAnOversizedDocumentIsFound() {
        val tail = "x".repeat(HtmlTitle.SCAN_LIMIT_CHARS * 2)
        assertEquals("early", HtmlTitle.extract("<title>early</title>$tail"))
    }

    @Test
    fun emptyDocumentReturnsNull() {
        assertNull(HtmlTitle.extract(""))
    }
}
