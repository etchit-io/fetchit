package io.etchit.fetchit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Unit tests for [EpubBook] — path normalization (the path-traversal guard),
 * EPUB detection, and [EpubBook.parse] on a valid book and malformed inputs.
 */
class EpubBookTest {

    // ── normalize: path-traversal / percent-decode / separators ──────────

    @Test
    fun normalize_leaves_a_clean_relative_path_unchanged() {
        assertEquals("OEBPS/Text/ch1.xhtml", EpubBook.normalize("OEBPS/Text/ch1.xhtml"))
    }

    @Test
    fun normalize_collapses_dot_and_double_dot_segments() {
        assertEquals("ch1.xhtml", EpubBook.normalize("OEBPS/../ch1.xhtml"))
        assertEquals("a/b", EpubBook.normalize("a/./b"))
        assertEquals("a/b", EpubBook.normalize("a//b"))
    }

    @Test
    fun normalize_cannot_escape_the_epub_root() {
        // `..` past the root is dropped — no traversal outside the archive.
        assertEquals("etc/passwd", EpubBook.normalize("../../etc/passwd"))
        assertEquals("x", EpubBook.normalize("../../../x"))
    }

    @Test
    fun normalize_strips_leading_slash_and_normalizes_backslashes() {
        assertEquals("a/b", EpubBook.normalize("/a/b"))
        assertEquals("a/b", EpubBook.normalize("a\\b"))
    }

    @Test
    fun normalize_percent_decodes() {
        assertEquals("a b/c", EpubBook.normalize("a%20b/c"))
    }

    @Test
    fun normalize_strips_synthetic_origin_prefix() {
        assertEquals("OEBPS/x", EpubBook.normalize("https://epub.local/OEBPS/x"))
        assertEquals("OEBPS/x", EpubBook.normalize("http://epub.local/OEBPS/x"))
    }

    // ── looksLikeEpub ────────────────────────────────────────────────────

    @Test
    fun looksLikeEpub_requires_the_container_entry() {
        assertTrue(EpubBook.looksLikeEpub(listOf("META-INF/container.xml", "content.opf")))
        assertFalse(EpubBook.looksLikeEpub(listOf("content.opf", "ch1.xhtml")))
        assertFalse(EpubBook.looksLikeEpub(emptyList()))
    }

    // ── parse: happy path ────────────────────────────────────────────────

    @Test
    fun parse_reads_title_author_chapters_and_toc() {
        val book = EpubBook.parse(minimalEpub())
        assertNotNull(book)
        book!!
        assertEquals("Test Book", book.title)
        assertEquals("An Author", book.author)
        assertEquals(1, book.chapters.size)
        assertEquals("ch1.xhtml", book.chapters[0].path)
        assertEquals(1, book.toc.size)
        assertTrue(book.chapterHtml(0)!!.contains("hello"))
    }

    // ── parse: malformed inputs all return null ──────────────────────────

    @Test
    fun parse_returns_null_for_non_zip_bytes() {
        assertNull(EpubBook.parse("this is not a zip file".toByteArray()))
    }

    @Test
    fun parse_returns_null_when_the_container_entry_is_missing() {
        assertNull(EpubBook.parse(epubZip("random.txt" to "nothing useful here")))
    }

    @Test
    fun parse_returns_null_when_the_container_names_no_rootfile() {
        assertNull(
            EpubBook.parse(
                epubZip("META-INF/container.xml" to """<?xml version="1.0"?><container></container>"""),
            ),
        )
    }

    @Test
    fun parse_returns_null_when_the_spine_is_empty() {
        assertNull(
            EpubBook.parse(
                epubZip(
                    "META-INF/container.xml" to CONTAINER_XML,
                    "content.opf" to """<?xml version="1.0"?>
                        <package xmlns:dc="http://purl.org/dc/elements/1.1/">
                          <metadata><dc:title>T</dc:title></metadata>
                          <manifest></manifest>
                          <spine></spine>
                        </package>""",
                ),
            ),
        )
    }

    // ── fixtures ─────────────────────────────────────────────────────────

    /** Build an in-memory ZIP from `name to content` pairs. */
    private fun epubZip(vararg entries: Pair<String, String>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zip ->
            for ((name, content) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(content.toByteArray())
                zip.closeEntry()
            }
        }
        return baos.toByteArray()
    }

    /** A minimal well-formed EPUB: container + OPF + one chapter. */
    private fun minimalEpub(): ByteArray = epubZip(
        "META-INF/container.xml" to CONTAINER_XML,
        "content.opf" to """<?xml version="1.0"?>
            <package xmlns:dc="http://purl.org/dc/elements/1.1/">
              <metadata>
                <dc:title>Test Book</dc:title>
                <dc:creator>An Author</dc:creator>
              </metadata>
              <manifest>
                <item id="c1" href="ch1.xhtml" media-type="application/xhtml+xml"/>
              </manifest>
              <spine><itemref idref="c1"/></spine>
            </package>""",
        "ch1.xhtml" to "<html><head><title>Chapter One</title></head><body><p>hello</p></body></html>",
    )

    private companion object {
        const val CONTAINER_XML = """<?xml version="1.0"?>
            <container version="1.0">
              <rootfiles>
                <rootfile full-path="content.opf" media-type="application/oebps-package+xml"/>
              </rootfiles>
            </container>"""
    }
}
