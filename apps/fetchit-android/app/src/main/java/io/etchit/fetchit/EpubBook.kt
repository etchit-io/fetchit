package io.etchit.fetchit

import android.util.Log
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

/**
 * A parsed EPUB: every entry's bytes in memory, the reading-order
 * chapter list (from the OPF `<spine>`), the table of contents (EPUB 3
 * `nav.xhtml` or EPUB 2 NCX, falling back to the spine), and the book's
 * title.
 *
 * An EPUB is just a ZIP of (X)HTML chapters + CSS + images + a package
 * document (the OPF) listing them. fetch>it already renders HTML, so the
 * reader is mostly: pick a chapter from the spine, hand its (X)HTML to a
 * WebView with the chapter's directory as the base URL, and serve the
 * chapter's CSS/images out of the in-memory entry map on demand.
 */
class EpubBook private constructor(
    val title: String,
    val author: String?,
    /** Reading-order chapters — EPUB-root-relative paths, e.g. `OEBPS/Text/ch1.xhtml`. */
    val chapters: List<Chapter>,
    /** Table of contents; each entry points at a chapter index (+ optional in-page anchor). */
    val toc: List<TocEntry>,
    /** Every ZIP entry: EPUB-root-relative path → bytes. */
    private val entries: Map<String, ByteArray>,
) {
    data class Chapter(
        /** EPUB-root-relative path of the chapter document. */
        val path: String,
        /** Directory of [path], with a trailing slash (or "" if at the root). */
        val dir: String,
        /** Best-effort chapter title (from the TOC, the `<title>`, or "Chapter N"). */
        var title: String,
    )

    data class TocEntry(
        val title: String,
        /** Index into [chapters], or -1 if the href didn't match any spine item. */
        val chapterIndex: Int,
        /** In-page anchor (the part after `#` in the TOC href), or null. */
        val anchor: String?,
        /** Nesting depth (0 = top level) — used purely for indentation in the TOC list. */
        val depth: Int,
    )

    /** Raw bytes of an entry by EPUB-root-relative path (handles `..`/`.`/percent-encoding). */
    fun entry(path: String): ByteArray? = entries[normalize(path)]

    /** The chapter document's bytes, decoded as UTF-8 (EPUB chapters are UTF-8). */
    fun chapterHtml(index: Int): String? =
        entries[chapters[index].path]?.toString(Charsets.UTF_8)

    companion object {
        private const val TAG = "fetchit.epub"
        private const val CONTAINER = "META-INF/container.xml"

        /** Refuse EPUBs whose total uncompressed size exceeds this — a zip-bomb guard. */
        private const val MAX_EPUB_UNCOMPRESSED = 200L * 1024 * 1024

        /** True if these bytes look like an EPUB (a ZIP carrying `META-INF/container.xml`). */
        fun looksLikeEpub(entryNames: Collection<String>): Boolean = entryNames.contains(CONTAINER)

        /**
         * Parse [bytes] (a full EPUB file). Returns null if it isn't a
         * well-formed enough EPUB to read (no container, no OPF, empty
         * spine). Best-effort everywhere else — a broken TOC falls back
         * to the spine, a missing title falls back to "Untitled".
         */
        fun parse(bytes: ByteArray): EpubBook? {
            return try {
            val entries = unzip(bytes)
            val containerXml = entries[CONTAINER] ?: return null.also { Log.w(TAG, "no $CONTAINER") }
            val opfPath = parseContainer(containerXml) ?: return null.also { Log.w(TAG, "no rootfile in container.xml") }
            val opfBytes = entries[normalize(opfPath)] ?: return null.also { Log.w(TAG, "OPF $opfPath not in archive") }
            val opfDir = dirOf(normalize(opfPath))

            val doc = xml(opfBytes)
            val title = firstText(doc, "title")?.trim()?.ifBlank { null } ?: "Untitled"
            val author = firstText(doc, "creator")?.trim()?.ifBlank { null }

            // manifest: id -> (href relative to OPF dir, media-type, properties)
            data class Item(val href: String, val mediaType: String, val properties: String)
            val manifest = HashMap<String, Item>()
            for (el in elements(doc, "item")) {
                val id = el.getAttribute("id") ?: continue
                if (id.isBlank()) continue
                manifest[id] = Item(
                    href = el.getAttribute("href") ?: "",
                    mediaType = el.getAttribute("media-type") ?: "",
                    properties = el.getAttribute("properties") ?: "",
                )
            }

            // spine: ordered idrefs -> chapter paths
            val spineEl = elements(doc, "spine").firstOrNull() ?: return null.also { Log.w(TAG, "no <spine>") }
            val ncxId = spineEl.getAttribute("toc")?.ifBlank { null }
            val chapters = ArrayList<Chapter>()
            for (ir in childElements(spineEl, "itemref")) {
                val idref = ir.getAttribute("idref") ?: continue
                val item = manifest[idref] ?: continue
                if (item.href.isBlank()) continue
                val path = normalize(opfDir + item.href)
                if (!entries.containsKey(path)) { Log.w(TAG, "spine item $path missing from archive"); continue }
                chapters.add(Chapter(path = path, dir = dirOf(path), title = ""))
            }
            if (chapters.isEmpty()) return null.also { Log.w(TAG, "spine resolved to 0 readable chapters") }

            // path -> chapter index (for resolving TOC hrefs)
            val pathToIndex = HashMap<String, Int>()
            chapters.forEachIndexed { i, c -> pathToIndex.putIfAbsent(c.path, i) }

            // table of contents — EPUB 3 nav, then EPUB 2 NCX, then the spine itself
            val toc = run {
                val navItem = manifest.values.firstOrNull { it.properties.split(Regex("\\s+")).contains("nav") }
                val ncxItem = ncxId?.let { manifest[it] } ?: manifest.values.firstOrNull { it.mediaType == "application/x-dtbncx+xml" }
                try {
                    if (navItem != null) {
                        val navPath = normalize(opfDir + navItem.href)
                        entries[navPath]?.let { parseNav(xml(it), dirOf(navPath), pathToIndex) }
                    } else null
                } catch (e: Exception) { Log.w(TAG, "nav parse failed: ${e.message}"); null }
                    ?: try {
                        if (ncxItem != null) {
                            val ncxPath = normalize(opfDir + ncxItem.href)
                            entries[ncxPath]?.let { parseNcx(xml(it), dirOf(ncxPath), pathToIndex) }
                        } else null
                    } catch (e: Exception) { Log.w(TAG, "ncx parse failed: ${e.message}"); null }
                    ?: chapters.indices.map { TocEntry("Chapter ${it + 1}", it, null, 0) }
            }

            // give each chapter a title: prefer the first TOC entry pointing at it, else <title>/<h1>, else "Chapter N"
            val firstTocForChapter = HashMap<Int, String>()
            toc.forEach { if (it.chapterIndex >= 0 && !firstTocForChapter.containsKey(it.chapterIndex)) firstTocForChapter[it.chapterIndex] = it.title }
            chapters.forEachIndexed { i, c ->
                c.title = firstTocForChapter[i]
                    ?: entries[c.path]?.toString(Charsets.UTF_8)?.let { titleFromHtml(it) }
                    ?: "Chapter ${i + 1}"
            }

            Log.i(TAG, "parsed \"$title\": ${chapters.size} chapters, ${toc.size} TOC entries")
            EpubBook(title, author, chapters, toc, entries)
        } catch (e: Exception) {
            Log.w(TAG, "EPUB parse failed: ${e.message}", e)
            null
        }
        }

        // ─── parsing helpers ───────────────────────────────────────────

        private fun unzip(bytes: ByteArray): Map<String, ByteArray> {
            val out = LinkedHashMap<String, ByteArray>()
            var total = 0L
            ZipInputStream(ByteArrayInputStream(bytes)).use { zin ->
                var e = zin.nextEntry
                val buf = ByteArray(16 * 1024)
                while (e != null) {
                    if (!e.isDirectory) {
                        val baos = java.io.ByteArrayOutputStream()
                        var n = zin.read(buf)
                        while (n >= 0) {
                            total += n
                            if (total > MAX_EPUB_UNCOMPRESSED) error("EPUB exceeds the uncompressed-size limit")
                            baos.write(buf, 0, n)
                            n = zin.read(buf)
                        }
                        out[normalize(e.name)] = baos.toByteArray()
                    }
                    zin.closeEntry()
                    e = zin.nextEntry
                }
            }
            return out
        }

        private fun xml(bytes: ByteArray): Document =
            DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = false   // match local element names; ignore namespaces
                isValidating = false
                runCatching { setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false) }
                runCatching { setFeature("http://xml.org/sax/features/external-general-entities", false) }
                runCatching { setFeature("http://xml.org/sax/features/external-parameter-entities", false) }
            }.newDocumentBuilder().parse(ByteArrayInputStream(bytes))

        private fun parseContainer(bytes: ByteArray): String? {
            val doc = xml(bytes)
            return elements(doc, "rootfile")
                .firstOrNull { val m = it.getAttribute("media-type"); m.isNullOrBlank() || m == "application/oebps-package+xml" || elements(doc, "rootfile").size == 1 }
                ?.getAttribute("full-path")?.ifBlank { null }
                ?: elements(doc, "rootfile").firstOrNull()?.getAttribute("full-path")?.ifBlank { null }
        }

        /** EPUB 3 navigation document: the `<nav epub:type="toc">` (or first `<nav>`) → flatten its `<ol>`. */
        private fun parseNav(doc: Document, navDir: String, pathToIndex: Map<String, Int>): List<TocEntry>? {
            val navs = elements(doc, "nav")
            val tocNav = navs.firstOrNull { val t = it.getAttribute("epub:type") ?: ""; t.split(Regex("\\s+")).contains("toc") }
                ?: navs.firstOrNull { (it.getAttribute("role") ?: "").contains("toc") }
                ?: navs.firstOrNull() ?: return null
            val ol = childElements(tocNav, "ol").firstOrNull() ?: return null
            val out = ArrayList<TocEntry>()
            fun walk(list: Element, depth: Int) {
                for (li in childElements(list, "li")) {
                    val a = descendants(li, "a").firstOrNull()
                    val span = descendants(li, "span").firstOrNull()
                    val label = (a?.textContent ?: span?.textContent)?.trim()?.replace(Regex("\\s+"), " ")?.ifBlank { null }
                    val href = a?.getAttribute("href")?.ifBlank { null }
                    if (label != null) out.add(tocEntry(label, href, navDir, pathToIndex, depth))
                    childElements(li, "ol").forEach { walk(it, depth + 1) }
                }
            }
            walk(ol, 0)
            return out.ifEmpty { null }
        }

        /** EPUB 2 NCX: `<navMap>` → recursive `<navPoint>` with `<navLabel><text>` + `<content src>`. */
        private fun parseNcx(doc: Document, ncxDir: String, pathToIndex: Map<String, Int>): List<TocEntry>? {
            val navMap = elements(doc, "navMap").firstOrNull() ?: return null
            val out = ArrayList<TocEntry>()
            fun walk(parent: Element, depth: Int) {
                for (np in childElements(parent, "navPoint")) {
                    val label = descendants(np, "text").firstOrNull()?.textContent?.trim()?.replace(Regex("\\s+"), " ")?.ifBlank { null }
                    val src = childElements(np, "content").firstOrNull()?.getAttribute("src")?.ifBlank { null }
                    if (label != null) out.add(tocEntry(label, src, ncxDir, pathToIndex, depth))
                    walk(np, depth + 1)
                }
            }
            walk(navMap, 0)
            return out.ifEmpty { null }
        }

        private fun tocEntry(title: String, href: String?, baseDir: String, pathToIndex: Map<String, Int>, depth: Int): TocEntry {
            if (href == null) return TocEntry(title, -1, null, depth)
            val anchor = href.substringAfter('#', "").ifBlank { null }
            val pathPart = href.substringBefore('#')
            val resolved = normalize(baseDir + pathPart)
            return TocEntry(title, pathToIndex[resolved] ?: -1, anchor, depth)
        }

        // ─── tiny DOM helpers (namespace-unaware: match by local/full name) ───

        private fun elements(doc: Document, name: String): List<Element> {
            val out = ArrayList<Element>()
            val nl = doc.getElementsByTagName("*")
            for (i in 0 until nl.length) {
                val n = nl.item(i)
                if (n is Element && localName(n).equals(name, ignoreCase = true)) out.add(n)
            }
            return out
        }

        private fun childElements(parent: Element, name: String): List<Element> {
            val out = ArrayList<Element>()
            val nl = parent.childNodes
            for (i in 0 until nl.length) {
                val n = nl.item(i)
                if (n is Element && localName(n).equals(name, ignoreCase = true)) out.add(n)
            }
            return out
        }

        private fun descendants(parent: Element, name: String): List<Element> {
            val out = ArrayList<Element>()
            val nl = parent.getElementsByTagName("*")
            for (i in 0 until nl.length) {
                val n = nl.item(i)
                if (n is Element && localName(n).equals(name, ignoreCase = true)) out.add(n)
            }
            return out
        }

        private fun localName(e: Element): String = e.localName ?: e.nodeName.substringAfter(':')

        private fun firstText(doc: Document, name: String): String? =
            elements(doc, name).firstOrNull()?.textContent

        private fun titleFromHtml(html: String): String? {
            Regex("<title[^>]*>(.*?)</title>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                .find(html)?.groupValues?.get(1)?.let { stripTags(it) }?.ifBlank { null }?.let { return it }
            Regex("<h[1-6][^>]*>(.*?)</h[1-6]>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                .find(html)?.groupValues?.get(1)?.let { stripTags(it) }?.ifBlank { null }?.let { return it }
            return null
        }

        private fun stripTags(s: String): String =
            s.replace(Regex("<[^>]+>"), " ")
                .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                .replace("&#39;", "'").replace("&quot;", "\"").replace("&nbsp;", " ")
                .replace(Regex("\\s+"), " ").trim()

        // ─── path normalization ────────────────────────────────────────

        /** EPUB-root-relative, percent-decoded, `..`/`.`-collapsed, no leading slash. */
        fun normalize(raw: String): String {
            var p = raw.trim()
            // strip a synthetic-origin prefix if one slipped through
            p = p.removePrefix("https://epub.local/").removePrefix("http://epub.local/")
            p = try { java.net.URLDecoder.decode(p, "UTF-8") } catch (_: Exception) { p }
            p = p.replace('\\', '/').removePrefix("/")
            val parts = ArrayDeque<String>()
            for (seg in p.split('/')) {
                when (seg) {
                    "", "." -> {}
                    ".." -> if (parts.isNotEmpty()) parts.removeLast()
                    else -> parts.addLast(seg)
                }
            }
            return parts.joinToString("/")
        }

        private fun dirOf(path: String): String {
            val i = path.lastIndexOf('/')
            return if (i < 0) "" else path.substring(0, i + 1)
        }
    }
}
