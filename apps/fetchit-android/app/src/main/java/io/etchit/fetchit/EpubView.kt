package io.etchit.fetchit

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.util.AttributeSet
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import java.io.ByteArrayInputStream

/**
 * An EPUB reader. An EPUB is a ZIP of (X)HTML chapters + CSS + images +
 * a package document; fetch>it already renders HTML, so this is mostly:
 * pick a chapter from the spine, hand its (X)HTML to a WebView with the
 * chapter's directory as the base URL, and serve the chapter's
 * CSS/images out of the parsed [`EpubBook`]'s in-memory entry map.
 *
 * Chrome on top: a slim bar — TOC, chapter title, A−/A+ font scaling,
 * ‹ prev / next ›. Nothing is persisted across books except the font
 * size; the current chapter is remembered per-book so re-opening
 * resumes where you left off. System back exits the reader (the host's
 * close button does too); chapter navigation is the ‹ › buttons.
 */
@SuppressLint("SetJavaScriptEnabled")
class EpubView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private var book: EpubBook? = null
    private var bookAddr: String? = null
    private var index = 0
    private var fontPct = loadFontPref()

    /** Fired when the user taps ✕ or presses system back — the host clears the rendition. */
    private var onExit: (() -> Unit)? = null
    private var backCb: androidx.activity.OnBackPressedCallback? = null
    fun setOnExit(cb: () -> Unit) { onExit = cb }

    private val titleView = TextView(context).apply {
        setTextColor(BONE); textSize = 12.5f; maxLines = 1
        ellipsize = android.text.TextUtils.TruncateAt.END
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(8), 0, dp(8), 0)
    }
    private val prevBtn = barButton("‹") { goRelative(-1) }
    private val nextBtn = barButton("›") { goRelative(1) }
    private val tocBtn = barButton("≡") { showToc() }

    private val webView: WebView = WebView(context).apply {
        settings.apply {
            javaScriptEnabled = true       // some EPUBs use JS; font scaling injects a property
            domStorageEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            cacheMode = WebSettings.LOAD_DEFAULT
        }
        setBackgroundColor(PAPER)
        overScrollMode = OVER_SCROLL_NEVER
        webViewClient = ReaderClient()
    }

    init {
        orientation = VERTICAL
        // ── chrome bar ───────────────────────────────────────────────
        val bar = LinearLayout(context).apply {
            orientation = HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(INK)
            setPadding(dp(4), dp(2), dp(4), dp(2))
        }
        bar.addView(barButton("✕") { onExit?.invoke() })
        bar.addView(tocBtn)
        bar.addView(titleView, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
        bar.addView(barButton("A−") { adjustFont(-10) })
        bar.addView(barButton("A+") { adjustFont(+10) })
        bar.addView(prevBtn)
        bar.addView(nextBtn)
        addView(bar, LayoutParams(LayoutParams.MATCH_PARENT, dp(40)))
        // ── content ──────────────────────────────────────────────────
        addView(webView, LayoutParams(LayoutParams.MATCH_PARENT, 0, 1f))
    }

    /** Parse [bytes] and show the EPUB. Returns false if it isn't a readable EPUB. */
    fun bind(addr: String, bytes: ByteArray): Boolean {
        val parsed = EpubBook.parse(bytes) ?: return false
        book = parsed
        bookAddr = addr
        index = loadChapterPref(addr).coerceIn(0, parsed.chapters.lastIndex)
        loadChapter(index, null)
        if (backCb == null) (context as? androidx.activity.ComponentActivity)?.let { ca ->
            val cb = object : androidx.activity.OnBackPressedCallback(true) {
                override fun handleOnBackPressed() { onExit?.invoke() }
            }
            ca.onBackPressedDispatcher.addCallback(cb)
            backCb = cb
        }
        return true
    }

    /** Free the in-memory EPUB and blank the WebView. Call from the host's clear path. */
    fun release() {
        backCb?.remove(); backCb = null
        webView.stopLoading()
        webView.loadUrl("about:blank")
        book = null
        bookAddr = null
    }

    // ─── chapter loading ───────────────────────────────────────────────

    private fun loadChapter(i: Int, anchor: String?) {
        val b = book ?: return
        if (i !in b.chapters.indices) return
        index = i
        val raw = b.chapterHtml(i) ?: run { Log.w(TAG, "chapter $i has no html"); return }
        val html = injectReaderCss(raw, fontPct)
        pendingAnchor = anchor
        webView.loadDataWithBaseURL("$EPUB_ORIGIN/${b.chapters[i].dir}", html, "text/html", "UTF-8", null)
        titleView.text = b.chapters[i].title
        prevBtn.isEnabled = i > 0
        nextBtn.isEnabled = i < b.chapters.lastIndex
        prevBtn.alpha = if (prevBtn.isEnabled) 1f else 0.3f
        nextBtn.alpha = if (nextBtn.isEnabled) 1f else 0.3f
        bookAddr?.let { saveChapterPref(it, i) }
    }

    private fun goRelative(delta: Int) = loadChapter(index + delta, null)

    private fun showToc() {
        val b = book ?: return
        val labels = b.toc.map { "    ".repeat(it.depth.coerceAtMost(3)) + it.title }.toTypedArray()
        AlertDialog.Builder(context)
            .setTitle(b.title)
            .setItems(labels) { _, which ->
                val e = b.toc[which]
                if (e.chapterIndex >= 0) loadChapter(e.chapterIndex, e.anchor)
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun adjustFont(delta: Int) {
        fontPct = (fontPct + delta).coerceIn(70, 220)
        saveFontPref(fontPct)
        webView.evaluateJavascript(
            "document.documentElement.style.setProperty('--epub-fs','${fontPct}%')", null,
        )
    }

    private var pendingAnchor: String? = null

    private inner class ReaderClient : WebViewClient() {
        override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
            val url = request?.url?.toString() ?: return null
            if (!url.startsWith(EPUB_PREFIX)) {
                // Only the EPUB-internal scheme resolves through this
                // client; data/blob/about pass through as page-internal,
                // everything else is refused.
                return when (request?.url?.scheme?.lowercase()) {
                    "data", "blob", "about" -> null
                    else -> blocked()
                }
            }
            val path = EpubBook.normalize(url.removePrefix(EPUB_PREFIX).substringBefore('?').substringBefore('#'))
            val raw = book?.entry(path)
                ?: return notFound(path)
            val mime = mimeFor(path, raw)
            // A full-size cover/illustration JPEG decodes into a tile far bigger
            // than the WebView's budget — downscale anything wide before serving.
            val data = if (mime.startsWith("image/") && mime != "image/svg+xml") downscaleImage(raw) else raw
            return WebResourceResponse(
                mime, null, 200, "OK",
                mapOf("Access-Control-Allow-Origin" to "*", "Cache-Control" to "no-store"),
                ByteArrayInputStream(data),
            )
        }

        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
            val url = request?.url?.toString() ?: return false
            if (url == "about:blank") return false
            if (url.startsWith(EPUB_PREFIX)) {
                // In-EPUB link: jump to that spine chapter (re-loading with the
                // correct base URL), or ignore if it's not a spine document.
                val href = url.removePrefix(EPUB_PREFIX)
                val anchor = href.substringAfter('#', "").ifBlank { null }
                val path = EpubBook.normalize(href.substringBefore('#'))
                val b = book ?: return true
                val target = b.chapters.indexOfFirst { it.path == path }
                if (target >= 0) loadChapter(target, anchor)
                return true
            }
            // Out-of-archive http(s) links are refused, not followed.
            if (url.startsWith("http://") || url.startsWith("https://")) return true
            return false
        }

        override fun onPageFinished(view: WebView?, url: String?) {
            if (url == "about:blank") return
            // Re-apply the chosen font size (the injected default is only a fallback)…
            view?.evaluateJavascript("document.documentElement.style.setProperty('--epub-fs','${fontPct}%')", null)
            // …and scroll to the in-page anchor, if the TOC/link aimed at one.
            pendingAnchor?.let { a ->
                val safe = a.replace("'", "\\'")
                view?.evaluateJavascript(
                    "(function(){var e=document.getElementById('$safe')||document.querySelector('[name=\"$safe\"]');if(e)e.scrollIntoView();})()",
                    null,
                )
            }
            pendingAnchor = null
        }
    }

    // ─── helpers ───────────────────────────────────────────────────────

    private fun injectReaderCss(html: String, pct: Int): String {
        val css = """
            <style id="__epub_reader__">
              html{font-size:var(--epub-fs,$pct%);-webkit-text-size-adjust:100%;}
              body{max-width:42em;margin:0 auto;padding:1.4em 1.15em 4.5em;line-height:1.7;
                   word-wrap:break-word;overflow-wrap:break-word;}
              img,svg,video{max-width:100%;height:auto;}
              a{overflow-wrap:break-word;}
              pre{white-space:pre-wrap;overflow-wrap:break-word;}
              table{max-width:100%;}
              /* A Gutenberg-style EPUB bundles several chapters per HTML file
                 → a 20k-px scroll the WebView can't fully rasterize. Skip
                 rendering off-screen blocks so it only paints what's visible. */
              p,blockquote,ul,ol,dl,table,pre,figure,div,h1,h2,h3,h4,h5,h6,hr{
                content-visibility:auto;contain-intrinsic-size:auto 1.4em;}
            </style>
        """.trimIndent()
        val headClose = Regex("</head\\s*>", RegexOption.IGNORE_CASE).find(html)
        return if (headClose != null) {
            html.substring(0, headClose.range.first) + css + html.substring(headClose.range.first)
        } else css + html
    }

    /** If the image is wider/taller than ~1400 px, decode it down and re-encode (JPEG q82). Otherwise pass through. */
    private fun downscaleImage(bytes: ByteArray): ByteArray = try {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        val (w, h) = bounds.outWidth to bounds.outHeight
        if (w <= 0 || h <= 0 || (w <= MAX_IMG_PX && h <= MAX_IMG_PX)) bytes else {
            var sample = 1
            while (w / (sample * 2) >= MAX_IMG_PX || h / (sample * 2) >= MAX_IMG_PX) sample *= 2
            val opts = BitmapFactory.Options().apply { inSampleSize = sample }
            val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts) ?: return bytes
            val scale = (MAX_IMG_PX.toFloat() / maxOf(bmp.width, bmp.height)).coerceAtMost(1f)
            val final = if (scale < 1f) Bitmap.createScaledBitmap(bmp, (bmp.width * scale).toInt().coerceAtLeast(1), (bmp.height * scale).toInt().coerceAtLeast(1), true) else bmp
            val out = java.io.ByteArrayOutputStream()
            final.compress(Bitmap.CompressFormat.JPEG, 82, out)
            if (final !== bmp) final.recycle()
            bmp.recycle()
            out.toByteArray()
        }
    } catch (_: Exception) { bytes }

    private fun mimeFor(path: String, bytes: ByteArray): String {
        val ext = path.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "css" -> "text/css"
            "js", "mjs" -> "application/javascript"
            "html", "htm", "xhtml" -> "text/html"
            "xml", "ncx", "opf" -> "application/xml"
            "json" -> "application/json"
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "webp" -> "image/webp"
            "svg" -> "image/svg+xml"
            "bmp" -> "image/bmp"
            "ttf" -> "font/ttf"
            "otf" -> "font/otf"
            "woff" -> "font/woff"
            "woff2" -> "font/woff2"
            "mp3" -> "audio/mpeg"
            "m4a", "aac" -> "audio/mp4"
            "ogg", "oga" -> "audio/ogg"
            "mp4", "m4v" -> "video/mp4"
            "webm" -> "video/webm"
            else -> when {
                bytes.size >= 4 && bytes[0] == 0x89.toByte() && bytes[1] == 0x50.toByte() -> "image/png"
                bytes.size >= 3 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() -> "image/jpeg"
                bytes.size >= 4 && bytes[0] == 'G'.code.toByte() && bytes[1] == 'I'.code.toByte() -> "image/gif"
                else -> "application/octet-stream"
            }
        }
    }

    private fun notFound(path: String): WebResourceResponse {
        // Browsers always probe /favicon.ico — not worth a warning every time.
        if (!path.endsWith("favicon.ico")) Log.w(TAG, "EPUB resource not in archive: $path")
        return WebResourceResponse(
            "text/plain", "utf-8", 404, "Not Found",
            mapOf("Access-Control-Allow-Origin" to "*"),
            ByteArrayInputStream(ByteArray(0)),
        )
    }

    private fun blocked(): WebResourceResponse = WebResourceResponse(
        "text/plain", "utf-8", 403, "Blocked",
        mapOf("Access-Control-Allow-Origin" to "*"),
        ByteArrayInputStream(ByteArray(0)),
    )

    private fun barButton(label: String, onClick: () -> Unit): TextView = TextView(context).apply {
        text = label
        setTextColor(COPPER)
        textSize = 16f
        gravity = Gravity.CENTER
        minWidth = dp(40)
        minHeight = dp(40)
        setPadding(dp(8), 0, dp(8), 0)
        isClickable = true
        isFocusable = true
        // ?attr/selectableItemBackgroundBorderless ripple
        val outValue = android.util.TypedValue()
        context.theme.resolveAttribute(android.R.attr.selectableItemBackgroundBorderless, outValue, true)
        if (outValue.resourceId != 0) setBackgroundResource(outValue.resourceId)
        setOnClickListener { onClick() }
    }

    private fun dp(v: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    // ─── per-book chapter memory + global font-size pref ──────────────

    private fun prefs() = context.getSharedPreferences("epub_reader", Context.MODE_PRIVATE)
    private fun loadFontPref() = context.getSharedPreferences("epub_reader", Context.MODE_PRIVATE).getInt("font_pct", 108)
    private fun saveFontPref(pct: Int) = prefs().edit().putInt("font_pct", pct).apply()
    private fun loadChapterPref(addr: String) = prefs().getInt("ch_$addr", 0)
    private fun saveChapterPref(addr: String, i: Int) = prefs().edit().putInt("ch_$addr", i).apply()

    private companion object {
        const val TAG = "fetchit.epub"
        const val EPUB_ORIGIN = "https://epub.local"
        const val EPUB_PREFIX = "$EPUB_ORIGIN/"
        const val MAX_IMG_PX = 1400
        val INK = Color.parseColor("#0a0a0a")
        val BONE = Color.parseColor("#d6cfc0")
        val COPPER = Color.parseColor("#c9732b")
        val PAPER = Color.parseColor("#fdfaf3")
    }
}
