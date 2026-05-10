package io.etchit.fetchit

import android.annotation.SuppressLint
import android.content.Context
import android.util.AttributeSet
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.net.URLConnection

/**
 * Loads a self-contained HTML body into a sandboxed `WebView` and
 * resolves any `autonomi://<64-hex>` resource references through
 * fetch/it's [`Client`].
 *
 * **Synthetic-origin trick (load-bearing).** The WebView is told its
 * base URL is [`SYNTH_ORIGIN`] (`https://aut.local`). At load time the
 * raw `autonomi://<addr>` references in the document are rewritten to
 * `https://aut.local/<addr>` so that *every* web-platform API — the
 * Fetch spec's `fetch()`, `XMLHttpRequest`, `<img>` / `<audio>` /
 * `<video>` / `<script>` / `<link>` / `<a>`, Streams, Service Workers,
 * `Range` requests, CORS — sees what looks like a perfectly normal
 * https URL and just works.
 *
 * Nothing about that origin actually exists on the traditional
 * internet. There is no DNS query for `aut.local`, no TLS handshake.
 * Every request to it is caught by [`shouldInterceptRequest`] inside
 * the app, the 64-hex path component is extracted, and the bytes are
 * pulled from the connected fetch/it [`Client`] over the Autonomi P2P
 * connection. The browser engine sees https plumbing; the actual
 * pipeline stays content-addressed and traditional-internet-free.
 *
 * **Why we can't just use `autonomi://`.** The Fetch spec restricts
 * `fetch()`/XHR to http(s)/data/blob/file. Custom schemes are rejected
 * at the URL parser layer before any embedder hook fires. Resource
 * elements have a different loader path; in some WebView versions
 * even those reject custom schemes silently. Wearing an https mask
 * is the only approach that guarantees the full standard API surface
 * works for SPAs.
 *
 * **Sandbox stance**:
 *  - JavaScript on (SPAs need it)
 *  - Network on (CDN-loaded https assets are real if the page reaches
 *    out beyond `aut.local`; SPAs that want zero traditional-internet
 *    dependency simply don't reference any other origin)
 *  - File-system access OFF (no `file://` reads of the device)
 *  - Content-provider access OFF
 *  - DOM storage OFF (don't persist anything across fetches)
 *  - No `JavascriptInterface` — fetched pages can't call into native
 *
 * **For SPA authors.** Either `autonomi://<addr>` or
 * `https://aut.local/<addr>` works as a static reference (the former
 * is rewritten to the latter on load). For URLs constructed
 * dynamically in JS, use the synthetic form directly:
 * ```js
 * const r = await fetch(`https://aut.local/${addr}`);
 * ```
 */
@SuppressLint("SetJavaScriptEnabled")
class HtmlView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : FrameLayout(context, attrs, defStyleAttr) {

    /** In-memory cache keyed by 64-hex address. Cleared on [`release`]. */
    private val resourceCache = HashMap<String, CachedResource>()

    /**
     * Fired when the rendered page contains a top-level link to an
     * Autonomi address the user taps. The host typically routes this
     * to a fresh fetch — the WebView itself doesn't follow the link.
     */
    private var onAutonomiNavigate: ((String) -> Unit)? = null

    /** Wire a handler for in-page top-level autonomi navigations. */
    fun setOnAutonomiNavigate(callback: (String) -> Unit) {
        onAutonomiNavigate = callback
    }

    private val webView: WebView = WebView(context).apply {
        settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            cacheMode = android.webkit.WebSettings.LOAD_DEFAULT
        }
        setBackgroundColor(0)
        webViewClient = AutonomiWebViewClient()
    }

    init {
        addView(
            webView,
            LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT),
        )
    }

    /**
     * Render `html`. Replaces any in-flight page. Rewrites every
     * `autonomi://<64-hex>` reference in the source to the synthetic
     * https form before handing the document to the WebView so that
     * fetch() / XHR / Streams etc. all work transparently. The
     * pattern is anchored to a real 64-hex address so prose that
     * mentions the scheme abstractly (e.g. "the autonomi:// URL
     * scheme...") is left alone.
     */
    fun load(html: String) {
        resourceCache.clear()
        val rewritten = ADDR_REWRITE.replace(html) { match ->
            "$SYNTH_PREFIX${match.groupValues[1]}"
        }
        webView.loadDataWithBaseURL(
            SYNTH_ORIGIN,
            rewritten,
            "text/html",
            "UTF-8",
            null,
        )
    }

    /** Stop loading and clear the page. Call from the host's clear path. */
    fun release() {
        webView.stopLoading()
        webView.loadUrl("about:blank")
        resourceCache.clear()
    }

    /**
     * Intercepts every resource request and top-level navigation.
     * Routes any URL that maps to an Autonomi address (synthetic-https
     * form after the load-time rewrite, or raw `autonomi://` for
     * defence in depth) through fetch/it's connected [`Client`]. All
     * other URLs flow through to the platform.
     */
    private inner class AutonomiWebViewClient : WebViewClient() {
        override fun shouldInterceptRequest(
            view: WebView?,
            request: WebResourceRequest?,
        ): WebResourceResponse? {
            val url = request?.url?.toString() ?: return null
            val addr = extractAddr(url) ?: return null
            return resolveAddr(addr)
        }

        override fun shouldOverrideUrlLoading(
            view: WebView?,
            request: WebResourceRequest?,
        ): Boolean {
            val url = request?.url?.toString() ?: return false
            val addr = extractAddr(url) ?: return false
            // Hand off to the host so it drives the address bar +
            // bookmark + back-stack surfaces consistently.
            onAutonomiNavigate?.invoke(addr)
            return true
        }
    }

    /**
     * Pull a 64-hex Autonomi address out of any URL that points at
     * one — the synthetic origin (`https://aut.local/<addr>`), the
     * raw scheme (`autonomi://<addr>`), or future variants. Returns
     * `null` for URLs that don't reference an Autonomi address (those
     * flow through to the WebView as normal).
     */
    private fun extractAddr(url: String): String? {
        val candidate = when {
            url.startsWith(SYNTH_PREFIX) -> url.removePrefix(SYNTH_PREFIX)
            url.startsWith(SCHEME) -> url.removePrefix(SCHEME)
            else -> return null
        }
        // Strip path / query / fragment past the address.
        val addr = candidate
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .trim()
        return if (isValidAutonomiAddress(addr)) addr else null
    }

    /** Resolve a 64-hex Autonomi address into a [`WebResourceResponse`]. */
    private fun resolveAddr(addr: String): WebResourceResponse {
        resourceCache[addr]?.let { return it.toResponse() }

        val app = context.applicationContext as FetchitApplication
        val client = app.client() ?: return errorResponse(503, "no client connected")

        val bytes = try {
            // shouldInterceptRequest runs on a WebView network thread,
            // not the main thread. runBlocking is safe here and the
            // tokio runtime owned by the FFI handles the async fetch
            // on its own threads.
            runBlocking { client.fetch(addr) }
        } catch (e: Exception) {
            Log.w(TAG, "autonomi fetch failed for $addr", e)
            return errorResponse(502, e.message ?: "fetch failed")
        }

        val mime = sniffMime(bytes) ?: "application/octet-stream"
        val cached = CachedResource(mime = mime, bytes = bytes)
        resourceCache[addr] = cached
        return cached.toResponse()
    }

    /**
     * Best-effort MIME sniff. Inline so we don't pay an FFI round-trip
     * per resource — the SPA-hosted assets we care about (images,
     * scripts, styles, JSON, audio, video) are all distinguishable
     * from their first few bytes.
     */
    @Suppress("ReturnCount")
    private fun sniffMime(bytes: ByteArray): String? {
        if (bytes.size < 4) return null
        // Image magics
        if (bytes.startsWith(0x89, 0x50, 0x4E, 0x47)) return "image/png"
        if (bytes.startsWith(0xFF, 0xD8, 0xFF)) return "image/jpeg"
        if (bytes.size >= 6 && bytes.copyOfRange(0, 6)
                .contentEquals(byteArrayOf('G'.code.toByte(), 'I'.code.toByte(), 'F'.code.toByte(),
                    '8'.code.toByte(), '7'.code.toByte(), 'a'.code.toByte()))) return "image/gif"
        if (bytes.size >= 6 && bytes.copyOfRange(0, 6)
                .contentEquals(byteArrayOf('G'.code.toByte(), 'I'.code.toByte(), 'F'.code.toByte(),
                    '8'.code.toByte(), '9'.code.toByte(), 'a'.code.toByte()))) return "image/gif"
        if (bytes.size >= 12 && bytes.startsWith(0x52, 0x49, 0x46, 0x46) &&
            bytes[8] == 0x57.toByte() && bytes[9] == 0x45.toByte() &&
            bytes[10] == 0x42.toByte() && bytes[11] == 0x50.toByte()) return "image/webp"
        if (bytes[0] == 0x42.toByte() && bytes[1] == 0x4D.toByte()) return "image/bmp"

        // Audio / video magics
        if (bytes.size >= 3 && bytes.startsWith(0x49, 0x44, 0x33)) return "audio/mpeg"          // ID3
        if (bytes.size >= 2 && (bytes[0] == 0xFF.toByte() &&
                (bytes[1].toInt() and 0xE0) == 0xE0)) return "audio/mpeg"                       // raw MP3 frame
        if (bytes.startsWith(0x66, 0x4C, 0x61, 0x43)) return "audio/flac"                       // fLaC
        if (bytes.startsWith(0x4F, 0x67, 0x67, 0x53)) return "audio/ogg"                        // OggS
        if (bytes.size >= 12 && bytes.startsWith(0x52, 0x49, 0x46, 0x46) &&
            bytes[8] == 0x57.toByte() && bytes[9] == 0x41.toByte() &&
            bytes[10] == 0x56.toByte() && bytes[11] == 0x45.toByte()) return "audio/wav"        // RIFF...WAVE
        if (bytes.size >= 12 && bytes[4] == 0x66.toByte() && bytes[5] == 0x74.toByte() &&
            bytes[6] == 0x79.toByte() && bytes[7] == 0x70.toByte()) return "video/mp4"          // ...ftyp
        if (bytes.size >= 4 && bytes.startsWith(0x1A, 0x45, 0xDF, 0xA3)) return "video/webm"    // EBML

        // Try treating it as text + sniff content
        val asText = try { String(bytes.copyOfRange(0, bytes.size.coerceAtMost(512)), Charsets.UTF_8) }
            catch (_: Exception) { return null }
        val trimmed = asText.trimStart()
        if (trimmed.startsWith("<!doctype html", ignoreCase = true) ||
            trimmed.startsWith("<html", ignoreCase = true)) return "text/html"
        if (trimmed.startsWith("<svg", ignoreCase = true) ||
            trimmed.startsWith("<?xml", ignoreCase = true)) return "image/svg+xml"
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "application/json"

        // Last resort — Java's built-in stream sniffer.
        return URLConnection.guessContentTypeFromStream(ByteArrayInputStream(bytes))
            ?: "application/octet-stream"
    }

    private fun errorResponse(status: Int, msg: String): WebResourceResponse =
        WebResourceResponse(
            "text/plain",
            "utf-8",
            status,
            msg.take(80).ifBlank { "error" },
            mapOf("Access-Control-Allow-Origin" to "*"),
            ByteArrayInputStream(msg.toByteArray()),
        )

    private data class CachedResource(val mime: String, val bytes: ByteArray) {
        fun toResponse(): WebResourceResponse = WebResourceResponse(
            mime,
            null,
            200,
            "OK",
            // Permissive CORS so SPA fetch() / XHR calls can read the
            // response body. Cross-origin doesn't really exist on
            // Autonomi — every address is content-addressed, no DNS
            // origin to attack — but the browser still asks.
            mapOf(
                "Access-Control-Allow-Origin" to "*",
                "Access-Control-Allow-Methods" to "GET",
                "Access-Control-Allow-Headers" to "*",
                "Cache-Control" to "public, max-age=31536000, immutable",
            ),
            ByteArrayInputStream(bytes),
        )
    }

    private companion object {
        /** User-facing scheme. Rewritten to [`SYNTH_PREFIX`] at load time. */
        const val SCHEME = "autonomi://"

        /**
         * Synthetic origin used as the WebView's base URL. Chosen to be
         * obviously non-routable on the traditional internet (`.local`
         * is the mDNS link-local TLD; `aut.local` is reserved for our
         * use). No DNS query for it ever leaves the device.
         */
        const val SYNTH_ORIGIN = "https://aut.local"
        const val SYNTH_PREFIX = "$SYNTH_ORIGIN/"

        /**
         * Anchored to a real 64-hex address so abstract mentions of
         * the scheme in prose (e.g. capability tables, docs) stay as
         * `autonomi://`. Live URL references with valid addresses get
         * rewritten to the synthetic https form.
         */
        val ADDR_REWRITE = Regex("""autonomi://([0-9a-fA-F]{64})""")

        const val TAG = "fetchit.html"
    }
}

private fun ByteArray.startsWith(vararg prefix: Int): Boolean {
    if (size < prefix.size) return false
    for (i in prefix.indices) {
        if (this[i] != prefix[i].toByte()) return false
    }
    return true
}
