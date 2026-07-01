package io.etchit.fetchit

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.util.AttributeSet
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.net.URLConnection

/**
 * Loads a self-contained HTML body into a sandboxed `WebView` and
 * resolves any `autonomi://<64-hex>` resource references through
 * fetch>it's [`Client`].
 *
 * **Synthetic-origin trick (load-bearing).** The WebView is told its
 * base URL is [`SYNTH_ORIGIN`] (`https://aut.local`). At load time the
 * raw `autonomi://<addr>` references in the document are rewritten to
 * `https://aut.local/<addr>` so that *every* web-platform API — the
 * Fetch spec's `fetch()`, `XMLHttpRequest`, `<img>` / `<audio>` /
 * `<video>` / `<script>` / `<link>` / `<a>`, Streams, `Range`
 * requests, CORS — sees what looks like a perfectly normal
 * https URL and just works.
 *
 * Nothing about that origin actually exists on the traditional
 * internet. There is no DNS query for `aut.local`, no TLS handshake.
 * Every request to it is caught by [`shouldInterceptRequest`] inside
 * the app, the 64-hex path component is extracted, and the bytes are
 * pulled from the connected fetch>it [`Client`] over the Autonomi P2P
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
 *  - Network sandboxed — only `autonomi://` / `aut.local` resources
 *    resolve; every other host is a blocked request, never a real one.
 *    SPAs must be fully self-contained (inline assets, or upload each
 *    asset to its own Autonomi address)
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
 *
 * **Range requests** are supported (`Accept-Ranges: bytes` advertised,
 * `RFC 7233` `Range` header honoured with 206 / 416 responses). The
 * first lookup of any address still blocks on a full Autonomi fetch,
 * but the bytes are then cached and any subsequent media seek or
 * partial fetch is served from memory. Truly progressive streaming
 * (feeding bytes to the browser as Autonomi chunks arrive) would
 * require a streaming API on the underlying client and is not yet
 * implemented.
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

    /**
     * Fired when a page links to the `autonomi://back` pseudo-target —
     * an in-page "← back" / breadcrumb affordance that pops the host's
     * navigation stack instead of hard-coding (and re-fetching) a
     * specific address. The host should treat it like a back press.
     */
    private var onAutonomiBack: (() -> Unit)? = null

    /** Wire a handler for the `autonomi://back` pseudo-link. */
    fun setOnAutonomiBack(callback: () -> Unit) {
        onAutonomiBack = callback
    }

    /** The fullscreen container view supplied by the WebView when an HTML
     * video element enters fullscreen. While non-null, [`fullscreenBackCb`]
     * is enabled so system back exits fullscreen first. */
    private var fullscreenView: View? = null
    private var fullscreenCallback: WebChromeClient.CustomViewCallback? = null
    private var fullscreenBackCb: OnBackPressedCallback? = null

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
        webChromeClient = AutonomiChromeClient()
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
     *
     * `query` (a `?…` string, or `""`) rides on the synthetic base URL
     * so the SPA reads it as a normal `location.search`.
     */
    fun load(html: String, query: String = "") {
        resourceCache.clear()
        val rewritten = ADDR_REWRITE.replace(html) { match ->
            "$SYNTH_PREFIX${match.groupValues[1]}"
        }
        webView.loadDataWithBaseURL(
            SYNTH_ORIGIN + query,
            rewritten,
            "text/html",
            "UTF-8",
            null,
        )
    }

    /** Stop loading and clear the page. Call from the host's clear path. */
    fun release() {
        // If a video is in fullscreen at teardown, exit fullscreen first
        // so the activity's system bars are restored before the WebView
        // unloads.
        if (fullscreenView != null) {
            (webView.webChromeClient as? AutonomiChromeClient)?.onHideCustomView()
        }
        webView.stopLoading()
        webView.loadUrl("about:blank")
        resourceCache.clear()
    }

    /**
     * Intercepts every resource request and top-level navigation.
     * Routes any URL that maps to an Autonomi address (synthetic-https
     * form after the load-time rewrite, or raw `autonomi://` for
     * defence in depth) through fetch>it's connected [`Client`]. All
     * other URLs flow through to the platform.
     */
    private inner class AutonomiWebViewClient : WebViewClient() {
        override fun shouldInterceptRequest(
            view: WebView?,
            request: WebResourceRequest?,
        ): WebResourceResponse? {
            val url = request?.url?.toString() ?: return null
            extractAddr(url)?.let { addr ->
                Log.i(TAG, "intercept ${addr.take(10)}… range=${request.requestHeaders?.get("Range") ?: "-"}")
                return resolveAddr(addr, request.requestHeaders)
            }
            // Only autonomi:// resolves through the client; data/blob/about
            // pass through as page-internal, everything else is refused.
            return when (request.url?.scheme?.lowercase()) {
                "data", "blob", "about" -> null
                else -> {
                    Log.w(TAG, "blocked non-Autonomi request: $url")
                    errorResponse(403, "blocked: non-Autonomi request")
                }
            }
        }

        override fun shouldOverrideUrlLoading(
            view: WebView?,
            request: WebResourceRequest?,
        ): Boolean {
            val url = request?.url?.toString() ?: return false
            // `autonomi://back` — a "go back" pseudo-link. Lets in-page
            // "← back" / breadcrumb affordances pop the host's nav stack
            // (like system back) instead of hard-coding a specific
            // address (which, for content-addressed pages, can never
            // reference the index a visitor actually arrived through).
            if (url.trimEnd('/').equals("autonomi://back", ignoreCase = true)) {
                onAutonomiBack?.invoke()
                return true
            }
            extractAddr(url)?.let { addr ->
                // Hand off to the host so it drives the address bar +
                // bookmark + back-stack surfaces consistently.
                onAutonomiNavigate?.invoke(addr)
                return true
            }
            // Top-level http(s) navigations are refused (not followed,
            // not handed off).
            val scheme = request?.url?.scheme?.lowercase()
            if (request?.isForMainFrame == true && (scheme == "http" || scheme == "https")) {
                return true
            }
            return false
        }
    }

    /**
     * Handles HTML5 video / SPA fullscreen requests. When a `<video>`
     * element calls `requestFullscreen()` (or the user taps the
     * native fullscreen button on the platform's media controls) the
     * WebView hands us a `View` to mount at the top of the activity
     * window and a callback to invoke when the page exits fullscreen.
     *
     * We attach the view to the activity's decor view at full size,
     * hide the system bars, and register a temporary back-press
     * callback so the system back gesture exits fullscreen instead
     * of running the host's autonomi:// back-stack navigation.
     */
    private inner class AutonomiChromeClient : WebChromeClient() {
        override fun onShowCustomView(view: View, callback: CustomViewCallback) {
            // Reject overlapping fullscreen requests — should only have
            // one video fullscreen at a time.
            if (fullscreenView != null) {
                callback.onCustomViewHidden()
                return
            }
            val activity = context as? Activity ?: run {
                callback.onCustomViewHidden()
                return
            }
            fullscreenView = view
            fullscreenCallback = callback

            val decor = activity.window.decorView as ViewGroup
            decor.addView(
                view,
                ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT,
                ),
            )
            WindowCompat.getInsetsController(activity.window, decor)
                .hide(WindowInsetsCompat.Type.systemBars())

            // Back exits fullscreen. Higher priority than the host's
            // autonomi:// back-stack callback because this is the most
            // recently registered enabled callback.
            (activity as? ComponentActivity)?.let { ca ->
                val cb = object : OnBackPressedCallback(true) {
                    override fun handleOnBackPressed() {
                        onHideCustomView()
                    }
                }
                ca.onBackPressedDispatcher.addCallback(cb)
                fullscreenBackCb = cb
            }
        }

        override fun onHideCustomView() {
            val activity = context as? Activity ?: return
            val decor = activity.window.decorView as ViewGroup
            fullscreenView?.let { decor.removeView(it) }
            fullscreenView = null
            fullscreenCallback?.onCustomViewHidden()
            fullscreenCallback = null
            fullscreenBackCb?.remove()
            fullscreenBackCb = null
            WindowCompat.getInsetsController(activity.window, decor)
                .show(WindowInsetsCompat.Type.systemBars())
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

    /**
     * Resolve a 64-hex Autonomi address into a [`WebResourceResponse`],
     * honouring any `Range` header on the request.
     *
     * Three-tier lookup:
     *  1. **Per-page in-memory cache** ([`resourceCache`]) — fastest,
     *     keeps mime alongside bytes so we don't re-sniff on each
     *     request. Cleared on every new page load.
     *  2. **App-level disk cache** ([`FetchitApplication.bytesCache`]) —
     *     survives app restart, gives us offline replay. Mime is
     *     re-sniffed when promoted into the in-memory tier.
     *  3. **Autonomi network** — only on a true miss. Result is
     *     written through both caches.
     *
     * Range-narrowed requests from media-element seeks always hit the
     * in-memory tier and are essentially free.
     */
    private fun resolveAddr(
        addr: String,
        requestHeaders: Map<String, String>?,
    ): WebResourceResponse {
        val app = context.applicationContext as FetchitApplication
        val short = addr.take(10)

        val memHit = resourceCache[addr]
        val cached = if (memHit != null) {
            Log.i(TAG, "resolve $short…: in-memory hit (${memHit.bytes.size}B)")
            memHit
        } else {
            val diskBytes = app.bytesCache.get(addr)
            val bytes = if (diskBytes != null) {
                Log.i(TAG, "resolve $short…: disk-cache hit (${diskBytes.size}B)")
                diskBytes
            } else {
                val client = app.client() ?: run {
                    Log.w(TAG, "resolve $short…: no client connected")
                    return errorResponse(503, "no client connected")
                }
                Log.i(TAG, "resolve $short…: network fetch starting")
                val t0 = System.currentTimeMillis()
                val fetched = try {
                    // shouldInterceptRequest runs on a WebView network
                    // thread, not the main thread. runBlocking is safe
                    // here and the tokio runtime owned by the FFI
                    // handles the async fetch on its own threads.
                    runBlocking { client.fetch(addr) }
                } catch (e: Exception) {
                    Log.w(TAG, "resolve $short…: fetch FAILED after ${System.currentTimeMillis() - t0}ms — ${e.message}")
                    return errorResponse(502, e.message ?: "fetch failed")
                }
                Log.i(TAG, "resolve $short…: fetched ${fetched.size}B in ${System.currentTimeMillis() - t0}ms")
                // Persist for next session before returning so a crash
                // mid-render doesn't lose the bytes.
                app.bytesCache.put(addr, fetched)
                fetched
            }
            val mime = sniffMime(bytes) ?: "application/octet-stream"
            Log.i(TAG, "resolve $short…: mime=$mime")
            CachedResource(mime = mime, bytes = bytes).also { resourceCache[addr] = it }
        }

        val range = parseRange(requestHeaders, cached.bytes.size)
        Log.i(
            TAG,
            "resolve $short…: -> " +
                if (range == null) "200 OK (${cached.bytes.size}B, ${cached.mime})"
                else if (range.unsatisfiable) "416 (total ${range.total})"
                else "206 ${range.start}-${range.end}/${range.total}",
        )
        return cached.toResponse(range)
    }

    /**
     * Parse an `RFC 7233` `Range: bytes=<start>-<end>` header into a
     * concrete `[start, end]` byte index pair (inclusive). Supports:
     *  - `bytes=0-499`   — explicit range
     *  - `bytes=500-`    — open-ended ("from byte N to end")
     *  - `bytes=-500`    — suffix length ("last N bytes")
     *
     * Multipart ranges (`bytes=0-99,200-299`) are treated as absent —
     * we fall back to a 200 with the full body, which browsers handle
     * fine. Returns `null` if the header is missing or unparseable.
     */
    @Suppress("ReturnCount")
    private fun parseRange(
        headers: Map<String, String>?,
        totalSize: Int,
    ): RangeSlice? {
        val raw = headers?.entries
            ?.firstOrNull { it.key.equals("Range", ignoreCase = true) }
            ?.value
            ?: return null
        val match = RANGE_PATTERN.matchEntire(raw.trim()) ?: return null
        val sStr = match.groupValues[1]
        val eStr = match.groupValues[2]
        if (sStr.isEmpty() && eStr.isEmpty()) return null

        return when {
            sStr.isEmpty() -> {
                // Suffix form: bytes=-N → last N bytes.
                val suffix = eStr.toLongOrNull()?.toInt() ?: return null
                if (suffix <= 0) return null
                RangeSlice(
                    start = (totalSize - suffix).coerceAtLeast(0),
                    end = totalSize - 1,
                    total = totalSize,
                )
            }
            eStr.isEmpty() -> {
                val start = sStr.toLongOrNull()?.toInt() ?: return null
                if (start >= totalSize) return RangeSlice.unsatisfiable(totalSize)
                RangeSlice(start = start, end = totalSize - 1, total = totalSize)
            }
            else -> {
                val start = sStr.toLongOrNull()?.toInt() ?: return null
                val end = eStr.toLongOrNull()?.toInt() ?: return null
                if (start >= totalSize || end < start) {
                    return RangeSlice.unsatisfiable(totalSize)
                }
                RangeSlice(
                    start = start,
                    end = end.coerceAtMost(totalSize - 1),
                    total = totalSize,
                )
            }
        }
    }

    /**
     * A resolved byte range to serve. `start == -1` flags an
     * unsatisfiable request (out-of-bounds), which we render as a 416
     * with a `Content-Range: bytes * /<total>` header.
     */
    private data class RangeSlice(val start: Int, val end: Int, val total: Int) {
        val length: Int get() = end - start + 1
        val unsatisfiable: Boolean get() = start < 0
        companion object {
            fun unsatisfiable(total: Int) = RangeSlice(-1, -1, total)
        }
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

        // WebAssembly: `\0asm` magic. Returning the right MIME lets a page
        // use `WebAssembly.instantiateStreaming(fetch("autonomi://…"))`
        // (which requires `Content-Type: application/wasm`) rather than
        // having to round-trip through `arrayBuffer()`.
        if (bytes.startsWith(0x00, 0x61, 0x73, 0x6D)) return "application/wasm"                  // \0asm

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
        /**
         * Render the cached bytes as a `WebResourceResponse`, honouring
         * a `Range` slice if present.
         *
         *  - `range == null`            → 200 OK, full body, advertise
         *                                  `Accept-Ranges: bytes` so the
         *                                  browser knows to ask for ranges
         *                                  on follow-up media requests.
         *  - `range.unsatisfiable`      → 416 Range Not Satisfiable with
         *                                  `Content-Range: bytes * /<total>`.
         *  - otherwise                  → 206 Partial Content with the
         *                                  requested bytes plus a proper
         *                                  `Content-Range` header.
         */
        fun toResponse(range: RangeSlice?): WebResourceResponse {
            // Permissive CORS — content-addressing makes origin-based
            // attacks meaningless, but the browser still asks. Same
            // permissive set on every response variant.
            val baseHeaders = mapOf(
                "Access-Control-Allow-Origin" to "*",
                "Access-Control-Allow-Methods" to "GET",
                "Access-Control-Allow-Headers" to "*",
                "Cache-Control" to "public, max-age=31536000, immutable",
                "Accept-Ranges" to "bytes",
            )
            if (range == null) {
                return WebResourceResponse(
                    mime,
                    null,
                    200,
                    "OK",
                    baseHeaders + ("Content-Length" to "${bytes.size}"),
                    ByteArrayInputStream(bytes),
                )
            }
            if (range.unsatisfiable) {
                return WebResourceResponse(
                    "text/plain",
                    "utf-8",
                    416,
                    "Range Not Satisfiable",
                    baseHeaders + ("Content-Range" to "bytes */${range.total}"),
                    ByteArrayInputStream(ByteArray(0)),
                )
            }
            return WebResourceResponse(
                mime,
                null,
                206,
                "Partial Content",
                baseHeaders + mapOf(
                    "Content-Range" to "bytes ${range.start}-${range.end}/${range.total}",
                    "Content-Length" to "${range.length}",
                ),
                ByteArrayInputStream(bytes, range.start, range.length),
            )
        }
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

        /**
         * `RFC 7233` Range header value for a single byte range.
         * Captures `bytes=<start>-<end>` where either side may be
         * empty (open-ended or suffix length).
         */
        val RANGE_PATTERN = Regex("""bytes=(\d*)-(\d*)""")

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
