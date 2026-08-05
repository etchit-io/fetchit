package io.etchit.fetchit.chat

import android.graphics.Bitmap
import android.util.LruCache

/**
 * Turns the photo a user picked into an image small enough to ride inside
 * a sealed chat message, and turns a received one back into a bitmap.
 *
 * An inline attachment travels INSIDE the encrypted payload, so it is
 * end-to-end encrypted like the text — and so it must stay small: the
 * engine caps a raw attachment at [MAX_BYTES], chosen about four times
 * under the relay's per-envelope limit. A phone photo is one to two
 * orders of magnitude over that, so every send goes through the ladder
 * below.
 *
 * Two properties are deliberate, not incidental:
 *
 * - **Re-encoding is privacy-load-bearing.** A camera JPEG carries EXIF,
 *   and EXIF routinely carries GPS coordinates, the camera's serial
 *   number and the exact capture time. Scaling alone would keep all of
 *   it. Decoding to a bitmap and compressing a fresh JPEG keeps only the
 *   pixels, so what leaves the phone is a picture, not a record of where
 *   the user was standing.
 * - **Aspect ratio is preserved.** Unlike a profile picture (which every
 *   surface draws in a circle, so a centre-crop loses nothing that would
 *   have been seen), a shared photo is the content. It is never cropped —
 *   only scaled down, and only far enough to fit.
 *
 * Decoding is bounded on both sides via [FediAvatars.decodeBounded]: the
 * declared dimensions are checked before a single pixel is allocated, and
 * `inSampleSize` keeps the full-resolution image from ever being
 * materialised. That guard matters most on the RECEIVE side, where the
 * bytes came from someone else.
 */
object ChatImageAttachment {

    /**
     * Hard cap on the raw bytes, mirroring
     * `fetchit_chat::attachment::MAX_ATTACHMENT_BYTES` (256 KiB). The FFI
     * re-checks it; this copy exists so the user is told at attach time
     * instead of watching a send fail.
     */
    const val MAX_BYTES = 256 * 1024

    /** What we always send: a re-encoded JPEG. */
    const val CONTENT_TYPE = "image/jpeg"

    /**
     * Longest edges to try, largest first. A photo that fits at 1600px is
     * sent at 1600px; the lower rungs are what a dense or noisy image
     * falls back to rather than being refused.
     */
    val EDGE_LADDER = intArrayOf(1600, 1280, 1024, 800, 640)

    /**
     * JPEG qualities tried at each edge, best first. The floor is 50:
     * below that the artefacts cost more than the pixels are worth, and a
     * picture that only fits as mush is better shared as an
     * `autonomi://` link.
     */
    val QUALITY_LADDER = intArrayOf(80, 70, 60, 50)

    /**
     * Largest source file read into memory. Generous for a modern phone
     * photo and still a bound on what one hostile (or simply enormous)
     * file can make us allocate.
     */
    const val MAX_SOURCE_BYTES = 32 * 1024 * 1024

    /**
     * Largest declared source dimension accepted when preparing a send.
     * Higher than the avatar path's bound because a 48MP phone photo is
     * genuinely 8000px wide and refusing it would be a bug, not a
     * defence; the subsampled decode below still never materialises more
     * than roughly [EDGE_LADDER]-sized pixels.
     */
    const val MAX_SOURCE_PX = 16384

    /** Target edge a RECEIVED image is decoded at for display. */
    const val DISPLAY_PX = 1024

    /** Width and height in pixels. */
    data class Size(val width: Int, val height: Int)

    /**
     * [width] x [height] scaled to fit inside a [maxEdge] box, keeping the
     * aspect ratio and never scaling up. Pure arithmetic, so the framing
     * rule is unit-testable without a decoder.
     *
     * The short edge is clamped to at least 1: a very wide panorama
     * scaled down would otherwise round to zero and fail to encode.
     * Returns null for a degenerate source.
     */
    fun scaledSize(width: Int, height: Int, maxEdge: Int): Size? {
        if (width <= 0 || height <= 0 || maxEdge <= 0) return null
        val longest = maxOf(width, height)
        if (longest <= maxEdge) return Size(width, height)
        val scale = maxEdge.toDouble() / longest.toDouble()
        return Size(
            width = maxOf(1, Math.round(width * scale).toInt()),
            height = maxOf(1, Math.round(height * scale).toInt()),
        )
    }

    /**
     * The (edge, quality) rungs in the order they are tried: every quality
     * at the largest edge first, then the next edge down. Resolution is
     * preferred over compression quality because a chat photo is usually
     * looked at, not studied — a 1600px image at q60 reads better than a
     * 640px one at q80.
     */
    fun ladder(): List<Pair<Int, Int>> =
        EDGE_LADDER.flatMap { edge -> QUALITY_LADDER.map { quality -> edge to quality } }

    /**
     * Walk [ladder] until [encode] returns something at or under
     * [MAX_BYTES]; null when nothing fits (the caller then steers the user
     * to the `autonomi://` share path).
     *
     * [encode] is injected so the rung-walking rule is unit-testable
     * without a JPEG encoder; the device path passes the real one.
     */
    fun chooseEncoding(encode: (edge: Int, quality: Int) -> ByteArray?): ByteArray? {
        for ((edge, quality) in ladder()) {
            val out = encode(edge, quality) ?: continue
            if (out.size <= MAX_BYTES) return out
        }
        return null
    }

    /**
     * What [prepare] made of the picked file. The two failures are kept
     * apart because they need different words: one asks the user for a
     * different file, the other points at the `autonomi://` share path.
     */
    sealed interface Prepared {
        /** Ready to send. */
        data class Ready(val attachment: ChatAttachment) : Prepared

        /** Not a picture we can decode (or absurd declared dimensions). */
        data object Unreadable : Prepared

        /** Decoded fine, but no rung of the ladder fits the cap. */
        data object TooLarge : Prepared
    }

    /**
     * Decode, downscale, re-encode. Device path (BitmapFactory +
     * Bitmap.compress); the arithmetic it relies on is tested separately.
     */
    fun prepare(bytes: ByteArray): Prepared {
        if (bytes.isEmpty()) return Prepared.Unreadable
        val decoded = FediAvatars.decodeBounded(bytes, EDGE_LADDER.first(), MAX_SOURCE_PX)
            ?: return Prepared.Unreadable
        var encodedSize: Size? = null
        val encoded = chooseEncoding { edge, quality ->
            val size = scaledSize(decoded.width, decoded.height, edge) ?: return@chooseEncoding null
            val scaled = runCatching {
                if (size.width == decoded.width && size.height == decoded.height) decoded
                else Bitmap.createScaledBitmap(decoded, size.width, size.height, true)
            }.getOrNull() ?: return@chooseEncoding null
            val out = java.io.ByteArrayOutputStream()
            val ok = runCatching {
                scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)
            }.getOrDefault(false)
            if (!ok) return@chooseEncoding null
            encodedSize = size
            out.toByteArray()
        }
        val size = encodedSize
        if (encoded == null || size == null) return Prepared.TooLarge
        return Prepared.Ready(
            ChatAttachment(
                mime = CONTENT_TYPE,
                width = size.width,
                height = size.height,
                bytes = encoded,
            ),
        )
    }

    /**
     * Decode a received attachment for display, bounded and subsampled.
     * Null for bytes that do not decode — a hostile image degrades to no
     * image, never to a crash.
     */
    fun decodeForDisplay(att: ChatAttachment): Bitmap? =
        FediAvatars.decodeBounded(att.bytes, DISPLAY_PX)

    /**
     * Process-lifetime cache of decoded attachment bitmaps, so scrolling a
     * thread does not re-decode the same photo on every bind.
     *
     * Keyed by the caller's stable row key (message id, or the outbox
     * bubble id while a send is in flight). Small on purpose: these are
     * full-width photos, not 96dp faces.
     */
    class Thumbs(maxEntries: Int = MAX_DECODED) {
        private val bitmaps = LruCache<String, Bitmap>(maxEntries)

        /** The decoded bitmap for [key], or null when nothing is cached. */
        fun cached(key: String): Bitmap? = bitmaps.get(key)

        /** Cache [bmp] under [key] and return it. */
        fun put(key: String, bmp: Bitmap): Bitmap {
            bitmaps.put(key, bmp)
            return bmp
        }

        /** Drop everything; used when the chat identity changes. */
        fun clear() = bitmaps.evictAll()

        companion object {
            /** Decoded photos held at once. */
            const val MAX_DECODED = 8
        }
    }
}
