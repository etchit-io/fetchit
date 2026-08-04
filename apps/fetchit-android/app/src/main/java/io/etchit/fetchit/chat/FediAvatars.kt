package io.etchit.fetchit.chat

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache

/**
 * Process-lifetime cache of decoded fediverse avatars.
 *
 * The engine hands us raw image bytes it fetched behind the SSRF guard and
 * never decoded. Decoding is the platform's job — `BitmapFactory` runs in the
 * OS media sandbox, which is exactly the isolation we want for bytes that came
 * off an arbitrary remote server. Two guards ride on top of it:
 *
 * - a bounds-only first pass, so nothing is allocated until the declared
 *   dimensions are known and checked against [MAX_SOURCE_PX] (a 30000×30000
 *   "avatar" is a decompression bomb, not a profile picture);
 * - `inSampleSize`, so the full-resolution image is never materialised — we
 *   only ever hold the ~96dp thumbnail a row actually draws.
 *
 * Each label is decoded at most once per process ([MAX_DECODED] entries, LRU).
 * A label the engine has no bytes for is remembered for [ABSENT_RECHECK_MS] so
 * scrolling can't turn a missing avatar into a query storm, while a background
 * fetch that lands later is still picked up on the next re-check.
 */
class FediAvatars(private val targetPx: Int) {

    private val bitmaps = LruCache<String, Bitmap>(MAX_DECODED)
    private val absentUntil = HashMap<String, Long>()
    private val inFlight = HashSet<String>()

    /** The decoded avatar for [label], or null when nothing is cached. */
    fun cached(label: String): Bitmap? = bitmaps.get(key(label))

    /**
     * Claim the right to ask the engine for [label]: false when we already
     * hold a bitmap, when a query for the same label is already running, or
     * when a recent miss is still inside its re-check window.
     *
     * Single-flight matters on the feed, where one author can occupy several
     * visible rows — without it a screenful of posts would fire one engine
     * fetch each for the same face.
     */
    fun shouldQuery(label: String, nowMs: Long): Boolean {
        val k = key(label)
        if (bitmaps.get(k) != null) return false
        synchronized(absentUntil) {
            if (k in inFlight) return false
            val until = absentUntil[k]
            if (until != null && nowMs < until) return false
            inFlight.add(k)
        }
        return true
    }

    /**
     * Give back a claim taken by [shouldQuery] without recording an answer.
     * Callers run this in a `finally` so a screen closed mid-fetch cannot
     * strand the label as permanently in-flight.
     */
    fun releaseQuery(label: String) {
        synchronized(absentUntil) { inFlight.remove(key(label)) }
    }

    /** Remember that the engine had no bytes for [label]. */
    fun noteAbsent(label: String, nowMs: Long) {
        val k = key(label)
        synchronized(absentUntil) {
            absentUntil[k] = nowMs + ABSENT_RECHECK_MS
            inFlight.remove(k)
        }
    }

    /**
     * Decode [bytes] for [label] and cache the result. Returns null (and arms
     * the absent window) for empty, oversized, or undecodable bytes — a
     * hostile image must degrade to the placeholder, never to a crash.
     */
    fun decodeAndCache(label: String, bytes: ByteArray?, nowMs: Long): Bitmap? {
        val k = key(label)
        val bmp = if (bytes == null || bytes.isEmpty()) null else decodeBounded(bytes, targetPx)
        if (bmp == null) {
            noteAbsent(label, nowMs)
            return null
        }
        synchronized(absentUntil) {
            absentUntil.remove(k)
            inFlight.remove(k)
        }
        bitmaps.put(k, bmp)
        return bmp
    }

    /** Drop everything; used when the chat identity changes. */
    fun clear() {
        bitmaps.evictAll()
        synchronized(absentUntil) {
            absentUntil.clear()
            inFlight.clear()
        }
    }

    companion object {
        /** Decoded bitmaps held at once. Avatars are ~96dp; 16 is a screenful. */
        const val MAX_DECODED = 16

        /** How long a "no bytes" answer suppresses re-querying the engine. */
        const val ABSENT_RECHECK_MS = 30_000L

        /**
         * Largest source dimension accepted before decoding. Well past any
         * real avatar and far below what a decompression bomb needs.
         */
        const val MAX_SOURCE_PX = 4096

        /** Avatars key on the same canonical `user@host` the engine stores. */
        fun key(label: String): String = canonicalFediHandle(label)

        /**
         * Largest power-of-two subsample that keeps both dimensions at or
         * above [targetPx]. Pure arithmetic, so it is unit-testable without
         * a decoder.
         */
        fun sampleSize(width: Int, height: Int, targetPx: Int): Int {
            if (targetPx <= 0 || width <= 0 || height <= 0) return 1
            var sample = 1
            var w = width
            var h = height
            while (w / 2 >= targetPx && h / 2 >= targetPx) {
                w /= 2
                h /= 2
                sample *= 2
            }
            return sample
        }

        /**
         * Bounds-checked, subsampled decode. Null for anything that does not
         * decode to a sane bitmap.
         */
        fun decodeBounded(bytes: ByteArray, targetPx: Int): Bitmap? {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds) }
            val w = bounds.outWidth
            val h = bounds.outHeight
            if (w <= 0 || h <= 0) return null
            if (w > MAX_SOURCE_PX || h > MAX_SOURCE_PX) return null
            val opts = BitmapFactory.Options().apply {
                inSampleSize = sampleSize(w, h, targetPx)
            }
            return runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts) }
                .getOrNull()
        }
    }
}
