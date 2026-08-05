package io.etchit.fetchit.chat

import android.graphics.Bitmap

/**
 * Turns the photo a user picked into the small square image we publish.
 *
 * Every step runs ON THE DEVICE, before a single byte is uploaded, and the
 * re-encode is the load-bearing one: a camera photo carries EXIF, and EXIF
 * routinely carries GPS coordinates, the camera's serial number, and the
 * exact capture time. Cropping and scaling alone would keep all of it.
 * Decoding to a bitmap and compressing a fresh JPEG keeps only the pixels —
 * so what leaves the phone is a picture, not a record of where the user was
 * standing.
 *
 * The rest is ordinary hygiene:
 *
 * - decode through [FediAvatars.decodeBounded], so a decompression bomb is
 *   refused on its declared dimensions rather than allocated;
 * - centre-crop to a square, because every surface draws avatars in a
 *   circle and a non-square source would be cropped by the view anyway —
 *   better to send only the pixels that will be seen;
 * - cap the long edge at [MAX_EDGE_PX];
 * - walk [QUALITY_LADDER] until the encoded result fits [MAX_BYTES], the
 *   same cap the engine and the bridge enforce, so the upload cannot be
 *   refused for size after the user has already waited for it.
 */
object ProfilePicture {

    /** Longest edge of the published image. */
    const val MAX_EDGE_PX = 512

    /** Hard byte cap, mirroring the engine + bridge limit (512 KiB). */
    const val MAX_BYTES = 512 * 1024

    /** What we always publish: a re-encoded JPEG. */
    const val CONTENT_TYPE = "image/jpeg"

    /**
     * JPEG qualities to try, in order. A 512px square at q85 lands well
     * under the cap for any ordinary photograph; the lower rungs exist for
     * pathological input (heavy noise, a photo of static) rather than for
     * everyday use.
     */
    val QUALITY_LADDER = intArrayOf(85, 70, 55, 40)

    /**
     * Largest source file we will read into memory. A phone photo is a few
     * megabytes; this is generous for a RAW-ish export and still bounds
     * what a hostile (or simply enormous) file can make us allocate before
     * the decoder's own dimension check gets a look at it.
     */
    const val MAX_SOURCE_BYTES = 32 * 1024 * 1024

    /** A square region of the source, in source pixels. */
    data class CropBox(val x: Int, val y: Int, val size: Int)

    /**
     * Read at most [max] bytes from [input], or null when the stream is
     * longer than that — refusing outright rather than truncating, since a
     * truncated image would decode to something the user did not pick.
     */
    fun readBounded(input: java.io.InputStream, max: Int = MAX_SOURCE_BYTES): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (out.size() + n > max) return null
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    /**
     * The centred square inside a [width] x [height] source.
     *
     * Pure arithmetic, so the framing rule is unit-testable without a
     * decoder: the square takes the shorter edge, and the surplus on the
     * longer edge is split evenly, leaving the middle of the picture —
     * which is where a face is.
     */
    fun cropBox(width: Int, height: Int): CropBox? {
        if (width <= 0 || height <= 0) return null
        val size = minOf(width, height)
        return CropBox(x = (width - size) / 2, y = (height - size) / 2, size = size)
    }

    /**
     * The edge to scale a [cropSize]-pixel square down to. Never scales
     * UP: enlarging a small avatar would spend bytes on invented detail.
     */
    fun scaledEdge(cropSize: Int): Int = minOf(cropSize, MAX_EDGE_PX)

    /**
     * The prepared image, or null when [bytes] do not decode to a usable
     * picture or will not fit the cap at any quality.
     *
     * Device path (BitmapFactory + Bitmap.compress); the arithmetic it
     * relies on is tested separately.
     */
    fun prepare(bytes: ByteArray): ByteArray? {
        if (bytes.isEmpty()) return null
        val decoded = FediAvatars.decodeBounded(bytes, MAX_EDGE_PX) ?: return null
        val box = cropBox(decoded.width, decoded.height) ?: return null
        val square = runCatching {
            Bitmap.createBitmap(decoded, box.x, box.y, box.size, box.size)
        }.getOrNull() ?: return null
        val edge = scaledEdge(square.width)
        val scaled = runCatching {
            if (edge == square.width) square
            else Bitmap.createScaledBitmap(square, edge, edge, true)
        }.getOrNull() ?: return null

        for (quality in QUALITY_LADDER) {
            val out = java.io.ByteArrayOutputStream()
            val ok = runCatching {
                scaled.compress(Bitmap.CompressFormat.JPEG, quality, out)
            }.getOrDefault(false)
            if (!ok) return null
            val encoded = out.toByteArray()
            if (encoded.size <= MAX_BYTES) return encoded
        }
        return null
    }
}
