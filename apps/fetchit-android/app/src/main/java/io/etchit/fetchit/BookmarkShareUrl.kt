package io.etchit.fetchit

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * Kotlin counterpart of the desktop encoder
 * (`apps/fetchit-desktop/src/bookmarkShare.ts`). Produces the
 * `fetchit://import?v=1&data=<base64url>` URL the desktop QR-share
 * emits, so the phone can share its bookmarks back to another device.
 *
 * Both sides cap a single share at [MAX_BOOKMARKS_PER_QR] so the QR
 * stays inside binary-mode QR-version-40 ECC-M capacity.
 */
const val MAX_BOOKMARKS_PER_QR = 20

/** Result of asking [encodeBookmarksForShare] to build a share URL. */
sealed class EncodeResult {
    /** The encoded `fetchit://import?…` URL. */
    data class Ok(val url: String) : EncodeResult()

    /** Caller passed an empty list — nothing to share. */
    data object Empty : EncodeResult()

    /** Caller asked to share more than [MAX_BOOKMARKS_PER_QR]; surface
     *  to the user instead of silently producing an unscannable QR. */
    data class TooMany(val attempted: Int) : EncodeResult()
}

/**
 * Build a `fetchit://import?…` URL carrying [bookmarks]. JSON shape
 * matches the desktop encoder exactly:
 *   {"bookmarks":[{"a":"<64hex>","l":"<label>"}, ...]}
 */
fun encodeBookmarksForShare(bookmarks: List<Bookmark>): EncodeResult {
    if (bookmarks.isEmpty()) return EncodeResult.Empty
    if (bookmarks.size > MAX_BOOKMARKS_PER_QR) {
        return EncodeResult.TooMany(bookmarks.size)
    }
    val arr = JSONArray()
    for (bm in bookmarks) {
        val obj = JSONObject()
        obj.put("a", bm.address)
        obj.put("l", bm.label)
        arr.put(obj)
    }
    val payload = JSONObject().put("bookmarks", arr)
    val json = payload.toString()
    val b64 = Base64.encodeToString(
        json.toByteArray(Charsets.UTF_8),
        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
    )
    return EncodeResult.Ok("fetchit://import?v=1&data=$b64")
}
