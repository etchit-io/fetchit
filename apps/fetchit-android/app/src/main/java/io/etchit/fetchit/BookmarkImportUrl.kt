package io.etchit.fetchit

import android.net.Uri
import android.util.Base64
import org.json.JSONObject

/**
 * A scanned / pasted bookmark-import URL parsed back into a list the
 * UI can confirm before merging into [`BookmarkStore`]. Matches the
 * encoder on the desktop side (`apps/fetchit-desktop/src/bookmarkShare.ts`).
 *
 * Wire format:
 *   fetchit://import?v=1&data=<base64url-encoded-JSON>
 * where the JSON is `{"bookmarks":[{"a":"<64hex>","l":"<label>"}, ...]}`.
 */
data class BookmarkImport(val bookmarks: List<ImportedBookmark>)

/** A single (address, label) pair from a parsed import URL. */
data class ImportedBookmark(val address: String, val label: String)

/**
 * Parse a `fetchit://import?…` URL. Returns `null` on any malformed
 * input (wrong scheme, wrong host, unknown `v`, undecodable data,
 * malformed JSON, etc.). Individual malformed entries inside an
 * otherwise valid payload are skipped rather than failing the whole
 * import.
 */
fun parseBookmarkImportUrl(raw: String): BookmarkImport? {
    val trimmed = raw.trim()
    if (!trimmed.startsWith("fetchit://import", ignoreCase = true)) return null

    val uri = try {
        Uri.parse(trimmed)
    } catch (_: Exception) {
        return null
    }
    if (!"fetchit".equals(uri.scheme, ignoreCase = true)) return null
    if (!"import".equals(uri.host, ignoreCase = true)) return null
    if (uri.getQueryParameter("v") != "1") return null
    val data = uri.getQueryParameter("data") ?: return null

    val bytes = try {
        Base64.decode(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
        return null
    }

    val json = try {
        String(bytes, Charsets.UTF_8)
    } catch (_: Exception) {
        return null
    }

    val arr = try {
        JSONObject(json).optJSONArray("bookmarks")
    } catch (_: Exception) {
        return null
    } ?: return null

    val out = mutableListOf<ImportedBookmark>()
    for (i in 0 until arr.length()) {
        val item = arr.optJSONObject(i) ?: continue
        val address = item.optString("a", "").lowercase()
        val label = item.optString("l", "")
        if (!isValidAutonomiAddress(address)) continue
        if (address.isBlank()) continue
        out.add(ImportedBookmark(address, label))
    }
    return BookmarkImport(out)
}
