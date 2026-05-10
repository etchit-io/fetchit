package io.etchit.fetchit

import org.json.JSONArray
import org.json.JSONObject

/**
 * JSON encode/decode for [`Bookmark`] storage and export.
 *
 * Two shapes share this module: the on-device storage form (a bare
 * `JSONArray` of bookmark objects) and the export envelope (`{version,
 * exportedAt, bookmarks}`). Keeping both in one file means the schema
 * is auditable in a single sitting.
 */
object BookmarkSerde {

    /** Export-envelope version. Bump only with a backwards-compat plan. */
    const val EXPORT_VERSION = 1

    fun toJson(b: Bookmark): JSONObject = JSONObject().apply {
        put("id", b.id)
        put("label", b.label)
        put("address", b.address)
        put("addedAt", b.addedAt)
        b.kind?.let { put("kind", it) }
    }

    fun fromJson(o: JSONObject): Bookmark? = try {
        Bookmark(
            id = o.getString("id"),
            label = o.getString("label"),
            address = o.getString("address"),
            addedAt = o.getLong("addedAt"),
            kind = o.optString("kind").takeIf { it.isNotEmpty() },
        )
    } catch (_: Exception) {
        null
    }

    fun encodeStorage(bookmarks: List<Bookmark>): String {
        val arr = JSONArray()
        bookmarks.forEach { arr.put(toJson(it)) }
        return arr.toString()
    }

    fun decodeStorage(raw: String?): List<Bookmark> {
        if (raw.isNullOrEmpty()) return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).mapNotNull { fromJson(arr.getJSONObject(it)) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun encodeExport(bookmarks: List<Bookmark>): String = JSONObject().apply {
        put("version", EXPORT_VERSION)
        put("exportedAt", System.currentTimeMillis())
        put("bookmarks", JSONArray().apply { bookmarks.forEach { put(toJson(it)) } })
    }.toString(2)

    /**
     * Decode an export envelope. Strict on `version` (we only know v1
     * today); permissive on unknown fields so future-version exports
     * round-trip if the structural shape is unchanged.
     */
    fun decodeExport(raw: String): Result<List<Bookmark>> = runCatching {
        val obj = JSONObject(raw)
        val version = obj.optInt("version", -1)
        require(version == EXPORT_VERSION) { "unsupported export version: $version" }
        val arr = obj.getJSONArray("bookmarks")
        (0 until arr.length()).mapNotNull { fromJson(arr.getJSONObject(it)) }
    }
}
