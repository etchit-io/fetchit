package io.etchit.fetchit

import android.content.Context
import android.content.Intent

/**
 * Side-effecting bookmark operations that need a [`Context`] but don't
 * own any state — share intent, file-picker plumbing, etc.
 */
object BookmarkActions {

    /**
     * Fire the system share sheet with the bookmark's address as the
     * shared text. Other apps can copy/forward/save it.
     */
    fun shareAsLink(context: Context, bookmark: Bookmark) {
        val text = "${bookmark.label}\n${bookmark.address}"
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, bookmark.label)
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(
            Intent.createChooser(send, context.getString(R.string.bookmark_share)),
        )
    }

    /**
     * Build the export envelope JSON. Caller writes it to a `Uri`
     * obtained from `ACTION_CREATE_DOCUMENT`.
     */
    fun exportJson(bookmarks: List<Bookmark>): String =
        BookmarkSerde.encodeExport(bookmarks)

    /**
     * Parse imported JSON (as read from a `Uri` chosen by the user via
     * `ACTION_OPEN_DOCUMENT`). Returns the parsed list or an error
     * suitable for surfacing in a Toast.
     */
    fun importJson(raw: String): Result<List<Bookmark>> = BookmarkSerde.decodeExport(raw)
}
