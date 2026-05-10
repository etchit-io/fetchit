package io.etchit.fetchit

import android.content.Context
import android.net.Uri

/**
 * Read/write helpers for bookmark export and import via Storage Access
 * Framework `Uri`s. The launchers themselves must register at fragment
 * creation time, but the IO they trigger lives here so the fragment
 * stays small.
 */
object BookmarkFileIO {

    fun writeExport(
        context: Context,
        uri: Uri,
        bookmarks: List<Bookmark>,
    ): Result<Unit> = runCatching {
        val json = BookmarkActions.exportJson(bookmarks)
        context.contentResolver.openOutputStream(uri)?.use { it.write(json.toByteArray()) }
            ?: error("could not open output stream for $uri")
    }

    fun readImport(
        context: Context,
        uri: Uri,
    ): Result<List<Bookmark>> = runCatching {
        val raw = context.contentResolver.openInputStream(uri)?.use {
            it.bufferedReader().readText()
        } ?: error("could not open input stream for $uri")
        BookmarkActions.importJson(raw).getOrThrow()
    }
}
