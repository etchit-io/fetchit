package io.etchit.fetchit

import android.content.Context
import androidx.appcompat.app.AlertDialog

/**
 * Show the long-press menu for a single bookmark — rename / share /
 * delete. Pulled out of [`BookmarkSheet`] so the sheet stays a small
 * orchestrator.
 */
fun showBookmarkContextMenu(
    context: Context,
    bookmark: Bookmark,
    store: BookmarkStore,
) {
    val items = arrayOf(
        context.getString(R.string.bookmark_rename),
        context.getString(R.string.bookmark_share),
        context.getString(R.string.bookmark_delete),
    )
    AlertDialog.Builder(context)
        .setTitle(bookmark.label)
        .setItems(items) { _, which ->
            when (which) {
                0 -> showBookmarkRenameDialog(
                    context = context,
                    title = context.getString(R.string.bookmark_rename),
                    prefill = bookmark.label,
                ) { newLabel ->
                    store.update(bookmark.id) { it.copy(label = newLabel) }
                }
                1 -> BookmarkActions.shareAsLink(context, bookmark)
                2 -> store.delete(bookmark.id)
            }
        }
        .show()
}
