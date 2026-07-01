package io.etchit.fetchit

import android.content.Context
import android.widget.Toast
import androidx.appcompat.app.AlertDialog

/**
 * Multi-bookmark share picker. Shows a checkbox list of all
 * bookmarks (the first [MAX_BOOKMARKS_PER_QR] pre-checked so a quick
 * "share all" works without ceremony when the user has ≤ that many
 * bookmarks). On confirm, encodes the selection as a
 * `fetchit://import?…` URL and surfaces the resulting QR via
 * [`showBookmarkImportQrDialog`].
 *
 * Caller pulls the list from [`BookmarkStore.bookmarks.value`] —
 * this dialog is a one-shot picker, not a reactive listener.
 */
fun showBookmarkMultiShareDialog(
    context: Context,
    bookmarks: List<Bookmark>,
) {
    if (bookmarks.isEmpty()) {
        Toast.makeText(
            context,
            R.string.bookmark_share_multi_empty,
            Toast.LENGTH_SHORT,
        ).show()
        return
    }

    val labels = bookmarks.map { it.label.ifBlank { it.address.take(12) + "…" } }
        .toTypedArray()
    val initiallyChecked = minOf(bookmarks.size, MAX_BOOKMARKS_PER_QR)
    val checked = BooleanArray(bookmarks.size) { i -> i < initiallyChecked }

    AlertDialog.Builder(context)
        .setTitle(R.string.bookmark_share_multi_title)
        .setMultiChoiceItems(labels, checked) { _, which, isChecked ->
            checked[which] = isChecked
        }
        .setPositiveButton(R.string.bookmark_share_multi_share) { _, _ ->
            val selected = bookmarks
                .filterIndexed { i, _ -> checked[i] }
                .take(MAX_BOOKMARKS_PER_QR)
            if (selected.isEmpty()) {
                Toast.makeText(
                    context,
                    R.string.bookmark_share_multi_none_selected,
                    Toast.LENGTH_SHORT,
                ).show()
                return@setPositiveButton
            }
            when (val r = encodeBookmarksForShare(selected)) {
                is EncodeResult.Ok -> {
                    val summary = context.resources.getQuantityString(
                        R.plurals.bookmark_share_multi_summary,
                        selected.size,
                        selected.size,
                    )
                    showBookmarkImportQrDialog(context, r.url, summary)
                }
                is EncodeResult.TooMany,
                EncodeResult.Empty -> Toast.makeText(
                    context,
                    R.string.bookmark_share_multi_too_many,
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}
