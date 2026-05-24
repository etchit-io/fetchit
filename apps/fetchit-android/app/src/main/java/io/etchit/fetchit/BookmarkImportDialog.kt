package io.etchit.fetchit

import android.content.Context
import androidx.appcompat.app.AlertDialog

/**
 * Show the "import these bookmarks?" confirmation dialog. Lists up to
 * [PREVIEW_LIMIT] labels inline so the user sees what they're about
 * to add; collapses the remainder to "…and N more".
 *
 * Callers route a parsed [`BookmarkImport`] (from
 * [`parseBookmarkImportUrl`]) here; on positive, [`onConfirmed`]
 * fires with the same list so the caller can hand it to
 * [`BookmarkStore.mergeImport`]. Empty imports surface no dialog —
 * caller decides whether to show a "nothing to import" message.
 */
fun showBookmarkImportDialog(
    context: Context,
    import: BookmarkImport,
    onConfirmed: (BookmarkImport) -> Unit,
) {
    if (import.bookmarks.isEmpty()) return

    val count = import.bookmarks.size
    val labels = import.bookmarks.take(PREVIEW_LIMIT)
    val message = buildString {
        append("Add ")
        append(count)
        append(if (count == 1) " bookmark" else " bookmarks")
        append(" to this device?\n\n")
        for (bm in labels) {
            append("• ")
            appendLine(bm.label.ifBlank { bm.address })
        }
        val remaining = count - labels.size
        if (remaining > 0) {
            append("…and ")
            append(remaining)
            append(if (remaining == 1) " more" else " more")
        }
    }

    AlertDialog.Builder(context)
        .setTitle("Import bookmarks")
        .setMessage(message.trim())
        .setPositiveButton("Import") { _, _ -> onConfirmed(import) }
        .setNegativeButton(android.R.string.cancel, null)
        .show()
}

private const val PREVIEW_LIMIT = 10
