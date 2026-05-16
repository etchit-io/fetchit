package io.etchit.fetchit

import android.view.LayoutInflater
import android.view.View
import io.etchit.fetchit.databinding.ActivityMainBinding
import uniffi.fetchit_ffi.ArchiveEntryFfi

/**
 * Drives the archive surface: a tappable list of entries inside the
 * `archiveView` ScrollView from `activity_main.xml`. Tapping an entry
 * hands the activity the entry's bytes so it can detect-and-render the
 * inner content with the existing rendition machinery (image / audio /
 * video / pdf / text / …). fetch>it is the viewer — there's no
 * hand-off to other apps for kinds the engine already understands.
 *
 * Pure UI layer — the activity owns the heavy lifting (FFI extraction,
 * SAF launchers, back-nav) via [Callbacks].
 */
class ArchiveView(
    private val binding: ActivityMainBinding,
    private val callbacks: Callbacks,
) {

    interface Callbacks {
        /** User tapped "save archive" — write the cached archive bytes
         *  to a SAF-picked location.                                      */
        fun onSaveArchive(address: String)

        /** User tapped an entry — extract its bytes and render the
         *  inner content. Kinds fetch>it doesn't render fall through to
         *  the OpaqueBinary path's existing save / open-with row.        */
        fun onEntryTap(address: String, entryPath: String)
    }

    /** Populate the list for the archive at `address`. Hides every other
     *  rendition surface; visible only when called.                       */
    fun bind(address: String, entries: List<ArchiveEntryFfi>) {
        val ctx = binding.root.context
        binding.archiveSummary.text = ctx.getString(R.string.archive_summary, entries.size)
        binding.saveArchiveButton.setOnClickListener { callbacks.onSaveArchive(address) }

        binding.archiveList.removeAllViews()
        val inflater = LayoutInflater.from(ctx)
        for (entry in entries) {
            val row = inflater.inflate(R.layout.archive_entry_row, binding.archiveList, false)
            val pathView = row.findViewById<android.widget.TextView>(R.id.entryPath)
            val sizeView = row.findViewById<android.widget.TextView>(R.id.entrySize)
            pathView.text = entry.path
            val s = entry.size
            sizeView.text = if (s != null) formatBytes(s) else "?"
            row.setOnClickListener { callbacks.onEntryTap(address, entry.path) }
            binding.archiveList.addView(row)
        }
        binding.archiveView.visibility = View.VISIBLE
    }

    /** Hide the surface (used by RenditionRenderer.clear()).             */
    fun hide() {
        binding.archiveView.visibility = View.GONE
        binding.archiveList.removeAllViews()
    }

    private fun formatBytes(n: ULong): String = when {
        n < 1024u -> "$n B"
        n < 1024u * 1024u -> "%.1f KB".format(n.toDouble() / 1024.0)
        n < 1024u * 1024u * 1024u -> "%.1f MB".format(n.toDouble() / (1024.0 * 1024.0))
        else -> "%.2f GB".format(n.toDouble() / (1024.0 * 1024.0 * 1024.0))
    }
}
