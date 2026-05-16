package io.etchit.fetchit

import android.graphics.BitmapFactory
import android.text.SpannableStringBuilder
import android.view.Gravity
import android.view.View
import android.webkit.MimeTypeMap
import androidx.media3.common.util.UnstableApi
import io.etchit.fetchit.databinding.ActivityMainBinding
import io.etchit.fetchit.syntax.apply as applySyntax
import io.etchit.fetchit.syntax.highlighterFor
import io.noties.markwon.Markwon
import uniffi.fetchit_ffi.RenditionFfi

/**
 * Binds a [`RenditionFfi`] into the views of [`ActivityMainBinding`].
 *
 * Per the spec, every kind of content fetch>it understands gets a
 * dedicated rendering path. This class isolates that big `when` so
 * [`MainActivity`] can stay an orchestrator and so adding a new
 * variant (PDF, archive index, code-with-syntax) is a single edit
 * scoped to one file.
 */
@UnstableApi
class RenditionRenderer(
    private val binding: ActivityMainBinding,
    private val audio: AudioPlayback,
    private val onError: (String) -> Unit,
    archiveCallbacks: ArchiveView.Callbacks,
) {

    private val archiveView = ArchiveView(binding, archiveCallbacks)

    /** Markdown renderer; instantiated lazily so plain-text renditions
     *  pay no startup cost. */
    private val markwon by lazy {
        Markwon.create(binding.root.context)
    }

    /**
     * Render `r` into the activity's content area.
     *
     * Hides the centred fetch button so the rendered content has the
     * full vertical space — caller restores the button by invoking
     * [`clear`].
     */
    fun render(r: RenditionFfi, address: String) {
        clear()
        binding.fetchButton.visibility = View.GONE
        binding.closeButton.visibility = View.VISIBLE
        binding.shareButton.visibility = View.VISIBLE
        // Lock pull-to-refresh while content is on screen — accidentally
        // resetting in the middle of viewing a 5MB video is a real
        // data-loss UX failure.
        binding.swipeRefresh.isEnabled = false
        when (r) {
            is RenditionFfi.Text -> bindText(
                label = if (r.language == "markdown") "text/markdown" else "text/plain",
                body = r.body,
                language = r.language,
            )
            is RenditionFfi.EtchitEnvelope -> bindText(
                label = "etchit/envelope-v1: ${r.title}",
                body = r.content,
                language = r.language,
            )
            is RenditionFfi.Json -> bindText(label = "application/json", body = r.prettyPrinted)
            is RenditionFfi.Pdf -> bindPdf(r.data)
            is RenditionFfi.Image -> bindImage(r.mime, r.data)
            is RenditionFfi.Audio -> bindAudio(r.mime, r.data)
            is RenditionFfi.Video -> bindVideo(r.mime, r.data)
            is RenditionFfi.Html -> bindHtml(r.body)
            is RenditionFfi.Tabular -> bindTabular(r.columns, r.rows)
            is RenditionFfi.Archive -> {
                binding.kindText.text = "application/zip"
                archiveView.bind(address, r.entries)
            }
            is RenditionFfi.OpaqueBinary -> bindBinary(r.mime, r.data)
            else -> bindText(label = "(unsupported rendition variant)", body = r.toString())
        }
    }

    /**
     * Hide every rendition surface, stop any in-flight audio, and
     * restore the fetch button so the user can fetch again. Called
     * before each new fetch and from the host's error path.
     */
    fun clear() {
        binding.contentScroll.visibility = View.GONE
        binding.imageView.visibility = View.GONE
        binding.playerView.visibility = View.GONE
        binding.htmlView.visibility = View.GONE
        binding.htmlView.release()
        binding.epubView.visibility = View.GONE
        binding.epubView.release()
        binding.pdfView.visibility = View.GONE
        binding.pdfView.release()
        archiveView.hide()
        binding.binaryActions.visibility = View.GONE
        binding.closeButton.visibility = View.GONE
        binding.shareButton.visibility = View.GONE
        binding.fetchButton.visibility = View.VISIBLE
        // Re-arm pull-to-refresh now that we're back on the idle
        // screen — pulling on the empty fetch-button area is harmless.
        binding.swipeRefresh.isEnabled = true
        binding.kindText.text = ""
        binding.contentText.text = ""
        // Reset content gravity — bindBinary centers it, bindText
        // wants the natural left alignment.
        binding.contentText.gravity = Gravity.START
        audio.release()
    }

    private fun bindText(label: String, body: String, language: String? = null) {
        // Restore left alignment in case a previous render was binary.
        binding.kindText.gravity = Gravity.START
        binding.contentText.gravity = Gravity.START
        binding.kindText.text = label
        when {
            language == "markdown" -> {
                // Markwon writes formatted spans to the existing TextView,
                // so headings get bigger, bold/italic apply, links go
                // clickable, code blocks go monospace.
                markwon.setMarkdown(binding.contentText, body)
            }
            else -> {
                // Try syntax highlighting: explicit `lang` first, then
                // content-based detection (shebang, first-line patterns).
                // Falls through to plain text when nothing matches.
                val highlighter = highlighterFor(language, body)
                if (highlighter != null) {
                    val sb = SpannableStringBuilder(body)
                    highlighter.applySyntax(sb)
                    binding.contentText.text = sb
                } else {
                    binding.contentText.text = body
                }
            }
        }
        binding.contentScroll.visibility = View.VISIBLE
    }

    private fun bindImage(mime: String, data: ByteArray) {
        binding.kindText.text = mime
        val bitmap = BitmapFactory.decodeByteArray(data, 0, data.size)
        binding.imageView.setImageBitmap(bitmap)
        binding.imageView.visibility = View.VISIBLE
    }

    private fun bindAudio(mime: String, data: ByteArray) {
        binding.kindText.text = "$mime (${data.size} bytes)"
        // Keep controls always visible for an audio-only rendition;
        // the default auto-hide is right for video but feels broken
        // with no surface to tap.
        binding.playerView.controllerShowTimeoutMs = 0
        binding.playerView.controllerHideOnTouch = false
        audio.play(data, onError)
        audio.attachTo(binding.playerView)
        binding.playerView.visibility = View.VISIBLE
    }

    private fun bindVideo(mime: String, data: ByteArray) {
        binding.kindText.text = "$mime (${data.size} bytes)"
        // Default auto-hide controls so the video frame isn't
        // permanently obscured. Tap the frame to bring controls back.
        binding.playerView.controllerShowTimeoutMs = DEFAULT_VIDEO_CONTROL_TIMEOUT_MS
        binding.playerView.controllerHideOnTouch = true
        audio.play(data, onError)
        audio.attachTo(binding.playerView)
        binding.playerView.visibility = View.VISIBLE
    }

    /**
     * Re-display the archive listing for an address whose entries are
     * already known — used by the activity to restore the listing when
     * the user backs out of an entry preview without re-fetching.
     */
    fun showArchive(address: String, entries: List<uniffi.fetchit_ffi.ArchiveEntryFfi>) {
        clear()
        binding.fetchButton.visibility = View.GONE
        binding.closeButton.visibility = View.VISIBLE
        binding.shareButton.visibility = View.VISIBLE
        binding.swipeRefresh.isEnabled = false
        binding.kindText.text = "application/zip"
        archiveView.bind(address, entries)
    }

    /**
     * Render an EPUB (a ZIP carrying `META-INF/container.xml`) as a book
     * in [EpubView]. If it looks like an EPUB but won't parse, fall back
     * to the plain archive listing.
     */
    fun bindEpub(addr: String, bytes: ByteArray, archiveEntries: List<uniffi.fetchit_ffi.ArchiveEntryFfi>) {
        clear()
        binding.fetchButton.visibility = View.GONE
        binding.closeButton.visibility = View.VISIBLE
        binding.shareButton.visibility = View.VISIBLE
        binding.swipeRefresh.isEnabled = false
        if (binding.epubView.bind(addr, bytes)) {
            binding.kindText.text = "application/epub+zip"
            binding.epubView.visibility = View.VISIBLE
        } else {
            archiveView.bind(addr, archiveEntries)
        }
    }

    private fun bindHtml(body: String) {
        binding.kindText.text = "text/html"
        binding.htmlView.load(body)
        binding.htmlView.visibility = View.VISIBLE
    }

    private fun bindTabular(columns: List<String>, rows: List<List<String>>) {
        binding.kindText.text = "text/csv"
        val widths = IntArray(columns.size) { i -> columns[i].length }
        for (row in rows) {
            for ((i, cell) in row.withIndex()) {
                if (i < widths.size && cell.length > widths[i]) widths[i] = cell.length
            }
        }
        val sb = StringBuilder()
        sb.append(columns.padTo(widths))
        sb.append('\n')
        sb.append("─".repeat(widths.sum() + 3 * (widths.size - 1).coerceAtLeast(0)))
        sb.append('\n')
        for (row in rows) {
            sb.append(row.padTo(widths))
            sb.append('\n')
        }
        binding.contentText.text = sb.toString()
        binding.contentScroll.visibility = View.VISIBLE
    }

    private fun List<String>.padTo(widths: IntArray): String =
        withIndex().joinToString("  |  ") { (i, cell) ->
            cell.padEnd(widths.getOrElse(i) { cell.length })
        }

    private fun bindPdf(data: ByteArray) {
        binding.kindText.text = "application/pdf"
        binding.pdfView.load(data)
        binding.pdfView.visibility = View.VISIBLE
    }

    private fun bindBinary(mime: String, data: ByteArray) {
        // Show a friendly extension when one's known (PDF, MP4, …) and
        // fall back to the full MIME otherwise.
        val ext = MimeTypeMap.getSingleton().getExtensionFromMimeType(mime)
        binding.kindText.text = ext?.uppercase() ?: mime
        binding.kindText.gravity = Gravity.CENTER

        val ctx = binding.root.context
        val message = buildString {
            append(ctx.getString(R.string.binary_success_size, formatBytes(data.size)))
            append("\n\n")
            append(ctx.getString(R.string.binary_success_help))
        }
        binding.contentText.text = message
        binding.contentText.gravity = Gravity.CENTER
        binding.contentScroll.visibility = View.VISIBLE

        // Buttons let the user hand the bytes to another app or save
        // them. MainActivity owns the click handlers (it has the
        // launchers + the rendition cache).
        binding.binaryActions.visibility = View.VISIBLE
    }

    private fun formatBytes(bytes: Int): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
        bytes < 1024 * 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
        else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
    }

    private companion object {
        const val DEFAULT_VIDEO_CONTROL_TIMEOUT_MS = 3_000
    }
}
