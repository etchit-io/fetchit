package io.etchit.fetchit.chat

import android.content.Context
import io.etchit.fetchit.SettingsStore
import io.etchit.fetchit.fetchAutonomiBytes
import io.etchit.fetchit.fetchitApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.fetchit_ffi.RenditionFfi
import uniffi.fetchit_ffi.detect

/**
 * Turns one address into the facts an address card shows.
 *
 * Runs the reader's own path — [io.etchit.fetchit.fetchAutonomiBytes] (disk
 * cache first, shared client, same peer list) then the FFI's [detect] — so a
 * preview and a later open never fetch the same bytes twice. Only ever
 * reached from a user tap; nothing here runs on message receipt.
 *
 * A preview therefore costs a full fetch of the content, exactly as opening
 * it would. That is the deal a tap makes, and why nothing previews itself.
 */
object AutonomiPreview {

    /** Whole body off the main thread: the peer list is a disk read and
     *  [detect] classifies every byte the address holds. */
    suspend fun load(context: Context, address: String): AddressPreview =
        withContext(Dispatchers.IO) {
            val bytes = context.fetchitApp()
                .fetchAutonomiBytes(address, SettingsStore(context).peers())
            val rendition = detect(bytes)
            AddressPreview(
                kind = kindOf(rendition),
                sizeBytes = bytes.size.toLong(),
                title = titleOf(rendition),
            )
        }

    private fun kindOf(rendition: RenditionFfi): AddressKind = when (rendition) {
        is RenditionFfi.Html -> AddressKind.WEB
        is RenditionFfi.Text -> AddressKind.TEXT
        is RenditionFfi.Image -> AddressKind.IMAGE
        is RenditionFfi.Audio -> AddressKind.AUDIO
        is RenditionFfi.Video -> AddressKind.VIDEO
        is RenditionFfi.Pdf -> AddressKind.PDF
        is RenditionFfi.Json -> AddressKind.DATA
        is RenditionFfi.Tabular -> AddressKind.TABLE
        is RenditionFfi.Archive -> AddressKind.ARCHIVE
        is RenditionFfi.EtchitEnvelope -> AddressKind.ETCH
        else -> AddressKind.BINARY
    }

    /** A name for the content, when the rendition carries one. HTML titles go
     *  through the bounded [HtmlTitle] scan — never a WebView. */
    private fun titleOf(rendition: RenditionFfi): String? = when (rendition) {
        is RenditionFfi.Html -> HtmlTitle.extract(rendition.body)
        is RenditionFfi.EtchitEnvelope -> rendition.title.trim().takeIf { it.isNotEmpty() }
        else -> null
    }
}
