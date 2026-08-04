package io.etchit.fetchit.chat

import android.content.Context
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import io.etchit.fetchit.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * Renders the content cards that sit under a message body or a feed post.
 *
 * A card is built from the address alone and **never** fetches on bind:
 * receiving a message must not spend cellular data, and must not tell the
 * network what landed in someone's inbox. Content facts appear only after the
 * reader taps the card; the outcome is remembered in [AddressCardStates] for
 * the life of the process, so scrolling away and back re-renders from memory.
 *
 * @param onOpen hands an address to the reader — the same entry the
 *   `autonomi://` deep link and the in-bubble link take.
 */
class AddressCardBinder(
    private val context: Context,
    private val scope: CoroutineScope,
    private val states: AddressCardStates,
    private val onOpen: (String) -> Unit,
) {

    /**
     * Fill [container] with one card per address mentioned in [body], or hide
     * it when there are none. Safe to call on every (re)bind of a recycled row.
     */
    fun bind(container: LinearLayout, body: String) {
        val addresses = AutonomiRefs.addresses(body).take(MAX_CARDS)
        container.removeAllViews()
        container.visibility = if (addresses.isEmpty()) View.GONE else View.VISIBLE
        val inflater = LayoutInflater.from(context)
        addresses.forEach { address ->
            val card = inflater.inflate(R.layout.view_address_card, container, false)
            container.addView(card)
            card.setTag(R.id.addressCardRoot, address)
            card.setOnClickListener {
                when (states.stateOf(address)) {
                    // Previewed: the second tap is the open.
                    is AddressCardState.Previewed -> onOpen(address)
                    AddressCardState.Previewing -> Unit
                    else -> preview(card, address)
                }
            }
            card.findViewById<View>(R.id.addressCardOpen).setOnClickListener { onOpen(address) }
            render(card, address)
        }
    }

    private fun preview(card: View, address: String) {
        if (!states.beginPreview(address)) return
        render(card, address)
        scope.launch {
            try {
                states.onPreviewed(address, AutonomiPreview.load(context, address))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Quiet by design: a card that couldn't load says so in place.
                // A Snackbar per failed preview would be noise on a busy thread.
                Log.w(TAG, "preview failed for $address", e)
                states.onFailed(address)
            }
            // The row may have been recycled onto another address while the
            // fetch was in flight. Only repaint the card still showing this
            // one; every other row picks the new state up on its next bind.
            if (card.getTag(R.id.addressCardRoot) == address) render(card, address)
        }
    }

    private fun render(card: View, address: String) {
        val glyph = card.findViewById<TextView>(R.id.addressCardGlyph)
        val title = card.findViewById<TextView>(R.id.addressCardTitle)
        val meta = card.findViewById<TextView>(R.id.addressCardMeta)
        val short = "${address.take(8)}…${address.takeLast(4)}"
        when (val state = states.stateOf(address)) {
            AddressCardState.AddressOnly -> {
                glyph.text = UNKNOWN_GLYPH
                title.text = short
                meta.setText(R.string.address_card_tap_to_preview)
            }
            AddressCardState.Previewing -> {
                glyph.text = UNKNOWN_GLYPH
                title.text = short
                meta.setText(R.string.address_card_previewing)
            }
            AddressCardState.Failed -> {
                glyph.text = UNKNOWN_GLYPH
                title.text = short
                meta.setText(R.string.address_card_failed)
            }
            is AddressCardState.Previewed -> {
                val preview = state.preview
                glyph.text = glyphFor(preview.kind)
                title.text = preview.title ?: short
                // The address stays visible when a title took the top line —
                // it is what actually identifies the content.
                meta.text = listOfNotNull(
                    context.getString(kindLabelFor(preview.kind)),
                    formatCardSize(preview.sizeBytes),
                    short.takeIf { preview.title != null },
                ).joinToString(" · ")
            }
        }
    }

    private fun glyphFor(kind: AddressKind): String = when (kind) {
        AddressKind.WEB -> "🌐"
        AddressKind.TEXT -> "📄"
        AddressKind.IMAGE -> "🖼"
        AddressKind.AUDIO -> "🎵"
        AddressKind.VIDEO -> "🎬"
        AddressKind.PDF -> "📕"
        AddressKind.DATA -> "🧾"
        AddressKind.TABLE -> "📊"
        AddressKind.ARCHIVE -> "🗜"
        AddressKind.ETCH -> "✎"
        AddressKind.BINARY -> "📦"
    }

    private fun kindLabelFor(kind: AddressKind): Int = when (kind) {
        AddressKind.WEB -> R.string.address_card_kind_web
        AddressKind.TEXT -> R.string.address_card_kind_text
        AddressKind.IMAGE -> R.string.address_card_kind_image
        AddressKind.AUDIO -> R.string.address_card_kind_audio
        AddressKind.VIDEO -> R.string.address_card_kind_video
        AddressKind.PDF -> R.string.address_card_kind_pdf
        AddressKind.DATA -> R.string.address_card_kind_data
        AddressKind.TABLE -> R.string.address_card_kind_table
        AddressKind.ARCHIVE -> R.string.address_card_kind_archive
        AddressKind.ETCH -> R.string.address_card_kind_etch
        AddressKind.BINARY -> R.string.address_card_kind_binary
    }

    private companion object {
        const val TAG = "fetchit.chat"

        /** Cap on cards per message so a link dump can't become a wall. */
        const val MAX_CARDS = 4

        /** Stand-in glyph until a preview says what the content actually is. */
        const val UNKNOWN_GLYPH = "◈"
    }
}
