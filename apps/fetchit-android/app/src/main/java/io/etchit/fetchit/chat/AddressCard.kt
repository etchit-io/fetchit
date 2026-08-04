package io.etchit.fetchit.chat

import java.util.Locale

/** What kind of thing lives at an address, condensed to card size. */
enum class AddressKind { WEB, TEXT, IMAGE, AUDIO, VIDEO, PDF, DATA, TABLE, ARCHIVE, ETCH, BINARY }

/** The card-sized facts one preview fetch yields. */
data class AddressPreview(
    val kind: AddressKind,
    val sizeBytes: Long,
    val title: String? = null,
)

/** Where one address card is in its lifecycle. */
sealed class AddressCardState {
    /** Built from the address alone — nothing has been fetched. */
    data object AddressOnly : AddressCardState()

    /** A tap started a fetch; it has not landed yet. */
    data object Previewing : AddressCardState()

    /** The fetch landed. */
    data class Previewed(val preview: AddressPreview) : AddressCardState()

    /** The fetch failed. A tap retries. */
    data object Failed : AddressCardState()
}

/**
 * Per-address card state, held for the life of the process.
 *
 * Two guarantees live here. Nothing moves off [AddressCardState.AddressOnly]
 * without a [beginPreview] call, so a card built while binding a received
 * message never touches the network — no cellular spend and no signal to the
 * network about what landed in an inbox. And a preview that already succeeded
 * refuses a second [beginPreview], so scrolling a conversation back and forth
 * re-renders from memory instead of refetching.
 *
 * Bounded by [capacity] on an access-ordered map: a long-lived process
 * browsing many conversations drops the least recently touched cards rather
 * than growing without limit.
 */
class AddressCardStates(private val capacity: Int = DEFAULT_CAPACITY) {

    private val states = object : LinkedHashMap<String, AddressCardState>(16, 0.75f, true) {
        override fun removeEldestEntry(
            eldest: MutableMap.MutableEntry<String, AddressCardState>,
        ): Boolean = size > capacity
    }

    /** Current state for [address]; unseen addresses read as address-only. */
    @Synchronized
    fun stateOf(address: String): AddressCardState =
        states[address] ?: AddressCardState.AddressOnly

    /**
     * Claim the right to fetch [address]. Returns `false` — and changes
     * nothing — when a fetch is already in flight or has already succeeded.
     */
    @Synchronized
    fun beginPreview(address: String): Boolean = when (states[address]) {
        AddressCardState.Previewing, is AddressCardState.Previewed -> false
        else -> {
            states[address] = AddressCardState.Previewing
            true
        }
    }

    /** Record a successful preview. */
    @Synchronized
    fun onPreviewed(address: String, preview: AddressPreview) {
        states[address] = AddressCardState.Previewed(preview)
    }

    /** Record a failed preview; the card offers a retry. */
    @Synchronized
    fun onFailed(address: String) {
        states[address] = AddressCardState.Failed
    }

    companion object {
        const val DEFAULT_CAPACITY: Int = 256
    }
}

/** Compact byte size for a card's meta line. */
fun formatCardSize(bytes: Long): String = when {
    bytes < KB -> "$bytes B"
    bytes < MB -> String.format(Locale.US, "%.1f KB", bytes / KB.toDouble())
    bytes < GB -> String.format(Locale.US, "%.1f MB", bytes / MB.toDouble())
    else -> String.format(Locale.US, "%.1f GB", bytes / GB.toDouble())
}

private const val KB = 1024L
private const val MB = KB * 1024
private const val GB = MB * 1024
