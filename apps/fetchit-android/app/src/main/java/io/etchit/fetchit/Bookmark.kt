package io.etchit.fetchit

import java.util.UUID

/**
 * User-authored persistent state — saved addresses plus labels.
 * Fetched network bytes are cached separately by [`BytesCache`];
 * nothing else is stored.
 *
 * Schema lives in [`BookmarkSerde`], storage in [`BookmarkStore`],
 * UI in [`BookmarkSheet`]. No network, no cross-device sync, no
 * derived state.
 */
data class Bookmark(
    val id: String,
    val label: String,
    val address: String,
    val addedAt: Long,
    val kind: String?,
) {
    companion object {
        /** Construct a fresh bookmark with a new UUID and current epoch-millis. */
        fun create(label: String, address: String, kind: String? = null): Bookmark =
            Bookmark(
                id = UUID.randomUUID().toString(),
                label = label,
                address = address,
                addedAt = System.currentTimeMillis(),
                kind = kind,
            )
    }
}
