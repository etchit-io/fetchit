package io.etchit.fetchit

import java.util.UUID

/**
 * The only persisted user data in fetch>it (spec §3a).
 *
 * Stays a plain data class — schema lives in [`BookmarkSerde`], storage
 * in [`BookmarkStore`], UI in [`BookmarkSheet`]. No network, no
 * cross-device sync, no derived state.
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
