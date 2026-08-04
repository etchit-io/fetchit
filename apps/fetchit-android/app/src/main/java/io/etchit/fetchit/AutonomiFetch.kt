package io.etchit.fetchit

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Cache-first byte fetch for one Autonomi address — the single network entry
 * point behind both the reader ([`MainActivity`]'s fetch) and the chat / feed
 * address-card preview.
 *
 * The disk cache is consulted first: addresses are content-addressed, so a hit
 * is always the right answer. On a miss the process-scoped [`Client`] is
 * connected (or reused) and whatever comes back is stored, which is why the
 * two surfaces warm the cache for each other — previewing a card in a
 * conversation makes opening it in the reader instant, and vice versa.
 */
suspend fun FetchitApplication.fetchAutonomiBytes(
    address: String,
    peers: List<String>,
): ByteArray = withContext(Dispatchers.IO) {
    bytesCache.get(address)?.let { return@withContext it }
    val bytes = ensureConnected(peers).fetch(address)
    bytesCache.put(address, bytes)
    bytes
}
