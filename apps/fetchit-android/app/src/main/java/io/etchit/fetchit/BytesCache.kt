package io.etchit.fetchit

import android.util.Log
import java.io.File

/**
 * Disk-backed byte cache keyed by 64-hex Autonomi address.
 *
 * Autonomi addresses are content-addressed: the bytes stored at any
 * given address are immutable forever. That makes the cache policy
 * the simplest possible — if we have it, we have the right answer.
 * No expiry, no revalidation, no staleness rules. Anything fetched
 * once is correct forever.
 *
 * Both top-level fetches and SPA subresources (every
 * `<img src="autonomi://…">`, `fetch("autonomi://…")`, etc.)
 * consult this cache before going to the network; entries survive
 * app restarts.
 *
 * **Storage layout**: `<rootDir>/<first-2-hex-chars>/<full-64-hex>`
 * sharding so a busy directory (256 shards × thousands of entries)
 * stays readable on a phone filesystem.
 *
 * **Eviction**: LRU by `mtime`. On every `put` we touch the file's
 * modification time; if total cache size exceeds [`maxSizeBytes`]
 * (default 500 MB) the oldest files are deleted until under the cap.
 *
 * **Thread-safety**: `get` and `put` synchronize on the cache instance.
 * Both `HtmlView.shouldInterceptRequest` (WebView network thread) and
 * `MainActivity.doFetch` (`Dispatchers.IO`) call into here, sometimes
 * concurrently.
 */
class BytesCache(
    private val rootDir: File,
    private val maxSizeBytes: Long = DEFAULT_MAX_SIZE,
) {
    init { rootDir.mkdirs() }

    /**
     * Read cached bytes for `addr`, or `null` on miss. Touches the
     * file's mtime so this counts as a recent access for LRU.
     */
    fun get(addr: String): ByteArray? {
        val file = fileFor(addr) ?: return null
        synchronized(this) {
            if (!file.exists()) return null
            return try {
                val bytes = file.readBytes()
                file.setLastModified(System.currentTimeMillis())
                bytes
            } catch (e: Exception) {
                Log.w(TAG, "cache read failed for $addr", e)
                null
            }
        }
    }

    /**
     * Write `bytes` for `addr`. Triggers LRU eviction if cache size
     * exceeds the cap. Failures (out of disk, permission issues) are
     * logged and swallowed — caching is best-effort.
     */
    fun put(addr: String, bytes: ByteArray) {
        val file = fileFor(addr) ?: return
        synchronized(this) {
            try {
                file.parentFile?.mkdirs()
                file.writeBytes(bytes)
                file.setLastModified(System.currentTimeMillis())
                evictIfNeeded()
            } catch (e: Exception) {
                Log.w(TAG, "cache write failed for $addr", e)
            }
        }
    }

    /** Snapshot of total cache size + entry count, for diagnostics. */
    fun stats(): Stats {
        synchronized(this) {
            var size = 0L
            var count = 0
            rootDir.walkTopDown().filter { it.isFile }.forEach {
                size += it.length()
                count++
            }
            return Stats(sizeBytes = size, entries = count)
        }
    }

    /** Wipe the cache. Used by settings "clear cache" and tests. */
    fun clear() {
        synchronized(this) {
            rootDir.deleteRecursively()
            rootDir.mkdirs()
        }
    }

    private fun fileFor(addr: String): File? {
        if (!isValidAutonomiAddress(addr)) return null
        val lower = addr.lowercase()
        val shard = lower.substring(0, 2)
        return File(rootDir, "$shard/$lower")
    }

    private fun evictIfNeeded() {
        val files = rootDir.walkTopDown().filter { it.isFile }.toList()
        var total = files.sumOf { it.length() }
        if (total <= maxSizeBytes) return
        // Oldest files first → drop until under cap.
        for (f in files.sortedBy { it.lastModified() }) {
            if (total <= maxSizeBytes) break
            total -= f.length()
            try { f.delete() } catch (_: Exception) { /* best-effort */ }
        }
    }

    data class Stats(val sizeBytes: Long, val entries: Int) {
        val sizeMb: Double get() = sizeBytes / (1024.0 * 1024.0)
    }

    companion object {
        const val DEFAULT_MAX_SIZE: Long = 500L * 1024 * 1024
        const val TAG = "fetchit.cache"
    }
}
