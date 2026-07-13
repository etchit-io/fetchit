package io.etchit.fetchit.chat

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject

/**
 * Bridged fediverse posts plus the user's own published posts, persisted so
 * the feed survives an app restart. Own posts are delivered to *other*
 * servers, never echoed back to their author, so without local persistence
 * they'd silently vanish on process death — which reads as data loss.
 *
 * Persistence is injected as [load]/[save] so plain-JVM tests can run
 * store logic without Android; [io.etchit.fetchit.chat.ChatController] wires
 * SharedPreferences-backed lambdas (the [io.etchit.fetchit.BookmarkStore]
 * idiom — public posts, nothing secret, so plain prefs are fine).
 */
class FeedStore(
    private val load: () -> List<FeedPost> = { emptyList() },
    private val save: (List<FeedPost>) -> Unit = {},
) {

    private val _posts = MutableStateFlow(load())

    /** All posts, newest-last (append order). Restored across restarts. */
    val posts: StateFlow<List<FeedPost>> = _posts.asStateFlow()

    /** Append [post], dropping the oldest entry if the cap is exceeded. */
    fun append(post: FeedPost) {
        val current = _posts.value
        val next = if (current.size >= MAX_POSTS) {
            current.drop(1) + post
        } else {
            current + post
        }
        _posts.value = next
        save(next)
    }

    /**
     * Merge a pulled batch of remote posts into the feed. Pulls repeat on
     * every refresh, so entries already present (same author + body) are
     * dropped; the merged feed is re-sorted oldest-first (the list renders
     * top-to-bottom) and capped keeping the NEWEST posts.
     */
    fun mergeRemote(remote: List<FeedPost>) {
        if (remote.isEmpty()) return
        val current = _posts.value
        val seen = current.mapTo(HashSet()) { it.actorUrl to it.body }
        val fresh = remote.filter { (it.actorUrl to it.body) !in seen }
        if (fresh.isEmpty()) return
        val next = (current + fresh)
            .sortedBy { it.receivedAtMs }
            .takeLast(MAX_POSTS)
        _posts.value = next
        save(next)
    }

    private companion object {
        const val MAX_POSTS = 200
    }
}

/**
 * JSON serde for the persisted feed (a single prefs key). Decode is
 * fail-soft: a corrupt or missing blob yields an empty feed, never a crash —
 * the feed is a cache of public content, always safe to drop.
 */
object FeedSerde {

    fun encode(posts: List<FeedPost>): String {
        val arr = JSONArray()
        posts.forEach { p ->
            arr.put(
                JSONObject()
                    .put("actorUrl", p.actorUrl)
                    .put("body", p.body)
                    .put("receivedAtMs", p.receivedAtMs),
            )
        }
        return arr.toString()
    }

    fun decode(raw: String?): List<FeedPost> = runCatching {
        val arr = JSONArray(raw ?: return emptyList())
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            FeedPost(
                actorUrl = o.optString("actorUrl"),
                body = o.optString("body"),
                receivedAtMs = o.optLong("receivedAtMs"),
            )
        }
    }.getOrDefault(emptyList())
}
