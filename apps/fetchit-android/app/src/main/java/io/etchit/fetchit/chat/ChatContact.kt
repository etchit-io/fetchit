package io.etchit.fetchit.chat

import org.json.JSONArray
import org.json.JSONObject

/** A paired peer. [agentIdHex] is the stable identity key (lowercase 64-hex). */
data class ChatContact(
    val agentIdHex: String,
    val displayName: String,
    val addedAtMs: Long,
)

/** JSON serde for the contacts pref blob, versioned like [BookmarkSerde]. */
object ChatContactSerde {
    fun encode(list: List<ChatContact>): String {
        val arr = JSONArray()
        list.forEach { c ->
            arr.put(
                JSONObject()
                    .put("agent", c.agentIdHex)
                    .put("name", c.displayName)
                    .put("added", c.addedAtMs),
            )
        }
        return arr.toString()
    }

    fun decode(raw: String?): List<ChatContact> {
        if (raw.isNullOrBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ChatContact(o.getString("agent"), o.getString("name"), o.optLong("added"))
            }
        }.getOrDefault(emptyList())
    }
}
