package io.etchit.fetchit

import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches WithAutonomi's canonical `bootstrap_peers.toml` so the
 * Settings sheet's "refresh from upstream" button can update the saved
 * peer list without shipping a new APK. Stdlib HTTP + a regex-based
 * TOML scan — no new dep, no full TOML parser.
 *
 * Tolerant on parse: any quoted string in the body that validates as
 * an `ip:port` socket or a `/ip4/`/`/ip6/`/`/dns…` multiaddr counts.
 * A minor schema rotation at WithAutonomi still lands at least some
 * peers rather than failing the refresh outright.
 */
object BootstrapPeersUpstream {

    private const val URL_STR =
        "https://raw.githubusercontent.com/WithAutonomi/ant-node/main/config/bootstrap_peers.toml"

    private val QUOTED = Regex("\"([^\"]+)\"")

    /** GET + parse. Throws on network / HTTP errors or zero peers found. */
    fun fetch(): List<String> {
        val conn = (URL(URL_STR).openConnection() as HttpURLConnection).apply {
            connectTimeout = 8_000
            readTimeout = 8_000
            requestMethod = "GET"
            setRequestProperty("Accept", "text/plain")
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) {
                throw IllegalStateException("HTTP $code from upstream")
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val peers = QUOTED.findAll(body)
                .map { it.groupValues[1].trim() }
                .filter { looksLikePeer(it) }
                .distinct()
                .toList()
            if (peers.isEmpty()) {
                throw IllegalStateException("upstream had no recognisable peer entries")
            }
            return peers
        } finally {
            conn.disconnect()
        }
    }

    private fun looksLikePeer(s: String): Boolean {
        // ip:port shorthand — quick check, no full SocketAddress parse.
        val colon = s.lastIndexOf(':')
        if (colon > 0 && colon < s.length - 1) {
            val port = s.substring(colon + 1).toIntOrNull()
            val host = s.substring(0, colon)
            if (port != null && port in 1..65_535 && host.isNotEmpty() &&
                host.all { it.isDigit() || it == '.' || it == ':' || it == '[' || it == ']' }
            ) return true
        }
        // multiaddr — common prefixes the FFI accepts.
        return s.startsWith("/ip4/") || s.startsWith("/ip6/") || s.startsWith("/dns")
    }
}
