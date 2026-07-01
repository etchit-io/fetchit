package io.etchit.fetchit

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [BootstrapPeersUpstream.looksLikePeer] — the shape filter
 * deciding which quoted strings from upstream TOML count as bootstrap peers.
 */
class BootstrapPeersUpstreamTest {

    private fun ok(s: String) = BootstrapPeersUpstream.looksLikePeer(s)

    @Test
    fun accepts_ipv4_host_and_port() {
        assertTrue(ok("1.2.3.4:10000"))
        assertTrue(ok("127.0.0.1:8080"))
        assertTrue(ok("203.0.113.4:1"))      // lowest valid port
        assertTrue(ok("203.0.113.4:65535"))  // highest valid port
    }

    @Test
    fun accepts_bracketed_ipv6_host_and_port() {
        assertTrue(ok("[::1]:9000"))
    }

    @Test
    fun accepts_known_multiaddr_prefixes() {
        assertTrue(ok("/ip4/1.2.3.4/udp/10000/quic"))
        assertTrue(ok("/ip6/::1/udp/10000/quic"))
        assertTrue(ok("/dns4/peer.example/tcp/443"))
    }

    @Test
    fun rejects_dns_hostname_with_port() {
        // Only numeric-IP hosts pass the ip:port shorthand — letters are out.
        assertFalse(ok("example.com:80"))
    }

    @Test
    fun rejects_out_of_range_or_non_numeric_port() {
        assertFalse(ok("1.2.3.4:0"))
        assertFalse(ok("1.2.3.4:65536"))
        assertFalse(ok("1.2.3.4:99999"))
        assertFalse(ok("1.2.3.4:abc"))
    }

    @Test
    fun rejects_malformed_input() {
        assertFalse(ok(""))
        assertFalse(ok("noport"))
        assertFalse(ok("1.2.3.4:"))      // colon is the last character
        assertFalse(ok(":8080"))         // colon at index 0
        assertFalse(ok("http://host"))   // a URL scheme, not a peer
        assertFalse(ok("/tcp/443"))      // multiaddr without an ip/dns prefix
    }
}
