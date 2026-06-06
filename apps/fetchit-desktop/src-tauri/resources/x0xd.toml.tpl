[network]
http_bind = "127.0.0.1:0"

[peer_relay]
enabled = true
fail_threshold = 3
fail_window_ms = 30000
candidates = [
    "PLACEHOLDER_NY_RELAY_AGENT_ID_HEX",
    "PLACEHOLDER_FRA_RELAY_AGENT_ID_HEX",
]
