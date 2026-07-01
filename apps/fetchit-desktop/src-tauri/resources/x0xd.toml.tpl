# fetch>it bundled x0xd config template (#251 Layer 1).
#
# Today this file is intentionally minimal: x0xd's DaemonConfig does
# not currently expose peer-relay candidate configuration via TOML,
# so the bundled binary runs on its built-in defaults.
#
# When X0X-0070c lands upstream (gossip-announce subscriber for
# discovering peer-relay candidates at runtime), this template stays
# the same; candidates flow in via the gossip path. When upstream
# adds explicit peer-relay TOML support, fill in:
#
#   [peer_relay]
#   candidates = [
#       "PLACEHOLDER_NY_RELAY_AGENT_ID_HEX",
#       "PLACEHOLDER_FRA_RELAY_AGENT_ID_HEX",
#   ]
#
# and update the first-run substitution in lib.rs to fill the
# placeholders. The substitution path already exists; it currently
# operates on no-op comment lines.

# identity_dir pins the daemon's identity material to an app-managed
# directory that fetch>it seeds from the chat vault before each spawn
# (identity unification: daemon agent id == chat agent id == what the
# recovery phrase restores). Substituted at first run.
identity_dir = "PLACEHOLDER_IDENTITY_DIR"
