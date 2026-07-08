# fetchit-mcp

MCP (Model Context Protocol) stdio server over `fetchit-core`: safe, read-only
Autonomi access for AI agents. Same engine as the human shells — same address
validation, same handler registry, same denylist — with a text-safe contract:
binary payloads are described (kind, MIME, size), never returned; text bodies
cap at 64 KiB.

## Build & register

```bash
cargo build -p fetchit-mcp --features net --release
claude mcp add fetchit -- target/release/fetchit-mcp
```

Any MCP-capable host works the same way (stdio transport, newline-delimited
JSON-RPC).

## Tools

| Tool | Input | Returns |
|---|---|---|
| `fetch_render` | `address` (64 hex, `autonomi://` prefix accepted) | Typed JSON summary: `text`/`html`/`json`/`markdown` bodies inline (capped), `image`/`audio`/`video`/`pdf`/`binary` as metadata only, `encrypted-envelope` shape, `blocked` with reason |
| `detect` | `bytes_base64` | Same summary for local bytes; no network |
| `extract_entry` | `address`, `entry_path` | Extracts one file from a ZIP at the address and renders it text-safely (filename hint improves detection); same caps and denylist |

## Environment

| Var | Effect |
|---|---|
| `FETCHIT_MCP_PEERS` | Comma-separated bootstrap peers; default = bundled `DEFAULT_PEERS` |
| `FETCHIT_MCP_TRUST_URL` | e.g. `https://etchit.io/v1` — fetches the signed community denylist at startup and refuses blocked addresses before any bytes move. Unset = no denylist (personal use). FAIL-CLOSED: if set but the denylist can't be loaded, startup aborts (refusing to run with the gate open) unless `FETCHIT_MCP_TRUST_OPTIONAL=1` |
| `FETCHIT_MCP_TRUST_OPTIONAL` | Set to `1` to run UNBLOCKED when the denylist is requested but unreachable, instead of aborting. Only meaningful with `FETCHIT_MCP_TRUST_URL` |

## Behavior notes

- The Autonomi client connects lazily on the first `fetch_render`, so the MCP
  handshake responds instantly; expect ~10–20 s on the first fetch while peers
  bootstrap.
- Fetched bytes are cached in memory (immutable addresses, 256 MiB cap):
  repeat fetches of the same address are instant.
- Read-only by construction: no wallet, no writes, no signing. The `net`
  feature gates the binary; the library (protocol + summaries) is
  network-free and cheap to test.
- Local-stdio prototype; MCPB bundling is the upgrade path if this is ever
  distributed beyond a dev machine.
