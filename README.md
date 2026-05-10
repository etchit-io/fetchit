# fetch/it

> *etch it. **fetch it.** chain it.*

A universal, modular, embeddable read-only viewer for content stored on
the [Autonomi](https://autonomi.com) network. Paste an address, see what
is there — text, image, audio, video, PDF, archive, code — without
installing a wallet, signing a message, or running a node.

fetch/it ships as a small library (`fetchit-core`), a CLI (`fetchit`),
and thin GUI shells over the same engine.

For end-user instructions — every gesture, address-bar format, supported
content type, the `autonomi://` URL scheme, and honest limitations — see
[`docs/USING.md`](docs/USING.md). For the Autonomi-native web protocol
depth, see [`docs/AUTONOMI-WEB.md`](docs/AUTONOMI-WEB.md).

## Status

`0.1.0-dev`. Pre-release. The crate workspace and the handler
architecture are landing first; Android shell and live network access
follow in subsequent commits.

## Layout

```
fetch-it/
├── crates/
│   ├── fetchit-core/     # the library — handler trait, registry, decoders
│   └── fetchit-cli/      # `fetchit get <addr>` — the command-line interface
└── docs/
    └── HANDLER-AUTHORS.md
```

GUI shells (`apps/fetchit-android/`, later `apps/fetchit-desktop/`) live
in this same workspace once they exist.

## Building

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

## License

GPL-3.0-only. See [`LICENSE`](LICENSE). Embedding into closed-source
applications is not supported by direct linking — use the CLI, the
Android intent surface, or (later) the WASM build via process-boundary
integration.

## Family

fetch/it sits alongside [etch/it](https://etchit.io) and chain/it. Same
palette, same fonts, same panel grammar. Look-and-feel parity across
the family is a stated goal, not an accident.
