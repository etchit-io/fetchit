# Contributing to fetch>it

Thanks for taking the time. fetch>it is small and tries to stay that
way; the handler trait is the seam where new work lands.

## Licensing of contributions

fetch>it is **dual-licensed** under [`AGPL-3.0-only`](LICENSE) and a
separate commercial license (see [`COMMERCIAL.md`](COMMERCIAL.md)). To
keep both tracks coherent, contributions must be licensable under both.

### Sign-off (DCO)

Every commit carries a `Signed-off-by:` trailer certifying you have the
right to submit the change. git does this with `-s`:

```bash
git commit -s -m "your message"
```

### Contributor License Agreement (CLA)

Before your first PR is merged, you'll be asked to confirm a short CLA:
you keep copyright of your contribution, license it to the project
under the AGPL, *and* grant the project the right to also offer it
under the commercial track. The CLA does not transfer ownership; it
just lets the project maintain both license offerings consistently.

If the CLA is a hard no for you, that's understandable — please open an
issue describing the change and a maintainer will pick it up.

## Quality bar

fetch>it ships open-source from commit one. That means:

- `cargo fmt --all` clean
- `cargo clippy --all-targets -- -D warnings` clean
- `cargo test --workspace` green
- Every public item has rustdoc
- `unwrap()` / `expect()` only in tests
- New public functions ship with the tests that cover them, in the
  same change

CI runs all of the above on every push and pull request. The full test
matrix — every app, plus the network-test tiers — is documented in
[`docs/TESTING.md`](docs/TESTING.md).

## Docs track code

Doc-comments and living architecture docs are part of the code, not a
separate artifact. When you change or add behavior:

- Update the affected doc-comments (`//!` / `///`) and any living
  architecture doc (per-crate module docs, files under `docs/`) in the
  **same change**. A behavior change that leaves the docs describing the
  old behavior is an incomplete change.
- Don't write doc-comments that expire. Describe what the code does now;
  phrasing like "ships X for now", "lands next milestone", "doesn't exist
  today", or "scaffolding, wiring lands later" becomes a lie the moment
  the work lands. Future work belongs in an issue or a `TODO` with an
  issue reference, not in a description of current behavior.
- Treat code as the source of truth for current behavior. Doc-comments
  and design docs can drift; verify against the code before relying on
  them. Dated specs and plans under `docs/superpowers/` are point-in-time
  records, not a description of the current system.

## Adding a content handler

See [`docs/HANDLER-AUTHORS.md`](docs/HANDLER-AUTHORS.md). One file,
one registration line, byte-fixture tests in the same commit.

## Scope

fetch>it is **read-only**. It does not write to the network, does not
hold a wallet, does not sign. Pull requests that introduce write paths,
wallet integration, or remote sync will be closed. Those concerns live
in [etch/it](https://etchit.io), not here.
