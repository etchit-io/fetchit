# Contributing to fetch/it

Thanks for taking the time. fetch/it is small and tries to stay that
way; the handler trait is the seam where new work lands.

## Sign-off (DCO)

Every commit must carry a `Signed-off-by:` trailer. This certifies you
have the right to submit the change under the project's license
(GPL-3.0-only). git does this automatically with `-s`:

```bash
git commit -s -m "your message"
```

There is no separate CLA. The DCO trailer is the agreement.

## Quality bar

fetch/it ships open-source from commit one. That means:

- `cargo fmt --all` clean
- `cargo clippy --all-targets -- -D warnings` clean
- `cargo test --workspace` green
- Every public item has rustdoc
- `unwrap()` / `expect()` only in tests
- New public functions ship with the tests that cover them, in the
  same change

CI runs all of the above on every push and pull request.

## Adding a content handler

See [`docs/HANDLER-AUTHORS.md`](docs/HANDLER-AUTHORS.md). One file,
one registration line, byte-fixture tests in the same commit.

## Scope

fetch/it is **read-only**. It does not write to the network, does not
hold a wallet, does not sign. Pull requests that introduce write paths,
wallet integration, or remote sync will be closed. Those concerns live
in [etch/it](https://etchit.io), not here.
