# Canonical Autonomi addresses for fetch>it example SPAs

This file pins the canonical 64-hex Autonomi addresses for the SPAs in
`docs/examples/`. Each row records the template name, its published
address on Autonomi, the BLAKE3 of its source bytes, and the fetch>it
commit those bytes came from.

etch>it's publisher templates (in `src/publisher/templates/pins.ts`)
reference these same addresses; this file is the joint source of truth.

## Pinned addresses

| Template      | Autonomi address                                                   | BLAKE3                                                             | Source commit | Source file                      |
| ------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ | ------------- | -------------------------------- |
| `showcase`    | `fb38c1cb22cb0bd2317580054d56f1f96b50884fc31eb399acec6dcc6a3a7e73` | `26ebbd022e6200c0d7e7f69a7f50c6ca013442b582e4469602405c28bf40143e` | `bd58bb5`     | `docs/examples/showcase.html`    |
| `file-viewer` | `394872d6e6a1523956d1bc28daa3994b28b7af00f978c1e8c1984998d43e31d4` | `55e070ca422db0bb36272dab33a6f2d6857f799f300cd28af82723d0f820873d` | `db2a830`     | `docs/examples/file-viewer.html` |

## How to verify a pin

The BLAKE3 column lets either side check that the address still
corresponds to the source file at the given commit. For each row:

```
git show <commit>:<source file> | b3sum                # if b3sum installed
# or
python3 -c "import sys, subprocess; from blake3 import blake3; \
    print(blake3(subprocess.run(['git','show','<commit>:<source file>'], \
        capture_output=True, check=True).stdout).hexdigest())"
```

The resulting hex should match the BLAKE3 column. If it does not, the
source has drifted from the pinned upload — the SPA must be re-published
and the row updated.

## How to add a new template SPA

1. Commit the new source HTML to `docs/examples/<name>.html`.
2. etch>it (or whoever holds the publish key) uploads the committed
   bytes to Autonomi via the **Etch** tab. The upload returns a
   64-hex address.
3. Compute BLAKE3 of the source bytes (see above) and confirm it
   matches whatever etch>it computed pre-upload.
4. Add a row to the table above with the template name, address,
   BLAKE3, and the commit that introduced the file.
5. Open the relevant publisher-template config in etch>it
   (`src/publisher/templates/pins.ts`) and reference the same address.
