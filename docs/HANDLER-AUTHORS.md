# Adding a content handler to fetch>it

Every kind of content fetch>it understands is a `ContentHandler`
implementation registered on a `HandlerRegistry`. This page walks
through adding one. The whole thing is one file plus one registration
line plus byte-fixture tests.

## The contract

```rust
pub trait ContentHandler: Send + Sync {
    fn kind(&self) -> &'static str;
    fn can_handle(&self, head: &[u8], hint: &Hint) -> Confidence;
    fn render(&self, bytes: Bytes, ctx: &RenderContext) -> Result<Rendition>;
}
```

| Method        | What it does                                                     | Cost budget                       |
| ------------- | ---------------------------------------------------------------- | --------------------------------- |
| `kind`        | Stable identifier, used in errors and telemetry.                 | constant                          |
| `can_handle`  | Cheap byte-sniff over the leading slice (≤ 4 KB).                | nanoseconds — runs on every fetch |
| `render`      | Turn the full payload into a typed `Rendition`. May fail.        | proportional to input size        |

## Confidence levels

`can_handle` returns one of:

| Variant      | When                                                       |
| ------------ | ---------------------------------------------------------- |
| `Definite`   | Magic-byte match — no plausible false positives.           |
| `High`       | Strong structural match (e.g. valid JSON parses cleanly).  |
| `Medium`     | Heuristic match (e.g. payload looks textual).              |
| `Low`        | Last-resort fallback. Reserved for the binary handler.     |
| `None`       | Cannot handle these bytes. Excluded from the candidate set. |

The registry picks the highest-confidence claimant. Ties break in
registration order, so register specific handlers first and the
fallback last.

## Adding a `Foo` handler

1. **Create `crates/fetchit-core/src/handlers/foo.rs`.** Mirror the
   shape of an existing handler such as `image.rs` (magic-byte
   sniffer over multiple formats) or `etchit_envelope.rs` (structural
   parser).

2. **Pick a `kind`.** Use the IANA MIME if one exists
   (`application/zip`, `audio/wav`); otherwise a `fetchit/` pseudo-MIME
   (`fetchit/some-format-v1`). Stable across releases — it shows up in
   error messages.

3. **Add the module and register it.** In `handlers/mod.rs`:

   ```rust
   pub mod foo;
   pub use foo::FooHandler;

   pub fn default_registry() -> HandlerRegistry {
       let mut reg = HandlerRegistry::new();
       reg.register(EtchitEnvelopeHandler)
           .register(ImageHandler)
           // ...
           .register(FooHandler)            // <- new line
           .register(BinaryHandler);
       reg
   }
   ```

   Order matters only for confidence ties. Place `Foo` such that
   higher-priority handlers get first refusal.

4. **Write byte-fixture tests in the same file.** At minimum: one
   positive case, one rejection case, and one rendering round-trip.
   Add an inner allow at the top of the test module:

   ```rust
   #[cfg(test)]
   mod tests {
       #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
       // ...
   }
   ```

5. **Add an integration test** in `crates/fetchit-core/tests/registry_integration.rs`
   that drives `default_registry()` against a `Foo` fixture and asserts
   the right `Rendition` variant comes out. This catches priority
   regressions caused by a future handler addition.

## What `Rendition` variant?

If `Foo` decodes to something that fits an existing variant
(`Text`, `Image`, `Audio`, `Video`, `Pdf`, `Json`, `Tabular`,
`Archive`, `Html`, `EtchitEnvelope`, `OpaqueBinary`), use it. Adding a
new variant is allowed but means a coordinated bump in every UI
surface — propose the change on the issue tracker first.

## Forbidden in handler code

- File-system access. Handlers receive bytes; they do not read or
  write paths.
- Network access. The bytes are already fetched; handlers do not call
  out.
- `unwrap()` or `expect()` in non-test paths. Return `Error::Render`
  with a useful reason instead.
- Persistent state. Handlers must be safe to share across threads
  and reuse for every fetch.
