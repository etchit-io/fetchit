//! Wire schemas for the trust service.
//!
//! The definitions live in the leaf `fetchit-trust-types` crate so
//! consumers (the reader engine, the chat stack, the verifier) can
//! depend on the vocabulary without compiling the server stack. This
//! module re-exports them so `fetchit_trust::types::*` and the
//! `crate::types::*` internal paths keep resolving unchanged.

pub use fetchit_trust_types::*;
