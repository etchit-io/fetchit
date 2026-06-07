//! `FediverseTransport` — outbound HTTPS POST delivery.
//!
//! Plan Stage 2.2 lands `FediverseTransport::deliver(&PublicPost,
//! to_handle)`. The `&PublicPost` parameter (not `&Envelope`) is the
//! type-system enforcement of the DM-never-bridge invariant from plan
//! decision [C].
