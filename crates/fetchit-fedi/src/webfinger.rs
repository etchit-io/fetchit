//! `WebFinger` client + handle resolution.
//!
//! Resolves `@user@instance` to an `ActivityPub` actor URL, then to the
//! actor's inbox/outbox URLs. Used by [`crate::transport`] before every
//! outbound POST and by `Client::subscribe_actor` per the Follow flow
//! in plan Stage 5.3.
