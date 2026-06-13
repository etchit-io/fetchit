//! Axum router + handlers for the registry + serving endpoints. Thin
//! handlers delegate to `?`-ergonomic inner fns the unit tests drive
//! without the axum layer (mirrors [`crate::inbox::router`]). Filled in
//! Tasks 9-12.
