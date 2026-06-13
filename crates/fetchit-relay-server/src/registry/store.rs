//! In-memory registry store: atomic FCFS + same-agent continuity +
//! strict hint-epoch monotonicity via a `DashMap` keyed by handle.
//! Filled in Tasks 2-3 of the M5.1 D-half plan.
