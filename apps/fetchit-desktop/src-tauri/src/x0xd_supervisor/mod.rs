//! Supervisor for the local `x0xd` daemon: binary selection, spawn,
//! crash-loop detection, and clean shutdown.

pub mod pick;
#[allow(unused_imports)]
pub use pick::{pick_binary, BinaryChoice};
