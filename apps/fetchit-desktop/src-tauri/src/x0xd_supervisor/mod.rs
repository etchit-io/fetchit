//! Supervisor for the local `x0xd` daemon: binary selection, spawn,
//! crash-loop detection, and clean shutdown.

pub mod pick;
#[allow(unused_imports)]
pub use pick::{pick_binary, BinaryChoice};

pub mod spawn;
#[allow(unused_imports)]
pub use spawn::{pick_free_port, spawn_bundled};

pub mod supervise;
#[allow(unused_imports)]
pub use supervise::CrashLoopDetector;
