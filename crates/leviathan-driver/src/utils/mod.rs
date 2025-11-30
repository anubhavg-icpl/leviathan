//! Kernel Utility Modules
//!
//! Common kernel-mode utilities for driver development:
//! - Timers and DPC (Deferred Procedure Calls)
//! - Work items for PASSIVE_LEVEL operations
//! - Memory management (MDL, pool allocations)
//! - Synchronization primitives
//! - ETW (Event Tracing for Windows) logging
//! - Kernel-User communication (ring buffer, shared memory)

pub mod timer;
pub mod memory;
pub mod sync;
pub mod etw;
pub mod comm;
