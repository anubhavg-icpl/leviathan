//! Kernel Timers, DPCs, and Work Items
//!
//! Provides mechanisms for deferred and scheduled execution in kernel mode.
//!
//! # Components
//! - **DPC (Deferred Procedure Call)**: High-priority kernel execution at DISPATCH_LEVEL
//! - **Timer + DPC**: Schedule code to run after a delay
//! - **Work Items**: Execute code at PASSIVE_LEVEL (can use blocking operations)
//!
//! # IRQL Considerations
//! - DPC routines run at DISPATCH_LEVEL (cannot page fault, no blocking)
//! - Work items run at PASSIVE_LEVEL (full kernel functionality)
//! - Timer callbacks run as DPCs (DISPATCH_LEVEL)
//!
//! # Use Cases
//! - Periodic polling/monitoring
//! - Deferred interrupt processing
//! - Background cleanup tasks
//! - Delayed operations

use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{
        KeInitializeDpc, KeInitializeTimer, KeSetTimerEx, KeCancelTimer,
        KeInitializeEvent, KeWaitForSingleObject,
        IoAllocateWorkItem, IoQueueWorkItem, IoFreeWorkItem,
    },
    KDPC, KTIMER, LARGE_INTEGER, PKDPC, PKTIMER, PVOID, PDEVICE_OBJECT,
    PIO_WORKITEM, IO_WORKITEM, WORK_QUEUE_TYPE,
};

/// Wrapper for a kernel timer with associated DPC
pub struct KernelTimer {
    timer: KTIMER,
    dpc: KDPC,
    active: bool,
}

impl KernelTimer {
    /// Create a new uninitialized timer
    ///
    /// # Safety
    /// Must call `init` before using the timer
    pub const unsafe fn new_uninit() -> Self {
        Self {
            timer: unsafe { core::mem::zeroed() },
            dpc: unsafe { core::mem::zeroed() },
            active: false,
        }
    }

    /// Initialize the timer with a DPC callback
    ///
    /// # Safety
    /// - Must be called at IRQL <= DISPATCH_LEVEL
    /// - Callback will be invoked at DISPATCH_LEVEL
    pub unsafe fn init(&mut self, callback: unsafe extern "C" fn(PKDPC, PVOID, PVOID, PVOID), context: PVOID) {
        unsafe {
            KeInitializeTimer(&mut self.timer);
            KeInitializeDpc(&mut self.dpc, Some(callback), context);
        }
    }

    /// Start the timer with specified interval
    ///
    /// # Parameters
    /// - `due_time_ms`: Initial delay in milliseconds (negative = relative)
    /// - `period_ms`: Repeat period in milliseconds (0 = one-shot)
    ///
    /// # Safety
    /// Timer must be initialized
    pub unsafe fn start(&mut self, due_time_ms: i64, period_ms: u32) {
        // Convert to 100-nanosecond units (negative = relative time)
        let due_time = LARGE_INTEGER {
            QuadPart: -due_time_ms * 10_000,
        };

        unsafe {
            KeSetTimerEx(&mut self.timer, due_time, period_ms as i32, &mut self.dpc);
        }
        self.active = true;

        println!(
            "[Leviathan] Timer started: due={}ms, period={}ms",
            due_time_ms, period_ms
        );
    }

    /// Cancel the timer
    ///
    /// # Safety
    /// Timer must be initialized
    pub unsafe fn cancel(&mut self) -> bool {
        if !self.active {
            return false;
        }

        let was_queued = unsafe { KeCancelTimer(&mut self.timer) };
        self.active = false;
        println!("[Leviathan] Timer cancelled");
        was_queued != 0
    }

    /// Check if timer is active
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// Example DPC callback function
///
/// # Safety
/// Called at DISPATCH_LEVEL - cannot page fault or block!
pub unsafe extern "C" fn example_dpc_callback(
    _dpc: PKDPC,
    context: PVOID,
    _arg1: PVOID,
    _arg2: PVOID,
) {
    // context contains the user-provided data
    let _ = context;

    // DPC rules:
    // - Cannot access paged memory
    // - Cannot call blocking functions
    // - Cannot acquire mutex/fast mutex
    // - Keep execution time short
    // - If lengthy work needed, queue a work item

    println!("[Leviathan] DPC callback executed");
}

/// Work item wrapper for PASSIVE_LEVEL execution
pub struct WorkItem {
    work_item: PIO_WORKITEM,
    device: PDEVICE_OBJECT,
}

impl WorkItem {
    /// Allocate a new work item
    ///
    /// # Safety
    /// - Must be called at IRQL <= DISPATCH_LEVEL
    /// - Device object must remain valid while work item exists
    pub unsafe fn new(device: PDEVICE_OBJECT) -> Option<Self> {
        let work_item = unsafe { IoAllocateWorkItem(device) };
        if work_item.is_null() {
            return None;
        }

        Some(Self { work_item, device })
    }

    /// Queue the work item for execution
    ///
    /// # Parameters
    /// - `callback`: Function to execute at PASSIVE_LEVEL
    /// - `context`: User-provided context
    /// - `queue_type`: DelayedWorkQueue (normal) or CriticalWorkQueue (higher priority)
    ///
    /// # Safety
    /// Work item must be valid and not already queued
    pub unsafe fn queue(
        &self,
        callback: unsafe extern "C" fn(PDEVICE_OBJECT, PVOID),
        context: PVOID,
        queue_type: WORK_QUEUE_TYPE,
    ) {
        unsafe {
            IoQueueWorkItem(
                self.work_item,
                Some(callback),
                queue_type,
                context,
            );
        }
        println!("[Leviathan] Work item queued");
    }
}

impl Drop for WorkItem {
    fn drop(&mut self) {
        if !self.work_item.is_null() {
            unsafe { IoFreeWorkItem(self.work_item) };
        }
    }
}

/// Example work item callback
///
/// Runs at PASSIVE_LEVEL - can perform any kernel operation
pub unsafe extern "C" fn example_work_callback(
    device: PDEVICE_OBJECT,
    context: PVOID,
) {
    let _ = (device, context);

    // At PASSIVE_LEVEL, we can:
    // - Access paged memory
    // - Call blocking functions
    // - Acquire mutexes
    // - Perform file I/O
    // - Sleep

    println!("[Leviathan] Work item callback executed at PASSIVE_LEVEL");
}

/// One-shot timer that automatically queues a work item
///
/// Useful pattern: DPC (fast) triggers work item (full functionality)
pub struct DeferredWork {
    timer: KTIMER,
    dpc: KDPC,
}

impl DeferredWork {
    /// Create deferred work that runs after a delay
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL
    pub unsafe fn schedule_after_ms(
        delay_ms: u64,
        work_callback: unsafe extern "C" fn(PDEVICE_OBJECT, PVOID),
        device: PDEVICE_OBJECT,
        context: PVOID,
    ) -> Option<Self> {
        let mut deferred = Self {
            timer: unsafe { core::mem::zeroed() },
            dpc: unsafe { core::mem::zeroed() },
        };

        // Store callback info in DPC context
        // In production, would allocate a context structure

        unsafe {
            KeInitializeTimer(&mut deferred.timer);
            // DPC would queue the work item
            KeInitializeDpc(&mut deferred.dpc, Some(deferred_dpc_handler), context);
        }

        let due_time = LARGE_INTEGER {
            QuadPart: -(delay_ms as i64 * 10_000),
        };

        unsafe {
            KeSetTimerEx(&mut deferred.timer, due_time, 0, &mut deferred.dpc);
        }

        Some(deferred)
    }
}

/// DPC handler that queues a work item
unsafe extern "C" fn deferred_dpc_handler(
    _dpc: PKDPC,
    context: PVOID,
    _arg1: PVOID,
    _arg2: PVOID,
) {
    // In production:
    // 1. Extract work item info from context
    // 2. Queue work item using IoQueueWorkItem
    // 3. Clean up timer resources

    let _ = context;
    println!("[Leviathan] Deferred DPC -> queueing work item");
}

/// Periodic task runner
///
/// Runs a callback at regular intervals using timer + DPC
pub struct PeriodicTask {
    timer: KernelTimer,
    interval_ms: u32,
}

impl PeriodicTask {
    /// Create a new periodic task
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL
    pub unsafe fn new(
        interval_ms: u32,
        callback: unsafe extern "C" fn(PKDPC, PVOID, PVOID, PVOID),
        context: PVOID,
    ) -> Self {
        let mut timer = unsafe { KernelTimer::new_uninit() };
        unsafe { timer.init(callback, context) };

        Self { timer, interval_ms }
    }

    /// Start the periodic task
    pub unsafe fn start(&mut self) {
        unsafe {
            self.timer.start(self.interval_ms as i64, self.interval_ms);
        }
    }

    /// Stop the periodic task
    pub unsafe fn stop(&mut self) {
        unsafe { self.timer.cancel() };
    }
}

/// Common periodic task implementations
pub mod tasks {
    use super::*;

    /// Heartbeat task - logs driver status periodically
    pub unsafe extern "C" fn heartbeat_callback(
        _dpc: PKDPC,
        _context: PVOID,
        _arg1: PVOID,
        _arg2: PVOID,
    ) {
        // Quick status check at DISPATCH_LEVEL
        // In production: update statistics, check health
        println!("[Leviathan] Heartbeat - driver alive");
    }

    /// Cleanup task - periodic resource cleanup
    pub unsafe extern "C" fn cleanup_callback(
        _dpc: PKDPC,
        context: PVOID,
        _arg1: PVOID,
        _arg2: PVOID,
    ) {
        // Queue a work item for actual cleanup (needs PASSIVE_LEVEL)
        let _ = context;
        println!("[Leviathan] Cleanup task triggered");
    }
}
