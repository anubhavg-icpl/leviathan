//! Kernel Synchronization Primitives
//!
//! Provides thread-safe synchronization for kernel-mode code:
//! - Spinlocks (DISPATCH_LEVEL)
//! - Fast Mutex (APC_LEVEL)
//! - Executive Resources (Read/Write locks)
//! - Event objects (signaling)
//! - Interlocked operations
//!
//! # IRQL Rules
//! - Spinlock: Raises to DISPATCH_LEVEL, cannot page fault
//! - Fast Mutex: Raises to APC_LEVEL, can access paged memory
//! - ERESOURCE: Can be acquired shared (read) or exclusive (write)
//! - Event: Wait lowers to PASSIVE_LEVEL

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{
        KeInitializeSpinLock, KeAcquireSpinLock, KeReleaseSpinLock,
        ExInitializeFastMutex, ExAcquireFastMutex, ExReleaseFastMutex,
        ExInitializeResourceLite, ExAcquireResourceExclusiveLite,
        ExAcquireResourceSharedLite, ExReleaseResourceLite, ExDeleteResourceLite,
        KeInitializeEvent, KeSetEvent, KeClearEvent, KeWaitForSingleObject,
    },
    KSPIN_LOCK, KIRQL, FAST_MUTEX, ERESOURCE, KEVENT,
    EVENT_TYPE, KWAIT_REASON, KPROCESSOR_MODE, LARGE_INTEGER,
};

/// Spinlock wrapper for kernel synchronization
///
/// Spinlocks are the fastest synchronization primitive but have restrictions:
/// - Cannot access paged memory while held
/// - Cannot call functions that may page fault
/// - Should be held for very short periods
pub struct SpinLock {
    lock: UnsafeCell<KSPIN_LOCK>,
}

// Safety: SpinLock is designed for multi-threaded kernel access
unsafe impl Send for SpinLock {}
unsafe impl Sync for SpinLock {}

impl SpinLock {
    /// Create a new spinlock
    ///
    /// # Safety
    /// Must call init() before using
    pub const fn new() -> Self {
        Self {
            lock: UnsafeCell::new(0),
        }
    }

    /// Initialize the spinlock
    ///
    /// # Safety
    /// Must be called at IRQL <= DISPATCH_LEVEL
    pub unsafe fn init(&self) {
        unsafe { KeInitializeSpinLock(self.lock.get()) };
    }

    /// Acquire the spinlock, returning the previous IRQL
    ///
    /// # Safety
    /// - Must be at IRQL <= DISPATCH_LEVEL
    /// - Must call release() with the returned IRQL
    pub unsafe fn acquire(&self) -> KIRQL {
        let mut old_irql: KIRQL = 0;
        unsafe { KeAcquireSpinLock(self.lock.get(), &mut old_irql) };
        old_irql
    }

    /// Release the spinlock
    ///
    /// # Safety
    /// - Must have called acquire() first
    /// - old_irql must be the value from acquire()
    pub unsafe fn release(&self, old_irql: KIRQL) {
        unsafe { KeReleaseSpinLock(self.lock.get(), old_irql) };
    }

    /// Execute a closure while holding the spinlock
    ///
    /// # Safety
    /// Closure must not:
    /// - Access paged memory
    /// - Call blocking functions
    /// - Acquire other locks that could deadlock
    pub unsafe fn with_lock<T, F: FnOnce() -> T>(&self, f: F) -> T {
        let irql = unsafe { self.acquire() };
        let result = f();
        unsafe { self.release(irql) };
        result
    }
}

/// Fast Mutex - lighter than regular mutex
///
/// Operates at APC_LEVEL, allowing paged memory access.
/// Cannot be acquired recursively.
pub struct FastMutex {
    mutex: UnsafeCell<FAST_MUTEX>,
}

unsafe impl Send for FastMutex {}
unsafe impl Sync for FastMutex {}

impl FastMutex {
    /// Create a new fast mutex
    ///
    /// # Safety
    /// Must call init() before using
    pub const fn new() -> Self {
        Self {
            mutex: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        }
    }

    /// Initialize the fast mutex
    ///
    /// # Safety
    /// Must be called at IRQL <= DISPATCH_LEVEL
    pub unsafe fn init(&self) {
        unsafe { ExInitializeFastMutex(self.mutex.get()) };
    }

    /// Acquire the fast mutex
    ///
    /// # Safety
    /// - Must be at IRQL < APC_LEVEL (typically PASSIVE_LEVEL)
    /// - Do not acquire recursively
    pub unsafe fn acquire(&self) {
        unsafe { ExAcquireFastMutex(self.mutex.get()) };
    }

    /// Release the fast mutex
    ///
    /// # Safety
    /// Must have called acquire() first
    pub unsafe fn release(&self) {
        unsafe { ExReleaseFastMutex(self.mutex.get()) };
    }

    /// Execute closure with mutex held
    ///
    /// # Safety
    /// Same restrictions as acquire()
    pub unsafe fn with_lock<T, F: FnOnce() -> T>(&self, f: F) -> T {
        unsafe { self.acquire() };
        let result = f();
        unsafe { self.release() };
        result
    }
}

/// Executive Resource - Read/Write Lock
///
/// Allows multiple readers or one exclusive writer.
/// Best for data that is read frequently but written rarely.
pub struct ExResource {
    resource: UnsafeCell<ERESOURCE>,
    initialized: AtomicU32,
}

unsafe impl Send for ExResource {}
unsafe impl Sync for ExResource {}

impl ExResource {
    /// Create a new executive resource
    pub const fn new() -> Self {
        Self {
            resource: UnsafeCell::new(unsafe { core::mem::zeroed() }),
            initialized: AtomicU32::new(0),
        }
    }

    /// Initialize the resource
    ///
    /// # Safety
    /// Must be called at IRQL <= DISPATCH_LEVEL
    pub unsafe fn init(&self) -> Result<(), ()> {
        if self.initialized.load(Ordering::SeqCst) != 0 {
            return Ok(()); // Already initialized
        }

        let status = unsafe { ExInitializeResourceLite(self.resource.get()) };
        if status == 0 {
            self.initialized.store(1, Ordering::SeqCst);
            Ok(())
        } else {
            Err(())
        }
    }

    /// Acquire exclusive (write) access
    ///
    /// # Safety
    /// Must be at IRQL < DISPATCH_LEVEL
    pub unsafe fn acquire_exclusive(&self, wait: bool) -> bool {
        unsafe {
            ExAcquireResourceExclusiveLite(self.resource.get(), wait as u8) != 0
        }
    }

    /// Acquire shared (read) access
    ///
    /// # Safety
    /// Must be at IRQL < DISPATCH_LEVEL
    pub unsafe fn acquire_shared(&self, wait: bool) -> bool {
        unsafe {
            ExAcquireResourceSharedLite(self.resource.get(), wait as u8) != 0
        }
    }

    /// Release the resource
    ///
    /// # Safety
    /// Must have acquired the resource first
    pub unsafe fn release(&self) {
        unsafe { ExReleaseResourceLite(self.resource.get()) };
    }

    /// Execute closure with exclusive access
    pub unsafe fn with_exclusive<T, F: FnOnce() -> T>(&self, f: F) -> Option<T> {
        if unsafe { self.acquire_exclusive(true) } {
            let result = f();
            unsafe { self.release() };
            Some(result)
        } else {
            None
        }
    }

    /// Execute closure with shared access
    pub unsafe fn with_shared<T, F: FnOnce() -> T>(&self, f: F) -> Option<T> {
        if unsafe { self.acquire_shared(true) } {
            let result = f();
            unsafe { self.release() };
            Some(result)
        } else {
            None
        }
    }
}

impl Drop for ExResource {
    fn drop(&mut self) {
        if self.initialized.load(Ordering::SeqCst) != 0 {
            unsafe { ExDeleteResourceLite(self.resource.get()) };
        }
    }
}

/// Kernel Event - Signaling mechanism
///
/// Used to synchronize between threads or signal completion.
pub struct KernelEvent {
    event: UnsafeCell<KEVENT>,
}

unsafe impl Send for KernelEvent {}
unsafe impl Sync for KernelEvent {}

/// Event type
pub enum KernelEventType {
    /// Automatically resets after one wait is satisfied
    SynchronizationEvent,
    /// Stays signaled until explicitly cleared
    NotificationEvent,
}

impl KernelEvent {
    /// Create a new kernel event
    ///
    /// # Safety
    /// Must call init() before using
    pub const fn new() -> Self {
        Self {
            event: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        }
    }

    /// Initialize the event
    ///
    /// # Safety
    /// Must be at IRQL <= DISPATCH_LEVEL
    pub unsafe fn init(&self, event_type: KernelEventType, signaled: bool) {
        let evt_type = match event_type {
            KernelEventType::SynchronizationEvent => wdk_sys::_EVENT_TYPE::SynchronizationEvent,
            KernelEventType::NotificationEvent => wdk_sys::_EVENT_TYPE::NotificationEvent,
        };

        unsafe {
            KeInitializeEvent(self.event.get(), evt_type as i32, signaled as u8);
        }
    }

    /// Set (signal) the event
    ///
    /// # Safety
    /// Must be at IRQL <= DISPATCH_LEVEL
    pub unsafe fn set(&self) -> i32 {
        unsafe { KeSetEvent(self.event.get(), 0, 0) }
    }

    /// Clear the event
    ///
    /// # Safety
    /// Must be at IRQL <= DISPATCH_LEVEL
    pub unsafe fn clear(&self) {
        unsafe { KeClearEvent(self.event.get()) };
    }

    /// Wait for the event to be signaled
    ///
    /// # Parameters
    /// - `timeout_ms`: Optional timeout in milliseconds (None = infinite)
    ///
    /// # Safety
    /// Must be at IRQL PASSIVE_LEVEL (waiting lowers IRQL)
    pub unsafe fn wait(&self, timeout_ms: Option<u64>) -> bool {
        let timeout = timeout_ms.map(|ms| {
            let mut t: LARGE_INTEGER = core::mem::zeroed();
            t.QuadPart = -(ms as i64 * 10_000);
            t
        });

        let timeout_ptr = timeout
            .as_ref()
            .map(|t| t as *const _)
            .unwrap_or(core::ptr::null());

        let status = unsafe {
            KeWaitForSingleObject(
                self.event.get() as *mut _,
                wdk_sys::_KWAIT_REASON::Executive as u32,
                wdk_sys::MODE::KernelMode as i8,
                0, // Not alertable
                timeout_ptr as *mut _,
            )
        };

        status == 0 // STATUS_SUCCESS
    }
}

/// Interlocked operations for atomic updates
pub mod interlocked {
    use core::sync::atomic::{AtomicI32, AtomicI64, AtomicPtr, Ordering};

    /// Atomic increment
    pub fn increment(value: &AtomicI32) -> i32 {
        value.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Atomic decrement
    pub fn decrement(value: &AtomicI32) -> i32 {
        value.fetch_sub(1, Ordering::SeqCst) - 1
    }

    /// Atomic exchange
    pub fn exchange(value: &AtomicI32, new_value: i32) -> i32 {
        value.swap(new_value, Ordering::SeqCst)
    }

    /// Atomic compare and exchange
    pub fn compare_exchange(
        value: &AtomicI32,
        expected: i32,
        new_value: i32,
    ) -> i32 {
        match value.compare_exchange(expected, new_value, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(v) => v,
            Err(v) => v,
        }
    }

    /// Atomic add
    pub fn add(value: &AtomicI64, addend: i64) -> i64 {
        value.fetch_add(addend, Ordering::SeqCst) + addend
    }
}
