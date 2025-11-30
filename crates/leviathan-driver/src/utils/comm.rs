//! Kernel-User Communication Framework
//!
//! High-performance communication between kernel driver and user-mode agent
//! using shared memory ring buffers and event signaling.
//!
//! # Communication Methods
//! - **Ring Buffer**: Lock-free event transfer for telemetry
//! - **Shared Memory**: Zero-copy data sharing
//! - **Named Events**: Kernel notifications to user-mode
//! - **IOCTL**: Control commands and queries
//!
//! # Architecture
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     KERNEL DRIVER                           │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              EVENT PRODUCER                          │   │
//! │  │  • Callbacks generate events                         │   │
//! │  │  • Events serialized to ring buffer                  │   │
//! │  │  • Signal event when data available                  │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                          │                                  │
//! │                          ▼                                  │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              SHARED RING BUFFER                      │   │
//! │  │  ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐         │   │
//! │  │  │ E │ E │ E │   │   │   │   │ E │ E │ E │         │   │
//! │  │  └───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘         │   │
//! │  │       ▲                           ▲                  │   │
//! │  │       │ Write                     │ Read             │   │
//! │  │       └───────────────────────────┘                  │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//!                            │
//!                            │ MDL Mapping
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     USER-MODE AGENT                         │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │              EVENT CONSUMER                          │   │
//! │  │  • Wait on named event                               │   │
//! │  │  • Read events from ring buffer                      │   │
//! │  │  • Process and analyze                               │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl,
        MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache,
        MmUnmapLockedPages, KeInitializeEvent, KeSetEvent, KeClearEvent,
    },
    KEVENT, MDL, NTSTATUS, PMDL, PVOID, STATUS_SUCCESS,
    STATUS_INSUFFICIENT_RESOURCES, POOL_FLAG_NON_PAGED,
    MmCached, KernelMode, SynchronizationEvent,
};

/// Pool tag for communication buffers
const COMM_POOL_TAG: u32 = u32::from_le_bytes(*b"COMM");

/// Default ring buffer size (1MB)
pub const DEFAULT_RING_SIZE: usize = 1024 * 1024;

/// Maximum event size
pub const MAX_EVENT_SIZE: usize = 4096;

/// Ring buffer header (shared between kernel and user)
#[repr(C)]
pub struct RingBufferHeader {
    /// Magic number for validation
    pub magic: u32,
    /// Version number
    pub version: u32,
    /// Total buffer size (excluding header)
    pub buffer_size: u32,
    /// Write position (kernel updates)
    pub write_pos: AtomicU32,
    /// Read position (user updates)
    pub read_pos: AtomicU32,
    /// Events written (statistics)
    pub events_written: AtomicU64,
    /// Events read (statistics)
    pub events_read: AtomicU64,
    /// Events dropped due to full buffer
    pub events_dropped: AtomicU64,
    /// Reserved for future use
    pub reserved: [u32; 8],
}

/// Ring buffer magic number
pub const RING_MAGIC: u32 = 0x4C455654; // "LEVT"

/// Ring buffer version
pub const RING_VERSION: u32 = 1;

impl RingBufferHeader {
    /// Initialize a new header
    pub fn init(&mut self, buffer_size: u32) {
        self.magic = RING_MAGIC;
        self.version = RING_VERSION;
        self.buffer_size = buffer_size;
        self.write_pos = AtomicU32::new(0);
        self.read_pos = AtomicU32::new(0);
        self.events_written = AtomicU64::new(0);
        self.events_read = AtomicU64::new(0);
        self.events_dropped = AtomicU64::new(0);
        self.reserved = [0; 8];
    }

    /// Check if buffer is valid
    pub fn is_valid(&self) -> bool {
        self.magic == RING_MAGIC && self.version == RING_VERSION
    }

    /// Get available space for writing
    pub fn available_write_space(&self) -> u32 {
        let write = self.write_pos.load(Ordering::Acquire);
        let read = self.read_pos.load(Ordering::Acquire);

        if write >= read {
            self.buffer_size - (write - read) - 1
        } else {
            read - write - 1
        }
    }

    /// Get available data for reading
    pub fn available_read_data(&self) -> u32 {
        let write = self.write_pos.load(Ordering::Acquire);
        let read = self.read_pos.load(Ordering::Acquire);

        if write >= read {
            write - read
        } else {
            self.buffer_size - read + write
        }
    }
}

/// Event header in ring buffer
#[repr(C)]
pub struct EventHeader {
    /// Event type
    pub event_type: u32,
    /// Event size (including header)
    pub size: u32,
    /// Timestamp (100ns intervals since boot)
    pub timestamp: u64,
    /// Process ID that generated event
    pub pid: u32,
    /// Thread ID that generated event
    pub tid: u32,
}

/// Event types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EventType {
    /// Process created
    ProcessCreate = 1,
    /// Process terminated
    ProcessExit = 2,
    /// Thread created
    ThreadCreate = 3,
    /// Thread terminated
    ThreadExit = 4,
    /// Image/DLL loaded
    ImageLoad = 5,
    /// Registry operation
    RegistryOp = 6,
    /// File operation
    FileOp = 7,
    /// Network connection
    NetworkOp = 8,
    /// Suspicious activity detected
    Alert = 100,
    /// Driver status message
    Status = 200,
}

/// Process event data
#[repr(C)]
pub struct ProcessEvent {
    /// Event header
    pub header: EventHeader,
    /// Process ID
    pub process_id: u32,
    /// Parent process ID
    pub parent_id: u32,
    /// Creating process ID
    pub creating_pid: u32,
    /// Creating thread ID
    pub creating_tid: u32,
    /// Session ID
    pub session_id: u32,
    /// Is WoW64 process
    pub is_wow64: u8,
    /// Reserved
    pub reserved: [u8; 3],
    /// Image path length
    pub image_path_len: u16,
    /// Command line length
    pub command_line_len: u16,
    /// Image path (variable length, follows this struct)
    // pub image_path: [u16; ...],
    /// Command line (variable length, follows image_path)
    // pub command_line: [u16; ...],
}

/// Thread event data
#[repr(C)]
pub struct ThreadEvent {
    /// Event header
    pub header: EventHeader,
    /// Thread ID
    pub thread_id: u32,
    /// Process ID
    pub process_id: u32,
    /// Start address
    pub start_address: u64,
    /// Is remote thread (created from another process)
    pub is_remote: u8,
    /// Reserved
    pub reserved: [u8; 7],
}

/// Image load event data
#[repr(C)]
pub struct ImageEvent {
    /// Event header
    pub header: EventHeader,
    /// Process ID where image loaded
    pub process_id: u32,
    /// Image base address
    pub image_base: u64,
    /// Image size
    pub image_size: u64,
    /// Is kernel mode image
    pub is_kernel: u8,
    /// Reserved
    pub reserved: [u8; 3],
    /// Image path length
    pub path_len: u16,
    /// Reserved
    pub reserved2: u16,
    // Image path follows
}

/// Shared memory communication channel
pub struct SharedChannel {
    /// Ring buffer kernel address
    kernel_addr: PVOID,
    /// Total allocation size
    alloc_size: usize,
    /// MDL for mapping
    mdl: PMDL,
    /// User-mode mapped address
    user_addr: PVOID,
    /// Notification event
    event: *mut KEVENT,
    /// Is channel initialized
    initialized: bool,
}

impl SharedChannel {
    /// Create a new shared channel
    pub fn new() -> Self {
        Self {
            kernel_addr: ptr::null_mut(),
            alloc_size: 0,
            mdl: ptr::null_mut(),
            user_addr: ptr::null_mut(),
            event: ptr::null_mut(),
            initialized: false,
        }
    }

    /// Initialize the channel
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL
    pub unsafe fn initialize(&mut self, size: usize) -> Result<(), NTSTATUS> {
        let total_size = core::mem::size_of::<RingBufferHeader>() + size;

        // Allocate non-paged pool for ring buffer
        let buffer = unsafe {
            ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                total_size,
                COMM_POOL_TAG,
            )
        };

        if buffer.is_null() {
            println!("[Leviathan] Failed to allocate ring buffer");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }

        // Zero the buffer
        unsafe {
            ptr::write_bytes(buffer as *mut u8, 0, total_size);
        }

        // Initialize header
        let header = buffer as *mut RingBufferHeader;
        unsafe {
            (*header).init(size as u32);
        }

        // Create MDL for sharing with user-mode
        let mdl = unsafe {
            IoAllocateMdl(
                buffer,
                total_size as u32,
                0, // Not secondary
                0, // Not charge quota
                ptr::null_mut(),
            )
        };

        if mdl.is_null() {
            unsafe { ExFreePoolWithTag(buffer, COMM_POOL_TAG) };
            println!("[Leviathan] Failed to allocate MDL");
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }

        // Build MDL for non-paged pool
        unsafe { MmBuildMdlForNonPagedPool(mdl) };

        // Allocate notification event
        let event_size = core::mem::size_of::<KEVENT>();
        let event = unsafe {
            ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                event_size,
                COMM_POOL_TAG,
            )
        } as *mut KEVENT;

        if event.is_null() {
            unsafe {
                IoFreeMdl(mdl);
                ExFreePoolWithTag(buffer, COMM_POOL_TAG);
            }
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }

        // Initialize event
        unsafe {
            KeInitializeEvent(event, SynchronizationEvent, 0);
        }

        self.kernel_addr = buffer;
        self.alloc_size = total_size;
        self.mdl = mdl;
        self.event = event;
        self.initialized = true;

        println!(
            "[Leviathan] Shared channel initialized: {}KB buffer at {:p}",
            total_size / 1024,
            buffer
        );

        Ok(())
    }

    /// Map buffer to user-mode process
    ///
    /// # Safety
    /// Must be called in the context of the target process
    pub unsafe fn map_to_user(&mut self) -> Result<PVOID, NTSTATUS> {
        if !self.initialized || self.mdl.is_null() {
            return Err(wdk_sys::STATUS_NOT_INITIALIZED);
        }

        let user_addr = unsafe {
            MmMapLockedPagesSpecifyCache(
                self.mdl,
                KernelMode as i8,
                MmCached,
                ptr::null_mut(),
                0, // Don't bug check on failure
                16, // NormalPagePriority
            )
        };

        if user_addr.is_null() {
            return Err(wdk_sys::STATUS_INSUFFICIENT_RESOURCES);
        }

        self.user_addr = user_addr;

        println!("[Leviathan] Buffer mapped to user-mode at {:p}", user_addr);
        Ok(user_addr)
    }

    /// Unmap buffer from user-mode
    ///
    /// # Safety
    /// Must be called in same process context as map_to_user
    pub unsafe fn unmap_from_user(&mut self) {
        if !self.user_addr.is_null() && !self.mdl.is_null() {
            unsafe { MmUnmapLockedPages(self.user_addr, self.mdl) };
            self.user_addr = ptr::null_mut();
        }
    }

    /// Get ring buffer header
    fn get_header(&self) -> Option<&mut RingBufferHeader> {
        if self.kernel_addr.is_null() {
            return None;
        }
        Some(unsafe { &mut *(self.kernel_addr as *mut RingBufferHeader) })
    }

    /// Get buffer data area
    fn get_buffer(&self) -> Option<*mut u8> {
        if self.kernel_addr.is_null() {
            return None;
        }
        Some(unsafe {
            (self.kernel_addr as *mut u8)
                .add(core::mem::size_of::<RingBufferHeader>())
        })
    }

    /// Write event to ring buffer
    ///
    /// # Safety
    /// Event data must be valid
    pub unsafe fn write_event(&self, event_type: EventType, data: &[u8]) -> Result<(), NTSTATUS> {
        let header = match self.get_header() {
            Some(h) => h,
            None => return Err(wdk_sys::STATUS_NOT_INITIALIZED),
        };

        let buffer = match self.get_buffer() {
            Some(b) => b,
            None => return Err(wdk_sys::STATUS_NOT_INITIALIZED),
        };

        let event_size = core::mem::size_of::<EventHeader>() + data.len();

        // Check available space
        if header.available_write_space() < event_size as u32 {
            header.events_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(wdk_sys::STATUS_BUFFER_OVERFLOW);
        }

        let write_pos = header.write_pos.load(Ordering::Acquire) as usize;
        let buffer_size = header.buffer_size as usize;

        // Create event header
        let event_header = EventHeader {
            event_type: event_type as u32,
            size: event_size as u32,
            timestamp: get_timestamp(),
            pid: get_current_pid(),
            tid: get_current_tid(),
        };

        // Write header
        let header_bytes = unsafe {
            core::slice::from_raw_parts(
                &event_header as *const _ as *const u8,
                core::mem::size_of::<EventHeader>(),
            )
        };

        let mut pos = write_pos;
        for &byte in header_bytes {
            unsafe { *buffer.add(pos % buffer_size) = byte };
            pos += 1;
        }

        // Write data
        for &byte in data {
            unsafe { *buffer.add(pos % buffer_size) = byte };
            pos += 1;
        }

        // Update write position
        header.write_pos.store((pos % buffer_size) as u32, Ordering::Release);
        header.events_written.fetch_add(1, Ordering::Relaxed);

        // Signal event to wake consumer
        if !self.event.is_null() {
            unsafe { KeSetEvent(self.event, 0, 0) };
        }

        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> Option<ChannelStats> {
        let header = self.get_header()?;

        Some(ChannelStats {
            events_written: header.events_written.load(Ordering::Relaxed),
            events_read: header.events_read.load(Ordering::Relaxed),
            events_dropped: header.events_dropped.load(Ordering::Relaxed),
            buffer_used: header.available_read_data(),
            buffer_size: header.buffer_size,
        })
    }
}

impl Drop for SharedChannel {
    fn drop(&mut self) {
        unsafe {
            // Unmap from user-mode first
            self.unmap_from_user();

            // Free MDL
            if !self.mdl.is_null() {
                IoFreeMdl(self.mdl);
            }

            // Free event
            if !self.event.is_null() {
                ExFreePoolWithTag(self.event as PVOID, COMM_POOL_TAG);
            }

            // Free buffer
            if !self.kernel_addr.is_null() {
                ExFreePoolWithTag(self.kernel_addr, COMM_POOL_TAG);
            }
        }

        println!("[Leviathan] Shared channel destroyed");
    }
}

/// Channel statistics
#[derive(Debug, Clone)]
pub struct ChannelStats {
    /// Total events written
    pub events_written: u64,
    /// Total events read
    pub events_read: u64,
    /// Events dropped (buffer full)
    pub events_dropped: u64,
    /// Current buffer used (bytes)
    pub buffer_used: u32,
    /// Total buffer size
    pub buffer_size: u32,
}

/// Get current timestamp (100ns intervals)
fn get_timestamp() -> u64 {
    // Would use KeQueryPerformanceCounter or KeQuerySystemTimePrecise
    0
}

/// Get current process ID
fn get_current_pid() -> u32 {
    // Would use PsGetCurrentProcessId
    0
}

/// Get current thread ID
fn get_current_tid() -> u32 {
    // Would use PsGetCurrentThreadId
    0
}

/// IOCTL codes for driver control
pub mod ioctl {
    use wdk_sys::{FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, METHOD_NEITHER};

    /// Base IOCTL code
    const IOCTL_BASE: u32 = 0x800;

    /// Macro to define IOCTL code
    const fn ctl_code(function: u32, method: u32, access: u32) -> u32 {
        (FILE_DEVICE_UNKNOWN << 16) | (access << 14) | (function << 2) | method
    }

    /// Get driver version
    pub const IOCTL_GET_VERSION: u32 = ctl_code(IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Get ring buffer address (for mapping)
    pub const IOCTL_GET_BUFFER: u32 = ctl_code(IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Enable/disable callbacks
    pub const IOCTL_SET_CALLBACKS: u32 = ctl_code(IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Add process to protection list
    pub const IOCTL_PROTECT_PROCESS: u32 = ctl_code(IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Remove process from protection list
    pub const IOCTL_UNPROTECT_PROCESS: u32 = ctl_code(IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Scan process memory
    pub const IOCTL_SCAN_PROCESS: u32 = ctl_code(IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Get statistics
    pub const IOCTL_GET_STATS: u32 = ctl_code(IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Enumerate hidden processes
    pub const IOCTL_ENUM_HIDDEN: u32 = ctl_code(IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Scan for hooks
    pub const IOCTL_SCAN_HOOKS: u32 = ctl_code(IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

/// Global communication channel (singleton)
static mut GLOBAL_CHANNEL: Option<SharedChannel> = None;

/// Initialize global channel
///
/// # Safety
/// Must be called once during driver initialization
pub unsafe fn init_global_channel(size: usize) -> Result<(), NTSTATUS> {
    let mut channel = SharedChannel::new();
    unsafe { channel.initialize(size)? };
    unsafe { GLOBAL_CHANNEL = Some(channel) };
    Ok(())
}

/// Get global channel reference
///
/// # Safety
/// Must be called after init_global_channel
pub unsafe fn get_global_channel() -> Option<&'static SharedChannel> {
    unsafe { GLOBAL_CHANNEL.as_ref() }
}

/// Cleanup global channel
///
/// # Safety
/// Must be called during driver unload
pub unsafe fn cleanup_global_channel() {
    unsafe { GLOBAL_CHANNEL = None };
}
