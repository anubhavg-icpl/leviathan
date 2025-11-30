//! Thread Creation and Termination Monitoring
//!
//! Uses PsSetCreateThreadNotifyRoutine to receive notifications when
//! threads are created or terminated system-wide.
//!
//! # Capabilities
//! - Monitor all thread creation events
//! - Detect remote thread injection (CreateRemoteThread)
//! - Track thread-to-process relationships
//! - Identify suspicious thread creation patterns
//!
//! # Use Cases
//! - Detect code injection attacks
//! - Monitor for shellcode execution
//! - EDR thread activity tracking
//! - Anti-debugging detection

use core::sync::atomic::{AtomicBool, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{PsSetCreateThreadNotifyRoutine, PsGetCurrentProcessId, PsIsSystemThread},
    HANDLE, NTSTATUS, PEPROCESS, STATUS_SUCCESS,
};

/// Flag indicating if thread callbacks are registered
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Thread event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadEventType {
    Create,
    Terminate,
}

/// Information about a thread event
#[repr(C)]
#[derive(Debug)]
pub struct ThreadEvent {
    pub event_type: ThreadEventType,
    pub process_id: usize,
    pub thread_id: usize,
    pub is_remote_thread: bool,
    pub is_system_thread: bool,
}

/// Register the thread creation callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn register() -> Result<(), NTSTATUS> {
    if REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let status = unsafe {
        PsSetCreateThreadNotifyRoutine(Some(thread_notify_callback))
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] Failed to register thread callback: {:#x}", status);
        return Err(status);
    }

    REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] Thread creation callback registered");
    Ok(())
}

/// Unregister the thread creation callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn unregister() {
    if !REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    let status = unsafe {
        wdk_sys::ntddk::PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback))
    };

    if status == STATUS_SUCCESS {
        REGISTERED.store(false, Ordering::SeqCst);
        println!("[Leviathan] Thread creation callback unregistered");
    }
}

/// Thread notification callback function
///
/// Called by the kernel when a thread is created or terminated.
///
/// # Parameters
/// - `process_id`: The process ID that owns the thread
/// - `thread_id`: The thread ID
/// - `create`: TRUE if creation, FALSE if termination
///
/// # Safety
/// Called at PASSIVE_LEVEL by the kernel
unsafe extern "C" fn thread_notify_callback(
    process_id: HANDLE,
    thread_id: HANDLE,
    create: u8,
) {
    let pid = process_id as usize;
    let tid = thread_id as usize;

    if create != 0 {
        unsafe { handle_thread_create(pid, tid) };
    } else {
        handle_thread_terminate(pid, tid);
    }
}

/// Handle thread creation event
unsafe fn handle_thread_create(process_id: usize, thread_id: usize) {
    // Check if this is a remote thread (thread created in another process)
    let current_pid = unsafe { PsGetCurrentProcessId() } as usize;
    let is_remote = current_pid != process_id && current_pid != 0;

    if is_remote {
        // Remote thread creation detected - potential code injection!
        println!(
            "[Leviathan] REMOTE Thread CREATE: TID={} in PID={} (from PID={})",
            thread_id, process_id, current_pid
        );

        // This is a strong indicator of:
        // - CreateRemoteThread API usage
        // - Process injection
        // - Shellcode injection
        // - DLL injection preparation

        // In production:
        // - Log to event system
        // - Check if source/target process is suspicious
        // - Potentially block or alert
    } else {
        println!(
            "[Leviathan] Thread CREATE: TID={} in PID={}",
            thread_id, process_id
        );
    }
}

/// Handle thread termination event
fn handle_thread_terminate(process_id: usize, thread_id: usize) {
    println!(
        "[Leviathan] Thread TERMINATE: TID={} in PID={}",
        thread_id, process_id
    );
}

/// Detect suspicious thread creation patterns
///
/// Common injection patterns:
/// 1. Remote thread in LSASS - credential theft
/// 2. Remote thread from unsigned process - malware injection
/// 3. Thread with RWX memory - shellcode execution
#[allow(dead_code)]
fn is_suspicious_thread_creation(
    source_pid: usize,
    target_pid: usize,
    _thread_start_address: usize,
) -> bool {
    // Example heuristics:

    // 1. Check if targeting a sensitive process
    let sensitive_processes = [
        "lsass.exe",
        "csrss.exe",
        "services.exe",
        "winlogon.exe",
    ];

    // 2. Check if source is an unsigned/untrusted process

    // 3. Check if thread start address is in executable heap/stack

    // 4. Rate limiting - too many remote threads from one process

    source_pid != target_pid // Simplified: any remote thread is suspicious
}
