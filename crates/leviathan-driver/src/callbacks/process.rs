//! Process Creation and Termination Monitoring
//!
//! Uses PsSetCreateProcessNotifyRoutineEx to receive notifications when
//! processes are created or terminated system-wide.
//!
//! # Capabilities
//! - Monitor all process creation events
//! - Block process creation (deny execution)
//! - Capture command line arguments
//! - Track parent-child process relationships
//! - Detect process hollowing and injection attempts
//!
//! # Use Cases
//! - Application whitelisting/blacklisting
//! - EDR process monitoring
//! - Malware detection
//! - Audit logging

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{PsSetCreateProcessNotifyRoutineEx, PsGetProcessId, PsGetProcessImageFileName},
    HANDLE, NTSTATUS, PEPROCESS, PPS_CREATE_NOTIFY_INFO, STATUS_SUCCESS,
};

/// Flag indicating if process callbacks are registered
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Process event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessEventType {
    /// Process is being created
    Create,
    /// Process is terminating
    Terminate,
}

/// Information about a process event
#[repr(C)]
#[derive(Debug)]
pub struct ProcessEvent {
    /// Type of event (create/terminate)
    pub event_type: ProcessEventType,
    /// Process ID
    pub process_id: usize,
    /// Parent process ID (for creation events)
    pub parent_process_id: usize,
    /// Whether creation was blocked
    pub blocked: bool,
}

/// Register the process creation callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL (typically DriverEntry)
pub unsafe fn register() -> Result<(), NTSTATUS> {
    if REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let status = unsafe {
        PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 0)
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] Failed to register process callback: {:#x}", status);
        return Err(status);
    }

    REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] Process creation callback registered");
    Ok(())
}

/// Unregister the process creation callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL (typically DriverUnload)
pub unsafe fn unregister() {
    if !REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    // Pass TRUE (1) to remove the callback
    let status = unsafe {
        PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), 1)
    };

    if status == STATUS_SUCCESS {
        REGISTERED.store(false, Ordering::SeqCst);
        println!("[Leviathan] Process creation callback unregistered");
    }
}

/// Process notification callback function
///
/// Called by the kernel when a process is created or terminated.
///
/// # Parameters
/// - `process`: Pointer to the EPROCESS structure
/// - `process_id`: The process ID
/// - `create_info`: If non-NULL, contains creation details; NULL means termination
///
/// # Safety
/// Called at PASSIVE_LEVEL by the kernel
unsafe extern "C" fn process_notify_callback(
    process: PEPROCESS,
    process_id: HANDLE,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let pid = process_id as usize;

    if create_info.is_null() {
        // Process termination
        handle_process_terminate(pid);
    } else {
        // Process creation
        unsafe { handle_process_create(process, pid, create_info) };
    }
}

/// Handle process creation event
unsafe fn handle_process_create(
    _process: PEPROCESS,
    process_id: usize,
    create_info: PPS_CREATE_NOTIFY_INFO,
) {
    let info = unsafe { &mut *create_info };
    let parent_pid = info.ParentProcessId as usize;

    println!(
        "[Leviathan] Process CREATE: PID={}, ParentPID={}",
        process_id, parent_pid
    );

    // Access command line if available
    if !info.CommandLine.is_null() {
        let cmd_line = unsafe { &*info.CommandLine };
        // Command line is a UNICODE_STRING
        // In production, would parse and log this
        println!(
            "[Leviathan] Command line length: {} chars",
            cmd_line.Length / 2
        );
    }

    // Access image file name if available
    if !info.ImageFileName.is_null() {
        let image_name = unsafe { &*info.ImageFileName };
        println!(
            "[Leviathan] Image file length: {} chars",
            image_name.Length / 2
        );
    }

    // Example: Block process creation by setting CreationStatus
    // info.CreationStatus = STATUS_ACCESS_DENIED;
    //
    // This would prevent the process from being created.
    // Use cases:
    // - Block known malware hashes
    // - Enforce application whitelisting
    // - Prevent execution from suspicious paths
}

/// Handle process termination event
fn handle_process_terminate(process_id: usize) {
    println!("[Leviathan] Process TERMINATE: PID={}", process_id);

    // Use cases:
    // - Clean up per-process tracking data
    // - Log process exit codes
    // - Detect unexpected termination of protected processes
}

/// Check if a process should be blocked based on policy
///
/// This is a placeholder for policy enforcement logic
#[allow(dead_code)]
fn should_block_process(_image_path: &[u16], _command_line: &[u16]) -> bool {
    // Example policies:
    // - Check against known malware signatures
    // - Verify digital signatures
    // - Check execution path (e.g., block from Temp folders)
    // - Enforce application whitelist

    false
}
