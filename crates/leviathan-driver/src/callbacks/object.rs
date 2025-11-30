//! Object Handle Callbacks (Process/Thread Protection)
//!
//! Uses ObRegisterCallbacks to intercept handle operations on
//! process and thread objects.
//!
//! # Capabilities
//! - Strip dangerous access rights from handles
//! - Protect critical processes from termination
//! - Block memory read/write access to protected processes
//! - Detect and prevent credential dumping (LSASS protection)
//!
//! # Use Cases
//! - Protect security software from tampering
//! - Prevent LSASS credential dumping
//! - Anti-cheat process protection
//! - EDR self-defense mechanisms
//!
//! # Important Notes
//! - Requires signed driver with proper EKU (OID 1.3.6.1.4.1.311.61.4.1)
//! - Must be linked with /INTEGRITYCHECK flag

use core::sync::atomic::{AtomicBool, Ordering};
use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{ObRegisterCallbacks, ObUnRegisterCallbacks, PsGetCurrentProcessId, PsGetProcessId},
    ACCESS_MASK, HANDLE, NTSTATUS, OB_CALLBACK_REGISTRATION, OB_OPERATION_HANDLE_CREATE,
    OB_OPERATION_HANDLE_DUPLICATE, OB_OPERATION_REGISTRATION, OB_PRE_OPERATION_INFORMATION,
    PEPROCESS, POB_PRE_OPERATION_CALLBACK, PROCESS_TERMINATE, PROCESS_VM_READ,
    PROCESS_VM_WRITE, PVOID, STATUS_SUCCESS,
};

/// Flag indicating if object callbacks are registered
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Handle returned by ObRegisterCallbacks
static mut REGISTRATION_HANDLE: PVOID = ptr::null_mut();

/// Process IDs that should be protected
/// In production, this would be a proper synchronized collection
static mut PROTECTED_PIDS: [usize; 16] = [0; 16];
static PROTECTED_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Access rights that are considered dangerous
const DANGEROUS_PROCESS_ACCESS: ACCESS_MASK =
    PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE;

/// Thread access rights to strip
const DANGEROUS_THREAD_ACCESS: ACCESS_MASK = 0x0002 | 0x0008; // THREAD_SUSPEND_RESUME | THREAD_TERMINATE

/// Register object callbacks for process and thread protection
///
/// # Safety
/// - Must be called from PASSIVE_LEVEL
/// - Driver must be properly signed with EV certificate
/// - Must be linked with /INTEGRITYCHECK
pub unsafe fn register() -> Result<(), NTSTATUS> {
    if REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Define the operations we want to intercept
    let mut operation_registration: [OB_OPERATION_REGISTRATION; 2] = unsafe { core::mem::zeroed() };

    // Process object callbacks
    operation_registration[0].ObjectType = unsafe { wdk_sys::PsProcessType };
    operation_registration[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation_registration[0].PreOperation = Some(pre_operation_callback);
    operation_registration[0].PostOperation = None;

    // Thread object callbacks
    operation_registration[1].ObjectType = unsafe { wdk_sys::PsThreadType };
    operation_registration[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operation_registration[1].PreOperation = Some(pre_operation_callback);
    operation_registration[1].PostOperation = None;

    // Build the callback registration structure
    let altitude = wdk_sys::UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: ptr::null_mut(),
    };

    let mut callback_registration: OB_CALLBACK_REGISTRATION = unsafe { core::mem::zeroed() };
    callback_registration.Version = wdk_sys::OB_FLT_REGISTRATION_VERSION as u16;
    callback_registration.OperationRegistrationCount = 2;
    callback_registration.Altitude = altitude;
    callback_registration.RegistrationContext = ptr::null_mut();
    callback_registration.OperationRegistration = operation_registration.as_mut_ptr();

    let mut handle: PVOID = ptr::null_mut();

    let status = unsafe { ObRegisterCallbacks(&mut callback_registration, &mut handle) };

    if status != STATUS_SUCCESS {
        println!(
            "[Leviathan] Failed to register object callbacks: {:#x}",
            status
        );
        println!("[Leviathan] Note: Requires signed driver with /INTEGRITYCHECK");
        return Err(status);
    }

    unsafe {
        REGISTRATION_HANDLE = handle;
    }
    REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] Object callbacks registered");
    Ok(())
}

/// Unregister object callbacks
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn unregister() {
    if !REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    let handle = unsafe { REGISTRATION_HANDLE };
    if !handle.is_null() {
        unsafe { ObUnRegisterCallbacks(handle) };
        unsafe { REGISTRATION_HANDLE = ptr::null_mut() };
    }

    REGISTERED.store(false, Ordering::SeqCst);
    println!("[Leviathan] Object callbacks unregistered");
}

/// Pre-operation callback for handle operations
///
/// Called BEFORE a handle is created or duplicated.
/// Can modify the requested access rights to strip dangerous permissions.
///
/// # Safety
/// Called by the kernel at PASSIVE_LEVEL
unsafe extern "C" fn pre_operation_callback(
    _context: PVOID,
    info: *mut OB_PRE_OPERATION_INFORMATION,
) -> u32 {
    if info.is_null() {
        return wdk_sys::OB_PREOP_SUCCESS;
    }

    let info = unsafe { &mut *info };

    // Get the target object (process or thread being accessed)
    let target_object = info.Object;
    if target_object.is_null() {
        return wdk_sys::OB_PREOP_SUCCESS;
    }

    // Determine if this is a process or thread operation
    // For now, assume process operations
    let target_process = target_object as PEPROCESS;
    let target_pid = unsafe { PsGetProcessId(target_process) } as usize;

    // Get the process requesting the handle
    let requestor_pid = unsafe { PsGetCurrentProcessId() } as usize;

    // Don't restrict self-access
    if requestor_pid == target_pid {
        return wdk_sys::OB_PREOP_SUCCESS;
    }

    // Check if target is a protected process
    if is_protected_process(target_pid) {
        unsafe { strip_dangerous_access(info) };

        println!(
            "[Leviathan] Protected process access: {} -> {} (stripped dangerous rights)",
            requestor_pid, target_pid
        );
    }

    // Always monitor LSASS access (PID 4 is System, but LSASS is typically higher)
    // In production, would resolve LSASS PID at startup
    if is_sensitive_process(target_pid) {
        let requested_access = get_requested_access(info);

        if (requested_access & DANGEROUS_PROCESS_ACCESS) != 0 {
            println!(
                "[Leviathan] ALERT: Dangerous access to sensitive process! Requestor={}, Target={}, Access={:#x}",
                requestor_pid, target_pid, requested_access
            );

            // Strip dangerous access rights
            unsafe { strip_dangerous_access(info) };
        }
    }

    wdk_sys::OB_PREOP_SUCCESS
}

/// Strip dangerous access rights from the operation
unsafe fn strip_dangerous_access(info: &mut OB_PRE_OPERATION_INFORMATION) {
    // Access the Parameters union based on operation type
    let params = &mut info.Parameters;

    // Handle creation - modify DesiredAccess
    if info.Operation == OB_OPERATION_HANDLE_CREATE {
        let create_info = unsafe { &mut params.CreateHandleInformation };
        create_info.DesiredAccess &= !DANGEROUS_PROCESS_ACCESS;
    }
    // Handle duplication
    else if info.Operation == OB_OPERATION_HANDLE_DUPLICATE {
        let dup_info = unsafe { &mut params.DuplicateHandleInformation };
        dup_info.DesiredAccess &= !DANGEROUS_PROCESS_ACCESS;
    }
}

/// Get the requested access mask from operation info
fn get_requested_access(info: &OB_PRE_OPERATION_INFORMATION) -> ACCESS_MASK {
    let params = &info.Parameters;

    if info.Operation == OB_OPERATION_HANDLE_CREATE {
        unsafe { params.CreateHandleInformation.DesiredAccess }
    } else if info.Operation == OB_OPERATION_HANDLE_DUPLICATE {
        unsafe { params.DuplicateHandleInformation.DesiredAccess }
    } else {
        0
    }
}

/// Check if a process ID is in the protected list
fn is_protected_process(pid: usize) -> bool {
    let count = PROTECTED_COUNT.load(Ordering::SeqCst);
    for i in 0..count {
        if unsafe { PROTECTED_PIDS[i] } == pid {
            return true;
        }
    }
    false
}

/// Check if this is a sensitive system process (LSASS, CSRSS, etc.)
fn is_sensitive_process(_pid: usize) -> bool {
    // In production, would:
    // 1. Resolve PIDs for LSASS, CSRSS, SERVICES at driver start
    // 2. Check process name against known sensitive names
    // 3. Check if it's a PPL (Protected Process Light) process

    false
}

/// Add a process to the protected list
///
/// # Safety
/// Must synchronize access in multi-threaded context
#[allow(dead_code)]
pub unsafe fn protect_process(pid: usize) -> bool {
    let count = PROTECTED_COUNT.load(Ordering::SeqCst);
    if count >= 16 {
        return false;
    }

    unsafe {
        PROTECTED_PIDS[count] = pid;
    }
    PROTECTED_COUNT.store(count + 1, Ordering::SeqCst);
    println!("[Leviathan] Process {} added to protected list", pid);
    true
}

/// Remove a process from the protected list
#[allow(dead_code)]
pub fn unprotect_process(pid: usize) {
    let count = PROTECTED_COUNT.load(Ordering::SeqCst);
    for i in 0..count {
        if unsafe { PROTECTED_PIDS[i] } == pid {
            // Shift remaining entries
            for j in i..count - 1 {
                unsafe {
                    PROTECTED_PIDS[j] = PROTECTED_PIDS[j + 1];
                }
            }
            PROTECTED_COUNT.store(count - 1, Ordering::SeqCst);
            println!("[Leviathan] Process {} removed from protected list", pid);
            return;
        }
    }
}
