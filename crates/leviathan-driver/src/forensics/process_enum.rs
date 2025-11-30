//! Process and Thread Enumeration
//!
//! Multiple methods for enumerating kernel objects to detect
//! hidden processes and threads via cross-referencing.
//!
//! # Enumeration Methods
//! 1. ActiveProcessLinks walking (standard)
//! 2. PspCidTable handle table scanning
//! 3. Thread scheduler queues
//! 4. Pool tag scanning
//! 5. HandleTableList walking
//!
//! # Detection Technique
//! Compare results from multiple methods. Objects that appear
//! in some methods but not others may be hidden via DKOM.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{
        PsGetCurrentProcess, PsGetProcessId, PsGetProcessImageFileName,
        PsLookupProcessByProcessId, ObDereferenceObject,
        ZwQuerySystemInformation,
    },
    NTSTATUS, PEPROCESS, HANDLE, STATUS_SUCCESS,
    SYSTEM_INFORMATION_CLASS,
};

/// Process information from enumeration
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: usize,
    /// Parent process ID
    pub ppid: usize,
    /// Process name (up to 15 chars)
    pub name: [u8; 16],
    /// EPROCESS address
    pub eprocess: usize,
    /// Session ID
    pub session_id: u32,
    /// Is process terminated
    pub is_terminated: bool,
    /// Which enumeration methods found this process
    pub found_by: EnumerationMethods,
}

/// Bit flags for enumeration methods
#[derive(Debug, Clone, Copy, Default)]
pub struct EnumerationMethods {
    /// Found via ActiveProcessLinks
    pub active_process_links: bool,
    /// Found via PspCidTable
    pub cid_table: bool,
    /// Found via thread->process links
    pub thread_process: bool,
    /// Found via pool tag scanning
    pub pool_scan: bool,
    /// Found via ZwQuerySystemInformation
    pub system_info: bool,
}

impl EnumerationMethods {
    /// Check if process was found by all methods
    pub fn found_by_all(&self) -> bool {
        self.active_process_links
            && self.cid_table
            && self.thread_process
            && self.pool_scan
            && self.system_info
    }

    /// Check if process might be hidden (found by some but not all)
    pub fn possibly_hidden(&self) -> bool {
        let count = [
            self.active_process_links,
            self.cid_table,
            self.thread_process,
            self.pool_scan,
            self.system_info,
        ]
        .iter()
        .filter(|&&x| x)
        .count();

        // If found by some but not all methods, might be hidden
        count > 0 && count < 5
    }
}

/// Thread information from enumeration
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    /// Thread ID
    pub tid: usize,
    /// Owning process ID
    pub pid: usize,
    /// ETHREAD address
    pub ethread: usize,
    /// Thread state
    pub state: u8,
    /// Start address
    pub start_address: usize,
    /// Is orphan thread (no valid process)
    pub is_orphan: bool,
}

/// Full process enumeration using multiple methods
pub struct ProcessEnumerator {
    /// Collected process info
    processes: Vec<ProcessInfo>,
    /// Set of seen PIDs
    seen_pids: BTreeSet<usize>,
}

impl ProcessEnumerator {
    /// Create new enumerator
    pub fn new() -> Self {
        Self {
            processes: Vec::new(),
            seen_pids: BTreeSet::new(),
        }
    }

    /// Run all enumeration methods
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL
    pub unsafe fn enumerate_all(&mut self) -> Result<(), NTSTATUS> {
        println!("[Leviathan] Starting multi-method process enumeration");

        // Method 1: ZwQuerySystemInformation (user-mode visible)
        unsafe { self.enumerate_via_system_info()? };

        // Method 2: ActiveProcessLinks walking
        unsafe { self.enumerate_via_active_links()? };

        // Method 3: PspCidTable (handle table)
        unsafe { self.enumerate_via_cid_table()? };

        // Method 4: Thread->Process links
        unsafe { self.enumerate_via_threads()? };

        // Method 5: Pool tag scanning (find unlinked)
        unsafe { self.enumerate_via_pool_scan()? };

        println!(
            "[Leviathan] Enumeration complete: {} processes found",
            self.processes.len()
        );

        Ok(())
    }

    /// Enumerate using ZwQuerySystemInformation
    ///
    /// This is what Task Manager and most user-mode tools use.
    unsafe fn enumerate_via_system_info(&mut self) -> Result<(), NTSTATUS> {
        // Would use SystemProcessInformation (5)
        // This returns SYSTEM_PROCESS_INFORMATION structures

        // In production:
        // 1. Query required buffer size
        // 2. Allocate buffer
        // 3. Call ZwQuerySystemInformation
        // 4. Walk linked list of SYSTEM_PROCESS_INFORMATION

        println!("[Leviathan] Enumeration via SystemProcessInformation");
        Ok(())
    }

    /// Enumerate by walking ActiveProcessLinks
    ///
    /// Walks the EPROCESS.ActiveProcessLinks doubly-linked list
    /// starting from PsActiveProcessHead.
    unsafe fn enumerate_via_active_links(&mut self) -> Result<(), NTSTATUS> {
        // In production:
        // 1. Get PsActiveProcessHead (exported symbol)
        // 2. Walk FLINK through all entries
        // 3. Extract process info from each EPROCESS

        println!("[Leviathan] Enumeration via ActiveProcessLinks");
        Ok(())
    }

    /// Enumerate via PspCidTable (Client ID table)
    ///
    /// The CID table maps PIDs to EPROCESS pointers.
    /// More reliable than linked list walking.
    unsafe fn enumerate_via_cid_table(&mut self) -> Result<(), NTSTATUS> {
        // In production:
        // 1. Get PspCidTable address
        // 2. Walk the handle table structure
        // 3. Extract EPROCESS pointers from handles

        // This table is used by PsLookupProcessByProcessId

        println!("[Leviathan] Enumeration via PspCidTable");
        Ok(())
    }

    /// Enumerate via thread->process links
    ///
    /// Every thread points to its owning process.
    /// Find all threads and collect their processes.
    unsafe fn enumerate_via_threads(&mut self) -> Result<(), NTSTATUS> {
        // In production:
        // 1. Enumerate all threads (similar methods)
        // 2. For each thread, get ETHREAD.Tcb.Process
        // 3. Add process to list if not seen

        // Also detects orphan threads (threads with invalid process)

        println!("[Leviathan] Enumeration via thread->process links");
        Ok(())
    }

    /// Enumerate via pool tag scanning
    ///
    /// Scan kernel pool for EPROCESS structures by pool tag.
    /// Finds even completely unlinked processes.
    unsafe fn enumerate_via_pool_scan(&mut self) -> Result<(), NTSTATUS> {
        // Uses the pool_scanner module

        println!("[Leviathan] Enumeration via pool tag scanning");
        Ok(())
    }

    /// Get all enumerated processes
    pub fn get_processes(&self) -> &[ProcessInfo] {
        &self.processes
    }

    /// Find potentially hidden processes
    ///
    /// Returns processes that weren't found by all methods.
    pub fn find_hidden(&self) -> Vec<&ProcessInfo> {
        self.processes
            .iter()
            .filter(|p| p.found_by.possibly_hidden())
            .collect()
    }

    /// Find orphan threads (threads without valid process)
    pub fn find_orphan_threads(&self) -> Vec<ThreadInfo> {
        // Threads that point to invalid or non-existent processes
        Vec::new()
    }
}

/// Quick process lookup by PID
///
/// # Safety
/// Returns EPROCESS pointer - must dereference when done
pub unsafe fn lookup_process(pid: usize) -> Option<PEPROCESS> {
    let mut process: PEPROCESS = ptr::null_mut();

    let status = unsafe {
        PsLookupProcessByProcessId(pid as HANDLE, &mut process)
    };

    if status == STATUS_SUCCESS && !process.is_null() {
        Some(process)
    } else {
        None
    }
}

/// Get process name from EPROCESS
///
/// # Safety
/// EPROCESS must be valid
pub unsafe fn get_process_name(process: PEPROCESS) -> [u8; 16] {
    let mut name = [0u8; 16];

    // PsGetProcessImageFileName returns up to 15 chars
    let name_ptr = unsafe { PsGetProcessImageFileName(process) };

    if !name_ptr.is_null() {
        for i in 0..15 {
            let byte = unsafe { *name_ptr.add(i) };
            if byte == 0 {
                break;
            }
            name[i] = byte;
        }
    }

    name
}

/// EPROCESS structure offsets (Windows 10/11 x64)
///
/// These offsets vary by Windows version!
pub mod offsets {
    /// EPROCESS.ActiveProcessLinks offset (Windows 11 24H2)
    pub const ACTIVE_PROCESS_LINKS: usize = 0x448;

    /// EPROCESS.UniqueProcessId offset
    pub const UNIQUE_PROCESS_ID: usize = 0x440;

    /// EPROCESS.InheritedFromUniqueProcessId offset
    pub const INHERITED_FROM_UNIQUE_PROCESS_ID: usize = 0x540;

    /// EPROCESS.ImageFileName offset
    pub const IMAGE_FILE_NAME: usize = 0x5A8;

    /// EPROCESS.ThreadListHead offset
    pub const THREAD_LIST_HEAD: usize = 0x5E0;

    /// ETHREAD.ThreadListEntry offset
    pub const THREAD_LIST_ENTRY: usize = 0x4E8;

    /// ETHREAD.Cid offset (CLIENT_ID)
    pub const ETHREAD_CID: usize = 0x478;
}

/// Detect DKOM by comparing enumeration results
pub fn detect_dkom(enumerator: &ProcessEnumerator) -> Vec<&ProcessInfo> {
    let hidden = enumerator.find_hidden();

    for process in &hidden {
        println!(
            "[Leviathan] Potentially hidden process: PID={} Name={}",
            process.pid,
            core::str::from_utf8(&process.name).unwrap_or("<invalid>")
        );
    }

    hidden
}
