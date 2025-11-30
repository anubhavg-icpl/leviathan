//! Filesystem Minifilter Driver
//!
//! Implements a Windows filesystem minifilter to intercept file I/O operations.
//!
//! # Capabilities
//! - Monitor file create/open/read/write/delete operations
//! - Block access to sensitive files
//! - Detect ransomware behavior patterns
//! - Implement on-access antivirus scanning
//! - File encryption/decryption (transparent encryption)
//!
//! # Architecture
//! Minifilters attach to the Filter Manager at a specific "altitude" which
//! determines their position in the filter stack. Higher altitude = earlier
//! in pre-operations, later in post-operations.
//!
//! # Use Cases
//! - Antivirus on-access scanning
//! - Data Loss Prevention (DLP)
//! - Ransomware detection
//! - File activity monitoring
//! - Backup/snapshot solutions

use core::sync::atomic::{AtomicBool, Ordering};
use core::ptr;
use wdk::println;
use wdk_sys::{
    NTSTATUS, PFLT_FILTER, PFLT_INSTANCE, PFLT_VOLUME, PVOID,
    STATUS_SUCCESS, STATUS_FLT_DO_NOT_ATTACH,
    FLT_REGISTRATION, FLT_OPERATION_REGISTRATION, FLT_PREOP_CALLBACK_STATUS,
    FLT_POSTOP_CALLBACK_STATUS, PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS,
};

/// Flag indicating if minifilter is registered
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Filter handle returned by FltRegisterFilter
static mut FILTER_HANDLE: PFLT_FILTER = ptr::null_mut();

/// Minifilter altitude (determines position in filter stack)
/// Range 320000-329999 is for Activity Monitor filters
/// Range 360000-389999 is for Anti-Virus filters
pub const FILTER_ALTITUDE: &str = "370030";

/// File extensions that should trigger scanning
const SCANNABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".hta", ".msi", ".jar",
];

/// Paths that should be protected from modification
const PROTECTED_PATHS: &[&str] = &[
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\",
];

/// Ransomware detection: suspicious file extensions
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    ".encrypted", ".locked", ".crypto", ".locky", ".zepto",
    ".cerber", ".crypt", ".cry", ".wncry",
];

/// IRP major function codes for file operations
mod irp_mj {
    pub const CREATE: u8 = 0x00;
    pub const READ: u8 = 0x03;
    pub const WRITE: u8 = 0x04;
    pub const SET_INFORMATION: u8 = 0x06; // Rename, delete
    pub const CLEANUP: u8 = 0x12;
    pub const CLOSE: u8 = 0x02;
}

/// Register the filesystem minifilter
///
/// # Safety
/// Must be called from DriverEntry context at PASSIVE_LEVEL
pub unsafe fn register(_driver_object: PVOID) -> Result<(), NTSTATUS> {
    if REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Define which operations we want to intercept
    let operations: [FLT_OPERATION_REGISTRATION; 6] = [
        // IRP_MJ_CREATE - File open/create
        FLT_OPERATION_REGISTRATION {
            MajorFunction: irp_mj::CREATE,
            Flags: 0,
            PreOperation: Some(pre_create),
            PostOperation: Some(post_create),
            Reserved1: ptr::null_mut(),
        },
        // IRP_MJ_READ - File read
        FLT_OPERATION_REGISTRATION {
            MajorFunction: irp_mj::READ,
            Flags: 0,
            PreOperation: Some(pre_read),
            PostOperation: None,
            Reserved1: ptr::null_mut(),
        },
        // IRP_MJ_WRITE - File write
        FLT_OPERATION_REGISTRATION {
            MajorFunction: irp_mj::WRITE,
            Flags: 0,
            PreOperation: Some(pre_write),
            PostOperation: None,
            Reserved1: ptr::null_mut(),
        },
        // IRP_MJ_SET_INFORMATION - Rename/Delete
        FLT_OPERATION_REGISTRATION {
            MajorFunction: irp_mj::SET_INFORMATION,
            Flags: 0,
            PreOperation: Some(pre_set_information),
            PostOperation: None,
            Reserved1: ptr::null_mut(),
        },
        // IRP_MJ_CLEANUP - Handle closed
        FLT_OPERATION_REGISTRATION {
            MajorFunction: irp_mj::CLEANUP,
            Flags: 0,
            PreOperation: None,
            PostOperation: Some(post_cleanup),
            Reserved1: ptr::null_mut(),
        },
        // Terminator
        FLT_OPERATION_REGISTRATION {
            MajorFunction: 0x80, // IRP_MJ_OPERATION_END
            Flags: 0,
            PreOperation: None,
            PostOperation: None,
            Reserved1: ptr::null_mut(),
        },
    ];

    // Build the filter registration structure
    let registration = FLT_REGISTRATION {
        Size: core::mem::size_of::<FLT_REGISTRATION>() as u16,
        Version: 0x0203, // FLT_REGISTRATION_VERSION
        Flags: 0,
        ContextRegistration: ptr::null(),
        OperationRegistration: operations.as_ptr(),
        FilterUnloadCallback: Some(filter_unload),
        InstanceSetupCallback: Some(instance_setup),
        InstanceQueryTeardownCallback: None,
        InstanceTeardownStartCallback: None,
        InstanceTeardownCompleteCallback: None,
        GenerateFileNameCallback: None,
        NormalizeNameComponentCallback: None,
        NormalizeContextCleanupCallback: None,
        TransactionNotificationCallback: None,
        NormalizeNameComponentExCallback: None,
        SectionNotificationCallback: None,
    };

    // Register the filter
    let mut filter_handle: PFLT_FILTER = ptr::null_mut();
    let status = unsafe {
        wdk_sys::fltKernel::FltRegisterFilter(
            _driver_object,
            &registration,
            &mut filter_handle,
        )
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] Failed to register minifilter: {:#x}", status);
        return Err(status);
    }

    unsafe { FILTER_HANDLE = filter_handle };

    // Start filtering
    let status = unsafe { wdk_sys::fltKernel::FltStartFiltering(filter_handle) };
    if status != STATUS_SUCCESS {
        unsafe { wdk_sys::fltKernel::FltUnregisterFilter(filter_handle) };
        println!("[Leviathan] Failed to start filtering: {:#x}", status);
        return Err(status);
    }

    REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] Minifilter registered and started");
    Ok(())
}

/// Unregister the filesystem minifilter
///
/// # Safety
/// Must be called from driver unload context
pub unsafe fn unregister() {
    if !REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    let handle = unsafe { FILTER_HANDLE };
    if !handle.is_null() {
        unsafe { wdk_sys::fltKernel::FltUnregisterFilter(handle) };
        unsafe { FILTER_HANDLE = ptr::null_mut() };
    }

    REGISTERED.store(false, Ordering::SeqCst);
    println!("[Leviathan] Minifilter unregistered");
}

/// Filter unload callback
///
/// Called when the minifilter is being unloaded
unsafe extern "C" fn filter_unload(_flags: u32) -> NTSTATUS {
    println!("[Leviathan] Minifilter unload requested");
    unsafe { unregister() };
    STATUS_SUCCESS
}

/// Instance setup callback
///
/// Called when attaching to a new volume. Return STATUS_SUCCESS to attach,
/// or STATUS_FLT_DO_NOT_ATTACH to skip this volume.
unsafe extern "C" fn instance_setup(
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _flags: u32,
    _volume_device_type: u32,
    _volume_filesystem_type: u32,
) -> NTSTATUS {
    // Attach to all volumes
    // In production, might skip network volumes, removable media, etc.
    println!("[Leviathan] Attaching to volume");
    STATUS_SUCCESS
}

/// Pre-operation callback for IRP_MJ_CREATE (file open/create)
///
/// Called BEFORE a file is opened or created.
unsafe extern "C" fn pre_create(
    data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    if data.is_null() {
        return wdk_sys::FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Get file name information here
    // FltGetFileNameInformation, FltParseFileNameInformation

    // Check for:
    // 1. Suspicious file extensions
    // 2. Protected paths
    // 3. Known malware file names

    // For on-access AV:
    // - Queue file for scanning
    // - If suspicious, return FLT_PREOP_COMPLETE with STATUS_ACCESS_DENIED

    wdk_sys::FLT_PREOP_SUCCESS_WITH_CALLBACK
}

/// Post-operation callback for IRP_MJ_CREATE
///
/// Called AFTER a file open/create completes
unsafe extern "C" fn post_create(
    data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: PVOID,
    _flags: u32,
) -> FLT_POSTOP_CALLBACK_STATUS {
    if data.is_null() {
        return wdk_sys::FLT_POSTOP_FINISHED_PROCESSING;
    }

    // File was successfully opened
    // Good place to:
    // - Log file access
    // - Start monitoring this file handle
    // - Cache file metadata

    wdk_sys::FLT_POSTOP_FINISHED_PROCESSING
}

/// Pre-operation callback for IRP_MJ_READ
unsafe extern "C" fn pre_read(
    _data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    // Monitor file reads
    // Use cases:
    // - Track data exfiltration
    // - Implement transparent decryption
    // - Log sensitive file access

    wdk_sys::FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-operation callback for IRP_MJ_WRITE
unsafe extern "C" fn pre_write(
    _data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    // Monitor file writes
    // Use cases:
    // - Ransomware detection (mass file modification)
    // - Prevent modification of system files
    // - Implement transparent encryption
    // - Data loss prevention

    // Ransomware heuristics:
    // - High entropy data being written
    // - Mass renaming with suspicious extensions
    // - Deletion of shadow copies
    // - Writing ransom notes

    wdk_sys::FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Pre-operation callback for IRP_MJ_SET_INFORMATION (rename/delete)
unsafe extern "C" fn pre_set_information(
    _data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: *mut PVOID,
) -> FLT_PREOP_CALLBACK_STATUS {
    // Monitor file rename and delete operations
    // Use cases:
    // - Detect ransomware renaming files
    // - Prevent deletion of critical files
    // - Track file movement

    wdk_sys::FLT_PREOP_SUCCESS_NO_CALLBACK
}

/// Post-operation callback for IRP_MJ_CLEANUP
unsafe extern "C" fn post_cleanup(
    _data: PFLT_CALLBACK_DATA,
    _flt_objects: PCFLT_RELATED_OBJECTS,
    _completion_context: PVOID,
    _flags: u32,
) -> FLT_POSTOP_CALLBACK_STATUS {
    // File handle is being closed
    // Good place to:
    // - Finalize file scanning
    // - Clean up per-file tracking state
    // - Log file session complete

    wdk_sys::FLT_POSTOP_FINISHED_PROCESSING
}

/// Calculate Shannon entropy of data (for ransomware detection)
#[allow(dead_code)]
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0f32;

    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Detect potential ransomware behavior
#[allow(dead_code)]
fn is_ransomware_behavior(
    _process_id: usize,
    _files_modified: usize,
    _files_renamed: usize,
    avg_entropy: f32,
) -> bool {
    // High entropy + mass modification = likely ransomware
    // Threshold: entropy > 7.5 (out of 8.0 max) is suspicious
    // Combined with many file modifications

    avg_entropy > 7.5
}
