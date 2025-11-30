//! Registry Operation Filtering
//!
//! Uses CmRegisterCallbackEx to intercept and filter registry operations.
//!
//! # Capabilities
//! - Monitor all registry read/write operations
//! - Block modifications to protected keys
//! - Detect registry-based persistence mechanisms
//! - Audit registry access patterns
//!
//! # Use Cases
//! - Protect system configuration from tampering
//! - Detect malware persistence (Run keys, Services, etc.)
//! - Monitor for credential theft (SAM access)
//! - Registry-based application whitelisting

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{CmRegisterCallbackEx, CmUnRegisterCallback},
    LARGE_INTEGER, NTSTATUS, PCUNICODE_STRING, PVOID, REG_NOTIFY_CLASS,
    STATUS_SUCCESS, STATUS_ACCESS_DENIED,
};

/// Flag indicating if registry callbacks are registered
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Cookie returned by CmRegisterCallbackEx for unregistration
static CALLBACK_COOKIE: AtomicU64 = AtomicU64::new(0);

/// Registry operation types we care about
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOperation {
    /// Key creation
    CreateKey,
    /// Key opened
    OpenKey,
    /// Key deleted
    DeleteKey,
    /// Value set/modified
    SetValue,
    /// Value deleted
    DeleteValue,
    /// Value queried
    QueryValue,
    /// Key enumerated
    EnumerateKey,
    /// Other operations
    Other,
}

/// Protected registry paths (persistence locations)
const PROTECTED_PATHS: &[&str] = &[
    "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\Registry\\Machine\\System\\CurrentControlSet\\Services",
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    "\\Registry\\Machine\\SAM",
    "\\Registry\\Machine\\SECURITY",
];

/// Register the registry callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn register() -> Result<(), NTSTATUS> {
    if REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut cookie: LARGE_INTEGER = core::mem::zeroed();

    // Altitude determines callback order (higher = earlier)
    // Use altitude string for registration
    let altitude = wdk_sys::UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: core::ptr::null_mut(),
    };

    let status = unsafe {
        CmRegisterCallbackEx(
            Some(registry_callback),
            &altitude,
            core::ptr::null_mut(), // Driver object
            core::ptr::null_mut(), // Context
            &mut cookie,
            core::ptr::null_mut(), // Reserved
        )
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] Failed to register registry callback: {:#x}", status);
        return Err(status);
    }

    CALLBACK_COOKIE.store(cookie.QuadPart as u64, Ordering::SeqCst);
    REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] Registry callback registered");
    Ok(())
}

/// Unregister the registry callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn unregister() {
    if !REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    let cookie = CALLBACK_COOKIE.load(Ordering::SeqCst);
    let mut large_cookie: LARGE_INTEGER = unsafe { core::mem::zeroed() };
    large_cookie.QuadPart = cookie as i64;

    let status = unsafe { CmUnRegisterCallback(large_cookie) };

    if status == STATUS_SUCCESS {
        REGISTERED.store(false, Ordering::SeqCst);
        println!("[Leviathan] Registry callback unregistered");
    }
}

/// Registry callback function
///
/// Called before and after registry operations.
///
/// # Parameters
/// - `context`: Driver-defined context (unused)
/// - `argument1`: REG_NOTIFY_CLASS indicating operation type
/// - `argument2`: Operation-specific information structure
///
/// # Returns
/// - STATUS_SUCCESS: Allow the operation
/// - STATUS_ACCESS_DENIED: Block the operation (pre-operation only)
///
/// # Safety
/// Called at various IRQLs depending on the operation
unsafe extern "C" fn registry_callback(
    _context: PVOID,
    argument1: PVOID,
    argument2: PVOID,
) -> NTSTATUS {
    let notify_class = argument1 as i32;

    // Map the notification class to our operation type
    let operation = map_notify_class(notify_class);

    match operation {
        RegistryOperation::SetValue => {
            unsafe { handle_set_value(argument2) }
        }
        RegistryOperation::CreateKey => {
            unsafe { handle_create_key(argument2) }
        }
        RegistryOperation::DeleteKey | RegistryOperation::DeleteValue => {
            unsafe { handle_delete_operation(argument2) }
        }
        _ => STATUS_SUCCESS,
    }
}

/// Map REG_NOTIFY_CLASS to our operation type
fn map_notify_class(class: i32) -> RegistryOperation {
    // REG_NOTIFY_CLASS values (from wdm.h)
    const REG_CREATE_KEY_INFORMATION: i32 = 0;
    const REG_PRE_CREATE_KEY_INFORMATION: i32 = 1;
    const REG_POST_CREATE_KEY_INFORMATION: i32 = 2;
    const REG_OPEN_KEY_INFORMATION: i32 = 3;
    const REG_PRE_SET_VALUE_KEY_INFORMATION: i32 = 6;
    const REG_DELETE_KEY_INFORMATION: i32 = 12;
    const REG_DELETE_VALUE_KEY_INFORMATION: i32 = 15;
    const REG_QUERY_VALUE_KEY_INFORMATION: i32 = 18;
    const REG_ENUMERATE_KEY_INFORMATION: i32 = 21;

    match class {
        REG_CREATE_KEY_INFORMATION | REG_PRE_CREATE_KEY_INFORMATION | REG_POST_CREATE_KEY_INFORMATION => {
            RegistryOperation::CreateKey
        }
        REG_OPEN_KEY_INFORMATION => RegistryOperation::OpenKey,
        REG_DELETE_KEY_INFORMATION => RegistryOperation::DeleteKey,
        REG_PRE_SET_VALUE_KEY_INFORMATION => RegistryOperation::SetValue,
        REG_DELETE_VALUE_KEY_INFORMATION => RegistryOperation::DeleteValue,
        REG_QUERY_VALUE_KEY_INFORMATION => RegistryOperation::QueryValue,
        REG_ENUMERATE_KEY_INFORMATION => RegistryOperation::EnumerateKey,
        _ => RegistryOperation::Other,
    }
}

/// Handle SetValue operations (potential persistence/config changes)
unsafe fn handle_set_value(_info: PVOID) -> NTSTATUS {
    // REG_SET_VALUE_KEY_INFORMATION structure contains:
    // - Object: The key being modified
    // - ValueName: Name of the value
    // - TitleIndex, Type, Data, DataSize

    println!("[Leviathan] Registry SetValue operation detected");

    // In production:
    // 1. Get the full key path
    // 2. Check if it's a protected path
    // 3. Log the operation details
    // 4. Optionally block with STATUS_ACCESS_DENIED

    STATUS_SUCCESS
}

/// Handle CreateKey operations
unsafe fn handle_create_key(_info: PVOID) -> NTSTATUS {
    println!("[Leviathan] Registry CreateKey operation detected");

    // Monitor for:
    // - New service registrations
    // - New Run key entries
    // - IFEO (Image File Execution Options) modifications

    STATUS_SUCCESS
}

/// Handle Delete operations
unsafe fn handle_delete_operation(_info: PVOID) -> NTSTATUS {
    println!("[Leviathan] Registry Delete operation detected");

    // Monitor for:
    // - Deletion of security settings
    // - Removal of audit policies
    // - Tampering with installed software records

    STATUS_SUCCESS
}

/// Check if a registry path is protected
#[allow(dead_code)]
fn is_protected_path(_path: &[u16]) -> bool {
    // Would compare against PROTECTED_PATHS
    // Using case-insensitive prefix matching
    false
}

/// Common persistence locations in Windows Registry
#[allow(dead_code)]
mod persistence_keys {
    /// User-specific autorun
    pub const HKCU_RUN: &str = "\\Registry\\User\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    /// System-wide autorun
    pub const HKLM_RUN: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    /// Services (can start executables)
    pub const SERVICES: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services";

    /// Scheduled tasks configuration
    pub const SCHEDULED_TASKS: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule";

    /// AppInit_DLLs (DLL injection)
    pub const APPINIT_DLLS: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

    /// Image File Execution Options (debugger hijacking)
    pub const IFEO: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";

    /// Shell extensions
    pub const SHELL_EXTENSIONS: &str = "\\Registry\\Machine\\Software\\Classes\\*\\shellex";

    /// COM hijacking locations
    pub const CLSID: &str = "\\Registry\\Machine\\Software\\Classes\\CLSID";
}
