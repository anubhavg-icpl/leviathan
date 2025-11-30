//! Image (DLL/EXE) Load Monitoring
//!
//! Uses PsSetLoadImageNotifyRoutine to receive notifications when
//! executable images are loaded into any process.
//!
//! # Capabilities
//! - Monitor all DLL and EXE loads system-wide
//! - Detect DLL injection attacks
//! - Identify unsigned or suspicious modules
//! - Track driver loading in kernel space
//!
//! # Use Cases
//! - Detect DLL hijacking
//! - Monitor for reflective DLL injection
//! - Block known malicious DLLs
//! - Audit module loading for compliance

use core::sync::atomic::{AtomicBool, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{PsSetLoadImageNotifyRoutine, PsRemoveLoadImageNotifyRoutine},
    HANDLE, NTSTATUS, PIMAGE_INFO, PUNICODE_STRING, STATUS_SUCCESS,
};

/// Flag indicating if image callbacks are registered
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// Image load event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    /// User-mode executable (EXE)
    UserExe,
    /// User-mode library (DLL)
    UserDll,
    /// Kernel-mode driver (SYS)
    KernelDriver,
    /// Unknown image type
    Unknown,
}

/// Information about an image load event
#[repr(C)]
#[derive(Debug)]
pub struct ImageLoadEvent {
    pub image_type: ImageType,
    pub process_id: usize,
    pub image_base: usize,
    pub image_size: usize,
    pub is_kernel_mode: bool,
}

/// Register the image load callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn register() -> Result<(), NTSTATUS> {
    if REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let status = unsafe {
        PsSetLoadImageNotifyRoutine(Some(image_load_callback))
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] Failed to register image callback: {:#x}", status);
        return Err(status);
    }

    REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] Image load callback registered");
    Ok(())
}

/// Unregister the image load callback
///
/// # Safety
/// Must be called from PASSIVE_LEVEL
pub unsafe fn unregister() {
    if !REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    let status = unsafe {
        PsRemoveLoadImageNotifyRoutine(Some(image_load_callback))
    };

    if status == STATUS_SUCCESS {
        REGISTERED.store(false, Ordering::SeqCst);
        println!("[Leviathan] Image load callback unregistered");
    }
}

/// Image load notification callback
///
/// Called by the kernel when an image is mapped into memory.
///
/// # Parameters
/// - `full_image_name`: Full path to the image (may be NULL for some images)
/// - `process_id`: Process ID (0 for kernel-mode images)
/// - `image_info`: Information about the loaded image
///
/// # Safety
/// Called at PASSIVE_LEVEL by the kernel
/// Note: This is called while holding the loader lock - do minimal work here!
unsafe extern "C" fn image_load_callback(
    full_image_name: PUNICODE_STRING,
    process_id: HANDLE,
    image_info: PIMAGE_INFO,
) {
    if image_info.is_null() {
        return;
    }

    let info = unsafe { &*image_info };
    let pid = process_id as usize;
    let is_kernel = pid == 0;

    // Determine image type
    let image_type = if is_kernel {
        ImageType::KernelDriver
    } else if info.SystemModeImage != 0 {
        ImageType::KernelDriver
    } else {
        // For user-mode, would need to check if it's main exe or dll
        ImageType::UserDll
    };

    // Log the image load
    if is_kernel {
        println!(
            "[Leviathan] KERNEL Image Load: Base={:#x}, Size={:#x}",
            info.ImageBase as usize,
            info.ImageSize as usize
        );
    } else {
        println!(
            "[Leviathan] USER Image Load: PID={}, Base={:#x}, Size={:#x}",
            pid,
            info.ImageBase as usize,
            info.ImageSize as usize
        );
    }

    // Log image name if available
    if !full_image_name.is_null() {
        let name = unsafe { &*full_image_name };
        if name.Length > 0 && !name.Buffer.is_null() {
            // In production, would extract and log the actual filename
            println!("[Leviathan] Image path length: {} chars", name.Length / 2);
        }
    }

    // Check for suspicious patterns
    unsafe { check_suspicious_load(pid, info, full_image_name) };
}

/// Check for suspicious image load patterns
unsafe fn check_suspicious_load(
    process_id: usize,
    info: &wdk_sys::IMAGE_INFO,
    _image_name: PUNICODE_STRING,
) {
    // Pattern 1: DLL loaded from suspicious paths
    // - Temp folders
    // - User Downloads
    // - AppData\Local\Temp
    // - Network shares

    // Pattern 2: Known malicious DLL names
    // - dbghelp.dll in unusual location (DLL hijacking)
    // - version.dll in non-system location
    // - Unsigned DLLs in system processes

    // Pattern 3: Reflective DLL injection indicators
    // - Image not backed by file (ImageFileName is NULL)
    // - Unusual section permissions
    // - Image base in heap/stack region

    // Pattern 4: Kernel driver loading (for BYOVD attacks)
    if process_id == 0 {
        // Kernel driver loading - check for known vulnerable drivers
        println!(
            "[Leviathan] Kernel driver loaded at {:#x}",
            info.ImageBase as usize
        );
    }

    // Pattern 5: Check if image was loaded by suspicious means
    // - Check calling process
    // - Check if path matches known hijack locations
}

/// Determine if an image path is suspicious
#[allow(dead_code)]
fn is_suspicious_path(path: &[u16]) -> bool {
    // Convert to lowercase and check for:
    // - Temp directories
    // - Downloads folder
    // - Unusual system32 entries
    // - Network paths

    let suspicious_patterns = [
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\appdata\\local\\temp\\",
    ];

    // Would need proper string comparison here
    let _ = (path, suspicious_patterns);
    false
}

/// Check if loading a known vulnerable driver (BYOVD)
#[allow(dead_code)]
fn is_vulnerable_driver(_image_base: usize, _image_size: usize) -> bool {
    // Known vulnerable drivers used in BYOVD attacks:
    // - RTCore64.sys (MSI Afterburner)
    // - DBUtil_2_3.sys (Dell)
    // - AsIO.sys (ASUS)
    // - etc.

    // Would check hash or signature of the driver
    false
}
