//! Kernel Callback Modules
//!
//! This module provides Windows kernel callback implementations for:
//! - Process creation/termination monitoring
//! - Thread creation/termination monitoring
//! - Image (DLL/EXE) load monitoring
//! - Object handle access control
//! - Registry operation filtering
//!
//! These callbacks are essential for EDR (Endpoint Detection and Response),
//! anti-virus, and security monitoring applications.

pub mod process;
pub mod thread;
pub mod image;
pub mod object;
pub mod registry;

use wdk_sys::NTSTATUS;

/// Initialize all kernel callbacks
///
/// # Safety
/// Must be called from DriverEntry or device initialization context
pub unsafe fn register_all_callbacks() -> Result<(), NTSTATUS> {
    // Register in order of dependency
    unsafe {
        process::register()?;
        thread::register()?;
        image::register()?;
        object::register()?;
        registry::register()?;
    }

    Ok(())
}

/// Unregister all kernel callbacks
///
/// # Safety
/// Must be called from driver unload context
pub unsafe fn unregister_all_callbacks() {
    // Unregister in reverse order
    unsafe {
        registry::unregister();
        object::unregister();
        image::unregister();
        thread::unregister();
        process::unregister();
    }
}
