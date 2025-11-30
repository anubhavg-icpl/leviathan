//! Leviathan - Windows Kernel-Mode Driver in Rust
//!
//! This is a sample KMDF driver demonstrating Windows driver development
//! using the Rust programming language with Microsoft's windows-drivers-rs.
//!
//! # Architecture
//! - Uses KMDF (Kernel-Mode Driver Framework) v1.33
//! - Implements basic driver lifecycle (DriverEntry, DriverUnload)
//! - Demonstrates device I/O control handling

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(internal_features)]
#![feature(lang_items)]

extern crate alloc;

mod device;
mod ioctl;

use wdk::println;
use wdk_alloc::WdkAllocator;
use wdk_sys::{
    ntddk::DbgPrint,
    DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    WDFDEVICE_INIT, WDFDRIVER,
};

/// Global allocator for kernel memory allocations
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// Driver version information
pub const DRIVER_NAME: &str = "Leviathan";
pub const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Driver entry point - called by Windows when the driver is loaded
///
/// # Safety
/// This function is called by the Windows kernel with valid pointers.
/// The caller ensures `driver_object` and `registry_path` are valid.
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver_object: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // Initialize panic handler for kernel mode
    wdk_panic::init();

    println!("[{}] Driver loading - version {}", DRIVER_NAME, DRIVER_VERSION);

    // Initialize the driver with KMDF
    match unsafe { init_driver(driver_object, registry_path) } {
        Ok(()) => {
            println!("[{}] Driver initialized successfully", DRIVER_NAME);
            STATUS_SUCCESS
        }
        Err(status) => {
            println!("[{}] Driver initialization failed: {:#x}", DRIVER_NAME, status);
            status
        }
    }
}

/// Initialize the KMDF driver
///
/// # Safety
/// Caller must ensure driver_object and registry_path are valid pointers
unsafe fn init_driver(
    driver_object: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> Result<(), NTSTATUS> {
    use wdk_sys::{
        call_unsafe_wdf_function_binding, WDF_DRIVER_CONFIG, WDF_NO_HANDLE,
        WDF_NO_OBJECT_ATTRIBUTES,
    };

    // Configure WDF driver
    let mut driver_config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as u32,
        EvtDriverDeviceAdd: Some(device::evt_device_add),
        EvtDriverUnload: Some(evt_driver_unload),
        DriverInitFlags: 0,
        DriverPoolTag: 0,
    };

    // Create the WDF driver object
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver_object as *mut _,
            registry_path,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut driver_config,
            WDF_NO_HANDLE as *mut WDFDRIVER
        )
    };

    if status != STATUS_SUCCESS {
        return Err(status);
    }

    Ok(())
}

/// Driver unload callback - called when driver is being unloaded
///
/// # Safety
/// Called by KMDF with a valid driver handle
unsafe extern "C" fn evt_driver_unload(_driver: WDFDRIVER) {
    println!("[{}] Driver unloading", DRIVER_NAME);
}

/// Panic handler for kernel mode
#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
