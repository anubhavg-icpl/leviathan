//! Leviathan - Windows Kernel-Mode Driver in Rust
//!
//! A comprehensive Windows kernel driver framework for building EDR/XDR solutions.
//! Provides all the kernel-mode components needed for endpoint security monitoring.
//!
//! # Modules
//!
//! ## Kernel Callbacks (`callbacks/`)
//! - **Process monitoring**: Track process creation/termination, block malicious processes
//! - **Thread monitoring**: Detect remote thread injection attacks
//! - **Image monitoring**: Monitor DLL/driver loading, detect DLL injection
//! - **Registry filtering**: Protect critical registry keys, detect persistence
//! - **Object callbacks**: Protect processes from termination, prevent credential dumping
//!
//! ## Kernel Filters (`filters/`)
//! - **Filesystem minifilter**: Intercept file I/O, ransomware detection, on-access scanning
//! - **Network filter (WFP)**: Application-aware firewall, block malicious connections
//!
//! ## Security (`security/`)
//! - **ELAM**: Early Launch Anti-Malware driver support
//! - **APC Injection**: Kernel-to-user mode code execution
//! - **Integrity**: Anti-tampering and callback verification
//! - **Hook Detection**: SSDT, IDT, inline hook scanning
//!
//! ## Detection (`detection/`)
//! - **Rule Engine**: Pattern-based threat detection rules
//! - **Behavioral Analysis**: Activity correlation and anomaly detection
//! - **Heuristics**: Command line, file path, and registry heuristics
//!
//! ## Forensics (`forensics/`)
//! - **Pool Scanner**: Find kernel objects by pool tag (DKOM detection)
//! - **Process Enum**: Multi-method process enumeration for hidden process detection
//! - **IRP Analysis**: Device stack and filter driver analysis
//! - **Memory Scanner**: Signature/pattern scanning for malware detection
//!
//! ## Utilities (`utils/`)
//! - **Timers & DPC**: Scheduled kernel execution, periodic tasks
//! - **Memory management**: Safe pool allocations, MDL handling, user buffer access
//! - **Synchronization**: Spinlocks, fast mutexes, read/write locks, events
//! - **ETW tracing**: High-performance event logging for diagnostics
//! - **Communication**: Ring buffer and shared memory for kernel-user IPC
//!
//! # Architecture
//! - Uses KMDF (Kernel-Mode Driver Framework) v1.33
//! - Built with Microsoft's windows-drivers-rs
//! - Designed for EDR/XDR security monitoring applications
//! - See ARCHITECTURE.md for detailed design documentation

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(internal_features)]
#![allow(dead_code)]
#![feature(lang_items)]

extern crate alloc;

// Core driver modules
mod device;
mod ioctl;

// Kernel callbacks for system monitoring
pub mod callbacks;

// Kernel filters (filesystem, network)
pub mod filters;

// Security modules (ELAM, APC, integrity)
pub mod security;

// Forensics modules (pool scanning, process enumeration)
pub mod forensics;

// Detection engine (rules, behavioral analysis, heuristics)
pub mod detection;

// Utility modules
pub mod utils;

use wdk::println;
use wdk_alloc::WdkAllocator;
use wdk_sys::{
    DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS,
    WDFDRIVER,
};

/// Global allocator for kernel memory allocations
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// Driver version information
pub const DRIVER_NAME: &str = "Leviathan";
pub const DRIVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Feature flags for enabling/disabling driver capabilities
pub mod features {
    /// Enable process/thread/image monitoring callbacks
    pub const ENABLE_CALLBACKS: bool = true;
    /// Enable filesystem minifilter
    pub const ENABLE_MINIFILTER: bool = false; // Requires separate minifilter registration
    /// Enable WFP network filtering
    pub const ENABLE_NETWORK_FILTER: bool = false;
    /// Enable ETW event tracing
    pub const ENABLE_ETW: bool = true;
}

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

    println!("╔══════════════════════════════════════════╗");
    println!("║  Leviathan Kernel Driver v{}         ║", DRIVER_VERSION);
    println!("║  Windows Driver Development in Rust      ║");
    println!("╚══════════════════════════════════════════╝");

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

/// Initialize the KMDF driver and all subsystems
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

    // Step 1: Register ETW provider for event tracing
    if features::ENABLE_ETW {
        if let Err(e) = unsafe { utils::etw::register() } {
            println!("[{}] Warning: ETW registration failed: {:#x}", DRIVER_NAME, e);
            // Continue anyway - ETW is optional
        }
    }

    // Step 2: Configure and create WDF driver
    let mut driver_config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as u32,
        EvtDriverDeviceAdd: Some(device::evt_device_add),
        EvtDriverUnload: Some(evt_driver_unload),
        DriverInitFlags: 0,
        DriverPoolTag: 0,
    };

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

    // Step 3: Register kernel callbacks for monitoring
    if features::ENABLE_CALLBACKS {
        println!("[{}] Registering kernel callbacks...", DRIVER_NAME);

        // Process monitoring
        if let Err(e) = unsafe { callbacks::process::register() } {
            println!("[{}] Warning: Process callback failed: {:#x}", DRIVER_NAME, e);
        }

        // Thread monitoring
        if let Err(e) = unsafe { callbacks::thread::register() } {
            println!("[{}] Warning: Thread callback failed: {:#x}", DRIVER_NAME, e);
        }

        // Image load monitoring
        if let Err(e) = unsafe { callbacks::image::register() } {
            println!("[{}] Warning: Image callback failed: {:#x}", DRIVER_NAME, e);
        }

        // Registry filtering
        if let Err(e) = unsafe { callbacks::registry::register() } {
            println!("[{}] Warning: Registry callback failed: {:#x}", DRIVER_NAME, e);
        }

        // Object callbacks (process protection) - requires signed driver
        // Uncomment when driver is properly signed:
        // if let Err(e) = unsafe { callbacks::object::register() } {
        //     println!("[{}] Warning: Object callback failed: {:#x}", DRIVER_NAME, e);
        // }

        println!("[{}] Kernel callbacks registered", DRIVER_NAME);
    }

    // Step 4: Register filesystem minifilter (if enabled)
    if features::ENABLE_MINIFILTER {
        println!("[{}] Registering filesystem minifilter...", DRIVER_NAME);
        // Note: Minifilter requires FltRegisterFilter which needs
        // the driver to be built as a minifilter driver type
        // if let Err(e) = unsafe { filters::minifilter::register(driver_object as *mut _ as _) } {
        //     println!("[{}] Warning: Minifilter failed: {:#x}", DRIVER_NAME, e);
        // }
    }

    // Step 5: Register WFP network filter (if enabled)
    if features::ENABLE_NETWORK_FILTER {
        println!("[{}] Registering network filter...", DRIVER_NAME);
        // Note: WFP requires a device object for callout registration
        // if let Err(e) = unsafe { filters::network::register(device_object) } {
        //     println!("[{}] Warning: Network filter failed: {:#x}", DRIVER_NAME, e);
        // }
    }

    println!("[{}] All subsystems initialized", DRIVER_NAME);
    Ok(())
}

/// Driver unload callback - called when driver is being unloaded
///
/// # Safety
/// Called by KMDF with a valid driver handle
unsafe extern "C" fn evt_driver_unload(_driver: WDFDRIVER) {
    println!("[{}] Driver unloading - cleaning up...", DRIVER_NAME);

    // Unregister in reverse order of registration

    // Network filter
    if features::ENABLE_NETWORK_FILTER {
        unsafe { filters::network::unregister() };
    }

    // Filesystem minifilter
    if features::ENABLE_MINIFILTER {
        unsafe { filters::minifilter::unregister() };
    }

    // Kernel callbacks
    if features::ENABLE_CALLBACKS {
        unsafe { callbacks::unregister_all_callbacks() };
    }

    // ETW provider
    if features::ENABLE_ETW {
        unsafe { utils::etw::unregister() };
    }

    println!("[{}] Driver unloaded successfully", DRIVER_NAME);
}

/// Panic handler for kernel mode
#[cfg(not(test))]
#[lang = "eh_personality"]
extern "C" fn eh_personality() {}
