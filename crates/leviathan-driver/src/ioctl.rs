//! I/O Control (IOCTL) handling for the Leviathan driver
//!
//! This module processes read, write, and device control requests
//! from user-mode applications.

use wdk::println;
use wdk_sys::{
    call_unsafe_wdf_function_binding, NTSTATUS, STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS, ULONG, WDFQUEUE, WDFREQUEST,
};

/// Custom IOCTL codes for the driver
/// Using METHOD_BUFFERED for simplicity
pub mod codes {
    use wdk_sys::ULONG;

    /// Device type for Leviathan driver
    pub const FILE_DEVICE_LEVIATHAN: ULONG = 0x8000;

    /// IOCTL to get driver version
    /// CTL_CODE(FILE_DEVICE_LEVIATHAN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    pub const IOCTL_LEVIATHAN_GET_VERSION: ULONG =
        (FILE_DEVICE_LEVIATHAN << 16) | (0x800 << 2) | 0 | 0;

    /// IOCTL to echo data back to user
    /// CTL_CODE(FILE_DEVICE_LEVIATHAN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
    pub const IOCTL_LEVIATHAN_ECHO: ULONG =
        (FILE_DEVICE_LEVIATHAN << 16) | (0x801 << 2) | 0 | 0;

    /// IOCTL to get driver statistics
    /// CTL_CODE(FILE_DEVICE_LEVIATHAN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
    pub const IOCTL_LEVIATHAN_GET_STATS: ULONG =
        (FILE_DEVICE_LEVIATHAN << 16) | (0x802 << 2) | 0 | 0;
}

/// Driver statistics structure
#[repr(C)]
#[derive(Default)]
pub struct DriverStats {
    pub read_count: u64,
    pub write_count: u64,
    pub ioctl_count: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Global statistics (in production, use proper synchronization)
static mut STATS: DriverStats = DriverStats {
    read_count: 0,
    write_count: 0,
    ioctl_count: 0,
    bytes_read: 0,
    bytes_written: 0,
};

/// Handle read requests from user-mode
///
/// # Safety
/// Called by KMDF with valid queue and request handles
#[no_mangle]
pub unsafe extern "C" fn evt_io_read(
    _queue: WDFQUEUE,
    request: WDFREQUEST,
    length: usize,
) {
    println!("[Leviathan] Read request received, length: {}", length);

    unsafe {
        STATS.read_count += 1;
    }

    // For demo: complete with no data (would normally read from device)
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestCompleteWithInformation,
            request,
            STATUS_SUCCESS,
            0
        );
    }
}

/// Handle write requests from user-mode
///
/// # Safety
/// Called by KMDF with valid queue and request handles
#[no_mangle]
pub unsafe extern "C" fn evt_io_write(
    _queue: WDFQUEUE,
    request: WDFREQUEST,
    length: usize,
) {
    println!("[Leviathan] Write request received, length: {}", length);

    unsafe {
        STATS.write_count += 1;
        STATS.bytes_written += length as u64;
    }

    // Complete the request successfully
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestCompleteWithInformation,
            request,
            STATUS_SUCCESS,
            length
        );
    }
}

/// Handle device control (IOCTL) requests
///
/// # Safety
/// Called by KMDF with valid queue and request handles
#[no_mangle]
pub unsafe extern "C" fn evt_io_device_control(
    _queue: WDFQUEUE,
    request: WDFREQUEST,
    _output_buffer_length: usize,
    _input_buffer_length: usize,
    io_control_code: ULONG,
) {
    println!("[Leviathan] IOCTL received: {:#x}", io_control_code);

    unsafe {
        STATS.ioctl_count += 1;
    }

    let status = match io_control_code {
        codes::IOCTL_LEVIATHAN_GET_VERSION => {
            unsafe { handle_get_version(request) }
        }
        codes::IOCTL_LEVIATHAN_ECHO => {
            unsafe { handle_echo(request) }
        }
        codes::IOCTL_LEVIATHAN_GET_STATS => {
            unsafe { handle_get_stats(request) }
        }
        _ => {
            println!("[Leviathan] Unknown IOCTL code: {:#x}", io_control_code);
            STATUS_INVALID_PARAMETER
        }
    };

    // Complete the request
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestComplete,
            request,
            status
        );
    }
}

/// Handle IOCTL_LEVIATHAN_GET_VERSION
///
/// # Safety
/// Caller must ensure request is valid
unsafe fn handle_get_version(request: WDFREQUEST) -> NTSTATUS {
    let version = crate::DRIVER_VERSION;
    println!("[Leviathan] Returning version: {}", version);

    // In a real implementation, copy version string to output buffer
    STATUS_SUCCESS
}

/// Handle IOCTL_LEVIATHAN_ECHO - echo input data back to output
///
/// # Safety
/// Caller must ensure request is valid
unsafe fn handle_echo(request: WDFREQUEST) -> NTSTATUS {
    println!("[Leviathan] Echo IOCTL");

    // In a real implementation:
    // 1. Get input buffer using WdfRequestRetrieveInputBuffer
    // 2. Get output buffer using WdfRequestRetrieveOutputBuffer
    // 3. Copy input to output
    // 4. Set information to bytes copied

    STATUS_SUCCESS
}

/// Handle IOCTL_LEVIATHAN_GET_STATS
///
/// # Safety
/// Caller must ensure request is valid
unsafe fn handle_get_stats(request: WDFREQUEST) -> NTSTATUS {
    println!("[Leviathan] Get stats IOCTL");

    // In a real implementation:
    // 1. Get output buffer
    // 2. Copy STATS to output buffer
    // 3. Set information to size of DriverStats

    STATUS_SUCCESS
}
