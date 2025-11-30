//! Device creation and management for the Leviathan driver
//!
//! This module handles KMDF device object creation, I/O queue setup,
//! and device interface registration.

use crate::ioctl;
use wdk::println;
use wdk_sys::{
    call_unsafe_wdf_function_binding, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS,
    WDFDEVICE, WDFDEVICE_INIT, WDFDRIVER, WDFQUEUE, WDF_DEVICE_IO_TYPE,
    WDF_IO_QUEUE_CONFIG, WDF_NO_HANDLE, WDF_NO_OBJECT_ATTRIBUTES,
    WDF_OBJECT_ATTRIBUTES, WDFREQUEST,
};

/// Device interface GUID for user-mode communication
/// {12345678-1234-1234-1234-123456789ABC}
pub const DEVICE_INTERFACE_GUID: wdk_sys::GUID = wdk_sys::GUID {
    Data1: 0x12345678,
    Data2: 0x1234,
    Data3: 0x1234,
    Data4: [0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
};

/// Callback invoked when a new device is added to the system
///
/// # Safety
/// Called by KMDF with valid driver and device_init pointers
#[no_mangle]
pub unsafe extern "C" fn evt_device_add(
    _driver: WDFDRIVER,
    device_init: *mut WDFDEVICE_INIT,
) -> NTSTATUS {
    println!("[Leviathan] Device add callback invoked");

    match unsafe { create_device(device_init) } {
        Ok(device) => {
            println!("[Leviathan] Device created successfully");

            // Create I/O queue for the device
            if let Err(status) = unsafe { create_io_queue(device) } {
                println!("[Leviathan] Failed to create I/O queue: {:#x}", status);
                return status;
            }

            // Register device interface for user-mode access
            if let Err(status) = unsafe { register_device_interface(device) } {
                println!("[Leviathan] Failed to register device interface: {:#x}", status);
                return status;
            }

            STATUS_SUCCESS
        }
        Err(status) => {
            println!("[Leviathan] Device creation failed: {:#x}", status);
            status
        }
    }
}

/// Create the WDFDEVICE object
///
/// # Safety
/// Caller must ensure device_init is a valid pointer from KMDF
unsafe fn create_device(device_init: *mut WDFDEVICE_INIT) -> Result<WDFDEVICE, NTSTATUS> {
    let mut device: WDFDEVICE = core::ptr::null_mut();

    // Set device characteristics
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetIoType,
            device_init,
            WDF_DEVICE_IO_TYPE::WdfDeviceIoBuffered
        );
    }

    // Create the device
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceCreate,
            &mut (device_init as *mut _),
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut device
        )
    };

    if status != STATUS_SUCCESS {
        return Err(status);
    }

    Ok(device)
}

/// Create and configure the I/O queue for handling requests
///
/// # Safety
/// Caller must ensure device is a valid WDFDEVICE handle
unsafe fn create_io_queue(device: WDFDEVICE) -> Result<WDFQUEUE, NTSTATUS> {
    let mut queue_config = WDF_IO_QUEUE_CONFIG {
        Size: core::mem::size_of::<WDF_IO_QUEUE_CONFIG>() as u32,
        PowerManaged: wdk_sys::_WDF_TRI_STATE::WdfUseDefault,
        DefaultQueue: true as u8,
        DispatchType: wdk_sys::_WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchSequential,
        EvtIoRead: Some(ioctl::evt_io_read),
        EvtIoWrite: Some(ioctl::evt_io_write),
        EvtIoDeviceControl: Some(ioctl::evt_io_device_control),
        EvtIoStop: None,
        EvtIoResume: None,
        EvtIoInternalDeviceControl: None,
        EvtIoCanceledOnQueue: None,
        AllowZeroLengthRequests: false as u8,
        NumberOfPresentedRequests: 0,
        Driver: core::ptr::null_mut(),
        Reserved: [core::ptr::null_mut(); 3],
    };

    let mut queue: WDFQUEUE = core::ptr::null_mut();

    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfIoQueueCreate,
            device,
            &mut queue_config,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut queue
        )
    };

    if status != STATUS_SUCCESS {
        return Err(status);
    }

    Ok(queue)
}

/// Register a device interface for user-mode communication
///
/// # Safety
/// Caller must ensure device is a valid WDFDEVICE handle
unsafe fn register_device_interface(device: WDFDEVICE) -> Result<(), NTSTATUS> {
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceCreateDeviceInterface,
            device,
            &DEVICE_INTERFACE_GUID,
            core::ptr::null()
        )
    };

    if status != STATUS_SUCCESS {
        return Err(status);
    }

    println!("[Leviathan] Device interface registered");
    Ok(())
}
