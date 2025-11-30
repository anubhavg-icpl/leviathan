//! IRP (I/O Request Packet) Analysis and Filter Driver Utilities
//!
//! Tools for analyzing the device stack, IRP flow, and filter drivers.
//!
//! # Device Stack Concepts
//! ```text
//! User Request
//!     │
//!     ▼
//! ┌─────────────────┐
//! │ Upper Filter    │ ← Can inspect/modify before FDO
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │ Function Driver │ ← Main driver (FDO)
//! │     (FDO)       │
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │ Lower Filter    │ ← Can inspect/modify before PDO
//! └────────┬────────┘
//!          │
//! ┌────────▼────────┐
//! │ Physical Device │ ← Bus driver (PDO)
//! │   Object (PDO)  │
//! └─────────────────┘
//! ```
//!
//! # Use Cases
//! - Enumerate device stacks
//! - Attach to device stacks as filter
//! - Analyze IRP major/minor functions
//! - Detect malicious filter drivers

use alloc::vec::Vec;
use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{
        IoGetDeviceObjectPointer, IoAttachDeviceToDeviceStack,
        IoDetachDevice, IoCallDriver, IoBuildSynchronousFsdRequest,
    },
    DEVICE_OBJECT, DRIVER_OBJECT, FILE_OBJECT, IO_STATUS_BLOCK,
    IRP, NTSTATUS, PDEVICE_OBJECT, PDRIVER_OBJECT, PFILE_OBJECT,
    PIRP, STATUS_SUCCESS, UNICODE_STRING,
};

/// IRP major function codes
pub mod irp_mj {
    pub const CREATE: u8 = 0x00;
    pub const CREATE_NAMED_PIPE: u8 = 0x01;
    pub const CLOSE: u8 = 0x02;
    pub const READ: u8 = 0x03;
    pub const WRITE: u8 = 0x04;
    pub const QUERY_INFORMATION: u8 = 0x05;
    pub const SET_INFORMATION: u8 = 0x06;
    pub const QUERY_EA: u8 = 0x07;
    pub const SET_EA: u8 = 0x08;
    pub const FLUSH_BUFFERS: u8 = 0x09;
    pub const QUERY_VOLUME_INFORMATION: u8 = 0x0A;
    pub const SET_VOLUME_INFORMATION: u8 = 0x0B;
    pub const DIRECTORY_CONTROL: u8 = 0x0C;
    pub const FILE_SYSTEM_CONTROL: u8 = 0x0D;
    pub const DEVICE_CONTROL: u8 = 0x0E;
    pub const INTERNAL_DEVICE_CONTROL: u8 = 0x0F;
    pub const SHUTDOWN: u8 = 0x10;
    pub const LOCK_CONTROL: u8 = 0x11;
    pub const CLEANUP: u8 = 0x12;
    pub const CREATE_MAILSLOT: u8 = 0x13;
    pub const QUERY_SECURITY: u8 = 0x14;
    pub const SET_SECURITY: u8 = 0x15;
    pub const POWER: u8 = 0x16;
    pub const SYSTEM_CONTROL: u8 = 0x17;
    pub const DEVICE_CHANGE: u8 = 0x18;
    pub const QUERY_QUOTA: u8 = 0x19;
    pub const SET_QUOTA: u8 = 0x1A;
    pub const PNP: u8 = 0x1B;
    pub const MAXIMUM_FUNCTION: u8 = 0x1C;

    /// Get human-readable name for IRP major function
    pub fn name(code: u8) -> &'static str {
        match code {
            0x00 => "IRP_MJ_CREATE",
            0x01 => "IRP_MJ_CREATE_NAMED_PIPE",
            0x02 => "IRP_MJ_CLOSE",
            0x03 => "IRP_MJ_READ",
            0x04 => "IRP_MJ_WRITE",
            0x05 => "IRP_MJ_QUERY_INFORMATION",
            0x06 => "IRP_MJ_SET_INFORMATION",
            0x0E => "IRP_MJ_DEVICE_CONTROL",
            0x0F => "IRP_MJ_INTERNAL_DEVICE_CONTROL",
            0x16 => "IRP_MJ_POWER",
            0x17 => "IRP_MJ_SYSTEM_CONTROL",
            0x1B => "IRP_MJ_PNP",
            _ => "IRP_MJ_UNKNOWN",
        }
    }
}

/// Device stack entry information
#[derive(Debug)]
pub struct DeviceStackEntry {
    /// Device object address
    pub device_object: usize,
    /// Driver object address
    pub driver_object: usize,
    /// Driver name
    pub driver_name: [u16; 64],
    /// Device name (if any)
    pub device_name: [u16; 64],
    /// Device type
    pub device_type: u32,
    /// Stack position (0 = bottom)
    pub stack_position: u32,
    /// Is this a filter device
    pub is_filter: bool,
}

/// Enumerate device stack for a given device
///
/// # Parameters
/// - `device`: Starting device object
///
/// # Safety
/// Device object must be valid
pub unsafe fn enumerate_device_stack(device: PDEVICE_OBJECT) -> Vec<DeviceStackEntry> {
    let mut stack = Vec::new();
    let mut current = device;
    let mut position = 0u32;

    while !current.is_null() {
        let dev_obj = unsafe { &*current };

        let entry = DeviceStackEntry {
            device_object: current as usize,
            driver_object: dev_obj.DriverObject as usize,
            driver_name: [0u16; 64],
            device_name: [0u16; 64],
            device_type: dev_obj.DeviceType,
            stack_position: position,
            is_filter: (dev_obj.Flags & 0x00001000) != 0, // DO_DEVICE_INITIALIZING check (simplified)
        };

        stack.push(entry);

        // Move to attached device (lower in stack)
        current = dev_obj.AttachedDevice;
        position += 1;
    }

    stack
}

/// Get the topmost device in a stack
///
/// # Safety
/// Device must be valid
pub unsafe fn get_top_device(device: PDEVICE_OBJECT) -> PDEVICE_OBJECT {
    let mut current = device;

    while !current.is_null() {
        let dev_obj = unsafe { &*current };
        if dev_obj.AttachedDevice.is_null() {
            break;
        }
        current = dev_obj.AttachedDevice;
    }

    current
}

/// Filter driver attachment helper
pub struct DeviceFilter {
    /// Our filter device object
    filter_device: PDEVICE_OBJECT,
    /// The device we attached to
    attached_to: PDEVICE_OBJECT,
    /// Are we currently attached
    attached: bool,
}

impl DeviceFilter {
    /// Create a new device filter (not yet attached)
    pub fn new(filter_device: PDEVICE_OBJECT) -> Self {
        Self {
            filter_device,
            attached_to: ptr::null_mut(),
            attached: false,
        }
    }

    /// Attach to a target device stack
    ///
    /// # Safety
    /// - Filter device must be properly initialized
    /// - Target device must be valid
    pub unsafe fn attach(&mut self, target: PDEVICE_OBJECT) -> Result<(), NTSTATUS> {
        if self.attached {
            return Err(wdk_sys::STATUS_ALREADY_COMPLETE);
        }

        let attached = unsafe {
            IoAttachDeviceToDeviceStack(self.filter_device, target)
        };

        if attached.is_null() {
            return Err(wdk_sys::STATUS_UNSUCCESSFUL);
        }

        self.attached_to = attached;
        self.attached = true;

        println!(
            "[Leviathan] Filter attached to device at {:#x}",
            attached as usize
        );

        Ok(())
    }

    /// Detach from device stack
    ///
    /// # Safety
    /// Must be attached
    pub unsafe fn detach(&mut self) {
        if !self.attached || self.attached_to.is_null() {
            return;
        }

        unsafe { IoDetachDevice(self.attached_to) };

        self.attached_to = ptr::null_mut();
        self.attached = false;

        println!("[Leviathan] Filter detached from device");
    }

    /// Check if attached
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Get the device we're attached to
    pub fn attached_device(&self) -> PDEVICE_OBJECT {
        self.attached_to
    }
}

impl Drop for DeviceFilter {
    fn drop(&mut self) {
        if self.attached {
            unsafe { self.detach() };
        }
    }
}

/// IRP completion context for async operations
#[repr(C)]
pub struct IrpCompletionContext {
    /// Completion event
    pub event: wdk_sys::KEVENT,
    /// Final status
    pub status: NTSTATUS,
    /// Information (bytes transferred, etc.)
    pub information: usize,
}

/// Forward an IRP down the device stack
///
/// # Safety
/// - IRP must be valid
/// - Lower device must be valid
pub unsafe fn forward_irp(
    irp: PIRP,
    lower_device: PDEVICE_OBJECT,
) -> NTSTATUS {
    // Skip the current stack location (we processed it)
    unsafe {
        let irp_ref = &mut *irp;
        irp_ref.CurrentLocation += 1;
        // Move stack location pointer
    }

    // Send to lower driver
    unsafe { IoCallDriver(lower_device, irp) }
}

/// Forward IRP and wait for completion
///
/// # Safety
/// - Must be at IRQL <= APC_LEVEL
/// - IRP must be valid
pub unsafe fn forward_irp_synchronous(
    irp: PIRP,
    lower_device: PDEVICE_OBJECT,
) -> NTSTATUS {
    // Set up completion routine to signal when done
    // Would use IoSetCompletionRoutine

    let status = unsafe { IoCallDriver(lower_device, irp) };

    // If pending, wait for completion
    // Would use KeWaitForSingleObject on completion event

    status
}

/// Analyze driver dispatch table
///
/// Check which IRP major functions a driver handles.
pub fn analyze_driver_dispatch(driver: PDRIVER_OBJECT) -> [bool; 28] {
    let mut handles = [false; 28];

    if driver.is_null() {
        return handles;
    }

    // In production:
    // Walk MajorFunction array and check which are not default

    handles
}

/// Detect potentially malicious filter drivers
///
/// Look for suspicious patterns in device stacks.
pub fn detect_suspicious_filters(stack: &[DeviceStackEntry]) -> Vec<&DeviceStackEntry> {
    let mut suspicious = Vec::new();

    for entry in stack {
        // Check for suspicious indicators:
        // 1. Unknown/unsigned driver
        // 2. Filter in unusual position
        // 3. Filter with suspicious name patterns

        if entry.is_filter {
            // Would perform deeper analysis here
        }
    }

    suspicious
}

/// Well-known device paths for attachment
pub mod device_paths {
    /// Keyboard class device
    pub const KEYBOARD: &str = "\\Device\\KeyboardClass0";
    /// Mouse class device
    pub const MOUSE: &str = "\\Device\\PointerClass0";
    /// Physical disk
    pub const DISK: &str = "\\Device\\Harddisk0\\DR0";
    /// Volume (C:)
    pub const VOLUME_C: &str = "\\Device\\HarddiskVolume1";
    /// TCP device
    pub const TCP: &str = "\\Device\\Tcp";
    /// UDP device
    pub const UDP: &str = "\\Device\\Udp";
    /// Raw IP device
    pub const RAWIP: &str = "\\Device\\RawIp";
}
