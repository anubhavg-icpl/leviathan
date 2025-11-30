//! Event Tracing for Windows (ETW) Support
//!
//! Provides kernel-mode ETW event logging for diagnostics and monitoring.
//!
//! # ETW Architecture
//! - **Provider**: Component that generates events (our driver)
//! - **Session**: Collects events from one or more providers
//! - **Consumer**: Reads and processes events (ETW tools, Event Viewer)
//!
//! # Benefits
//! - High-performance event logging
//! - Structured event data
//! - Integration with Windows diagnostic tools
//! - Real-time and file-based collection
//!
//! # Use Cases
//! - Driver diagnostics and debugging
//! - Security event auditing
//! - Performance monitoring
//! - Forensic logging

use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use wdk::println;
use wdk_sys::{
    ntddk::{EtwRegister, EtwUnregister, EtwWrite, EtwWriteString},
    GUID, NTSTATUS, REGHANDLE, STATUS_SUCCESS,
    EVENT_DESCRIPTOR, EVENT_DATA_DESCRIPTOR,
};

/// Provider registration handle
static mut PROVIDER_HANDLE: REGHANDLE = 0;

/// Flag indicating if ETW is registered
static ETW_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Event counter for diagnostics
static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Leviathan ETW Provider GUID
/// {DEADBEEF-CAFE-BABE-DEAD-BEEFCAFEBABE}
pub const PROVIDER_GUID: GUID = GUID {
    Data1: 0xDEADBEEF,
    Data2: 0xCAFE,
    Data3: 0xBABE,
    Data4: [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
};

/// ETW Event Levels (verbosity)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    /// Critical errors
    Critical = 1,
    /// Error conditions
    Error = 2,
    /// Warning conditions
    Warning = 3,
    /// Informational messages
    Info = 4,
    /// Detailed diagnostic messages
    Verbose = 5,
}

/// ETW Event Keywords (categories)
///
/// Use as bit flags to categorize events.
pub mod keywords {
    /// Process-related events
    pub const PROCESS: u64 = 0x0001;
    /// Thread-related events
    pub const THREAD: u64 = 0x0002;
    /// Image/module load events
    pub const IMAGE: u64 = 0x0004;
    /// Registry events
    pub const REGISTRY: u64 = 0x0008;
    /// File system events
    pub const FILESYSTEM: u64 = 0x0010;
    /// Network events
    pub const NETWORK: u64 = 0x0020;
    /// Security events
    pub const SECURITY: u64 = 0x0040;
    /// Performance events
    pub const PERFORMANCE: u64 = 0x0080;
    /// Debug/diagnostic events
    pub const DEBUG: u64 = 0x8000_0000_0000_0000;
    /// All events
    pub const ALL: u64 = 0xFFFF_FFFF_FFFF_FFFF;
}

/// ETW Event IDs for different event types
pub mod event_ids {
    /// Driver loaded
    pub const DRIVER_LOAD: u16 = 1;
    /// Driver unloading
    pub const DRIVER_UNLOAD: u16 = 2;
    /// Process created
    pub const PROCESS_CREATE: u16 = 100;
    /// Process terminated
    pub const PROCESS_TERMINATE: u16 = 101;
    /// Thread created
    pub const THREAD_CREATE: u16 = 200;
    /// Thread terminated
    pub const THREAD_TERMINATE: u16 = 201;
    /// Remote thread detected
    pub const REMOTE_THREAD: u16 = 202;
    /// Image loaded
    pub const IMAGE_LOAD: u16 = 300;
    /// Suspicious image detected
    pub const SUSPICIOUS_IMAGE: u16 = 301;
    /// Registry operation
    pub const REGISTRY_OPERATION: u16 = 400;
    /// Protected registry access
    pub const REGISTRY_PROTECTED: u16 = 401;
    /// File operation
    pub const FILE_OPERATION: u16 = 500;
    /// Ransomware behavior detected
    pub const RANSOMWARE_DETECTED: u16 = 501;
    /// Network connection
    pub const NETWORK_CONNECTION: u16 = 600;
    /// Connection blocked
    pub const NETWORK_BLOCKED: u16 = 601;
    /// Object handle operation
    pub const OBJECT_HANDLE: u16 = 700;
    /// Protected process access
    pub const PROTECTED_PROCESS: u16 = 701;
    /// Generic security event
    pub const SECURITY_EVENT: u16 = 900;
    /// Generic error
    pub const ERROR: u16 = 999;
}

/// Register the ETW provider
///
/// # Safety
/// Must be called from DriverEntry at PASSIVE_LEVEL
pub unsafe fn register() -> Result<(), NTSTATUS> {
    if ETW_REGISTERED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut handle: REGHANDLE = 0;

    let status = unsafe {
        EtwRegister(
            &PROVIDER_GUID,
            None, // No enable callback
            ptr::null_mut(),
            &mut handle,
        )
    };

    if status != STATUS_SUCCESS {
        println!("[Leviathan] Failed to register ETW provider: {:#x}", status);
        return Err(status);
    }

    unsafe { PROVIDER_HANDLE = handle };
    ETW_REGISTERED.store(true, Ordering::SeqCst);
    println!("[Leviathan] ETW provider registered");

    // Log driver load event
    unsafe { log_driver_event(event_ids::DRIVER_LOAD, "Driver loaded") };

    Ok(())
}

/// Unregister the ETW provider
///
/// # Safety
/// Must be called from driver unload at PASSIVE_LEVEL
pub unsafe fn unregister() {
    if !ETW_REGISTERED.load(Ordering::SeqCst) {
        return;
    }

    // Log driver unload event
    unsafe { log_driver_event(event_ids::DRIVER_UNLOAD, "Driver unloading") };

    let handle = unsafe { PROVIDER_HANDLE };
    if handle != 0 {
        let _ = unsafe { EtwUnregister(handle) };
        unsafe { PROVIDER_HANDLE = 0 };
    }

    ETW_REGISTERED.store(false, Ordering::SeqCst);
    println!("[Leviathan] ETW provider unregistered");
}

/// Check if ETW is registered and enabled
pub fn is_enabled() -> bool {
    ETW_REGISTERED.load(Ordering::SeqCst)
}

/// Get total events logged
pub fn event_count() -> u64 {
    EVENT_COUNT.load(Ordering::SeqCst)
}

/// Log a generic driver event
///
/// # Safety
/// ETW must be registered
pub unsafe fn log_driver_event(event_id: u16, message: &str) {
    if !is_enabled() {
        return;
    }

    let descriptor = EVENT_DESCRIPTOR {
        Id: event_id,
        Version: 0,
        Channel: 0,
        Level: EventLevel::Info as u8,
        Opcode: 0,
        Task: 0,
        Keyword: keywords::DEBUG,
    };

    // Convert message to data descriptor
    let msg_bytes = message.as_bytes();
    let data_desc = EVENT_DATA_DESCRIPTOR {
        Ptr: msg_bytes.as_ptr() as u64,
        Size: msg_bytes.len() as u32,
        Reserved: 0,
    };

    let handle = unsafe { PROVIDER_HANDLE };
    let _ = unsafe {
        EtwWrite(handle, &descriptor, 0, 1, &data_desc)
    };

    EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Log a process event
///
/// # Safety
/// ETW must be registered
pub unsafe fn log_process_event(
    event_id: u16,
    process_id: usize,
    parent_id: usize,
    image_name: Option<&str>,
) {
    if !is_enabled() {
        return;
    }

    let descriptor = EVENT_DESCRIPTOR {
        Id: event_id,
        Version: 0,
        Channel: 0,
        Level: EventLevel::Info as u8,
        Opcode: 0,
        Task: 0,
        Keyword: keywords::PROCESS,
    };

    // Build data descriptors for each field
    let pid_bytes = process_id.to_le_bytes();
    let ppid_bytes = parent_id.to_le_bytes();

    let mut data_descs: [EVENT_DATA_DESCRIPTOR; 3] = unsafe { core::mem::zeroed() };

    data_descs[0] = EVENT_DATA_DESCRIPTOR {
        Ptr: pid_bytes.as_ptr() as u64,
        Size: pid_bytes.len() as u32,
        Reserved: 0,
    };

    data_descs[1] = EVENT_DATA_DESCRIPTOR {
        Ptr: ppid_bytes.as_ptr() as u64,
        Size: ppid_bytes.len() as u32,
        Reserved: 0,
    };

    let img_name = image_name.unwrap_or("");
    let img_bytes = img_name.as_bytes();
    data_descs[2] = EVENT_DATA_DESCRIPTOR {
        Ptr: img_bytes.as_ptr() as u64,
        Size: img_bytes.len() as u32,
        Reserved: 0,
    };

    let handle = unsafe { PROVIDER_HANDLE };
    let _ = unsafe {
        EtwWrite(handle, &descriptor, 0, 3, data_descs.as_ptr())
    };

    EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Log a security event
///
/// # Safety
/// ETW must be registered
pub unsafe fn log_security_event(
    event_id: u16,
    level: EventLevel,
    source_pid: usize,
    target_pid: usize,
    action: &str,
    blocked: bool,
) {
    if !is_enabled() {
        return;
    }

    let descriptor = EVENT_DESCRIPTOR {
        Id: event_id,
        Version: 0,
        Channel: 0,
        Level: level as u8,
        Opcode: 0,
        Task: 0,
        Keyword: keywords::SECURITY,
    };

    // Build event data
    let source_bytes = source_pid.to_le_bytes();
    let target_bytes = target_pid.to_le_bytes();
    let action_bytes = action.as_bytes();
    let blocked_byte: [u8; 1] = [blocked as u8];

    let mut data_descs: [EVENT_DATA_DESCRIPTOR; 4] = unsafe { core::mem::zeroed() };

    data_descs[0] = EVENT_DATA_DESCRIPTOR {
        Ptr: source_bytes.as_ptr() as u64,
        Size: source_bytes.len() as u32,
        Reserved: 0,
    };

    data_descs[1] = EVENT_DATA_DESCRIPTOR {
        Ptr: target_bytes.as_ptr() as u64,
        Size: target_bytes.len() as u32,
        Reserved: 0,
    };

    data_descs[2] = EVENT_DATA_DESCRIPTOR {
        Ptr: action_bytes.as_ptr() as u64,
        Size: action_bytes.len() as u32,
        Reserved: 0,
    };

    data_descs[3] = EVENT_DATA_DESCRIPTOR {
        Ptr: blocked_byte.as_ptr() as u64,
        Size: 1,
        Reserved: 0,
    };

    let handle = unsafe { PROVIDER_HANDLE };
    let _ = unsafe {
        EtwWrite(handle, &descriptor, 0, 4, data_descs.as_ptr())
    };

    EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Log a network event
///
/// # Safety
/// ETW must be registered
pub unsafe fn log_network_event(
    event_id: u16,
    process_id: usize,
    local_addr: &[u8; 4],
    local_port: u16,
    remote_addr: &[u8; 4],
    remote_port: u16,
    protocol: u8,
    blocked: bool,
) {
    if !is_enabled() {
        return;
    }

    let descriptor = EVENT_DESCRIPTOR {
        Id: event_id,
        Version: 0,
        Channel: 0,
        Level: if blocked { EventLevel::Warning as u8 } else { EventLevel::Info as u8 },
        Opcode: 0,
        Task: 0,
        Keyword: keywords::NETWORK,
    };

    // Pack network data
    let pid_bytes = process_id.to_le_bytes();
    let local_port_bytes = local_port.to_le_bytes();
    let remote_port_bytes = remote_port.to_le_bytes();
    let flags: [u8; 2] = [protocol, blocked as u8];

    let mut data_descs: [EVENT_DATA_DESCRIPTOR; 6] = unsafe { core::mem::zeroed() };

    data_descs[0] = EVENT_DATA_DESCRIPTOR {
        Ptr: pid_bytes.as_ptr() as u64,
        Size: pid_bytes.len() as u32,
        Reserved: 0,
    };

    data_descs[1] = EVENT_DATA_DESCRIPTOR {
        Ptr: local_addr.as_ptr() as u64,
        Size: 4,
        Reserved: 0,
    };

    data_descs[2] = EVENT_DATA_DESCRIPTOR {
        Ptr: local_port_bytes.as_ptr() as u64,
        Size: 2,
        Reserved: 0,
    };

    data_descs[3] = EVENT_DATA_DESCRIPTOR {
        Ptr: remote_addr.as_ptr() as u64,
        Size: 4,
        Reserved: 0,
    };

    data_descs[4] = EVENT_DATA_DESCRIPTOR {
        Ptr: remote_port_bytes.as_ptr() as u64,
        Size: 2,
        Reserved: 0,
    };

    data_descs[5] = EVENT_DATA_DESCRIPTOR {
        Ptr: flags.as_ptr() as u64,
        Size: 2,
        Reserved: 0,
    };

    let handle = unsafe { PROVIDER_HANDLE };
    let _ = unsafe {
        EtwWrite(handle, &descriptor, 0, 6, data_descs.as_ptr())
    };

    EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Manifest template for the ETW provider
///
/// This would be compiled into the driver as a resource.
/// Consumers can use this manifest to decode events.
#[allow(dead_code)]
const ETW_MANIFEST: &str = r#"
<?xml version="1.0" encoding="UTF-8"?>
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <instrumentation>
    <events>
      <provider name="Leviathan-Driver"
                guid="{DEADBEEF-CAFE-BABE-DEAD-BEEFCAFEBABE}"
                symbol="LEVIATHAN_PROVIDER"
                resourceFileName="leviathan.sys"
                messageFileName="leviathan.sys">
        <channels>
          <channel name="Leviathan-Driver/Operational"
                   chid="OPERATIONAL"
                   type="Operational"
                   enabled="true"/>
        </channels>
        <keywords>
          <keyword name="Process" mask="0x0001"/>
          <keyword name="Thread" mask="0x0002"/>
          <keyword name="Image" mask="0x0004"/>
          <keyword name="Registry" mask="0x0008"/>
          <keyword name="FileSystem" mask="0x0010"/>
          <keyword name="Network" mask="0x0020"/>
          <keyword name="Security" mask="0x0040"/>
        </keywords>
        <tasks>
          <task name="ProcessEvent" value="1"/>
          <task name="ThreadEvent" value="2"/>
          <task name="ImageEvent" value="3"/>
          <task name="SecurityEvent" value="9"/>
        </tasks>
        <events>
          <event value="100" symbol="ProcessCreate"
                 task="ProcessEvent" level="win:Informational"
                 keywords="Process" message="$(string.ProcessCreate)"/>
          <event value="101" symbol="ProcessTerminate"
                 task="ProcessEvent" level="win:Informational"
                 keywords="Process" message="$(string.ProcessTerminate)"/>
        </events>
      </provider>
    </events>
  </instrumentation>
</instrumentationManifest>
"#;
