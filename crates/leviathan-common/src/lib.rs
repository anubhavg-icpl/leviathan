//! Common types and definitions shared between driver and user-mode applications
//!
//! This crate provides shared IOCTL definitions, structures, and constants
//! that are used by both the kernel-mode driver and user-mode applications.

#![no_std]

/// Device interface GUID for finding the Leviathan device
/// {12345678-1234-1234-1234-123456789ABC}
pub const DEVICE_INTERFACE_GUID: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, // Data1 (little-endian)
    0x34, 0x12,             // Data2
    0x34, 0x12,             // Data3
    0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // Data4
];

/// Custom device type for IOCTL codes
pub const FILE_DEVICE_LEVIATHAN: u32 = 0x8000;

/// IOCTL code definitions
pub mod ioctl {
    use super::FILE_DEVICE_LEVIATHAN;

    /// Helper macro to create IOCTL codes
    const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    // Method types
    pub const METHOD_BUFFERED: u32 = 0;
    pub const METHOD_IN_DIRECT: u32 = 1;
    pub const METHOD_OUT_DIRECT: u32 = 2;
    pub const METHOD_NEITHER: u32 = 3;

    // Access types
    pub const FILE_ANY_ACCESS: u32 = 0;
    pub const FILE_READ_ACCESS: u32 = 1;
    pub const FILE_WRITE_ACCESS: u32 = 2;

    /// Get driver version string
    pub const IOCTL_GET_VERSION: u32 =
        ctl_code(FILE_DEVICE_LEVIATHAN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Echo data back (input -> output)
    pub const IOCTL_ECHO: u32 =
        ctl_code(FILE_DEVICE_LEVIATHAN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

    /// Get driver statistics
    pub const IOCTL_GET_STATS: u32 =
        ctl_code(FILE_DEVICE_LEVIATHAN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);
}

/// Driver statistics structure - shared between kernel and user mode
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverStats {
    pub read_count: u64,
    pub write_count: u64,
    pub ioctl_count: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Version information structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VersionInfo {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl VersionInfo {
    pub const fn new(major: u16, minor: u16, patch: u16, build: u16) -> Self {
        Self { major, minor, patch, build }
    }
}
