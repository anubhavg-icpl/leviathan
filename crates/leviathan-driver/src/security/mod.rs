//! Security Modules
//!
//! Advanced security capabilities for kernel-mode protection:
//! - ELAM (Early Launch Anti-Malware) driver support
//! - Anti-tampering and integrity verification
//! - APC injection for kernel-to-user communication
//! - Process/driver protection mechanisms
//! - Hook detection (SSDT, IDT, inline)

pub mod elam;
pub mod integrity;
pub mod apc;
pub mod hooks;
