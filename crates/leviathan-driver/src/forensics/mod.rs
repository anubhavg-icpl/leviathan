//! Forensics and Detection Modules
//!
//! Tools for memory forensics, artifact detection, and system analysis:
//! - Pool tag scanning for kernel object discovery
//! - EPROCESS/ETHREAD enumeration
//! - Hidden process/driver detection
//! - IRP stack analysis
//! - Memory scanning for signatures/patterns

pub mod pool_scanner;
pub mod process_enum;
pub mod irp_analysis;
pub mod memory_scanner;
