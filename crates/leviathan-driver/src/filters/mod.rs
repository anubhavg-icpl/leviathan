//! Kernel Filter Modules
//!
//! This module provides Windows kernel filter implementations:
//! - Filesystem minifilter (file I/O interception)
//! - Network filter (WFP - Windows Filtering Platform)
//!
//! These filters allow deep inspection and control of system I/O.

pub mod minifilter;
pub mod network;
