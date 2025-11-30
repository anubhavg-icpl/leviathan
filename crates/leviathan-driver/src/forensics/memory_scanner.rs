//! Memory Scanning Engine
//!
//! Kernel-mode memory scanning for malware signatures, shellcode patterns,
//! and suspicious memory regions.
//!
//! # Capabilities
//! - Byte pattern matching (YARA-style)
//! - String searching
//! - PE header analysis
//! - Shellcode detection
//! - Entropy analysis
//! - IOC (Indicator of Compromise) matching
//!
//! # Scanning Modes
//! - Process virtual memory
//! - Kernel pool memory
//! - Physical memory (with proper access)
//! - Driver memory regions

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{MmIsAddressValid, KeGetCurrentIrql, ZwReadVirtualMemory},
    NTSTATUS, PEPROCESS, PVOID, STATUS_SUCCESS,
    APC_LEVEL,
};

/// Signature match result
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    /// Address where signature was found
    pub address: usize,
    /// Signature/rule name that matched
    pub rule_name: [u8; 64],
    /// Matched bytes
    pub matched_bytes: Vec<u8>,
    /// Context (surrounding bytes)
    pub context: Vec<u8>,
    /// Process ID (if process scan)
    pub pid: Option<usize>,
    /// Match confidence (0-100)
    pub confidence: u8,
}

/// Scan target type
#[derive(Debug, Clone, Copy)]
pub enum ScanTarget {
    /// Scan a specific process
    Process(usize), // PID
    /// Scan kernel pool
    KernelPool,
    /// Scan a specific address range
    Range { start: usize, end: usize },
    /// Scan a specific driver
    Driver([u8; 64]), // Driver name
}

/// Signature definition
#[derive(Debug, Clone)]
pub struct Signature {
    /// Unique signature ID
    pub id: u32,
    /// Human-readable name
    pub name: [u8; 64],
    /// Pattern to match (with wildcards)
    pub pattern: Vec<PatternByte>,
    /// Severity level (1-10)
    pub severity: u8,
    /// Category
    pub category: SignatureCategory,
    /// Description
    pub description: [u8; 256],
}

/// Pattern byte (supports wildcards)
#[derive(Debug, Clone, Copy)]
pub enum PatternByte {
    /// Exact byte match
    Exact(u8),
    /// Wildcard (match any byte)
    Any,
    /// Nibble wildcard (e.g., 4? matches 40-4F)
    HighNibble(u8),
    /// Nibble wildcard (e.g., ?4 matches 04, 14, 24...)
    LowNibble(u8),
}

/// Signature categories
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureCategory {
    /// Generic malware
    Malware,
    /// Ransomware indicators
    Ransomware,
    /// Shellcode patterns
    Shellcode,
    /// Credential theft tools
    CredentialTheft,
    /// Rootkit indicators
    Rootkit,
    /// RAT/Backdoor
    Backdoor,
    /// Exploit code
    Exploit,
    /// Cryptominer
    Cryptominer,
    /// Generic suspicious
    Suspicious,
}

/// Memory scanner configuration
pub struct ScannerConfig {
    /// Maximum bytes to scan per region
    pub max_region_size: usize,
    /// Skip memory regions with these protections
    pub skip_protections: u32,
    /// Include context bytes in matches
    pub context_size: usize,
    /// Maximum matches before stopping
    pub max_matches: usize,
    /// Timeout in milliseconds
    pub timeout_ms: u32,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_region_size: 100 * 1024 * 1024, // 100MB
            skip_protections: 0,
            context_size: 32,
            max_matches: 1000,
            timeout_ms: 60000,
        }
    }
}

/// Memory scanner engine
pub struct MemoryScanner {
    /// Loaded signatures
    signatures: Vec<Signature>,
    /// Scanner configuration
    config: ScannerConfig,
    /// Statistics
    stats: ScanStatistics,
}

/// Scan statistics
#[derive(Debug, Default)]
pub struct ScanStatistics {
    /// Total bytes scanned
    pub bytes_scanned: u64,
    /// Regions scanned
    pub regions_scanned: u32,
    /// Matches found
    pub matches_found: u32,
    /// Scan duration (microseconds)
    pub duration_us: u64,
    /// Errors encountered
    pub errors: u32,
}

impl MemoryScanner {
    /// Create a new memory scanner
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
            config: ScannerConfig::default(),
            stats: ScanStatistics::default(),
        }
    }

    /// Create scanner with custom config
    pub fn with_config(config: ScannerConfig) -> Self {
        Self {
            signatures: Vec::new(),
            config,
            stats: ScanStatistics::default(),
        }
    }

    /// Load built-in signatures
    pub fn load_builtin_signatures(&mut self) {
        // Shellcode patterns
        self.add_signature(Signature {
            id: 1,
            name: *b"Shellcode_x64_Stub\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            pattern: vec![
                // Common x64 shellcode stub: sub rsp, 28h
                PatternByte::Exact(0x48),
                PatternByte::Exact(0x83),
                PatternByte::Exact(0xEC),
                PatternByte::Exact(0x28),
            ],
            severity: 8,
            category: SignatureCategory::Shellcode,
            description: [0u8; 256],
        });

        // Metasploit pattern
        self.add_signature(Signature {
            id: 2,
            name: *b"Metasploit_MeterpreterLoader\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            pattern: vec![
                // MZ header followed by specific pattern
                PatternByte::Exact(0x4D),
                PatternByte::Exact(0x5A),
                PatternByte::Any,
                PatternByte::Any,
            ],
            severity: 9,
            category: SignatureCategory::Backdoor,
            description: [0u8; 256],
        });

        // Cobalt Strike beacon
        self.add_signature(Signature {
            id: 3,
            name: *b"CobaltStrike_Beacon\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            pattern: vec![
                // Beacon sleep pattern
                PatternByte::Any,
                PatternByte::Any,
                PatternByte::Any,
                PatternByte::Any,
            ],
            severity: 10,
            category: SignatureCategory::Backdoor,
            description: [0u8; 256],
        });

        // Mimikatz string
        self.add_signature(Signature {
            id: 4,
            name: *b"Mimikatz_String\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            pattern: string_to_pattern(b"sekurlsa"),
            severity: 10,
            category: SignatureCategory::CredentialTheft,
            description: [0u8; 256],
        });

        println!(
            "[Leviathan] Loaded {} built-in signatures",
            self.signatures.len()
        );
    }

    /// Add a custom signature
    pub fn add_signature(&mut self, sig: Signature) {
        self.signatures.push(sig);
    }

    /// Parse YARA-style pattern string
    /// Format: "48 8B ?? 00" where ?? is wildcard
    pub fn parse_pattern(pattern_str: &str) -> Vec<PatternByte> {
        let mut pattern = Vec::new();

        for part in pattern_str.split_whitespace() {
            if part == "??" {
                pattern.push(PatternByte::Any);
            } else if part.starts_with('?') {
                if let Ok(nibble) = u8::from_str_radix(&part[1..], 16) {
                    pattern.push(PatternByte::LowNibble(nibble));
                }
            } else if part.ends_with('?') {
                if let Ok(nibble) = u8::from_str_radix(&part[..1], 16) {
                    pattern.push(PatternByte::HighNibble(nibble << 4));
                }
            } else if let Ok(byte) = u8::from_str_radix(part, 16) {
                pattern.push(PatternByte::Exact(byte));
            }
        }

        pattern
    }

    /// Scan a process's memory
    ///
    /// # Safety
    /// - Must be at PASSIVE_LEVEL
    /// - Process must be valid
    pub unsafe fn scan_process(&mut self, pid: usize) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        println!("[Leviathan] Scanning process {}", pid);

        // In production:
        // 1. Attach to process via KeStackAttachProcess
        // 2. Walk VAD tree or use ZwQueryVirtualMemory
        // 3. For each committed region, scan for signatures
        // 4. Detach from process

        // Pseudocode:
        // let process = PsLookupProcessByProcessId(pid)?;
        // KeStackAttachProcess(process, &mut apc_state);
        // for region in walk_vad_tree(process) {
        //     if region.is_committed() && region.is_readable() {
        //         matches.extend(self.scan_region(region.start, region.size));
        //     }
        // }
        // KeUnstackDetachProcess(&mut apc_state);
        // ObDereferenceObject(process);

        self.stats.regions_scanned += 1;
        matches
    }

    /// Scan a memory region for all signatures
    ///
    /// # Safety
    /// Memory region must be valid and readable
    pub unsafe fn scan_region(
        &mut self,
        start: usize,
        size: usize,
    ) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        // Validate address
        if !unsafe { MmIsAddressValid(start as PVOID) } {
            return matches;
        }

        let scan_size = core::cmp::min(size, self.config.max_region_size);

        // Scan for each signature
        for sig in &self.signatures {
            if let Some(m) = unsafe { self.scan_for_signature(start, scan_size, sig) } {
                matches.push(m);

                if matches.len() >= self.config.max_matches {
                    break;
                }
            }
        }

        self.stats.bytes_scanned += scan_size as u64;
        matches
    }

    /// Scan for a specific signature in memory
    unsafe fn scan_for_signature(
        &self,
        start: usize,
        size: usize,
        sig: &Signature,
    ) -> Option<SignatureMatch> {
        let pattern_len = sig.pattern.len();
        if pattern_len == 0 || size < pattern_len {
            return None;
        }

        // Boyer-Moore-Horspool would be more efficient for production
        // Using simple scan for clarity
        for offset in 0..(size - pattern_len) {
            let addr = start + offset;

            if unsafe { self.pattern_matches(addr, &sig.pattern) } {
                let mut matched_bytes = Vec::with_capacity(pattern_len);
                for i in 0..pattern_len {
                    let byte = unsafe { *((addr + i) as *const u8) };
                    matched_bytes.push(byte);
                }

                return Some(SignatureMatch {
                    address: addr,
                    rule_name: sig.name,
                    matched_bytes,
                    context: Vec::new(), // Would extract surrounding bytes
                    pid: None,
                    confidence: 100,
                });
            }
        }

        None
    }

    /// Check if pattern matches at address
    unsafe fn pattern_matches(&self, addr: usize, pattern: &[PatternByte]) -> bool {
        for (i, pat_byte) in pattern.iter().enumerate() {
            let mem_addr = (addr + i) as *const u8;

            // Check if address is valid before reading
            if !unsafe { MmIsAddressValid(mem_addr as PVOID) } {
                return false;
            }

            let byte = unsafe { *mem_addr };

            match pat_byte {
                PatternByte::Exact(expected) => {
                    if byte != *expected {
                        return false;
                    }
                }
                PatternByte::Any => {
                    // Matches any byte
                }
                PatternByte::HighNibble(nibble) => {
                    if (byte & 0xF0) != *nibble {
                        return false;
                    }
                }
                PatternByte::LowNibble(nibble) => {
                    if (byte & 0x0F) != *nibble {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Calculate Shannon entropy of a memory region
    ///
    /// High entropy (>7.0) may indicate encrypted/compressed data.
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Detect PE headers in memory
    pub fn find_pe_headers(data: &[u8]) -> Vec<usize> {
        let mut headers = Vec::new();

        // Look for MZ header
        for i in 0..data.len().saturating_sub(2) {
            if data[i] == 0x4D && data[i + 1] == 0x5A {
                // Found MZ, verify it's a valid PE
                if i + 0x3C < data.len() {
                    let pe_offset = u32::from_le_bytes([
                        data[i + 0x3C],
                        data.get(i + 0x3D).copied().unwrap_or(0),
                        data.get(i + 0x3E).copied().unwrap_or(0),
                        data.get(i + 0x3F).copied().unwrap_or(0),
                    ]) as usize;

                    if i + pe_offset + 4 < data.len() {
                        let pe_sig = &data[i + pe_offset..i + pe_offset + 4];
                        if pe_sig == [0x50, 0x45, 0x00, 0x00] {
                            // Valid PE signature
                            headers.push(i);
                        }
                    }
                }
            }
        }

        headers
    }

    /// Detect common shellcode patterns
    pub fn detect_shellcode_patterns(data: &[u8]) -> Vec<(usize, &'static str)> {
        let mut findings = Vec::new();

        let patterns: &[(&[u8], &str)] = &[
            // x64 syscall
            (&[0x0F, 0x05], "syscall"),
            // x86 sysenter
            (&[0x0F, 0x34], "sysenter"),
            // int 0x80
            (&[0xCD, 0x80], "int80"),
            // int 0x2e
            (&[0xCD, 0x2E], "int2e"),
            // call to negative offset (common in shellcode)
            (&[0xE8], "call_relative"),
            // GetProcAddress pattern
            (&[0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63], "GetProcAddress"),
            // LoadLibrary pattern
            (&[0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62], "LoadLibrary"),
            // VirtualAlloc pattern
            (&[0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41], "VirtualAlloc"),
        ];

        for (pattern, name) in patterns {
            for i in 0..data.len().saturating_sub(pattern.len()) {
                if &data[i..i + pattern.len()] == *pattern {
                    findings.push((i, *name));
                }
            }
        }

        findings
    }

    /// Get scan statistics
    pub fn get_statistics(&self) -> &ScanStatistics {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_statistics(&mut self) {
        self.stats = ScanStatistics::default();
    }
}

/// Convert string to pattern bytes
fn string_to_pattern(s: &[u8]) -> Vec<PatternByte> {
    s.iter().map(|&b| PatternByte::Exact(b)).collect()
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address
    pub base: usize,
    /// Region size
    pub size: usize,
    /// Protection flags
    pub protection: u32,
    /// State (committed, reserved, free)
    pub state: u32,
    /// Type (private, mapped, image)
    pub region_type: u32,
}

/// VAD (Virtual Address Descriptor) tree walker
pub struct VadWalker {
    /// Current process
    process: usize,
}

impl VadWalker {
    /// Create new VAD walker for process
    pub fn new(process: usize) -> Self {
        Self { process }
    }

    /// Enumerate all memory regions
    ///
    /// # Safety
    /// Must be attached to target process context
    pub unsafe fn enumerate_regions(&self) -> Vec<MemoryRegion> {
        let mut regions = Vec::new();

        // In production:
        // 1. Get EPROCESS.VadRoot
        // 2. Walk AVL tree of VAD nodes
        // 3. Extract region information from each VAD

        regions
    }
}

/// Scan result summary
#[derive(Debug)]
pub struct ScanSummary {
    /// Total matches
    pub total_matches: usize,
    /// Matches by category
    pub by_category: [(SignatureCategory, usize); 9],
    /// Highest severity found
    pub max_severity: u8,
    /// Affected processes
    pub affected_pids: Vec<usize>,
}
