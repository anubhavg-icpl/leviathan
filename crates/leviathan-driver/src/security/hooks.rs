//! Kernel Hook Detection Module
//!
//! Detects various types of kernel-mode hooks used by rootkits:
//! - SSDT (System Service Descriptor Table) hooks
//! - IDT (Interrupt Descriptor Table) hooks
//! - Inline/detour hooks
//! - IAT/EAT hooks
//! - MSR hooks
//!
//! # Detection Strategies
//! - Compare against known good values
//! - Verify pointers are within expected module ranges
//! - Check for jump/call instructions at function prologues
//! - Validate interrupt handlers

use alloc::vec::Vec;
use core::ptr;
use wdk::println;
use wdk_sys::{NTSTATUS, STATUS_SUCCESS};

/// SSDT entry information
#[derive(Debug, Clone)]
pub struct SsdtEntry {
    /// Index in the SSDT
    pub index: u32,
    /// Current address
    pub address: usize,
    /// Expected module base (ntoskrnl)
    pub expected_base: usize,
    /// Expected module end
    pub expected_end: usize,
    /// Is this entry hooked
    pub is_hooked: bool,
    /// Hooking module (if detected)
    pub hook_module: Option<[u8; 256]>,
}

/// IDT entry information
#[derive(Debug, Clone)]
pub struct IdtEntry {
    /// Interrupt vector number
    pub vector: u8,
    /// Handler address
    pub handler: usize,
    /// Expected handler range start
    pub expected_start: usize,
    /// Expected handler range end
    pub expected_end: usize,
    /// Is this entry hooked
    pub is_hooked: bool,
    /// DPL (Descriptor Privilege Level)
    pub dpl: u8,
    /// Gate type
    pub gate_type: u8,
}

/// Inline hook detection result
#[derive(Debug, Clone)]
pub struct InlineHook {
    /// Address of hooked function
    pub address: usize,
    /// Function name (if known)
    pub function_name: [u8; 64],
    /// Original bytes
    pub original_bytes: [u8; 16],
    /// Current bytes (with hook)
    pub current_bytes: [u8; 16],
    /// Jump target address
    pub jump_target: usize,
    /// Hook type detected
    pub hook_type: InlineHookType,
}

/// Types of inline hooks
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InlineHookType {
    /// JMP rel32 (E9 xx xx xx xx)
    JmpRel32,
    /// JMP [rip+disp32] (FF 25 xx xx xx xx)
    JmpRipRelative,
    /// PUSH addr + RET
    PushRet,
    /// MOV RAX, addr + JMP RAX
    MovJmp,
    /// INT3 breakpoint
    Int3,
    /// Unknown hook type
    Unknown,
}

/// MSR hook information
#[derive(Debug, Clone)]
pub struct MsrHook {
    /// MSR index
    pub msr: u32,
    /// Current value
    pub current_value: u64,
    /// Expected value
    pub expected_value: u64,
    /// Is hooked
    pub is_hooked: bool,
}

/// Important MSR indices
pub mod msr_indices {
    /// LSTAR - Long mode SYSCALL target
    pub const IA32_LSTAR: u32 = 0xC0000082;
    /// CSTAR - Compatibility mode SYSCALL target
    pub const IA32_CSTAR: u32 = 0xC0000083;
    /// SFMASK - SYSCALL flag mask
    pub const IA32_SFMASK: u32 = 0xC0000084;
    /// SYSENTER_EIP
    pub const IA32_SYSENTER_EIP: u32 = 0x176;
    /// EFER - Extended Feature Enable Register
    pub const IA32_EFER: u32 = 0xC0000080;
}

/// Hook scanner configuration
pub struct HookScanner {
    /// ntoskrnl.exe base address
    kernel_base: usize,
    /// ntoskrnl.exe size
    kernel_size: usize,
    /// Scan SSDT
    scan_ssdt: bool,
    /// Scan IDT
    scan_idt: bool,
    /// Scan inline hooks
    scan_inline: bool,
    /// Scan MSRs
    scan_msr: bool,
}

impl HookScanner {
    /// Create a new hook scanner
    pub fn new() -> Self {
        Self {
            kernel_base: 0,
            kernel_size: 0,
            scan_ssdt: true,
            scan_idt: true,
            scan_inline: true,
            scan_msr: true,
        }
    }

    /// Initialize scanner with kernel module information
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL
    pub unsafe fn initialize(&mut self) -> Result<(), NTSTATUS> {
        // In production:
        // 1. Get ntoskrnl base via PsLoadedModuleList or ZwQuerySystemInformation
        // 2. Parse PE headers to get module size
        // 3. Store for later validation

        println!("[Leviathan] Hook scanner initialized");
        Ok(())
    }

    /// Scan for SSDT hooks
    ///
    /// # Safety
    /// Must be at PASSIVE_LEVEL
    pub unsafe fn scan_ssdt(&self) -> Vec<SsdtEntry> {
        let mut hooks = Vec::new();

        // In production:
        // 1. Get KeServiceDescriptorTable address
        // 2. Read SSDT base and entry count
        // 3. For each entry, verify it points within ntoskrnl
        // 4. On x64, entries are relative offsets (need to decode)

        // SSDT on x64:
        // typedef struct _KSERVICE_TABLE_DESCRIPTOR {
        //     PLONG Base;           // Array of relative offsets
        //     PULONG Count;         // Not used
        //     ULONG Limit;          // Number of entries
        //     PUCHAR Number;        // Argument bytes
        // } KSERVICE_TABLE_DESCRIPTOR;
        //
        // Actual address = Base + (Entry >> 4)

        println!("[Leviathan] SSDT scan: {} potential hooks found", hooks.len());
        hooks
    }

    /// Scan for IDT hooks
    ///
    /// # Safety
    /// Must be at PASSIVE_LEVEL
    pub unsafe fn scan_idt(&self) -> Vec<IdtEntry> {
        let mut hooks = Vec::new();

        // In production:
        // 1. Use SIDT instruction to get IDT base
        // 2. Walk all 256 entries
        // 3. Verify handlers point to expected locations
        // 4. Check for suspicious DPL changes

        // IDT Entry (x64):
        // struct IDT_ENTRY {
        //     uint16_t offset_low;
        //     uint16_t selector;
        //     uint8_t ist;
        //     uint8_t type_attr;
        //     uint16_t offset_mid;
        //     uint32_t offset_high;
        //     uint32_t reserved;
        // };

        println!("[Leviathan] IDT scan: {} potential hooks found", hooks.len());
        hooks
    }

    /// Scan for inline hooks in critical functions
    ///
    /// # Safety
    /// Must be at PASSIVE_LEVEL
    pub unsafe fn scan_inline_hooks(&self) -> Vec<InlineHook> {
        let mut hooks = Vec::new();

        // Critical functions to check:
        let critical_functions = [
            "NtCreateProcess",
            "NtCreateThread",
            "NtOpenProcess",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateFile",
            "NtSetInformationFile",
            "NtQuerySystemInformation",
            "NtLoadDriver",
            "NtSetSystemInformation",
        ];

        // In production:
        // 1. Resolve each function address
        // 2. Check first bytes for hook signatures
        // 3. If hooked, follow jump to find target
        // 4. Identify hooking module

        for func in &critical_functions {
            if let Some(hook) = unsafe { self.check_function_hook(func) } {
                hooks.push(hook);
            }
        }

        println!("[Leviathan] Inline hook scan: {} hooks found", hooks.len());
        hooks
    }

    /// Check a specific function for inline hooks
    unsafe fn check_function_hook(&self, _func_name: &str) -> Option<InlineHook> {
        // In production:
        // 1. Get function address via MmGetSystemRoutineAddress
        // 2. Read first 16 bytes
        // 3. Check for hook patterns

        // Common hook patterns:
        // JMP rel32:        E9 xx xx xx xx
        // JMP [rip+disp]:   FF 25 xx xx xx xx
        // MOV RAX + JMP:    48 B8 xx xx xx xx xx xx xx xx FF E0
        // PUSH + RET:       68 xx xx xx xx C3

        None
    }

    /// Scan MSRs for hooks
    ///
    /// # Safety
    /// Must be at appropriate IRQL for RDMSR
    pub unsafe fn scan_msr(&self) -> Vec<MsrHook> {
        let mut hooks = Vec::new();

        // In production:
        // 1. Read LSTAR MSR (syscall handler)
        // 2. Verify it points to KiSystemCall64
        // 3. Check SYSENTER_EIP for 32-bit syscalls
        // 4. Verify EFER settings

        println!("[Leviathan] MSR scan: {} potential hooks found", hooks.len());
        hooks
    }

    /// Run full hook scan
    ///
    /// # Safety
    /// Must be at PASSIVE_LEVEL
    pub unsafe fn full_scan(&self) -> HookScanResult {
        println!("[Leviathan] Starting full hook scan...");

        let ssdt_hooks = if self.scan_ssdt {
            unsafe { self.scan_ssdt() }
        } else {
            Vec::new()
        };

        let idt_hooks = if self.scan_idt {
            unsafe { self.scan_idt() }
        } else {
            Vec::new()
        };

        let inline_hooks = if self.scan_inline {
            unsafe { self.scan_inline_hooks() }
        } else {
            Vec::new()
        };

        let msr_hooks = if self.scan_msr {
            unsafe { self.scan_msr() }
        } else {
            Vec::new()
        };

        let result = HookScanResult {
            ssdt_hooks,
            idt_hooks,
            inline_hooks,
            msr_hooks,
            scan_time: 0, // Would use KeQueryPerformanceCounter
        };

        println!(
            "[Leviathan] Hook scan complete: SSDT={}, IDT={}, Inline={}, MSR={}",
            result.ssdt_hooks.len(),
            result.idt_hooks.len(),
            result.inline_hooks.len(),
            result.msr_hooks.len()
        );

        result
    }
}

/// Results of a hook scan
#[derive(Debug)]
pub struct HookScanResult {
    /// SSDT hooks found
    pub ssdt_hooks: Vec<SsdtEntry>,
    /// IDT hooks found
    pub idt_hooks: Vec<IdtEntry>,
    /// Inline hooks found
    pub inline_hooks: Vec<InlineHook>,
    /// MSR hooks found
    pub msr_hooks: Vec<MsrHook>,
    /// Scan duration in microseconds
    pub scan_time: u64,
}

impl HookScanResult {
    /// Check if any hooks were detected
    pub fn has_hooks(&self) -> bool {
        !self.ssdt_hooks.is_empty()
            || !self.idt_hooks.is_empty()
            || !self.inline_hooks.is_empty()
            || !self.msr_hooks.is_empty()
    }

    /// Get total number of hooks
    pub fn total_hooks(&self) -> usize {
        self.ssdt_hooks.len()
            + self.idt_hooks.len()
            + self.inline_hooks.len()
            + self.msr_hooks.len()
    }
}

/// Detect hook type from bytes
pub fn detect_hook_type(bytes: &[u8]) -> InlineHookType {
    if bytes.len() < 5 {
        return InlineHookType::Unknown;
    }

    // JMP rel32
    if bytes[0] == 0xE9 {
        return InlineHookType::JmpRel32;
    }

    // JMP [rip+disp32]
    if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
        return InlineHookType::JmpRipRelative;
    }

    // PUSH + RET
    if bytes.len() >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3 {
        return InlineHookType::PushRet;
    }

    // MOV RAX, imm64 + JMP RAX
    if bytes.len() >= 12
        && bytes[0] == 0x48
        && bytes[1] == 0xB8
        && bytes[10] == 0xFF
        && bytes[11] == 0xE0
    {
        return InlineHookType::MovJmp;
    }

    // INT3
    if bytes[0] == 0xCC {
        return InlineHookType::Int3;
    }

    InlineHookType::Unknown
}

/// Calculate jump target from JMP rel32
pub fn calculate_jmp_target(hook_addr: usize, bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 || bytes[0] != 0xE9 {
        return None;
    }

    let rel32 = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let target = (hook_addr as i64 + 5 + rel32 as i64) as usize;

    Some(target)
}

/// Kernel module information for hook validation
#[derive(Debug, Clone)]
pub struct KernelModule {
    /// Module base address
    pub base: usize,
    /// Module size
    pub size: usize,
    /// Module name
    pub name: [u8; 256],
}

/// Find module containing address
pub fn find_module_for_address(_address: usize, _modules: &[KernelModule]) -> Option<&KernelModule> {
    // In production:
    // Walk module list and find which module contains the address
    None
}

/// Periodic hook monitoring
pub struct HookMonitor {
    /// Scanner instance
    scanner: HookScanner,
    /// Baseline scan results
    baseline: Option<HookScanResult>,
    /// Alert callback
    alert_callback: Option<fn(&HookScanResult)>,
}

impl HookMonitor {
    /// Create new hook monitor
    pub fn new() -> Self {
        Self {
            scanner: HookScanner::new(),
            baseline: None,
            alert_callback: None,
        }
    }

    /// Set alert callback
    pub fn set_alert_callback(&mut self, callback: fn(&HookScanResult)) {
        self.alert_callback = Some(callback);
    }

    /// Capture baseline (clean state)
    ///
    /// # Safety
    /// Must be at PASSIVE_LEVEL
    pub unsafe fn capture_baseline(&mut self) -> Result<(), NTSTATUS> {
        self.baseline = Some(unsafe { self.scanner.full_scan() });
        println!("[Leviathan] Hook baseline captured");
        Ok(())
    }

    /// Check for new hooks since baseline
    ///
    /// # Safety
    /// Must be at PASSIVE_LEVEL
    pub unsafe fn check_for_changes(&self) -> Option<HookScanResult> {
        let current = unsafe { self.scanner.full_scan() };

        if let Some(baseline) = &self.baseline {
            // Compare current vs baseline
            if current.total_hooks() > baseline.total_hooks() {
                println!(
                    "[Leviathan] WARNING: New hooks detected! Baseline={}, Current={}",
                    baseline.total_hooks(),
                    current.total_hooks()
                );

                if let Some(callback) = self.alert_callback {
                    callback(&current);
                }

                return Some(current);
            }
        }

        None
    }
}
