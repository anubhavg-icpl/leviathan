# Leviathan

Windows kernel-mode driver development in Rust using Microsoft's [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs).

## Overview

Leviathan is a comprehensive KMDF (Kernel-Mode Driver Framework) driver demonstrating advanced Windows kernel capabilities for EDR (Endpoint Detection and Response), security monitoring, and forensic analysis.

### Features

**Kernel Callbacks**
- Process creation/termination monitoring with blocking capability
- Thread monitoring with remote injection detection (CreateRemoteThread)
- Image/DLL load monitoring for injection detection
- Registry filtering to protect persistence locations
- Object callbacks for process protection (anti-dumping)

**Kernel Filters**
- Filesystem minifilter for file I/O interception and ransomware detection
- WFP network filter for application-aware firewall

**Security**
- ELAM (Early Launch Anti-Malware) driver support
- APC injection for kernel-to-user code execution
- Integrity monitoring and anti-tampering

**Forensics**
- Pool tag scanning for hidden object detection
- Multi-method process enumeration (DKOM detection)
- Device stack and IRP analysis

## Project Structure

```
leviathan/
├── crates/
│   ├── leviathan-driver/           # Kernel-mode driver (cdylib)
│   │   ├── src/
│   │   │   ├── lib.rs              # Driver entry point
│   │   │   ├── device.rs           # Device management
│   │   │   ├── ioctl.rs            # IOCTL handlers
│   │   │   ├── callbacks/          # Kernel callbacks
│   │   │   │   ├── process.rs      # PsSetCreateProcessNotifyRoutineEx
│   │   │   │   ├── thread.rs       # PsSetCreateThreadNotifyRoutine
│   │   │   │   ├── image.rs        # PsSetLoadImageNotifyRoutine
│   │   │   │   ├── registry.rs     # CmRegisterCallbackEx
│   │   │   │   └── object.rs       # ObRegisterCallbacks
│   │   │   ├── filters/            # Kernel filters
│   │   │   │   ├── minifilter.rs   # Filesystem minifilter
│   │   │   │   └── network.rs      # WFP network filter
│   │   │   ├── security/           # Security modules
│   │   │   │   ├── elam.rs         # Early Launch Anti-Malware
│   │   │   │   ├── apc.rs          # APC injection utilities
│   │   │   │   └── integrity.rs    # Anti-tampering, DKOM detection
│   │   │   ├── forensics/          # Forensics modules
│   │   │   │   ├── pool_scanner.rs # Pool tag scanning
│   │   │   │   ├── process_enum.rs # Multi-method enumeration
│   │   │   │   └── irp_analysis.rs # Device stack analysis
│   │   │   └── utils/              # Utilities
│   │   │       ├── timer.rs        # DPC, timers, work items
│   │   │       ├── memory.rs       # Pool allocations, MDL
│   │   │       ├── sync.rs         # Spinlocks, mutexes, events
│   │   │       └── etw.rs          # Event Tracing for Windows
│   │   └── build.rs                # WDK build configuration
│   └── leviathan-common/           # Shared types (no_std)
├── .cargo/config.toml              # Cargo build settings
├── Makefile.toml                   # cargo-make tasks
├── rust-toolchain.toml             # Nightly toolchain config
└── Cargo.toml                      # Workspace manifest
```

## Kernel Capabilities

### Callbacks Module

| Callback | API | Purpose |
|----------|-----|---------|
| Process | `PsSetCreateProcessNotifyRoutineEx` | Monitor/block process creation |
| Thread | `PsSetCreateThreadNotifyRoutine` | Detect remote thread injection |
| Image | `PsSetLoadImageNotifyRoutine` | Monitor DLL/driver loading |
| Registry | `CmRegisterCallbackEx` | Filter registry operations |
| Object | `ObRegisterCallbacks` | Protect process handles |

### Filters Module

| Filter | API | Purpose |
|--------|-----|---------|
| Minifilter | `FltRegisterFilter` | File I/O interception, AV scanning |
| Network | `FwpsCalloutRegister` | WFP packet filtering, firewall |

### Security Module

| Component | Purpose |
|-----------|---------|
| ELAM | Boot-time driver validation, rootkit prevention |
| APC Injection | Kernel-to-user mode code execution, DLL injection |
| Integrity | Callback verification, DKOM detection, VBS/KDP support |

### Forensics Module

| Component | Purpose |
|-----------|---------|
| Pool Scanner | Find kernel objects by pool tag, detect hidden objects |
| Process Enum | Multi-method enumeration to detect hidden processes |
| IRP Analysis | Device stack walking, filter driver detection |

### Utilities Module

| Utility | Purpose |
|---------|---------|
| Timer/DPC | Scheduled kernel execution, periodic tasks |
| Memory | Pool allocations, MDL handling, user buffer access |
| Sync | Spinlocks, fast mutexes, read/write locks |
| ETW | High-performance structured event logging |

## Advanced Techniques

### Virtualization-Based Security (VBS)
- HVCI compatibility for memory integrity
- Kernel Data Protection (KDP) support
- Secure enclave integration

### Anti-Tampering
- Callback registration monitoring
- Driver code integrity verification
- Hook detection (SSDT, IDT, inline)

### DKOM Detection
- Multi-method process enumeration
- Cross-reference ActiveProcessLinks, PspCidTable, thread links
- Pool tag scanning for unlinked objects

### ELAM (Early Launch Anti-Malware)
- Boot driver classification (Good/Bad/Unknown)
- Signature-based boot driver validation
- TPM measured boot integration

## Requirements

### Development Environment

1. **Windows 11/10** with Developer Mode enabled
2. **Windows Driver Kit (WDK)** - [eWDK download](https://docs.microsoft.com/windows-hardware/drivers/download-the-wdk)
3. **LLVM 17.0.6** - Required for bindgen
   ```powershell
   winget install LLVM.LLVM --version 17.0.6
   ```
4. **Rust Nightly** - Configured via `rust-toolchain.toml`
5. **cargo-make** - Build automation
   ```powershell
   cargo install cargo-make --no-default-features --features tls-native
   ```

### Environment Setup

```powershell
$env:WDKContentRoot = "C:\Program Files (x86)\Windows Kits\10"
$env:WDKVersion = "10.0.22621.0"
```

## Building

```bash
cargo make          # Debug build
cargo make release  # Release build
cargo make package  # Create driver package
```

## Installation (Test Mode)

```powershell
bcdedit /set testsigning on  # Enable test signing (reboot required)
devcon install leviathan.inf Root\Leviathan
sc start leviathan
```

## Resources

### Microsoft Official
- [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs)
- [Windows-rust-driver-samples](https://github.com/microsoft/Windows-rust-driver-samples)
- [WDK Documentation](https://docs.microsoft.com/windows-hardware/drivers/)

### Security & Forensics
- [Filtering Registry Calls](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls)
- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [ELAM Documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [VBS Enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves)
- [Kernel Data Protection](https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/)

### Memory Forensics
- [Pool Tag Scanning](https://www.sciencedirect.com/science/article/pii/S1742287616000062)
- [Using MDLs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)
- [Volatility Framework](https://volatility-labs.blogspot.com/)

### Network Filtering
- [Windows Filtering Platform](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [wfp-rs](https://github.com/dlon/wfp-rs)

### APC & Injection
- [APC Internals](https://repnz.github.io/posts/apc/kernel-user-apc-api/)
- [Types of APCs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/types-of-apcs)

## License

MIT OR Apache-2.0
