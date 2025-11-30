# Leviathan

Windows kernel-mode driver framework for building EDR/XDR solutions in Rust using Microsoft's [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs).

## Overview

Leviathan is a comprehensive KMDF (Kernel-Mode Driver Framework) driver providing all the kernel-mode components needed to build an Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solution. It serves as a foundation for security monitoring, threat detection, and forensic analysis on Windows systems.

**For detailed architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md)**.

### Core Capabilities

| Category | Components | Description |
|----------|------------|-------------|
| **Telemetry** | Callbacks, Filters, ETW | Real-time system activity monitoring |
| **Detection** | Rules, Behavioral, Heuristics | Multi-layered threat detection engine |
| **Protection** | ELAM, Integrity, Hooks | System and self-protection mechanisms |
| **Forensics** | Pool Scanner, Enumeration, IRP | Memory forensics and rootkit detection |
| **Communication** | Ring Buffer, Shared Memory | High-performance kernel-user IPC |

## Features

### Kernel Callbacks
- Process creation/termination monitoring with blocking capability
- Thread monitoring with remote injection detection (CreateRemoteThread)
- Image/DLL load monitoring for injection detection
- Registry filtering to protect persistence locations
- Object callbacks for process protection (anti-dumping)

### Kernel Filters
- Filesystem minifilter for file I/O interception and ransomware detection
- WFP network filter for application-aware firewall

### Security
- ELAM (Early Launch Anti-Malware) driver support
- APC injection for kernel-to-user code execution
- Integrity monitoring and anti-tampering
- Hook detection (SSDT, IDT, inline hooks, MSR)

### Detection Engine
- Rule-based threat detection with MITRE ATT&CK mapping
- Behavioral analysis for attack pattern correlation
- Heuristics for command line, file path, and registry analysis
- Anomaly scoring and baseline deviation detection

### Forensics
- Pool tag scanning for hidden object detection
- Multi-method process enumeration (DKOM detection)
- Device stack and IRP analysis
- Memory scanning with pattern/signature matching

### Communication
- Lock-free ring buffer for high-throughput telemetry
- Shared memory with MDL mapping
- IOCTL interface for control operations
- Named event signaling for notifications

## Project Structure

```
leviathan/
├── crates/
│   ├── leviathan-driver/              # Kernel-mode driver (cdylib)
│   │   ├── src/
│   │   │   ├── lib.rs                 # Driver entry point
│   │   │   ├── device.rs              # Device management
│   │   │   ├── ioctl.rs               # IOCTL handlers
│   │   │   ├── callbacks/             # Kernel callbacks
│   │   │   │   ├── process.rs         # PsSetCreateProcessNotifyRoutineEx
│   │   │   │   ├── thread.rs          # PsSetCreateThreadNotifyRoutine
│   │   │   │   ├── image.rs           # PsSetLoadImageNotifyRoutine
│   │   │   │   ├── registry.rs        # CmRegisterCallbackEx
│   │   │   │   └── object.rs          # ObRegisterCallbacks
│   │   │   ├── filters/               # Kernel filters
│   │   │   │   ├── minifilter.rs      # Filesystem minifilter
│   │   │   │   └── network.rs         # WFP network filter
│   │   │   ├── security/              # Security modules
│   │   │   │   ├── elam.rs            # Early Launch Anti-Malware
│   │   │   │   ├── apc.rs             # APC injection utilities
│   │   │   │   ├── integrity.rs       # Anti-tampering, DKOM detection
│   │   │   │   └── hooks.rs           # Hook detection (SSDT/IDT/inline)
│   │   │   ├── detection/             # Detection engine
│   │   │   │   ├── mod.rs             # Detection engine core
│   │   │   │   ├── rules.rs           # Rule-based detection
│   │   │   │   ├── behavior.rs        # Behavioral analysis
│   │   │   │   └── heuristics.rs      # Heuristic detection
│   │   │   ├── forensics/             # Forensics modules
│   │   │   │   ├── pool_scanner.rs    # Pool tag scanning
│   │   │   │   ├── process_enum.rs    # Multi-method enumeration
│   │   │   │   ├── irp_analysis.rs    # Device stack analysis
│   │   │   │   └── memory_scanner.rs  # Signature/pattern scanning
│   │   │   └── utils/                 # Utilities
│   │   │       ├── timer.rs           # DPC, timers, work items
│   │   │       ├── memory.rs          # Pool allocations, MDL
│   │   │       ├── sync.rs            # Spinlocks, mutexes, events
│   │   │       ├── etw.rs             # Event Tracing for Windows
│   │   │       └── comm.rs            # Kernel-user communication
│   │   └── build.rs                   # WDK build configuration
│   └── leviathan-common/              # Shared types (no_std)
├── ARCHITECTURE.md                    # Detailed architecture documentation
├── .cargo/config.toml                 # Cargo build settings
├── Makefile.toml                      # cargo-make tasks
├── rust-toolchain.toml                # Nightly toolchain config
└── Cargo.toml                         # Workspace manifest
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER MODE (Ring 3)                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  User-Mode Agent (PPL)                   │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │   │
│  │  │  Event  │ │  Rule   │ │Behavior │ │  YARA   │       │   │
│  │  │Processor│ │ Engine  │ │Analyzer │ │ Scanner │       │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘       │   │
│  └──────────────────────────┬──────────────────────────────┘   │
│                             │ Ring Buffer / Shared Memory       │
├─────────────────────────────┼───────────────────────────────────┤
│                      KERNEL MODE (Ring 0)                       │
│  ┌──────────────────────────┴──────────────────────────────┐   │
│  │                   Leviathan Driver                       │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │              Telemetry Collection                   │ │   │
│  │  │  Process │ Thread │ Image │ Registry │ Object      │ │   │
│  │  │  Callback│Callback│Callback│ Callback │ Callback   │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │              Kernel Filters                         │ │   │
│  │  │         Minifilter       │      WFP Network         │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │         Security & Protection Layer                 │ │   │
│  │  │    ELAM │ Integrity │ Hook Detection │ APC          │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │              Forensics Engine                       │ │   │
│  │  │  Pool Scanner │ Process Enum │ IRP │ Memory Scan   │ │   │
│  │  └────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Detection Capabilities

### MITRE ATT&CK Coverage

| Tactic | Techniques | Detection Method |
|--------|------------|------------------|
| Execution | T1055 (Process Injection) | Thread callback, ETW-TI |
| Persistence | T1547 (Boot/Logon) | Registry callback |
| Privilege Escalation | T1068 (Exploitation) | Memory scanner |
| Defense Evasion | T1562 (Disable Security) | Integrity monitoring |
| Credential Access | T1003 (OS Credential Dumping) | Object callback |
| Discovery | T1057 (Process Discovery) | Process enumeration |
| Lateral Movement | T1021 (Remote Services) | Network filter |
| Impact | T1486 (Data Encrypted) | Minifilter entropy |

### Detection Rules

The detection engine includes pre-built rules for:

- **Process Injection**: CreateRemoteThread, APC injection, process hollowing
- **Credential Theft**: LSASS access, SAM registry access
- **Persistence**: Registry run keys, scheduled tasks, services
- **Defense Evasion**: AMSI bypass, ETW patching, unhooking
- **Ransomware**: High entropy writes, mass file operations, shadow copy deletion

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

## Building Your Own EDR

Leviathan provides all the kernel-mode primitives needed to build a complete EDR. Here's how to use the components:

### 1. Telemetry Collection

```rust
// Register callbacks for system monitoring
callbacks::process::register()?;    // Process events
callbacks::thread::register()?;     // Thread events (injection detection)
callbacks::image::register()?;      // DLL/driver loading
callbacks::registry::register()?;   // Registry modifications
```

### 2. File System Protection

```rust
// Enable minifilter for file I/O monitoring
filters::minifilter::register(driver)?;
// Detects: Ransomware (entropy), sensitive file access, suspicious writes
```

### 3. Network Visibility

```rust
// Enable WFP for network monitoring
filters::network::register(device)?;
// Detects: C2 communication, data exfiltration, lateral movement
```

### 4. Threat Detection

```rust
// Initialize detection engine
let mut engine = detection::DetectionEngine::new();
engine.load_default_rules();
engine.set_alert_callback(handle_alert);

// Process events through detection
let alert = engine.process_event(event_type, &context, &data);
```

### 5. Memory Forensics

```rust
// Scan for signatures/patterns
let mut scanner = forensics::memory_scanner::MemoryScanner::new();
scanner.load_builtin_signatures();
let matches = scanner.scan_process(pid)?;

// Detect hidden processes
let mut enumerator = forensics::process_enum::ProcessEnumerator::new();
enumerator.enumerate_all()?;
let hidden = enumerator.find_hidden();
```

### 6. Communication

```rust
// Set up kernel-user communication
utils::comm::init_global_channel(1024 * 1024)?;  // 1MB ring buffer
let channel = utils::comm::get_global_channel()?;
channel.write_event(EventType::ProcessCreate, &event_data)?;
```

## Resources

### Microsoft Official
- [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs)
- [Windows-rust-driver-samples](https://github.com/microsoft/Windows-rust-driver-samples)
- [WDK Documentation](https://docs.microsoft.com/windows-hardware/drivers/)

### EDR Architecture
- [EDR Internals](https://docs.contactit.fr/posts/evasion/edr-internals/) - Comprehensive EDR architecture
- [From Windows Drivers to EDR](https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/)
- [Kernel ETW is Best ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw) - Elastic Security Labs

### Security Research
- [ETW Threat Intelligence](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer) - Rust ETW-TI consumer
- [SSDT Hooking Detection](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/)
- [Pool Tag Scanning](https://www.sciencedirect.com/science/article/pii/S1742287617300592)

### Ransomware Detection
- [RansomWatch](https://github.com/RafWu/RansomWatch) - Minifilter-based detection
- [Entropy Analysis](https://academic.oup.com/cybersecurity/article/11/1/tyaf009/8109429)

### Microsoft Security
- [ELAM Documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [Kernel Data Protection](https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/)
- [VBS Enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves)

## Production Considerations

### Driver Signing
- EV Code Signing Certificate required
- Microsoft attestation signing for Windows 10+
- WHQL certification for enterprise deployment

### ELAM Requirements
- Microsoft Virus Initiative (MVI) partnership
- ELAM certificate from Microsoft
- PPL service registration for ETW-TI access

### HVCI Compatibility
- No dynamic code generation
- No writable+executable memory
- Proper memory protection flags

## License

MIT OR Apache-2.0
