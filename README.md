# Leviathan

Windows kernel-mode driver framework for building EDR/XDR solutions in Rust using Microsoft's [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs).

[![crates.io](https://img.shields.io/crates/v/leviathan-driver.svg)](https://crates.io/crates/leviathan-driver)
[![crates.io](https://img.shields.io/crates/v/leviathan-common.svg)](https://crates.io/crates/leviathan-common)

![Leviathan EDR/XDR Architecture](assets/leviathan-edr-architecture.png)

*End-to-End EDR/XDR Framework Architecture. Illustration by baeb.*

## Overview

Leviathan is a comprehensive KMDF (Kernel-Mode Driver Framework) driver providing all the kernel-mode components needed to build an Endpoint Detection and Response (EDR) or Extended Detection and Response (XDR) solution. It serves as a foundation for security monitoring, threat detection, and forensic analysis on Windows systems.

**For detailed architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md)**.

### Core Capabilities

| Category | Components | Status |
|----------|------------|--------|
| **Telemetry** | Process, Thread, Image, Registry, Object Callbacks | Active |
| **Detection** | Rules Engine, Behavioral Analysis, Heuristics | Active |
| **Protection** | ELAM, Integrity, Hook Detection, APC | Active |
| **Forensics** | Pool Scanner, Process Enum, IRP Analysis, Memory Scanner | Active |
| **Communication** | Ring Buffer, Shared Memory, IOCTL | Active |
| **Filesystem** | Minifilter | Stub (pending wdk-sys bindings) |
| **Network** | WFP Filter | Stub (pending wdk-sys bindings) |

## Crates

| Crate | Version | Description |
|-------|---------|-------------|
| [`leviathan-driver`](https://crates.io/crates/leviathan-driver) | 0.3.0 | Kernel-mode driver (cdylib) |
| [`leviathan-common`](https://crates.io/crates/leviathan-common) | 0.3.0 | Shared types and IOCTL codes (no_std) |

## Features

### Kernel Callbacks (Active)
- Process creation/termination monitoring via `PsSetCreateProcessNotifyRoutineEx`
- Thread monitoring with remote injection detection via `PsSetCreateThreadNotifyRoutine`
- Image/DLL load monitoring via `PsSetLoadImageNotifyRoutine`
- Registry filtering via `CmRegisterCallbackEx`
- Object callbacks for process protection via `ObRegisterCallbacks` (requires signed driver)

### Kernel Filters (Stub)
- Filesystem minifilter for file I/O interception and ransomware detection
- WFP network filter for application-aware firewall
- Both use placeholder types pending `wdk-sys` 0.5+ binding support

### Security
- **ELAM** (Early Launch Anti-Malware) driver support with boot driver classification
- **APC injection** for kernel-to-user code execution via `KeInitializeApc`/`KeInsertQueueApc`
- **Integrity monitoring** - callback array verification, VBS/HVCI detection, DKOM detection
- **Hook detection** - SSDT, IDT, inline hook scanning, MSR validation

### Detection Engine
- **Rule engine** with pattern matching, condition evaluation, and MITRE ATT&CK mapping
- **Behavioral analyzers**: `ProcessTreeAnalyzer`, `InjectionDetector`, `RansomwareDetector`, `LateralMovementDetector`, `CredentialAccessDetector`, `AnomalyScorer`
- **Heuristics**: command line analysis, file path analysis, registry path analysis, network beaconing detection (using `libm` for entropy/statistical calculations)
- 5 built-in detection rules covering process injection, credential access, persistence, defense evasion, and ransomware

### Forensics
- Pool tag scanning for hidden object detection (`scan_for_processes`, `scan_for_threads`, `scan_for_drivers`)
- Multi-method process enumeration with DKOM detection (`ProcessEnumerator`)
- Device stack and IRP analysis (`IrpAnalysis`)
- Memory scanning with wildcard pattern matching (`MemoryScanner`, `VadWalker`)

### Communication
- Lock-free ring buffer (`SharedChannel`) for high-throughput telemetry (default 1MB)
- MDL-based shared memory for zero-copy kernel-user IPC
- IOCTL interface with `METHOD_BUFFERED` I/O
- Typed event headers (process, thread, image, file, registry, network events)

## Project Structure

```
leviathan/
├── crates/
│   ├── leviathan-driver/              # Kernel-mode driver (cdylib)
│   │   ├── src/
│   │   │   ├── lib.rs                 # Driver entry point, feature flags, fma/fmaf shims
│   │   │   ├── device.rs              # WDF device creation, I/O queue setup
│   │   │   ├── ioctl.rs               # IOCTL handlers (GET_VERSION, ECHO, GET_STATS)
│   │   │   ├── callbacks/             # Kernel callbacks
│   │   │   │   ├── mod.rs             # register_all_callbacks / unregister_all
│   │   │   │   ├── process.rs         # PsSetCreateProcessNotifyRoutineEx
│   │   │   │   ├── thread.rs          # PsSetCreateThreadNotifyRoutine
│   │   │   │   ├── image.rs           # PsSetLoadImageNotifyRoutine
│   │   │   │   ├── registry.rs        # CmRegisterCallbackEx
│   │   │   │   └── object.rs          # ObRegisterCallbacks
│   │   │   ├── filters/               # Kernel filters (stub)
│   │   │   │   ├── mod.rs
│   │   │   │   ├── minifilter.rs      # Filesystem minifilter (placeholder types)
│   │   │   │   └── network.rs         # WFP network filter (placeholder types)
│   │   │   ├── security/              # Security modules
│   │   │   │   ├── mod.rs
│   │   │   │   ├── elam.rs            # Early Launch Anti-Malware
│   │   │   │   ├── apc.rs             # APC injection (KeInitializeApc)
│   │   │   │   ├── integrity.rs       # Anti-tampering, callback verification, VBS/HVCI
│   │   │   │   └── hooks.rs           # SSDT/IDT/inline/MSR hook detection
│   │   │   ├── detection/             # Detection engine
│   │   │   │   ├── mod.rs             # DetectionEngine, Alert, Severity, EventType
│   │   │   │   ├── rules.rs           # DetectionRule, RuleType, RuleCondition
│   │   │   │   ├── behavior.rs        # BehaviorAnalyzer trait, 6 analyzers
│   │   │   │   └── heuristics.rs      # Command line, file path, registry, beaconing
│   │   │   ├── forensics/             # Forensics modules
│   │   │   │   ├── mod.rs
│   │   │   │   ├── pool_scanner.rs    # Pool tag scanning
│   │   │   │   ├── process_enum.rs    # Multi-method enumeration, detect_dkom
│   │   │   │   ├── irp_analysis.rs    # Device stack, dispatch analysis
│   │   │   │   └── memory_scanner.rs  # Signature/pattern scanning, VAD walking
│   │   │   └── utils/                 # Utilities
│   │   │       ├── mod.rs
│   │   │       ├── timer.rs           # KernelTimer, WorkItem, DeferredWork, PeriodicTask
│   │   │       ├── memory.rs          # PoolAllocation, Mdl, LookasideList, secure_zero
│   │   │       ├── sync.rs            # SpinLock, FastMutex, ExResource, KernelEvent
│   │   │       ├── etw.rs             # ETW provider, EventLevel, event macros
│   │   │       └── comm.rs            # SharedChannel, RingBuffer, EventHeader, EventType
│   │   └── Cargo.toml
│   └── leviathan-common/              # Shared types (no_std)
│       ├── src/
│       │   └── lib.rs                 # IOCTL codes, DriverStats, VersionInfo, GUID
│       └── Cargo.toml
├── .cargo/
│   └── config.toml                    # Build-std, kernel linker flags
├── ARCHITECTURE.md                    # Detailed architecture documentation
├── Makefile.toml                      # cargo-make tasks (build, release, package)
├── rust-toolchain.toml                # Nightly toolchain config
└── Cargo.toml                         # Workspace manifest
```

## Architecture Overview

```mermaid
graph TB
    subgraph KERNEL["KERNEL MODE (Ring 0)"]
        DRIVER["Leviathan Kernel Driver<br/>KMDF v1.33"]

        subgraph TELEMETRY["Telemetry Collection -- ACTIVE"]
            CB["Process | Thread | Image<br/>Registry | Object Callbacks"]
        end

        subgraph SECURITY["Security & Protection"]
            SEC_MODS["ELAM | Integrity Monitoring<br/>Hook Detection | APC Injection"]
        end

        subgraph DETECTION["Detection Engine"]
            DET_MODS["Rule Engine | Behavioral Analysis<br/>Heuristics (entropy, beaconing)"]
        end

        subgraph FORENSICS["Forensics"]
            FORE_MODS["Pool Scanner | Process Enum<br/>IRP Analysis | Memory Scanner"]
        end

        subgraph COMMS["Communication"]
            COMM_MODS["Ring Buffer | Shared Memory<br/>IOCTL | Named Events"]
        end

        subgraph FILTERS["Kernel Filters -- STUB"]
            FIL_MODS["Minifilter | WFP Network"]
        end
    end

    DRIVER --> TELEMETRY
    DRIVER --> SECURITY
    DRIVER --> DETECTION
    DRIVER --> FORENSICS
    DRIVER --> COMMS
    DRIVER --> FILTERS
    TELEMETRY --> DETECTION

    style FILTERS fill:#555,stroke:#999,stroke-dasharray: 5 5
    style FIL_MODS fill:#555,stroke:#999,stroke-dasharray: 5 5
```

### Event Processing Pipeline

```mermaid
flowchart LR
    SYS["System Activity"] --> CB["Kernel Callbacks"]
    CB --> ENGINE["DetectionEngine"]
    ENGINE --> RULES["Rule Engine"]
    ENGINE --> BEHAV["Behavioral Analysis"]
    ENGINE --> HEUR["Heuristics"]
    RULES --> ALERT{"Alert?"}
    BEHAV --> ALERT
    HEUR --> ALERT
    ALERT -->|Yes| ACTION["Block/Alert/Terminate"]
    ALERT -->|No| ETW["ETW + Ring Buffer"]
    ETW --> USER["User-Mode Client"]
    ACTION --> USER
```

## Detection Capabilities

### MITRE ATT&CK Coverage

| Tactic | Techniques | Detection Method |
|--------|------------|------------------|
| Execution | T1055 (Process Injection) | Thread callback, InjectionDetector |
| Persistence | T1547 (Boot/Logon) | Registry callback, heuristics |
| Privilege Escalation | T1068 (Exploitation) | Memory scanner, hook detection |
| Defense Evasion | T1562 (Disable Security) | Integrity monitoring, hooks |
| Credential Access | T1003 (OS Credential Dumping) | Object callback, CredentialAccessDetector |
| Discovery | T1057 (Process Discovery) | Process enumeration |
| Lateral Movement | T1021 (Remote Services) | LateralMovementDetector |
| Impact | T1486 (Data Encrypted) | RansomwareDetector, entropy heuristics |

### Built-in Detection Rules

| ID | Name | Severity | MITRE Technique |
|----|------|----------|-----------------|
| 1 | RemoteThreadInjection | High | T1055 (Defense Evasion) |
| 2 | LsassAccess | Critical | T1003 (Credential Access) |
| 3 | RegistryRunKey | Medium | T1547 (Persistence) |
| 4 | AmsiBypass | High | T1562 (Defense Evasion) |
| 5 | RansomwareIndicator | Critical | T1486 (Impact) |

## Requirements

### Development Environment

1. **Windows 11/10** with Developer Mode enabled
2. **Windows Driver Kit (WDK)** - [eWDK download](https://docs.microsoft.com/windows-hardware/drivers/download-the-wdk)
3. **LLVM 17.0.6** - Required for bindgen
   ```powershell
   winget install LLVM.LLVM --version 17.0.6
   ```
4. **Rust Nightly** - Configured via `rust-toolchain.toml` (includes `rust-src`, `clippy`, `llvm-tools-preview`)
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
cargo make package  # Create driver package (.sys + .inf)
cargo make test     # Run unit tests (leviathan-common)
cargo make clippy   # Run clippy lints
cargo make fmt      # Format code
```

### Build Output

The build produces `leviathan_driver.dll` in `target/x86_64-pc-windows-msvc/debug/` (or `release/`). The `cargo make package` task renames this to `leviathan.sys` and generates an INF file in `target/driver/Package/`.

## Installation (Test Mode)

```powershell
bcdedit /set testsigning on  # Enable test signing (reboot required)
devcon install leviathan.inf Root\Leviathan
sc start leviathan
```

## Using the Framework

### 1. Telemetry Collection

```rust
// Register callbacks for system monitoring
unsafe { callbacks::process::register() }?;
unsafe { callbacks::thread::register() }?;
unsafe { callbacks::image::register() }?;
unsafe { callbacks::registry::register() }?;

// Or register all at once:
unsafe { callbacks::register_all_callbacks() }?;
```

### 2. Threat Detection

```rust
// Initialize detection engine with built-in rules
let mut engine = detection::DetectionEngine::new();
engine.load_default_rules(); // Loads 5 rules: injection, lsass, run key, AMSI, ransomware
engine.set_alert_callback(|alert: &detection::Alert| {
    println!("[ALERT] {:?}: {}", alert.severity, core::str::from_utf8(&alert.title).unwrap_or(""));
});

// Process events through detection engine
if let Some(alert) = engine.process_event(detection::EventType::ThreadCreate, &context, &data) {
    // Handle alert based on alert.action (Log, Alert, Block, Terminate, Quarantine, Isolate)
}
```

### 3. Memory Forensics

```rust
// Scan for hidden processes via pool tags
let processes = forensics::pool_scanner::scan_for_processes();
let drivers = forensics::pool_scanner::scan_for_drivers();

// Multi-method process enumeration for DKOM detection
let mut enumerator = forensics::process_enum::ProcessEnumerator::new();
let _ = unsafe { enumerator.enumerate_all() };
let hidden = forensics::process_enum::detect_dkom(&enumerator);
```

### 4. Hook Detection

```rust
// Scan for SSDT, IDT, inline hooks, and MSR modifications
let scanner = security::hooks::HookScanner::new();
let result = scanner.scan_all();

// Verify kernel callback integrity
let tampered_count = security::integrity::verify_callbacks();
```

### 5. Communication

```rust
// Set up shared channel for kernel-user telemetry
let mut channel = utils::comm::SharedChannel::new(1024 * 1024)?; // 1MB ring buffer
channel.write_event(
    utils::comm::EventType::ProcessCreate,
    &event_data,
)?;
```

## Known Limitations

- **Minifilter and WFP network filter** are stub implementations using placeholder types. Full implementations require `wdk-sys` 0.5+ to expose the necessary WFP and Filter Manager bindings.
- **Object callback** (`ObRegisterCallbacks`) is commented out in `init_driver` because it requires a properly EV-signed driver.
- **`fma`/`fmaf` workaround**: Non-fused fallback shims are provided to work around [rust-lang/rust#143172](https://github.com/rust-lang/rust/issues/143172), a nightly regression where `compiler_builtins` 0.1.148+ references these symbols which MSVC's kernel-mode linker cannot resolve.

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
