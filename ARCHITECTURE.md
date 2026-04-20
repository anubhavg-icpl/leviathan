# Leviathan EDR/XDR Architecture

A comprehensive Windows kernel-mode security framework for building Endpoint Detection and Response (EDR) and Extended Detection and Response (XDR) solutions.

## System Architecture

```mermaid
graph TB
    subgraph KERNEL["KERNEL MODE (Ring 0)"]
        DRIVER["Leviathan Kernel Driver<br/>KMDF v1.33"]

        subgraph TELEMETRY["Telemetry Collection Layer -- ACTIVE"]
            CB_PROC["Process Callback<br/>PsSetCreateProcessNotifyRoutineEx"]
            CB_THREAD["Thread Callback<br/>PsSetCreateThreadNotifyRoutine"]
            CB_IMAGE["Image Callback<br/>PsSetLoadImageNotifyRoutine"]
            CB_REG["Registry Callback<br/>CmRegisterCallbackEx"]
            CB_OBJ["Object Callback<br/>ObRegisterCallbacks<br/>(requires signed driver)"]
        end

        subgraph FILTERS["Kernel Filters Layer -- STUB"]
            MINIFILTER["Filesystem Minifilter<br/>FltRegisterFilter"]
            WFP["WFP Network Filter<br/>FwpsCalloutRegister"]
            NOTE_FILT["placeholder types pending<br/>wdk-sys 0.5+ bindings"]
        end

        subgraph ETW_MOD["ETW Provider -- ACTIVE"]
            ETW_PROVIDER["Custom ETW Provider<br/>High-performance event logging<br/>Structured event data<br/>Real-time streaming"]
        end

        subgraph SECURITY["Security & Protection Layer"]
            ELAM["ELAM Module<br/>Boot driver classification<br/>Signature verification<br/>PPL enablement"]
            INTEGRITY["Integrity Module<br/>Callback array verification<br/>VBS/HVCI detection<br/>DKOM detection"]
            HOOKS["Hook Scanner<br/>SSDT/IDT/Inline/MSR<br/>Jmp target calculation<br/>Kernel module mapping"]
            APC["APC Injection<br/>KeInitializeApc<br/>KeInsertQueueApc<br/>User-mode APC queuing"]
        end

        subgraph FORENSICS["Forensics Layer"]
            POOL["Pool Scanner<br/>EPROCESS/ETHREAD/DRIVER<br/>FILE_OBJECT/Network<br/>Hidden object detection"]
            PROC_ENUM["Process Enumerator<br/>ZwQuerySystemInformation<br/>ActiveProcessLinks walking<br/>PspCidTable enumeration"]
            IRP["IRP Analysis<br/>Device stack analysis<br/>Filter detection<br/>Dispatch table mapping"]
            MEM_SCAN["Memory Scanner<br/>Signature/pattern matching<br/>VAD walking<br/>Wildcard byte patterns"]
        end

        subgraph DETECTION["Detection Engine"]
            RULES["Rule Engine<br/>DetectionRule/RuleType<br/>Condition evaluation<br/>MITRE ATT&CK mapping"]
            BEHAVIOR["Behavioral Analysis<br/>ProcessTreeAnalyzer<br/>InjectionDetector<br/>RansomwareDetector<br/>LateralMovementDetector<br/>CredentialAccessDetector<br/>AnomalyScorer"]
            HEURISTICS["Heuristics<br/>Command line analysis<br/>File path analysis<br/>Registry path analysis<br/>Network beaconing detection<br/>Entropy analysis via libm"]
        end

        subgraph COMMS["Communication Layer"]
            IOCTL["IOCTL Interface<br/>IOCTL_GET_VERSION 0x800<br/>IOCTL_ECHO 0x801<br/>IOCTL_GET_STATS 0x802<br/>METHOD_BUFFERED"]
            RING["SharedChannel<br/>Lock-free ring buffer 1MB<br/>MDL-based zero-copy<br/>EventHeader with typed events"]
            EVENTS["Event Signaling<br/>Named kernel events<br/>Notification mechanism<br/>Synchronization"]
        end

        subgraph UTILS["Utilities Layer"]
            MEM_MGR["Memory Management<br/>PoolAllocation/Mdl<br/>LookasideList<br/>secure_zero"]
            SYNC["Sync Primitives<br/>SpinLock/FastMutex<br/>ExResource/KernelEvent"]
            TIMER["Timer & DPC<br/>KernelTimer/WorkItem<br/>DeferredWork/PeriodicTask"]
        end
    end

    DRIVER --> TELEMETRY
    DRIVER --> SECURITY
    DRIVER --> FORENSICS
    DRIVER --> DETECTION
    DRIVER --> COMMS
    DRIVER --> UTILS
    TELEMETRY --> DETECTION
    COMMS --> UTILS

    style FILTERS fill:#555,stroke:#999,stroke-dasharray: 5 5
    style MINIFILTER fill:#555,stroke:#999,stroke-dasharray: 5 5
    style WFP fill:#555,stroke:#999,stroke-dasharray: 5 5
    style NOTE_FILT fill:#555,stroke:#999,stroke-dasharray: 5 5
```

## Module Dependency Graph

```mermaid
graph LR
    subgraph driver["leviathan-driver"]
        lib["lib.rs<br/>DriverEntry + Feature Flags"]
        device["device.rs<br/>WDF Device + I/O Queue"]
        ioctl["ioctl.rs<br/>IOCTL Handlers"]
        callbacks["callbacks/<br/>5 Kernel Callbacks"]
        filters["filters/<br/>Minifilter + WFP"]
        security["security/<br/>ELAM/APC/Integrity/Hooks"]
        detection["detection/<br/>Rules/Behavior/Heuristics"]
        forensics["forensics/<br/>Pool/ProcessEnum/IRP/Memory"]
        utils["utils/<br/>Timer/Memory/Sync/ETW/Comm"]
    end

    subgraph common["leviathan-common"]
        common_lib["lib.rs<br/>IOCTL Codes<br/>DriverStats<br/>VersionInfo<br/>Device GUID"]
    end

    lib --> device
    lib --> ioctl
    lib --> callbacks
    lib --> filters
    lib --> security
    lib --> detection
    lib --> forensics
    lib --> utils

    device --> ioctl
    ioctl -.->|"shared IOCTL codes"| common_lib
    callbacks --> utils
    detection --> utils
    filters --> utils

    lib -.->|"wdk, wdk-sys, wdk-alloc, libm"| WDK["Windows Driver Kit"]
```

## Driver Initialization Sequence

```mermaid
sequenceDiagram
    participant Windows
    participant DriverEntry
    participant ETW
    participant WDF
    participant Callbacks
    participant Filters

    Windows->>DriverEntry: Load driver
    activate DriverEntry

    DriverEntry->>ETW: register() [ENABLE_ETW=true]
    alt ETW registration fails
        ETW-->>DriverEntry: Warning logged, continues
    end

    DriverEntry->>WDF: WdfDriverCreate()
    WDF-->>DriverEntry: WDFDRIVER handle
    WDF->>WDF: EvtDriverDeviceAdd
    WDF->>WDF: Create I/O Queue (Read/Write/IOCTL)
    WDF->>WDF: Register device interface

    DriverEntry->>Callbacks: register_all [ENABLE_CALLBACKS=true]
    Callbacks->>Callbacks: process::register()
    Callbacks->>Callbacks: thread::register()
    Callbacks->>Callbacks: image::register()
    Callbacks->>Callbacks: registry::register()
    Note over Callbacks: object::register() commented out<br/>(requires signed driver)

    DriverEntry->>Filters: register [ENABLE_MINIFILTER=false]
    Note over Filters: Disabled by default
    DriverEntry->>Filters: register [ENABLE_NETWORK_FILTER=false]
    Note over Filters: Disabled by default

    DriverEntry-->>Windows: STATUS_SUCCESS
    deactivate DriverEntry

    Note over Windows,Filters: On driver unload, teardown in reverse order
```

## Event Data Flow

```mermaid
flowchart TD
    SYS["System Activity"] --> PROC_EV["Process Events"]
    SYS --> THREAD_EV["Thread Events"]
    SYS --> IMAGE_EV["Image Events"]
    SYS --> REG_EV["Registry Events"]

    PROC_EV --> COLLECTOR["Event Collector<br/>Kernel Callbacks"]
    THREAD_EV --> COLLECTOR
    IMAGE_EV --> COLLECTOR
    REG_EV --> COLLECTOR

    COLLECTOR --> ENGINE["DetectionEngine::process_event()"]

    ENGINE --> RULES["Rule Evaluation<br/>DetectionRule matches"]
    ENGINE --> BEHAVIOR["Behavioral Analysis<br/>BehaviorAnalyzer trait"]
    ENGINE --> HEURISTICS["Heuristic Scoring<br/>run_all_heuristics()"]

    RULES --> ALERT{"Alert Generated?"}
    BEHAVIOR --> ALERT
    HEURISTICS --> ALERT

    ALERT -->|Yes| CALLBACK["Alert Callback<br/>fn(&Alert)"]
    ALERT -->|No| NO_ALERT["No Action"]

    CALLBACK --> ACTION["RecommendedAction<br/>Log/Alert/Block/Terminate"]

    COLLECTOR --> ETW_OUT["ETW Stream<br/>(Optional)"]
    COLLECTOR --> RING_OUT["Ring Buffer<br/>SharedChannel<br/>(Primary)"]

    ETW_OUT --> USER["User-Mode Client"]
    RING_OUT --> USER
    ACTION --> USER
```

## Detection Engine Class Diagram

```mermaid
classDiagram
    class DetectionEngine {
        -rules: Vec~DetectionRule~
        -analyzers: Vec~Box~dyn BehaviorAnalyzer~~
        -alert_counter: AtomicU64
        -alert_callback: Option~fn(&Alert)~
        -stats: DetectionStats
        -process_cache: BTreeMap~u32, ProcessActivity~
        +new() DetectionEngine
        +load_default_rules()
        +add_rule(rule: DetectionRule)
        +set_alert_callback(callback: fn(&Alert))
        +process_event(event_type, context, data) Option~Alert~
        +cleanup_cache(max_age_ms: u64)
        +get_stats() &DetectionStats
    }

    class DetectionRule {
        +id: u32
        +name: [u8; 64]
        +severity: Severity
        +tactic: MitreTactic
        +technique_id: [u8; 8]
        +enabled: bool
        +rule_type: RuleType
        +conditions: Vec~RuleCondition~
    }

    class RuleType {
        <<enumeration>>
        ThreadCreation
        ProcessCreation
        ProcessAccess
        ImageLoad
        RegistryMod
        FileOp
        MemoryMod
        NetworkOp
    }

    class Severity {
        <<enumeration>>
        Info = 0
        Low = 1
        Medium = 2
        High = 3
        Critical = 4
    }

    class MitreTactic {
        <<enumeration>>
        InitialAccess = 1
        Execution = 2
        Persistence = 3
        PrivilegeEscalation = 4
        DefenseEvasion = 5
        CredentialAccess = 6
        Discovery = 7
        LateralMovement = 8
        Collection = 9
        Exfiltration = 10
        CommandAndControl = 11
        Impact = 40
    }

    class Alert {
        +id: u64
        +rule_id: u32
        +severity: Severity
        +tactic: MitreTactic
        +technique_id: [u8; 8]
        +title: [u8; 128]
        +description: [u8; 512]
        +source_pid: u32
        +target_pid: Option~u32~
        +timestamp: u64
        +action: RecommendedAction
    }

    class RecommendedAction {
        <<enumeration>>
        Log
        Alert
        Block
        Terminate
        Quarantine
        Isolate
    }

    class BehaviorAnalyzer {
        <<trait>>
        +analyze(context, cache) Option~Alert~
    }

    class ProcessTreeAnalyzer {
        +analyze() Option~Alert~
    }
    class InjectionDetector {
        +analyze() Option~Alert~
    }
    class RansomwareDetector {
        +analyze() Option~Alert~
    }
    class LateralMovementDetector {
        +analyze() Option~Alert~
    }
    class CredentialAccessDetector {
        +analyze() Option~Alert~
    }
    class AnomalyScorer {
        +analyze() Option~Alert~
    }

    DetectionEngine *-- DetectionRule
    DetectionEngine *-- Alert
    DetectionEngine o-- BehaviorAnalyzer
    DetectionRule --> Severity
    DetectionRule --> MitreTactic
    DetectionRule --> RuleType
    Alert --> Severity
    Alert --> MitreTactic
    Alert --> RecommendedAction

    BehaviorAnalyzer <|.. ProcessTreeAnalyzer
    BehaviorAnalyzer <|.. InjectionDetector
    BehaviorAnalyzer <|.. RansomwareDetector
    BehaviorAnalyzer <|.. LateralMovementDetector
    BehaviorAnalyzer <|.. CredentialAccessDetector
    BehaviorAnalyzer <|.. AnomalyScorer
```

## Kernel-User Communication

```mermaid
sequenceDiagram
    participant KM as Kernel Mode (Driver)
    participant MDL as MDL Shared Memory
    participant Ring as Ring Buffer
    participant UM as User Mode (Client)

    KM->>MDL: MmCreateMdl() - Allocate shared memory
    KM->>UM: MmMapLockedPagesSpecifyCache() - Map to user space

    loop Event Streaming
        KM->>Ring: write_event(EventType, data)
        Note over Ring: Lock-free write<br/>Update write_ptr
        KM->>UM: Signal kernel event
        UM->>Ring: read_event()
        Note over Ring: Read from read_ptr<br/>Zero-copy access
    end

    UM->>KM: DeviceIoCtl(IOCTL_GET_STATS)
    KM-->>UM: DriverStats struct
    UM->>KM: DeviceIoCtl(IOCTL_GET_VERSION)
    KM-->>UM: Version string
    UM->>KM: DeviceIoCtl(IOCTL_ECHO)
    KM-->>UM: Echoed data
```

## Feature Flags

The driver uses compile-time feature flags to enable/disable subsystems:

| Flag | Default | Status | Notes |
|------|---------|--------|-------|
| `ENABLE_CALLBACKS` | `true` | Active | Process, thread, image, registry callbacks |
| `ENABLE_MINIFILTER` | `false` | Stub | Placeholder types pending wdk-sys 0.5+ bindings |
| `ENABLE_NETWORK_FILTER` | `false` | Stub | Placeholder types pending wdk-sys 0.5+ bindings |
| `ENABLE_ETW` | `true` | Active | Custom ETW provider for event logging |

> **Note:** Object callback (`ObRegisterCallbacks`) requires a properly signed driver and is commented out in `init_driver` by default.

## Detection Capabilities Matrix

### Process Monitoring

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| Process Injection | Remote thread creation, APC queuing | Thread callback |
| Parent PID Spoofing | Parent-child relationship validation | Process callback |
| Command Line Obfuscation | Command line analysis | Process callback |
| Process Hollowing | Memory protection changes | Heuristic engine |

### Memory Attacks

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| Shellcode Injection | Signature/pattern scanning | Memory scanner |
| DLL Injection | Remote LoadLibrary calls | Image callback |
| Reflective DLL Loading | Manual mapping detection | Memory scanner |
| DKOM | Multi-method enumeration | Process enumerator |

### Persistence Mechanisms

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| Registry Run Keys | Key modification monitoring | Registry callback |
| Services | Service creation/modification | Registry callback |
| DLL Search Order Hijacking | Path validation | Image callback |

### Defense Evasion

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| AMSI Bypass | Memory patching detection | Memory scanner |
| ETW Patching | ETW integrity monitoring | Integrity module |
| Unhooking | Hook restoration detection | Hooks module |
| DKOM | Multi-method enumeration | Process enumeration |

### Ransomware Detection

| Indicator | Detection Method | Data Source |
|-----------|------------------|-------------|
| Mass File Encryption | Entropy analysis (via libm) | Heuristic engine |
| Network Beaconing | Statistical timing analysis | Heuristic engine |
| Known Signatures | Pattern matching | Memory scanner |

## Component Details

### 1. Kernel Driver (`leviathan-driver`)

The kernel driver operates at Ring 0 and provides:

- **Real-time telemetry collection** via kernel callbacks (process, thread, image, registry)
- **File system monitoring** via minifilter (stub - pending wdk-sys bindings)
- **Network monitoring** via WFP callouts (stub - pending wdk-sys bindings)
- **Detection engine** with rules, behavioral analysis, and heuristics
- **Memory forensics** capabilities (pool scanning, process enumeration, IRP analysis, memory scanning)
- **Anti-tampering** protection (SSDT/IDT/inline hook detection, callback integrity)
- **ETW provider** for high-performance event logging

### 2. Shared Types (`leviathan-common`)

A `no_std` crate providing shared types for kernel-user communication:

- **IOCTL codes**: `IOCTL_GET_VERSION`, `IOCTL_ECHO`, `IOCTL_GET_STATS`
- **`DriverStats`**: Read/write/ioctl counters shared between kernel and user mode
- **`VersionInfo`**: Structured version information
- **`DEVICE_INTERFACE_GUID`**: Device interface GUID for user-mode discovery

### 3. Communication Layer

High-performance kernel-to-user communication via `utils::comm`:

- **`SharedChannel`** with lock-free ring buffer (default 1MB)
- **MDL-based memory mapping** for zero-copy data sharing
- **`EventHeader`** with typed events (process, thread, image, file, registry, network)
- **IOCTL interface** for control operations (version, echo, stats)
- **`ChannelStats`** for monitoring channel health

## Building an EDR with Leviathan

### Step 1: Core Telemetry

```rust
// Register callbacks for system monitoring (called in DriverEntry)
unsafe { callbacks::process::register() }?;
unsafe { callbacks::thread::register() }?;
unsafe { callbacks::image::register() }?;
unsafe { callbacks::registry::register() }?;

// Or register all at once:
unsafe { callbacks::register_all_callbacks() }?;
```

### Step 2: Threat Detection

```rust
// Create detection engine with default rules
let mut engine = detection::DetectionEngine::new();
engine.load_default_rules();
engine.set_alert_callback(handle_alert);

// Process events through detection
let alert = engine.process_event(
    detection::EventType::ThreadCreate,
    &context,
    &event_data,
);
```

### Step 3: Memory Forensics

```rust
// Scan for hidden processes via pool tags
let processes = forensics::pool_scanner::scan_for_processes();
let drivers = forensics::pool_scanner::scan_for_drivers();

// Multi-method process enumeration for DKOM detection
let mut enumerator = forensics::process_enum::ProcessEnumerator::new();
let _ = unsafe { enumerator.enumerate_all() };
let hidden = forensics::process_enum::detect_dkom(&enumerator);
```

### Step 4: Hook Detection

```rust
// Scan for SSDT, IDT, and inline hooks
let scanner = security::hooks::HookScanner::new();
let result = scanner.scan_all();

// Verify kernel callback integrity
let tampered = security::integrity::verify_callbacks();
```

### Step 5: Kernel-User Communication

```rust
// Set up shared channel for telemetry
let mut channel = utils::comm::SharedChannel::new(1024 * 1024)?; // 1MB
channel.write_event(
    utils::comm::EventType::ProcessCreate,
    &process_event_data,
)?;
```

## Build Configuration

### Toolchain

- **Rust nightly** with `rust-src`, `rustfmt`, `clippy`, `llvm-tools-preview` components
- **Targets**: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`
- **Build-std**: `core`, `alloc` with `compiler-builtins-mem`
- **`fma`/`fmaf` workaround**: `extern "C"` shims for rust-lang/rust#143172 linker regression

### Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `wdk` | 0.4 | KMDF/WDM bindings |
| `wdk-sys` | 0.5 | Low-level WDK FFI |
| `wdk-alloc` | 0.4 | Kernel memory allocator |
| `wdk-panic` | 0.4 | Kernel panic handler |
| `wdk-build` | 0.5 | Build script support |
| `libm` | 0.2 | Math functions (log2, sqrt) for entropy/beaconing detection |
| `leviathan-common` | 0.3.0 | Shared IOCTL codes and types |

## Security Considerations

### Driver Signing

Production deployment requires:

1. **EV Code Signing Certificate** for kernel driver signing
2. **Microsoft attestation signing** for Windows 10+
3. **WHQL certification** for broad deployment

### ELAM Requirements

For ETW Threat Intelligence access:

1. **Microsoft Virus Initiative (MVI)** partnership
2. **ELAM certificate** from Microsoft
3. **PPL service** registration

### HVCI Compatibility

For Virtualization-Based Security:

1. No dynamic code generation
2. No writable+executable memory
3. Proper memory protection flags

## References

### Microsoft Documentation
- [Windows Driver Kit (WDK)](https://docs.microsoft.com/windows-hardware/drivers/)
- [Kernel-Mode Driver Framework](https://docs.microsoft.com/windows-hardware/drivers/wdf/)
- [File System Minifilter Drivers](https://docs.microsoft.com/windows-hardware/drivers/ifs/file-system-minifilter-drivers)
- [Windows Filtering Platform](https://docs.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page)

### Security Research
- [EDR Internals](https://docs.contactit.fr/posts/evasion/edr-internals/) - Comprehensive EDR architecture
- [ETW Threat Intelligence](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer) - Rust ETW-TI consumer
- [Kernel ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw) - Elastic Security Labs
- [SSDT Hooking Detection](https://www.adlice.com/kernelmode-rootkits-part-1-ssdt-hooks/) - Rootkit detection

### Memory Forensics
- [Pool Tag Scanning](https://www.sciencedirect.com/science/article/pii/S1742287617300592) - Memory scanning with YARA
- [DKOM Detection](https://volatility-labs.blogspot.com/) - Volatility Framework

### Ransomware Detection
- [RansomWatch](https://github.com/RafWu/RansomWatch) - Minifilter-based ransomware detection
- [Entropy Analysis](https://academic.oup.com/cybersecurity/article/11/1/tyaf009/8109429) - High-entropy file detection

## License

MIT OR Apache-2.0
