# Leviathan EDR/XDR Architecture

A comprehensive Windows kernel-mode security framework for building Endpoint Detection and Response (EDR) and Extended Detection and Response (XDR) solutions.

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                    LEVIATHAN EDR/XDR                        │
                                    │              Windows Security Framework                      │
                                    └─────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           KERNEL MODE (Ring 0)                                                    │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                                    LEVIATHAN KERNEL DRIVER                                                   │ │
│  │                              (leviathan-driver - KMDF v1.33)                                                  │ │
│  ├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    TELEMETRY COLLECTION LAYER [ACTIVE]                                │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                               KERNEL CALLBACKS MODULE                                            │  │ │ │
│  │  │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │  │ │ │
│  │  │  │  │   Process   │ │   Thread    │ │   Image     │ │  Registry   │ │   Object    │               │  │ │ │
│  │  │  │  │  Callback   │ │  Callback   │ │  Callback   │ │  Callback   │ │  Callback   │               │  │ │ │
│  │  │  │  │             │ │             │ │             │ │             │ │  (requires  │               │  │ │ │
│  │  │  │  │ PsSetCreate │ │ PsSetCreate │ │ PsSetLoad   │ │ CmRegister  │ │  signed     │               │  │ │ │
│  │  │  │  │ ProcessNot- │ │ ThreadNot-  │ │ ImageNot-   │ │ CallbackEx  │ │  driver)    │               │  │ │ │
│  │  │  │  │ ifyRoutineEx│ │ ifyRoutine  │ │ ifyRoutine  │ │             │ │             │               │  │ │ │
│  │  │  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘               │  │ │ │
│  │  │  │                                                                                                  │  │ │ │
│  │  │  │  Monitors:                                                                                       │  │ │ │
│  │  │  │  • Process creation/termination    • Parent-child relationships    • Command line arguments      │  │ │ │
│  │  │  │  • Thread creation (local/remote)  • Remote thread injection       • Cross-process operations    │  │ │ │
│  │  │  │  • DLL/Driver loading              • Image base addresses          • Signature verification      │  │ │ │
│  │  │  │  • Registry modifications          • Persistence mechanisms        • Key/value monitoring        │  │ │ │
│  │  │  │  • Handle operations               • Process protection            • Anti-dumping                │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                               KERNEL FILTERS MODULE [STUB]                                       │  │ │ │
│  │  │  │  ┌──────────────────────────────────────┐  ┌──────────────────────────────────────┐             │  │ │ │
│  │  │  │  │      FILESYSTEM MINIFILTER           │  │         WFP NETWORK FILTER           │             │  │ │ │
│  │  │  │  │         (FltRegisterFilter)          │  │       (FwpsCalloutRegister)          │             │  │ │ │
│  │  │  │  ├──────────────────────────────────────┤  ├──────────────────────────────────────┤             │  │ │ │
│  │  │  │  │ • Pre/Post operation callbacks       │  │ • Inbound/Outbound packet filtering  │             │  │ │ │
│  │  │  │  │ • IRP_MJ_CREATE, READ, WRITE, etc.   │  │ • Application-aware firewall         │             │  │ │ │
│  │  │  │  │ • Ransomware detection (entropy)     │  │ • Connection tracking                │             │  │ │ │
│  │  │  │  │ • File integrity monitoring          │  │ • DNS/HTTP inspection                │             │  │ │ │
│  │  │  │  │ • Honeypot file detection            │  │ • C2 communication blocking          │             │  │ │ │
│  │  │  │  │ • Shadow copy protection             │  │ • Data exfiltration prevention       │             │  │ │ │
│  │  │  │  └──────────────────────────────────────┘  └──────────────────────────────────────┘             │  │ │ │
│  │  │  │  NOTE: Both filters use placeholder types pending wdk-sys 0.5+ binding support.                 │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                               ETW PROVIDER MODULE [ACTIVE]                                        │  │ │ │
│  │  │  │  ┌──────────────────────────────────────┐                                                            │  │ │ │
│  │  │  │  │      CUSTOM ETW PROVIDER             │                                                            │  │ │ │
│  │  │  │  ├──────────────────────────────────────┤                                                            │  │ │ │
│  │  │  │  │ • High-performance event logging     │                                                            │  │ │ │
│  │  │  │  │ • Structured event data              │                                                            │  │ │ │
│  │  │  │  │ • Minimal overhead tracing           │                                                            │  │ │ │
│  │  │  │  │ • Real-time streaming to user mode   │                                                            │  │ │ │
│  │  │  │  └──────────────────────────────────────┘                                                            │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    SECURITY & PROTECTION LAYER                                         │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                                   ELAM MODULE                                                    │  │ │ │
│  │  │  │                        (Early Launch Anti-Malware)                                               │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │ Boot-Time Protection:                     Runtime Protection:                                    │  │ │ │
│  │  │  │ • Boot driver classification              • PPL (Protected Process Light) enablement             │  │ │ │
│  │  │  │ • Signature verification                  • ETW-TI provider access                               │  │ │ │
│  │  │  │ • Boot-start driver validation            • Anti-tampering protection                            │  │ │ │
│  │  │  │ • Rootkit prevention at boot              • Secure ETW channel access                            │  │ │ │
│  │  │  │ • TPM measured boot integration           • Kernel callback protection                           │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                              INTEGRITY MONITORING MODULE                                         │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │                                                                                                  │  │ │ │
│  │  │  │  Hook Detection:                    Callback Integrity:              Kernel Protection:          │  │ │ │
│  │  │  │  ┌────────────────────┐             ┌────────────────────┐          ┌────────────────────┐       │  │ │ │
│  │  │  │  │ • SSDT validation  │             │ • Callback array   │          │ • PatchGuard compat│       │  │ │ │
│  │  │  │  │ • IDT verification │             │   verification     │          │ • HVCI support     │       │  │ │ │
│  │  │  │  │ • Inline hook scan │             │ • Registration     │          │ • KDP (Kernel Data │       │  │ │ │
│  │  │  │  │ • IAT/EAT checks   │             │   monitoring       │          │   Protection)      │       │  │ │ │
│  │  │  │  │ • MSR validation   │             │ • Integrity hashes │          │ • VBS integration  │       │  │ │ │
│  │  │  │  └────────────────────┘             └────────────────────┘          └────────────────────┘       │  │ │ │
│  │  │  │                                                                                                  │  │ │ │
│  │  │  │  DKOM Detection:                                                                                 │  │ │ │
│  │  │  │  • ActiveProcessLinks manipulation detection                                                     │  │ │ │
│  │  │  │  • PspCidTable tampering detection                                                               │  │ │ │
│  │  │  │  • Thread list manipulation detection                                                            │  │ │ │
│  │  │  │  • Handle table modification detection                                                           │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                                APC INJECTION MODULE                                              │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │ Kernel-to-User Communication:            Use Cases:                                              │  │ │ │
│  │  │  │ • User-mode APC queuing                  • DLL injection for monitoring                          │  │ │ │
│  │  │  │ • Thread alerting mechanism              • Process instrumentation                               │  │ │ │
│  │  │  │ • Context manipulation                   • Response actions                                      │  │ │ │
│  │  │  │ • Safe code injection                    • Forensic data collection                              │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    FORENSICS & DETECTION LAYER                                         │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                              POOL SCANNER MODULE                                                 │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │ Pool Tag Scanning:                       Object Discovery:                                       │  │ │ │
│  │  │  │ • Proc (EPROCESS)                        • Hidden process detection                              │  │ │ │
│  │  │  │ • Thre (ETHREAD)                         • Unlinked object discovery                             │  │ │ │
│  │  │  │ • Driv (DRIVER_OBJECT)                   • Orphan thread detection                               │  │ │ │
│  │  │  │ • File (FILE_OBJECT)                     • Hidden driver detection                               │  │ │ │
│  │  │  │ • TcpE (Network endpoints)               • Rootkit artifact discovery                            │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                           PROCESS ENUMERATION MODULE                                             │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │ Multi-Method Enumeration:                Cross-Reference Analysis:                               │  │ │ │
│  │  │  │ • ZwQuerySystemInformation               • Compare results across methods                        │  │ │ │
│  │  │  │ • ActiveProcessLinks walking             • Identify discrepancies                                │  │ │ │
│  │  │  │ • PspCidTable enumeration                • Detect DKOM attacks                                   │  │ │ │
│  │  │  │ • Thread->Process traversal              • Find hidden processes                                 │  │ │ │
│  │  │  │ • Pool tag scanning                      • Validate process integrity                            │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                              IRP ANALYSIS MODULE                                                 │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │ Device Stack Analysis:                   Filter Detection:                                       │  │ │ │
│  │  │  │ • Device object enumeration              • Suspicious filter identification                      │  │ │ │
│  │  │  │ • Driver dispatch table analysis         • Unauthorized driver detection                         │  │ │ │
│  │  │  │ • IRP major function mapping             • Stack integrity verification                          │  │ │ │
│  │  │  │ • Upper/lower filter enumeration         • Malicious attachment detection                        │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                           MEMORY SCANNER MODULE                                                  │  │ │ │
│  │  │  ├─────────────────────────────────────────────────────────────────────────────────────────────────┤  │ │ │
│  │  │  │ Signature Scanning:                      Pattern Detection:                                      │  │ │ │
│  │  │  │ • YARA-compatible rule engine            • Shellcode patterns                                    │  │ │ │
│  │  │  │ • Byte pattern matching                  • Known malware signatures                              │  │ │ │
│  │  │  │ • String search                          • Encryption routines                                   │  │ │ │
│  │  │  │ • PE header analysis                     • Suspicious code sequences                             │  │ │ │
│  │  │  │ • Context-aware scanning                 • IOC matching                                          │  │ │ │
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    DETECTION ENGINE LAYER                                              │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐                        │ │ │
│  │  │  │   RULE ENGINE        │  │  BEHAVIORAL ANALYSIS  │  │    HEURISTICS        │                        │ │ │
│  │  │  ├──────────────────────┤  ├──────────────────────┤  ├──────────────────────┤                        │ │ │
│  │  │  │ • Pattern matching   │  │ • ProcessTreeAnalyzer │  │ • Command line       │                        │ │ │
│  │  │  │ • Condition-based    │  │ • InjectionDetector   │  │ • File path          │                        │ │ │
│  │  │  │ • MITRE ATT&CK map   │  │ • RansomwareDetector  │  │ • Registry path      │                        │ │ │
│  │  │  │ • Severity scoring   │  │ • LateralMovementDet. │  │ • Network beaconing  │                        │ │ │
│  │  │  │ • RuleType enum      │  │ • CredentialAccessDet │  │ • Entropy analysis   │                        │ │ │
│  │  │  │ • RuleCondition eval │  │ • AnomalyScorer       │  │ • run_all_heuristics │                        │ │ │
│  │  │  └──────────────────────┘  └──────────────────────┘  └──────────────────────┘                        │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    COMMUNICATION LAYER                                                 │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌──────────────────────────────┐  ┌──────────────────────────────┐  ┌──────────────────────────────┐ │ │ │
│  │  │  │      IOCTL INTERFACE         │  │      SHARED CHANNEL          │  │      EVENT SIGNALING         │ │ │ │
│  │  │  ├──────────────────────────────┤  ├──────────────────────────────┤  ├──────────────────────────────┤ │ │ │
│  │  │  │ • IOCTL_GET_VERSION (0x800)  │  │ • Lock-free ring buffer      │  │ • Named kernel events        │ │ │ │
│  │  │  │ • IOCTL_ECHO (0x801)         │  │ • Zero-copy event transfer   │  │ • Notification mechanism     │ │ │ │
│  │  │  │ • IOCTL_GET_STATS (0x802)    │  │ • High-throughput telemetry  │  │ • Synchronization            │ │ │ │
│  │  │  │ • METHOD_BUFFERED I/O        │  │ • MDL-based sharing          │  │ • Wake-up signals            │ │ │ │
│  │  │  └──────────────────────────────┘  └──────────────────────────────┘  └──────────────────────────────┘ │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    UTILITIES LAYER                                                     │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │ │ │
│  │  │  │   Memory    │  │   Sync      │  │   Timer     │  │    ETW      │  │    Comm     │                  │ │ │
│  │  │  │  Management │  │ Primitives  │  │   & DPC     │  │  Tracing    │  │  Ring Buf   │                  │ │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘                  │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
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

## Data Flow Architecture

```
                    ┌──────────────┐
                    │   System     │
                    │   Activity   │
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │   Process    │ │   Registry   │ │    Image     │
    │   Events     │ │   Events     │ │   Events     │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │     EVENT COLLECTOR    │
              │   (Kernel Callbacks)   │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │     DETECTION ENGINE   │
              │  • Rule evaluation     │
              │  • Behavioral analysis │
              │  • Heuristic scoring   │
              └────────────┬───────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │  ETW Stream  │ │  Ring Buffer │ │    Alert     │
    │  (Optional)  │ │  (Primary)   │ │  Generation  │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │    USER-MODE CLIENT    │
              │    (via DeviceIoCtl)   │
              └────────────────────────┘
```

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

## Driver Initialization Sequence

The driver initializes subsystems in this order during `DriverEntry`:

1. **ETW provider registration** (optional - continues on failure)
2. **WDF driver creation** with `EvtDriverDeviceAdd` and `EvtDriverUnload` callbacks
3. **Kernel callback registration** (process, thread, image, registry; object commented out)
4. **Filesystem minifilter** registration (disabled by default)
5. **WFP network filter** registration (disabled by default)

On unload, subsystems are torn down in reverse order.

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
