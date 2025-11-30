# Leviathan EDR/XDR Architecture

A comprehensive Windows kernel-mode security framework for building Endpoint Detection and Response (EDR) and Extended Detection and Response (XDR) solutions.

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                    LEVIATHAN EDR/XDR                        │
                                    │              Windows Security Framework                      │
                                    └─────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           USER MODE (Ring 3)                                                      │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                                   │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐       │
│  │   Management UI     │    │   Threat Hunter     │    │   Forensics Tool    │    │   Response Agent    │       │
│  │   (Dashboard)       │    │   (Query Engine)    │    │   (Analysis)        │    │   (Remediation)     │       │
│  └──────────┬──────────┘    └──────────┬──────────┘    └──────────┬──────────┘    └──────────┬──────────┘       │
│             │                          │                          │                          │                   │
│             └──────────────────────────┼──────────────────────────┼──────────────────────────┘                   │
│                                        │                          │                                              │
│                                        ▼                          ▼                                              │
│                          ┌─────────────────────────────────────────────────────┐                                 │
│                          │              LEVIATHAN AGENT SERVICE                 │                                 │
│                          │         (leviathan-agent - PPL Process)             │                                 │
│                          ├─────────────────────────────────────────────────────┤                                 │
│                          │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │                                 │
│                          │  │   Event     │ │   Rule      │ │  Response   │   │                                 │
│                          │  │  Processor  │ │   Engine    │ │   Handler   │   │                                 │
│                          │  └─────────────┘ └─────────────┘ └─────────────┘   │                                 │
│                          │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │                                 │
│                          │  │   YARA      │ │  Behavior   │ │   Threat    │   │                                 │
│                          │  │  Scanner    │ │  Analyzer   │ │   Intel     │   │                                 │
│                          │  └─────────────┘ └─────────────┘ └─────────────┘   │                                 │
│                          └────────────────────────┬────────────────────────────┘                                 │
│                                                   │                                                              │
│  ┌────────────────────────────────────────────────┼────────────────────────────────────────────────────────┐    │
│  │                              COMMUNICATION LAYER                                                         │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐                 │    │
│  │  │   IOCTL Handler  │  │   Shared Memory  │  │   Named Events   │  │   ETW Consumer   │                 │    │
│  │  │   (DeviceIoCtl)  │  │   (Ring Buffer)  │  │  (Notifications) │  │  (Threat Intel)  │                 │    │
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘  └──────────────────┘                 │    │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                   │
                                                   │ System Calls / Filter Manager / WFP
                                                   ▼
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           KERNEL MODE (Ring 0)                                                    │
├───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                                    LEVIATHAN KERNEL DRIVER                                                   │ │
│  │                              (leviathan-driver - KMDF/WDM)                                                   │ │
│  ├─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    TELEMETRY COLLECTION LAYER                                          │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                               KERNEL CALLBACKS MODULE                                            │  │ │ │
│  │  │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐               │  │ │ │
│  │  │  │  │   Process   │ │   Thread    │ │   Image     │ │  Registry   │ │   Object    │               │  │ │ │
│  │  │  │  │  Callback   │ │  Callback   │ │  Callback   │ │  Callback   │ │  Callback   │               │  │ │ │
│  │  │  │  │             │ │             │ │             │ │             │ │             │               │  │ │ │
│  │  │  │  │ PsSetCreate │ │ PsSetCreate │ │ PsSetLoad   │ │ CmRegister  │ │ ObRegister  │               │  │ │ │
│  │  │  │  │ ProcessNot- │ │ ThreadNot-  │ │ ImageNot-   │ │ CallbackEx  │ │ Callbacks   │               │  │ │ │
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
│  │  │  │                               KERNEL FILTERS MODULE                                              │  │ │ │
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
│  │  │  └─────────────────────────────────────────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐  │ │ │
│  │  │  │                               ETW PROVIDER MODULE                                                │  │ │ │
│  │  │  │  ┌──────────────────────────────────────┐  ┌──────────────────────────────────────┐             │  │ │ │
│  │  │  │  │      CUSTOM ETW PROVIDER             │  │     ETW THREAT INTELLIGENCE          │             │  │ │ │
│  │  │  │  │                                      │  │    (Microsoft-Windows-Threat-Intel)  │             │  │ │ │
│  │  │  │  ├──────────────────────────────────────┤  ├──────────────────────────────────────┤             │  │ │ │
│  │  │  │  │ • High-performance event logging     │  │ • ALLOCVM_REMOTE detection           │             │  │ │ │
│  │  │  │  │ • Structured event data              │  │ • PROTECTVM_REMOTE monitoring        │             │  │ │ │
│  │  │  │  │ • Minimal overhead tracing           │  │ • MAPVIEW_REMOTE tracking            │             │  │ │ │
│  │  │  │  │ • Integration with Windows events    │  │ • QUEUEUSERAPC_REMOTE detection      │             │  │ │ │
│  │  │  │  │ • Real-time streaming to agent       │  │ • SETTHREADCONTEXT_REMOTE            │             │  │ │ │
│  │  │  │  │                                      │  │ • Requires ELAM + PPL                │             │  │ │ │
│  │  │  │  └──────────────────────────────────────┘  └──────────────────────────────────────┘             │  │ │ │
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
│  │  │                                    COMMUNICATION LAYER                                                 │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                                                        │ │ │
│  │  │  ┌──────────────────────────────┐  ┌──────────────────────────────┐  ┌──────────────────────────────┐ │ │ │
│  │  │  │      IOCTL INTERFACE         │  │      SHARED MEMORY           │  │      EVENT SIGNALING         │ │ │ │
│  │  │  ├──────────────────────────────┤  ├──────────────────────────────┤  ├──────────────────────────────┤ │ │ │
│  │  │  │ • Configuration commands     │  │ • Lock-free ring buffer      │  │ • Named kernel events        │ │ │ │
│  │  │  │ • Query operations           │  │ • Zero-copy event transfer   │  │ • Notification mechanism     │ │ │ │
│  │  │  │ • Control requests           │  │ • High-throughput telemetry  │  │ • Synchronization            │ │ │ │
│  │  │  │ • Response actions           │  │ • MDL-based sharing          │  │ • Wake-up signals            │ │ │ │
│  │  │  └──────────────────────────────┘  └──────────────────────────────┘  └──────────────────────────────┘ │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                                              │ │
│  │  ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                                    UTILITIES LAYER                                                     │ │ │
│  │  ├────────────────────────────────────────────────────────────────────────────────────────────────────────┤ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │ │ │
│  │  │  │   Memory    │  │   Sync      │  │   Timer     │  │   String    │  │   Debug     │                  │ │ │
│  │  │  │  Management │  │ Primitives  │  │   & DPC     │  │  Utilities  │  │  Logging    │                  │ │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘                  │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                                                   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                        EVENT DATA FLOW                                               │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────┐
                    │   System     │
                    │   Activity   │
                    └──────┬───────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │   Process    │ │    File      │ │   Network    │
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
              │     EVENT ENRICHER     │
              │  • Process context     │
              │  • User context        │
              │  • Parent relationships│
              └────────────┬───────────┘
                           │
           ┌───────────────┴───────────────┐
           │                               │
           ▼                               ▼
    ┌──────────────┐              ┌──────────────┐
    │  ETW Stream  │              │  Ring Buffer │
    │  (Optional)  │              │  (Primary)   │
    └──────┬───────┘              └──────┬───────┘
           │                             │
           └───────────────┬─────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │    USER-MODE AGENT     │
              │    Event Processor     │
              └────────────┬───────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │  Behavioral  │ │    Rule      │ │    YARA      │
    │  Analysis    │ │   Engine     │ │   Scanner    │
    └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │   THREAT CORRELATION   │
              │   • Event correlation  │
              │   • Attack patterns    │
              │   • TTP mapping        │
              └────────────┬───────────┘
                           │
           ┌───────────────┴───────────────┐
           │                               │
           ▼                               ▼
    ┌──────────────┐              ┌──────────────┐
    │    Alert     │              │   Response   │
    │  Generation  │              │   Actions    │
    └──────────────┘              └──────────────┘
```

## Detection Capabilities Matrix

### Process Monitoring

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| Process Injection | Remote thread creation, APC queuing | Thread callback, ETW-TI |
| Process Hollowing | Memory protection changes, unmapping | ETW-TI PROTECTVM |
| Parent PID Spoofing | Parent-child relationship validation | Process callback |
| Command Line Obfuscation | Command line analysis | Process callback |
| PPID Spoofing | Handle inheritance tracking | Object callback |

### Memory Attacks

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| Shellcode Injection | Memory allocation + execution | ETW-TI ALLOCVM |
| DLL Injection | Remote LoadLibrary calls | Image callback |
| Reflective DLL Loading | Manual mapping detection | Memory scanner |
| Process Doppelganging | Transacted file operations | Minifilter |
| AtomBombing | APC code execution | ETW-TI QUEUEUSERAPC |

### Persistence Mechanisms

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| Registry Run Keys | Key modification monitoring | Registry callback |
| Scheduled Tasks | File/registry changes | Minifilter, Registry |
| Services | Service creation/modification | Registry callback |
| WMI Subscriptions | WMI namespace monitoring | ETW |
| DLL Search Order Hijacking | Path validation | Image callback |

### Defense Evasion

| Technique | Detection Method | Data Source |
|-----------|------------------|-------------|
| AMSI Bypass | Memory patching detection | Memory scanner |
| ETW Patching | ETW integrity monitoring | Integrity module |
| Unhooking | Hook restoration detection | Integrity module |
| Direct Syscalls | Stack analysis | ETW-TI |
| DKOM | Multi-method enumeration | Process enumeration |

### Ransomware Detection

| Indicator | Detection Method | Data Source |
|-----------|------------------|-------------|
| Mass File Encryption | Entropy analysis | Minifilter |
| File Extension Changes | Rename monitoring | Minifilter |
| Shadow Copy Deletion | VSS operation blocking | Minifilter |
| Rapid File Modification | I/O rate monitoring | Minifilter |
| Known Ransomware Signatures | YARA scanning | Memory scanner |

## Component Details

### 1. Kernel Driver (leviathan-driver)

The kernel driver operates at Ring 0 and provides:

- **Real-time telemetry collection** via kernel callbacks
- **File system monitoring** via minifilter
- **Network monitoring** via WFP callouts
- **Memory forensics** capabilities
- **Anti-tampering** protection

### 2. User-Mode Agent (leviathan-agent)

The agent runs as a protected process (PPL) and provides:

- **Event processing** from kernel telemetry
- **Behavioral analysis** engine
- **YARA scanning** for signatures
- **Rule-based detection** engine
- **Response actions** execution

### 3. Communication Layer

High-performance kernel-to-user communication:

- **Ring buffer** for lock-free event transfer
- **Shared memory** for zero-copy data sharing
- **IOCTL interface** for control operations
- **Named events** for notifications

## Building an EDR with Leviathan

### Step 1: Core Telemetry

```rust
// Enable kernel callbacks for process monitoring
callbacks::process::register()?;
callbacks::thread::register()?;
callbacks::image::register()?;
```

### Step 2: File System Protection

```rust
// Register minifilter for file I/O monitoring
filters::minifilter::register(driver)?;

// Configure ransomware detection
minifilter::config::set_entropy_threshold(7.5);
minifilter::config::enable_honeypot_detection(true);
```

### Step 3: Network Visibility

```rust
// Register WFP callouts for network monitoring
filters::network::register(device)?;

// Configure connection tracking
network::config::enable_connection_tracking(true);
network::config::set_blocked_ports(&[4444, 5555]);
```

### Step 4: Memory Protection

```rust
// Initialize memory scanner
let scanner = forensics::memory_scanner::Scanner::new();
scanner.load_yara_rules("rules/")?;

// Scan suspicious processes
scanner.scan_process(pid)?;
```

### Step 5: Behavioral Analysis

```rust
// Create behavior analyzer
let analyzer = detection::BehaviorAnalyzer::new();

// Add detection rules
analyzer.add_rule(rules::ProcessInjection::new());
analyzer.add_rule(rules::CredentialDumping::new());
analyzer.add_rule(rules::Ransomware::new());
```

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
