# Leviathan

Windows kernel-mode driver development in Rust using Microsoft's [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs).

## Overview

Leviathan is a comprehensive KMDF (Kernel-Mode Driver Framework) driver demonstrating advanced Windows kernel capabilities for EDR (Endpoint Detection and Response) and security monitoring applications.

### Features

- **Process Monitoring** - Track process creation/termination, block malicious processes
- **Thread Monitoring** - Detect remote thread injection attacks (CreateRemoteThread)
- **Image Load Monitoring** - Monitor DLL/driver loading, detect DLL injection
- **Registry Filtering** - Protect critical registry keys, detect persistence mechanisms
- **Object Callbacks** - Protect processes from termination, prevent credential dumping
- **Filesystem Minifilter** - Intercept file I/O, ransomware detection, on-access scanning
- **Network Filter (WFP)** - Application-aware firewall, block malicious connections
- **ETW Tracing** - High-performance event logging for diagnostics

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

### Utilities Module

| Utility | Purpose |
|---------|---------|
| Timer/DPC | Scheduled kernel execution, periodic tasks |
| Memory | Pool allocations, MDL handling, user buffer access |
| Sync | Spinlocks, fast mutexes, read/write locks |
| ETW | High-performance structured event logging |

## Requirements

### Development Environment

1. **Windows 11/10** with Developer Mode enabled
2. **Windows Driver Kit (WDK)** - Install via Visual Studio Installer or [eWDK](https://docs.microsoft.com/windows-hardware/drivers/download-the-wdk)
3. **LLVM 17.0.6** - Required for bindgen (avoid LLVM 18 due to ARM64 issues)
   ```powershell
   winget install LLVM.LLVM --version 17.0.6
   ```
4. **Rust Nightly** - Configured via `rust-toolchain.toml`
5. **cargo-make** - Build task automation
   ```powershell
   cargo install cargo-make --no-default-features --features tls-native
   ```
6. **cargo-wdk** (optional) - Microsoft's driver packaging tool
   ```powershell
   cargo install cargo-wdk
   ```

### Environment Setup

Run from an **eWDK Developer Command Prompt** or set these environment variables:

```powershell
# Point to your WDK installation
$env:WDKContentRoot = "C:\Program Files (x86)\Windows Kits\10"
$env:WDKVersion = "10.0.22621.0"
```

## Building

### Debug Build
```bash
cargo make
```

### Release Build
```bash
cargo make release
```

### Create Driver Package
```bash
cargo make package
```

This creates a `target/driver/Package/` directory with:
- `leviathan.sys` - Driver binary
- `leviathan.inf` - Installation file
- `leviathan.cat` - Catalog file (requires signing)

## Driver Installation (Test Mode)

1. **Enable Test Signing** (requires reboot):
   ```powershell
   bcdedit /set testsigning on
   ```

2. **Install the Driver**:
   ```powershell
   # Using devcon (from WDK)
   devcon install leviathan.inf Root\Leviathan

   # Or using pnputil
   pnputil /add-driver leviathan.inf /install
   ```

3. **Start the Driver**:
   ```powershell
   sc start leviathan
   ```

4. **Check Status**:
   ```powershell
   sc query leviathan
   ```

5. **View Debug Output**:
   ```powershell
   # Use DbgView or WinDbg to see driver output
   ```

## IOCTL Interface

The driver exposes these control codes:

| IOCTL | Code | Description |
|-------|------|-------------|
| `IOCTL_GET_VERSION` | `0x80002000` | Get driver version |
| `IOCTL_ECHO` | `0x80002004` | Echo data back |
| `IOCTL_GET_STATS` | `0x80002008` | Get driver statistics |

### Device Interface GUID
```
{12345678-1234-1234-1234-123456789ABC}
```

## Architecture

### KMDF Driver Model

```
DriverEntry
    ├─► ETW Provider Registration
    ├─► WdfDriverCreate
    │       └─► EvtDriverDeviceAdd
    │               ├─► WdfDeviceCreate
    │               ├─► WdfIoQueueCreate
    │               └─► WdfDeviceCreateDeviceInterface
    ├─► Process Callback (PsSetCreateProcessNotifyRoutineEx)
    ├─► Thread Callback (PsSetCreateThreadNotifyRoutine)
    ├─► Image Callback (PsSetLoadImageNotifyRoutine)
    ├─► Registry Callback (CmRegisterCallbackEx)
    ├─► Object Callback (ObRegisterCallbacks) [requires signed driver]
    ├─► Minifilter (FltRegisterFilter) [optional]
    └─► WFP Filter (FwpsCalloutRegister) [optional]
```

### Security Monitoring Flow

```
System Event ──► Kernel Callback ──► Policy Check ──► Action
                     │                    │              │
              Process Create        Whitelist/      Allow/Block
              Thread Create         Blacklist       Log via ETW
              Image Load            Heuristics      Alert
              Registry Op
              File I/O
              Network Conn
```

## Use Cases

### EDR (Endpoint Detection and Response)
- Process execution monitoring
- DLL injection detection
- Credential theft prevention (LSASS protection)
- Persistence mechanism detection

### Ransomware Detection
- File entropy analysis
- Mass file modification detection
- Suspicious extension monitoring

### Application Control
- Process whitelisting/blacklisting
- Network application firewall
- Registry protection

## Development

### Code Quality
```bash
cargo make dev        # Format, check, and lint
cargo make clippy     # Run clippy
cargo make fmt        # Format code
```

### Documentation
```bash
cargo make doc
```

## Resources

### Microsoft Official
- [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) - Rust driver platform
- [Windows-rust-driver-samples](https://github.com/microsoft/Windows-rust-driver-samples) - Official samples
- [WDK Documentation](https://docs.microsoft.com/windows-hardware/drivers/)
- [KMDF Reference](https://docs.microsoft.com/windows-hardware/drivers/wdf/summary-of-framework-objects)

### Kernel Callbacks
- [Filtering Registry Calls](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls)
- [ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [ObCallback Sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/obcallback-callback-registration-driver/)

### Filesystem Minifilters
- [File System Minifilter Drivers](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-minifilter-drivers)

### Network Filtering
- [Windows Filtering Platform](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [wfp-rs](https://github.com/dlon/wfp-rs) - Rust WFP bindings

### Memory Management
- [Using MDLs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)
- [Memory Management for Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-memory-for-drivers)

### ETW
- [Adding ETW to Kernel-Mode Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/adding-event-tracing-to-kernel-mode-drivers)

## License

MIT OR Apache-2.0
