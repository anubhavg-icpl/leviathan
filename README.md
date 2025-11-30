# Leviathan

Windows kernel-mode driver development in Rust using Microsoft's [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs).

## Overview

Leviathan is a sample KMDF (Kernel-Mode Driver Framework) driver demonstrating:

- Driver lifecycle management (DriverEntry, DriverUnload)
- Device creation and I/O queue handling
- IOCTL (Device I/O Control) processing
- User-mode/kernel-mode communication via device interface

## Project Structure

```
leviathan/
├── crates/
│   ├── leviathan-driver/     # Kernel-mode driver (cdylib)
│   │   ├── src/
│   │   │   ├── lib.rs        # Driver entry point
│   │   │   ├── device.rs     # Device management
│   │   │   └── ioctl.rs      # IOCTL handlers
│   │   └── build.rs          # WDK build configuration
│   └── leviathan-common/     # Shared types (no_std)
├── .cargo/config.toml        # Cargo build settings
├── Makefile.toml             # cargo-make tasks
├── rust-toolchain.toml       # Nightly toolchain config
└── Cargo.toml                # Workspace manifest
```

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

## Architecture

### KMDF Driver Model

The driver uses Windows Driver Framework (WDF) for kernel-mode:

```
DriverEntry
    └─► WdfDriverCreate
            └─► EvtDriverDeviceAdd (callback)
                    ├─► WdfDeviceCreate
                    ├─► WdfIoQueueCreate
                    └─► WdfDeviceCreateDeviceInterface
```

### I/O Processing

```
User Request ──► I/O Manager ──► KMDF ──► I/O Queue ──► Handler
                                                           │
                                                    EvtIoRead
                                                    EvtIoWrite
                                                    EvtIoDeviceControl
```

## Resources

- [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs) - Microsoft's Rust driver platform
- [Windows-rust-driver-samples](https://github.com/microsoft/Windows-rust-driver-samples) - Official samples
- [WDK Documentation](https://docs.microsoft.com/windows-hardware/drivers/)
- [KMDF Reference](https://docs.microsoft.com/windows-hardware/drivers/wdf/summary-of-framework-objects)

## License

MIT OR Apache-2.0
