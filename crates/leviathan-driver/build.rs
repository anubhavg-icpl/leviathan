//! Build script for the Leviathan Windows driver
//!
//! This script configures the WDK build environment and generates
//! necessary FFI bindings for Windows Driver Kit APIs.

fn main() -> Result<(), wdk_build::ConfigError> {
    // Configure WDK linking and generate bindings
    wdk_build::Config::from_env_auto()?.configure_binary_build()
}
