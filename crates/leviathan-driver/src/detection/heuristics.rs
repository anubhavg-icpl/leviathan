//! Heuristic Detection Engine
//!
//! Known attack pattern detection using heuristic rules.

use alloc::vec::Vec;
use super::{DetectionContext, Severity};

/// Heuristic check result
#[derive(Debug, Clone)]
pub struct HeuristicResult {
    /// Heuristic ID
    pub id: u32,
    /// Heuristic name
    pub name: &'static str,
    /// Detection confidence (0-100)
    pub confidence: u8,
    /// Severity if detected
    pub severity: Severity,
    /// Description
    pub description: &'static str,
}

/// Command line heuristics
pub mod cmdline {
    use super::*;

    /// Check for encoded PowerShell commands
    pub fn check_encoded_powershell(cmdline: &[u16]) -> Option<HeuristicResult> {
        // Look for -EncodedCommand, -enc, -e with base64
        let cmdline_str = String::from_utf16_lossy(cmdline);
        let lower = cmdline_str.to_lowercase();

        if lower.contains("-encodedcommand") || lower.contains("-enc ") || lower.contains(" -e ") {
            if lower.contains("powershell") {
                return Some(HeuristicResult {
                    id: 1001,
                    name: "EncodedPowerShell",
                    confidence: 85,
                    severity: Severity::High,
                    description: "PowerShell with encoded command detected",
                });
            }
        }

        None
    }

    /// Check for suspicious download cradles
    pub fn check_download_cradle(cmdline: &[u16]) -> Option<HeuristicResult> {
        let cmdline_str = String::from_utf16_lossy(cmdline);
        let lower = cmdline_str.to_lowercase();

        // Common download patterns
        let patterns = [
            "downloadstring",
            "downloadfile",
            "wget",
            "curl",
            "invoke-webrequest",
            "iwr ",
            "bits transfer",
            "certutil -urlcache",
            "bitsadmin /transfer",
        ];

        for pattern in &patterns {
            if lower.contains(pattern) {
                return Some(HeuristicResult {
                    id: 1002,
                    name: "DownloadCradle",
                    confidence: 70,
                    severity: Severity::Medium,
                    description: "Potential download cradle detected",
                });
            }
        }

        None
    }

    /// Check for obfuscation techniques
    pub fn check_obfuscation(cmdline: &[u16]) -> Option<HeuristicResult> {
        let cmdline_str = String::from_utf16_lossy(cmdline);

        // Check for excessive carets (cmd.exe obfuscation)
        let caret_count = cmdline_str.matches('^').count();
        if caret_count > 5 {
            return Some(HeuristicResult {
                id: 1003,
                name: "CaretObfuscation",
                confidence: 75,
                severity: Severity::Medium,
                description: "Command line caret obfuscation detected",
            });
        }

        // Check for string concatenation
        if cmdline_str.contains("'+'") || cmdline_str.contains("\"+\"") {
            return Some(HeuristicResult {
                id: 1004,
                name: "StringConcatenation",
                confidence: 60,
                severity: Severity::Low,
                description: "Command line string concatenation detected",
            });
        }

        None
    }

    /// Check for credential dumping commands
    pub fn check_credential_access(cmdline: &[u16]) -> Option<HeuristicResult> {
        let cmdline_str = String::from_utf16_lossy(cmdline);
        let lower = cmdline_str.to_lowercase();

        let patterns = [
            "sekurlsa",
            "lsadump",
            "procdump",
            "comsvcs.dll",
            "minidump",
            "ntdsutil",
            "shadowcopy",
        ];

        for pattern in &patterns {
            if lower.contains(pattern) {
                return Some(HeuristicResult {
                    id: 1005,
                    name: "CredentialAccess",
                    confidence: 90,
                    severity: Severity::Critical,
                    description: "Potential credential dumping detected",
                });
            }
        }

        None
    }

    use alloc::string::String;
}

/// File path heuristics
pub mod filepath {
    use super::*;

    /// Check for suspicious file locations
    pub fn check_suspicious_location(path: &[u16]) -> Option<HeuristicResult> {
        let path_str = String::from_utf16_lossy(path);
        let lower = path_str.to_lowercase();

        // Executables in temp directories
        if (lower.contains("\\temp\\") || lower.contains("\\tmp\\"))
            && (lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".scr"))
        {
            return Some(HeuristicResult {
                id: 2001,
                name: "TempExecutable",
                confidence: 65,
                severity: Severity::Medium,
                description: "Executable in temporary directory",
            });
        }

        // Double extensions
        let suspicious_doubles = [".doc.exe", ".pdf.exe", ".txt.exe", ".jpg.exe"];
        for ext in &suspicious_doubles {
            if lower.ends_with(ext) {
                return Some(HeuristicResult {
                    id: 2002,
                    name: "DoubleExtension",
                    confidence: 85,
                    severity: Severity::High,
                    description: "Suspicious double file extension",
                });
            }
        }

        // AppData executables
        if lower.contains("\\appdata\\") && lower.ends_with(".exe") {
            return Some(HeuristicResult {
                id: 2003,
                name: "AppDataExecutable",
                confidence: 50,
                severity: Severity::Low,
                description: "Executable in AppData directory",
            });
        }

        None
    }

    /// Check for suspicious file names
    pub fn check_suspicious_name(path: &[u16]) -> Option<HeuristicResult> {
        let path_str = String::from_utf16_lossy(path);
        let lower = path_str.to_lowercase();

        // Extract filename
        let filename = lower.rsplit('\\').next().unwrap_or(&lower);

        // Random-looking names (high entropy)
        if filename.len() > 8 {
            let alpha_count = filename.chars().filter(|c| c.is_alphabetic()).count();
            let digit_count = filename.chars().filter(|c| c.is_numeric()).count();

            if digit_count > alpha_count && digit_count > 4 {
                return Some(HeuristicResult {
                    id: 2004,
                    name: "RandomFileName",
                    confidence: 55,
                    severity: Severity::Low,
                    description: "Potentially randomly generated filename",
                });
            }
        }

        // Known malware names (simplified)
        let known_bad = ["mimikatz", "lazagne", "rubeus", "seatbelt"];
        for name in &known_bad {
            if filename.contains(name) {
                return Some(HeuristicResult {
                    id: 2005,
                    name: "KnownMalwareName",
                    confidence: 95,
                    severity: Severity::Critical,
                    description: "Known malware tool name detected",
                });
            }
        }

        None
    }

    use alloc::string::String;
}

/// Registry heuristics
pub mod registry {
    use super::*;

    /// Check for persistence registry keys
    pub fn check_persistence_key(key_path: &[u16]) -> Option<HeuristicResult> {
        let key_str = String::from_utf16_lossy(key_path);
        let lower = key_str.to_lowercase();

        let persistence_keys = [
            "\\software\\microsoft\\windows\\currentversion\\run",
            "\\software\\microsoft\\windows\\currentversion\\runonce",
            "\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
            "\\software\\microsoft\\windows nt\\currentversion\\winlogon",
            "\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
            "\\system\\currentcontrolset\\services",
            "\\software\\classes\\clsid",
            "\\software\\classes\\\\shell\\open\\command",
        ];

        for key in &persistence_keys {
            if lower.contains(key) {
                return Some(HeuristicResult {
                    id: 3001,
                    name: "PersistenceRegistry",
                    confidence: 75,
                    severity: Severity::Medium,
                    description: "Modification to persistence registry key",
                });
            }
        }

        None
    }

    /// Check for security product tampering
    pub fn check_security_tampering(key_path: &[u16], _value: &[u8]) -> Option<HeuristicResult> {
        let key_str = String::from_utf16_lossy(key_path);
        let lower = key_str.to_lowercase();

        let security_keys = [
            "\\software\\policies\\microsoft\\windows defender",
            "\\software\\microsoft\\amsi",
            "\\system\\currentcontrolset\\control\\lsa",
        ];

        for key in &security_keys {
            if lower.contains(key) {
                return Some(HeuristicResult {
                    id: 3002,
                    name: "SecurityTampering",
                    confidence: 85,
                    severity: Severity::High,
                    description: "Potential security product tampering",
                });
            }
        }

        None
    }

    use alloc::string::String;
}

/// Network heuristics
pub mod network {
    use super::*;

    /// Known malicious IP ranges (simplified)
    pub fn check_suspicious_ip(ip: u32) -> Option<HeuristicResult> {
        // Example: Check for TOR exit nodes, known C2, etc.
        // This would use real threat intelligence in production

        // RFC 1918 from external process might be C2 pivoting
        let is_private = (ip & 0xFF000000 == 0x0A000000)  // 10.x.x.x
            || (ip & 0xFFF00000 == 0xAC100000)  // 172.16.x.x - 172.31.x.x
            || (ip & 0xFFFF0000 == 0xC0A80000); // 192.168.x.x

        // Suspicious ports
        None
    }

    /// Check for suspicious ports
    pub fn check_suspicious_port(port: u16) -> Option<HeuristicResult> {
        // Common C2/backdoor ports
        let suspicious_ports = [
            4444,  // Metasploit default
            5555,  // Various RATs
            1337,  // Common backdoor
            31337, // Elite/Back Orifice
            6666,  // IRC bots
            6667,  // IRC
            8080,  // HTTP proxy (suspicious outbound)
            8443,  // HTTPS alt
        ];

        if suspicious_ports.contains(&port) {
            return Some(HeuristicResult {
                id: 4001,
                name: "SuspiciousPort",
                confidence: 60,
                severity: Severity::Medium,
                description: "Connection to commonly malicious port",
            });
        }

        None
    }

    /// Check for beaconing behavior
    pub fn check_beaconing(
        connection_times: &[u64],
        _threshold_variance: f64,
    ) -> Option<HeuristicResult> {
        if connection_times.len() < 5 {
            return None;
        }

        // Calculate intervals between connections
        let mut intervals: Vec<i64> = Vec::new();
        for i in 1..connection_times.len() {
            intervals.push((connection_times[i] - connection_times[i - 1]) as i64);
        }

        // Calculate variance - low variance = regular beaconing
        if intervals.len() > 2 {
            let mean: f64 = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
            let variance: f64 = intervals
                .iter()
                .map(|&x| {
                    let diff = x as f64 - mean;
                    diff * diff
                })
                .sum::<f64>()
                / intervals.len() as f64;

            // Low variance relative to mean indicates regular intervals
            let cv = variance.sqrt() / mean; // Coefficient of variation

            if cv < 0.1 && intervals.len() >= 5 {
                return Some(HeuristicResult {
                    id: 4002,
                    name: "BeaconingBehavior",
                    confidence: 80,
                    severity: Severity::High,
                    description: "Regular network beaconing pattern detected",
                });
            }
        }

        None
    }
}

/// Run all heuristics against context
pub fn run_all_heuristics(context: &DetectionContext) -> Vec<HeuristicResult> {
    let mut results = Vec::new();

    // Command line checks
    if let Some(r) = cmdline::check_encoded_powershell(&context.command_line) {
        results.push(r);
    }
    if let Some(r) = cmdline::check_download_cradle(&context.command_line) {
        results.push(r);
    }
    if let Some(r) = cmdline::check_obfuscation(&context.command_line) {
        results.push(r);
    }
    if let Some(r) = cmdline::check_credential_access(&context.command_line) {
        results.push(r);
    }

    // File path checks
    if let Some(r) = filepath::check_suspicious_location(&context.image_path) {
        results.push(r);
    }
    if let Some(r) = filepath::check_suspicious_name(&context.image_path) {
        results.push(r);
    }

    results
}
