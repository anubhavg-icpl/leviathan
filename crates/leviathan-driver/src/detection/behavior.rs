//! Behavioral Analysis Engine
//!
//! Correlates events over time to detect complex attack patterns
//! that span multiple events and processes.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use super::{Alert, DetectionContext, ProcessActivity, Severity, MitreTactic, RecommendedAction};

/// Behavioral analyzer trait
pub trait BehaviorAnalyzer {
    /// Analyze current context against cached activity
    fn analyze(
        &self,
        context: &DetectionContext,
        process_cache: &BTreeMap<u32, ProcessActivity>,
    ) -> Option<Alert>;

    /// Get analyzer name
    fn name(&self) -> &'static str;
}

/// Process tree analyzer - detects suspicious parent-child relationships
pub struct ProcessTreeAnalyzer {
    /// Suspicious parent processes
    suspicious_parents: Vec<[u8; 64]>,
    /// Known LOLBins (Living off the Land binaries)
    lolbins: Vec<[u8; 64]>,
}

impl ProcessTreeAnalyzer {
    pub fn new() -> Self {
        Self {
            suspicious_parents: Vec::new(),
            lolbins: Vec::new(),
        }
    }

    /// Load known suspicious patterns
    pub fn load_patterns(&mut self) {
        // Suspicious when spawning cmd/powershell
        let suspicious = [
            b"winword.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"excel.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"outlook.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"powerpnt.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ];

        for s in &suspicious {
            self.suspicious_parents.push(*s);
        }

        // LOLBins commonly abused
        let lolbins = [
            b"cmd.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"powershell.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"wscript.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"cscript.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"mshta.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"regsvr32.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"rundll32.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"certutil.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            b"bitsadmin.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ];

        for l in &lolbins {
            self.lolbins.push(*l);
        }
    }
}

impl BehaviorAnalyzer for ProcessTreeAnalyzer {
    fn analyze(
        &self,
        _context: &DetectionContext,
        _process_cache: &BTreeMap<u32, ProcessActivity>,
    ) -> Option<Alert> {
        // Would check parent-child relationships against suspicious patterns
        None
    }

    fn name(&self) -> &'static str {
        "ProcessTreeAnalyzer"
    }
}

/// Injection detector - detects various injection techniques
pub struct InjectionDetector {
    /// Threshold for remote thread alerts
    remote_thread_threshold: u32,
}

impl InjectionDetector {
    pub fn new() -> Self {
        Self {
            remote_thread_threshold: 3,
        }
    }
}

impl BehaviorAnalyzer for InjectionDetector {
    fn analyze(
        &self,
        context: &DetectionContext,
        process_cache: &BTreeMap<u32, ProcessActivity>,
    ) -> Option<Alert> {
        // Check if process has created many remote threads
        if let Some(activity) = process_cache.get(&context.pid) {
            if activity.remote_threads >= self.remote_thread_threshold {
                return Some(Alert {
                    id: 0,
                    rule_id: 1000,
                    severity: Severity::High,
                    tactic: MitreTactic::DefenseEvasion,
                    technique_id: *b"T1055   ",
                    title: *b"Multiple_Remote_Threads\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    description: [0u8; 512],
                    source_pid: context.pid,
                    target_pid: None,
                    timestamp: 0,
                    event_ids: Vec::new(),
                    action: RecommendedAction::Alert,
                });
            }
        }
        None
    }

    fn name(&self) -> &'static str {
        "InjectionDetector"
    }
}

/// Ransomware detector - behavioral patterns
pub struct RansomwareDetector {
    /// File operations threshold for alerting
    file_op_threshold: u32,
    /// Time window in seconds
    time_window_sec: u64,
    /// High entropy threshold
    entropy_threshold: f64,
}

impl RansomwareDetector {
    pub fn new() -> Self {
        Self {
            file_op_threshold: 100, // 100 file ops
            time_window_sec: 60,    // per minute
            entropy_threshold: 7.5, // High entropy indicates encryption
        }
    }
}

impl BehaviorAnalyzer for RansomwareDetector {
    fn analyze(
        &self,
        context: &DetectionContext,
        process_cache: &BTreeMap<u32, ProcessActivity>,
    ) -> Option<Alert> {
        if let Some(activity) = process_cache.get(&context.pid) {
            // Check for rapid file operations
            if activity.files_accessed >= self.file_op_threshold {
                return Some(Alert {
                    id: 0,
                    rule_id: 2000,
                    severity: Severity::Critical,
                    tactic: MitreTactic::Impact,
                    technique_id: *b"T1486   ",
                    title: *b"Ransomware_Behavior\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    description: [0u8; 512],
                    source_pid: context.pid,
                    target_pid: None,
                    timestamp: 0,
                    event_ids: Vec::new(),
                    action: RecommendedAction::Terminate,
                });
            }
        }
        None
    }

    fn name(&self) -> &'static str {
        "RansomwareDetector"
    }
}

/// Lateral movement detector
pub struct LateralMovementDetector {
    /// Monitored remote admin tools
    remote_tools: Vec<[u8; 64]>,
}

impl LateralMovementDetector {
    pub fn new() -> Self {
        let remote_tools = vec![
            *b"psexec.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"wmic.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"winrs.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ];
        Self { remote_tools }
    }
}

impl BehaviorAnalyzer for LateralMovementDetector {
    fn analyze(
        &self,
        _context: &DetectionContext,
        _process_cache: &BTreeMap<u32, ProcessActivity>,
    ) -> Option<Alert> {
        // Would detect lateral movement patterns
        None
    }

    fn name(&self) -> &'static str {
        "LateralMovementDetector"
    }
}

/// Credential access detector
pub struct CredentialAccessDetector {
    /// Protected process names
    protected_processes: Vec<[u8; 64]>,
}

impl CredentialAccessDetector {
    pub fn new() -> Self {
        let protected = vec![
            *b"lsass.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"csrss.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"winlogon.exe\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ];
        Self { protected_processes: protected }
    }
}

impl BehaviorAnalyzer for CredentialAccessDetector {
    fn analyze(
        &self,
        _context: &DetectionContext,
        _process_cache: &BTreeMap<u32, ProcessActivity>,
    ) -> Option<Alert> {
        // Would detect credential access attempts
        None
    }

    fn name(&self) -> &'static str {
        "CredentialAccessDetector"
    }
}

/// Anomaly score calculator
pub struct AnomalyScorer {
    /// Baseline activity levels
    baseline: ProcessActivityBaseline,
}

/// Baseline activity for anomaly detection
#[derive(Debug, Clone, Default)]
pub struct ProcessActivityBaseline {
    /// Average threads created per process
    pub avg_threads: f64,
    /// Average images loaded per process
    pub avg_images: f64,
    /// Average file operations per minute
    pub avg_file_ops_per_min: f64,
    /// Average registry operations per minute
    pub avg_registry_ops_per_min: f64,
    /// Average network connections per process
    pub avg_network_conns: f64,
}

impl AnomalyScorer {
    pub fn new() -> Self {
        Self {
            baseline: ProcessActivityBaseline::default(),
        }
    }

    /// Calculate anomaly score (0-100)
    pub fn calculate_score(&self, activity: &ProcessActivity) -> u32 {
        let mut score = 0u32;

        // Check deviation from baseline
        if activity.threads_created as f64 > self.baseline.avg_threads * 3.0 {
            score += 20;
        }

        if activity.images_loaded as f64 > self.baseline.avg_images * 2.0 {
            score += 15;
        }

        if activity.files_accessed as f64 > self.baseline.avg_file_ops_per_min * 5.0 {
            score += 25;
        }

        if activity.remote_threads > 0 {
            score += 30;
        }

        if activity.suspicious_count > 0 {
            score += activity.suspicious_count * 10;
        }

        core::cmp::min(score, 100)
    }

    /// Update baseline with new observation
    pub fn update_baseline(&mut self, activity: &ProcessActivity) {
        // Simple exponential moving average
        let alpha = 0.1;

        self.baseline.avg_threads =
            self.baseline.avg_threads * (1.0 - alpha) + activity.threads_created as f64 * alpha;
        self.baseline.avg_images =
            self.baseline.avg_images * (1.0 - alpha) + activity.images_loaded as f64 * alpha;
    }
}
