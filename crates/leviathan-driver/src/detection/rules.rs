//! Detection Rules Engine
//!
//! Pattern-based detection rules for identifying malicious activity.

use alloc::vec::Vec;
use super::{DetectionContext, EventType, Severity, MitreTactic};

/// Detection rule definition
#[derive(Debug, Clone)]
pub struct DetectionRule {
    /// Unique rule ID
    pub id: u32,
    /// Rule name
    pub name: [u8; 64],
    /// Severity level
    pub severity: Severity,
    /// MITRE tactic
    pub tactic: MitreTactic,
    /// MITRE technique ID
    pub technique_id: [u8; 8],
    /// Is rule enabled
    pub enabled: bool,
    /// Rule type
    pub rule_type: RuleType,
    /// Rule conditions
    pub conditions: Vec<RuleCondition>,
}

/// Types of detection rules
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RuleType {
    /// Process creation events
    ProcessCreation,
    /// Thread creation events
    ThreadCreation,
    /// Process access (handle operations)
    ProcessAccess,
    /// Image/DLL load events
    ImageLoad,
    /// File operations
    FileOp,
    /// Registry modifications
    RegistryMod,
    /// Network activity
    Network,
    /// Memory operations
    MemoryMod,
    /// Composite (multiple event types)
    Composite,
}

/// Rule condition
#[derive(Debug, Clone)]
pub struct RuleCondition {
    /// Field to check
    pub field: ConditionField,
    /// Operator
    pub operator: ConditionOperator,
    /// Value to compare
    pub value: ConditionValue,
}

/// Fields that can be checked in conditions
#[derive(Debug, Clone, Copy)]
pub enum ConditionField {
    ProcessName,
    ParentProcessName,
    ImagePath,
    CommandLine,
    TargetProcessName,
    RegistryPath,
    RegistryValue,
    FilePath,
    FileExtension,
    RemoteAddress,
    RemotePort,
    IsElevated,
    IsSystem,
}

/// Condition operators
#[derive(Debug, Clone, Copy)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Matches, // Regex
    GreaterThan,
    LessThan,
    In, // In a list
}

/// Condition values
#[derive(Debug, Clone)]
pub enum ConditionValue {
    String([u8; 256]),
    StringList(Vec<[u8; 256]>),
    Number(u64),
    Boolean(bool),
}

impl DetectionRule {
    /// Check if rule matches event type
    pub fn matches_event_type(&self, event_type: EventType) -> bool {
        match self.rule_type {
            RuleType::ProcessCreation => matches!(event_type, EventType::ProcessCreate),
            RuleType::ThreadCreation => matches!(event_type, EventType::ThreadCreate),
            RuleType::ProcessAccess => matches!(event_type, EventType::HandleOp),
            RuleType::ImageLoad => matches!(event_type, EventType::ImageLoad),
            RuleType::FileOp => matches!(event_type, EventType::FileOp),
            RuleType::RegistryMod => matches!(event_type, EventType::RegistryOp),
            RuleType::Network => matches!(event_type, EventType::NetworkOp),
            RuleType::MemoryMod => matches!(event_type, EventType::MemoryOp),
            RuleType::Composite => true, // Check all events
        }
    }

    /// Evaluate rule conditions against context
    pub fn evaluate_conditions(&self, context: &DetectionContext) -> bool {
        if self.conditions.is_empty() {
            // No conditions means rule matches by event type only
            // In production, you'd want more specific matching
            return false;
        }

        for condition in &self.conditions {
            if !evaluate_condition(condition, context) {
                return false;
            }
        }

        true
    }
}

/// Evaluate a single condition
fn evaluate_condition(condition: &RuleCondition, context: &DetectionContext) -> bool {
    match condition.field {
        ConditionField::ProcessName => {
            match_string(&context.process_name, &condition.operator, &condition.value)
        }
        ConditionField::IsElevated => {
            if let ConditionValue::Boolean(expected) = condition.value {
                context.is_elevated == expected
            } else {
                false
            }
        }
        ConditionField::IsSystem => {
            if let ConditionValue::Boolean(expected) = condition.value {
                context.is_system == expected
            } else {
                false
            }
        }
        _ => {
            // Other field types would be implemented similarly
            false
        }
    }
}

/// Match string against condition
fn match_string(value: &[u8], operator: &ConditionOperator, expected: &ConditionValue) -> bool {
    let ConditionValue::String(expected_bytes) = expected else {
        return false;
    };

    // Find null terminator
    let value_len = value.iter().position(|&b| b == 0).unwrap_or(value.len());
    let expected_len = expected_bytes.iter().position(|&b| b == 0).unwrap_or(expected_bytes.len());

    let value_slice = &value[..value_len];
    let expected_slice = &expected_bytes[..expected_len];

    match operator {
        ConditionOperator::Equals => value_slice == expected_slice,
        ConditionOperator::NotEquals => value_slice != expected_slice,
        ConditionOperator::Contains => {
            // Simple substring search
            if expected_len > value_len {
                return false;
            }
            for i in 0..=(value_len - expected_len) {
                if &value_slice[i..i + expected_len] == expected_slice {
                    return true;
                }
            }
            false
        }
        ConditionOperator::StartsWith => {
            value_len >= expected_len && &value_slice[..expected_len] == expected_slice
        }
        ConditionOperator::EndsWith => {
            value_len >= expected_len && &value_slice[value_len - expected_len..] == expected_slice
        }
        _ => false,
    }
}

/// Predefined rule sets
pub mod rulesets {
    use super::*;

    /// Get credential theft detection rules
    pub fn credential_theft_rules() -> Vec<DetectionRule> {
        vec![
            // LSASS memory access
            DetectionRule {
                id: 100,
                name: *b"LSASS_Memory_Access\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Critical,
                tactic: MitreTactic::CredentialAccess,
                technique_id: *b"T1003.01",
                enabled: true,
                rule_type: RuleType::ProcessAccess,
                conditions: vec![],
            },
            // SAM registry access
            DetectionRule {
                id: 101,
                name: *b"SAM_Registry_Access\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::High,
                tactic: MitreTactic::CredentialAccess,
                technique_id: *b"T1003.02",
                enabled: true,
                rule_type: RuleType::RegistryMod,
                conditions: vec![],
            },
        ]
    }

    /// Get process injection detection rules
    pub fn injection_rules() -> Vec<DetectionRule> {
        vec![
            // CreateRemoteThread
            DetectionRule {
                id: 200,
                name: *b"CreateRemoteThread_Injection\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::High,
                tactic: MitreTactic::DefenseEvasion,
                technique_id: *b"T1055.01",
                enabled: true,
                rule_type: RuleType::ThreadCreation,
                conditions: vec![],
            },
            // APC injection
            DetectionRule {
                id: 201,
                name: *b"APC_Injection\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::High,
                tactic: MitreTactic::DefenseEvasion,
                technique_id: *b"T1055.04",
                enabled: true,
                rule_type: RuleType::MemoryMod,
                conditions: vec![],
            },
            // Process hollowing
            DetectionRule {
                id: 202,
                name: *b"Process_Hollowing\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Critical,
                tactic: MitreTactic::DefenseEvasion,
                technique_id: *b"T1055.12",
                enabled: true,
                rule_type: RuleType::MemoryMod,
                conditions: vec![],
            },
        ]
    }

    /// Get persistence detection rules
    pub fn persistence_rules() -> Vec<DetectionRule> {
        vec![
            // Registry Run key
            DetectionRule {
                id: 300,
                name: *b"Registry_Run_Key_Modification\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Medium,
                tactic: MitreTactic::Persistence,
                technique_id: *b"T1547.01",
                enabled: true,
                rule_type: RuleType::RegistryMod,
                conditions: vec![],
            },
            // Scheduled task creation
            DetectionRule {
                id: 301,
                name: *b"Scheduled_Task_Creation\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Medium,
                tactic: MitreTactic::Persistence,
                technique_id: *b"T1053.05",
                enabled: true,
                rule_type: RuleType::ProcessCreation,
                conditions: vec![],
            },
            // Service creation
            DetectionRule {
                id: 302,
                name: *b"Service_Creation\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Medium,
                tactic: MitreTactic::Persistence,
                technique_id: *b"T1543.03",
                enabled: true,
                rule_type: RuleType::RegistryMod,
                conditions: vec![],
            },
        ]
    }

    /// Get defense evasion detection rules
    pub fn defense_evasion_rules() -> Vec<DetectionRule> {
        vec![
            // AMSI bypass
            DetectionRule {
                id: 400,
                name: *b"AMSI_Bypass_Attempt\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::High,
                tactic: MitreTactic::DefenseEvasion,
                technique_id: *b"T1562.01",
                enabled: true,
                rule_type: RuleType::MemoryMod,
                conditions: vec![],
            },
            // ETW patching
            DetectionRule {
                id: 401,
                name: *b"ETW_Patching\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::High,
                tactic: MitreTactic::DefenseEvasion,
                technique_id: *b"T1562.01",
                enabled: true,
                rule_type: RuleType::MemoryMod,
                conditions: vec![],
            },
        ]
    }

    /// Get ransomware detection rules
    pub fn ransomware_rules() -> Vec<DetectionRule> {
        vec![
            // High entropy file write
            DetectionRule {
                id: 500,
                name: *b"High_Entropy_File_Write\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::High,
                tactic: MitreTactic::Impact,
                technique_id: *b"T1486   ",
                enabled: true,
                rule_type: RuleType::FileOp,
                conditions: vec![],
            },
            // Mass file rename
            DetectionRule {
                id: 501,
                name: *b"Mass_File_Rename\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Critical,
                tactic: MitreTactic::Impact,
                technique_id: *b"T1486   ",
                enabled: true,
                rule_type: RuleType::FileOp,
                conditions: vec![],
            },
            // Shadow copy deletion
            DetectionRule {
                id: 502,
                name: *b"Shadow_Copy_Deletion\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                severity: Severity::Critical,
                tactic: MitreTactic::Impact,
                technique_id: *b"T1490   ",
                enabled: true,
                rule_type: RuleType::ProcessCreation,
                conditions: vec![],
            },
        ]
    }
}
