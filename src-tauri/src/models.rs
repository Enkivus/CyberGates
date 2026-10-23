use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 4,
            Self::High => 3,
            Self::Medium => 2,
            Self::Low => 1,
            Self::Info => 0,
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
    Unavailable,
    NotApplicable,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warning => "warning",
            Self::Fail => "fail",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "pass" => Self::Pass,
            "warning" => Self::Warning,
            "fail" => Self::Fail,
            "unavailable" => Self::Unavailable,
            _ => Self::NotApplicable,
        }
    }

    pub fn is_finding(self) -> bool {
        matches!(self, Self::Warning | Self::Fail)
    }

    pub fn is_scored(self) -> bool {
        matches!(self, Self::Pass | Self::Warning | Self::Fail)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub category: String,
    pub status: CheckStatus,
    pub severity: Severity,
    pub weight: u32,
    pub evidence: String,
    pub explanation: String,
    pub remediation: String,
    pub verification: String,
    pub source: String,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreFactor {
    pub id: String,
    pub title: String,
    pub category: String,
    pub status: CheckStatus,
    pub severity: Severity,
    pub weight: u32,
    pub earned: u32,
    pub evidence: String,
    pub explanation: String,
    pub remediation: String,
    pub verification: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreBreakdown {
    pub score: Option<u8>,
    pub label: String,
    pub earned: u32,
    pub evaluated: u32,
    pub factors: Vec<ScoreFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub audit_id: String,
    pub check_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: String,
    pub category: String,
    pub evidence: String,
    pub explanation: String,
    pub remediation: String,
    pub verification: String,
    pub source: String,
    pub detected_at: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub id: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub score: Option<u8>,
    pub status: String,
    pub platform: String,
    pub findings_count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub cpu_brand: String,
    pub cpu_cores: usize,
    pub memory_total_mb: u64,
    pub uptime_seconds: u64,
    pub platform: String,
    pub supported: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub system: SystemInfo,
    pub score: Option<u8>,
    pub score_label: String,
    pub earned: u32,
    pub evaluated: u32,
    pub factors: Vec<ScoreFactor>,
    pub findings: Vec<Finding>,
    pub counts: SeverityCounts,
    pub last_audit: Option<AuditRecord>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f64,
    pub executable: Option<String>,
    pub run_time_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleStatus {
    pub id: String,
    pub name: String,
    pub status: String,
    pub detail: String,
}

impl Finding {
    pub fn severity_counts(findings: &[Finding]) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for finding in findings.iter().filter(|f| f.resolved_at.is_none()) {
            match finding.severity {
                Severity::Critical => counts.critical += 1,
                Severity::High => counts.high += 1,
                Severity::Medium => counts.medium += 1,
                Severity::Low => counts.low += 1,
                Severity::Info => counts.info += 1,
            }
        }
        counts
    }
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub type Timestamp = DateTime<Utc>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: i64,
    pub at: String,
    pub action: String,
    pub detail: String,
    pub outcome: String,
}
