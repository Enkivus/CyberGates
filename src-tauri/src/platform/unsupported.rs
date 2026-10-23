use crate::models::{now_rfc3339, CheckResult, CheckStatus, Severity};
use crate::platform::PlatformAudit;

pub struct UnsupportedAdapter;

impl PlatformAudit for UnsupportedAdapter {
    fn platform_name(&self) -> &'static str {
        std::env::consts::OS
    }

    fn supported(&self) -> bool {
        false
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "No native audit adapter is implemented for this operating system yet.".to_string(),
            "CyberGates reports no security claims on unsupported platforms rather than guessing."
                .to_string(),
        ]
    }

    fn audit(&self) -> Vec<CheckResult> {
        vec![CheckResult {
            id: "platform.unsupported".to_string(),
            title: "Platform audit adapter unavailable".to_string(),
            category: "platform".to_string(),
            status: CheckStatus::Unavailable,
            severity: Severity::Info,
            weight: 0,
            evidence: format!("Operating system: {}", std::env::consts::OS),
            explanation: "CyberGates does not yet implement native security checks for this operating system. No protection status or score is claimed.".to_string(),
            remediation: "Run CyberGates on a supported platform or wait for this platform adapter to be implemented and verified.".to_string(),
            verification: "Re-run the audit after installing a CyberGates release that explicitly supports this platform.".to_string(),
            source: "CyberGates capability detection".to_string(),
            checked_at: now_rfc3339(),
        }]
    }
}
