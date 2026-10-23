use crate::models::ModuleStatus;

pub fn list() -> Vec<ModuleStatus> {
    let macos = cfg!(target_os = "macos");
    let status = |implemented: bool| -> &'static str {
        if implemented {
            "partial"
        } else {
            "planned"
        }
    };

    vec![
        ModuleStatus {
            id: "overview".to_string(),
            name: "Overview".to_string(),
            status: if macos { "available" } else { "unavailable" }.to_string(),
            detail: if macos {
                "Live posture audit with an explainable weighted score and persisted findings.".to_string()
            } else {
                "No native audit adapter for this platform yet; the dashboard makes no security claims.".to_string()
            },
        },
        ModuleStatus {
            id: "threat-protection".to_string(),
            name: "Threat Protection".to_string(),
            status: status(macos).to_string(),
            detail: "XProtect presence is verified. File scanning, real-time protection, and quarantine are not implemented yet.".to_string(),
        },
        ModuleStatus {
            id: "scanner".to_string(),
            name: "Security Scanner".to_string(),
            status: "planned".to_string(),
            detail: "Scan orchestration, progress, cancellation, and quarantine workflows are not implemented yet.".to_string(),
        },
        ModuleStatus {
            id: "vulnerabilities".to_string(),
            name: "Vulnerabilities".to_string(),
            status: if macos { "partial" } else { "unavailable" }.to_string(),
            detail: if macos {
                "Installed application and Homebrew inventory is live on macOS. Traceable advisory matching and remediation tracking are not implemented, so no vulnerability status is claimed.".to_string()
            } else {
                "Installed-software inventory is not implemented for this platform yet.".to_string()
            },
        },
        ModuleStatus {
            id: "network".to_string(),
            name: "Network Security".to_string(),
            status: "partial".to_string(),
            detail: "Read-only active connection inventory using native tools. Discovery, scanning, and reputation checks are not implemented.".to_string(),
        },
        ModuleStatus {
            id: "firewall".to_string(),
            name: "Firewall".to_string(),
            status: "partial".to_string(),
            detail: "Firewall and stealth-mode status are audited read-only. Rule management and remediation are not implemented yet.".to_string(),
        },
        ModuleStatus {
            id: "monitoring".to_string(),
            name: "System Monitoring".to_string(),
            status: "partial".to_string(),
            detail: "Process inventory is live. Event monitoring, startup items, and behavioral detection are not implemented yet.".to_string(),
        },
        ModuleStatus {
            id: "privacy".to_string(),
            name: "Privacy".to_string(),
            status: "partial".to_string(),
            detail: "Screen lock, guest account, and encryption signals are audited. Application permission and browser auditing are not implemented.".to_string(),
        },
        ModuleStatus {
            id: "account".to_string(),
            name: "Account Security".to_string(),
            status: "planned".to_string(),
            detail: "No account integrations exist. CyberGates will never collect passwords or authentication codes.".to_string(),
        },
        ModuleStatus {
            id: "incident-response".to_string(),
            name: "Incident Response".to_string(),
            status: "planned".to_string(),
            detail: "Incident creation, evidence timelines, and verified response actions are not implemented yet.".to_string(),
        },
        ModuleStatus {
            id: "backup".to_string(),
            name: "Backup and Recovery".to_string(),
            status: "partial".to_string(),
            detail: "Time Machine metadata is checked. Restore verification is not performed.".to_string(),
        },
        ModuleStatus {
            id: "toolkit".to_string(),
            name: "Security Toolkit".to_string(),
            status: "planned".to_string(),
            detail: "Hashing, certificate inspection, DNS tools, and safe file analysis are not implemented yet.".to_string(),
        },
        ModuleStatus {
            id: "devices".to_string(),
            name: "Device Management".to_string(),
            status: "unavailable".to_string(),
            detail: "Requires a separate authenticated backend, which does not exist yet.".to_string(),
        },
        ModuleStatus {
            id: "reports".to_string(),
            name: "Reports and History".to_string(),
            status: "partial".to_string(),
            detail: "Audit history and sanitized JSON/HTML exports are implemented. Scan and incident reports come later.".to_string(),
        },
        ModuleStatus {
            id: "settings".to_string(),
            name: "Settings".to_string(),
            status: "available".to_string(),
            detail: "Theme, retention, notification preference, and local data locations are configurable.".to_string(),
        },
    ]
}
