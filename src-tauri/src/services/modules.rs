use crate::models::ModuleStatus;

pub fn list() -> Vec<ModuleStatus> {
    let macos = cfg!(target_os = "macos");
    let linux = cfg!(target_os = "linux");
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
            status: if macos { "partial" } else { "planned" }.to_string(),
            detail: if macos {
                "XProtect presence is verified. File scanning, real-time protection, and quarantine are not implemented yet.".to_string()
            } else {
                "No native malware-protection integration is implemented for this platform.".to_string()
            },
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
            status: if macos || linux { "partial" } else { "unavailable" }.to_string(),
            detail: if macos {
                "Installed application and Homebrew inventory is live. Homebrew patch-declared CVEs can be matched against a downloaded advisory database with explicit freshness and scope; coverage is not complete.".to_string()
            } else if linux {
                "Installed packages are inventoried through a supported native package database. Linux package advisory matching is not implemented.".to_string()
            } else {
                "Installed-software inventory is not implemented for this platform yet.".to_string()
            },
        },
        ModuleStatus {
            id: "network".to_string(),
            name: "Network Security".to_string(),
            status: if macos || linux { "partial" } else { "unavailable" }.to_string(),
            detail: if macos {
                "Read-only socket, interface-address, and DNS resolver inventory is available. Discovery, scanning, and DNS reputation checks are not implemented.".to_string()
            } else if linux {
                "Read-only interface-address and configured resolver inventory is available. Socket ownership, discovery, scanning, and DNS reputation checks are not implemented.".to_string()
            } else {
                "Read-only network connection and configuration inventory is unavailable on this platform.".to_string()
            },
        },
        ModuleStatus {
            id: "firewall".to_string(),
            name: "Firewall".to_string(),
            status: if macos || linux {
                "partial"
            } else {
                "unavailable"
            }
            .to_string(),
            detail: if macos {
                "Read-only macOS Application Firewall state and per-application rules are live. Rule changes, impact preview, and revert are not implemented.".to_string()
            } else if linux {
                "Read-only UFW/firewalld status and nftables ruleset visibility are reported independently. This is partial coverage, not a complete policy audit; Linux posture scoring and firewall changes are unavailable.".to_string()
            } else {
                "Read-only firewall inspection is not implemented for this platform yet.".to_string()
            },
        },
        ModuleStatus {
            id: "monitoring".to_string(),
            name: "System Monitoring".to_string(),
            status: "partial".to_string(),
            detail: if macos {
                "Process inventory, launchd startup files, and current-user loaded jobs are available. System services, event monitoring, and behavioral detection are not implemented.".to_string()
            } else if linux {
                "Process inventory, XDG autostart file listing, enabled systemd service units, and current-user loaded units are available. Event monitoring and behavioral detection are not implemented.".to_string()
            } else {
                "Process inventory is available; native startup and service inventories are not implemented on this platform.".to_string()
            },
        },
        ModuleStatus {
            id: "privacy".to_string(),
            name: "Privacy".to_string(),
            status: if macos { "partial" } else { "planned" }.to_string(),
            detail: if macos {
                "Screen lock, guest account, and FileVault signals are audited. Application permission and browser auditing are not implemented.".to_string()
            } else {
                "Native privacy posture checks are not implemented for this platform. Application permission and browser auditing are not available.".to_string()
            },
        },
        ModuleStatus {
            id: "account".to_string(),
            name: "Account Security".to_string(),
            status: "partial".to_string(),
            detail: "A private local checklist is available; marks are temporary and do not inspect accounts or persist. Provider integrations are not implemented. CyberGates will never collect passwords or authentication codes.".to_string(),
        },
        ModuleStatus {
            id: "incident-response".to_string(),
            name: "Incident Response".to_string(),
            status: "partial".to_string(),
            detail: "Local cases can be created from posture findings with linked evidence, timeline notes, status history, and JSON/HTML exports. System response actions and independent remediation verification are not implemented.".to_string(),
        },
        ModuleStatus {
            id: "backup".to_string(),
            name: "Backup and Recovery".to_string(),
            status: if macos { "partial" } else { "planned" }.to_string(),
            detail: if macos {
                "Time Machine metadata is checked. Restore verification is not performed.".to_string()
            } else {
                "Native backup inventory and restore verification are not implemented for this platform.".to_string()
            },
        },
        ModuleStatus {
            id: "toolkit".to_string(),
            name: "Security Toolkit".to_string(),
            status: "partial".to_string(),
            detail: "Local file hashing and bounded signature inspection, user-triggered DNS/TLS host diagnostics, and a bounded read-only CyberGates application log viewer are available. Reputation verdicts, malware scanning, and operating-system event monitoring are not implemented.".to_string(),
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
            detail: "Audit and incident history with sanitized JSON/HTML exports are implemented. Scan reports depend on the malware scanner, which is not implemented.".to_string(),
        },
        ModuleStatus {
            id: "settings".to_string(),
            name: "Settings".to_string(),
            status: "available".to_string(),
            detail: "Theme, retention, notification preference, and local data locations are configurable.".to_string(),
        },
    ]
}
