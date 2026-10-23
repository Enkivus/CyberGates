use std::time::Duration;

use crate::error::{AppError, AppResult};
use crate::models::{
    now_rfc3339, CheckResult, CheckStatus, InstalledApp, NetworkConnection, Severity,
};
use crate::platform::PlatformAudit;
use crate::security::process::{run_optional, CommandOutput};

const SOURCE: &str = "macOS native tooling";
const TOOL_TIMEOUT: Duration = Duration::from_secs(6);

pub struct MacOsAdapter;

impl PlatformAudit for MacOsAdapter {
    fn platform_name(&self) -> &'static str {
        "macOS"
    }

    fn supported(&self) -> bool {
        true
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "Checks run locally with read-only native tools; no settings are changed.".to_string(),
            "Some results may require Full Disk Access or administrator rights.".to_string(),
        ]
    }

    fn audit(&self) -> Vec<CheckResult> {
        vec![
            firewall_check(),
            stealth_mode_check(),
            filevault_check(),
            sip_check(),
            gatekeeper_check(),
            os_supported_check(),
            screen_lock_check(),
            auto_updates_check(),
            remote_login_check(),
            screen_sharing_check(),
            guest_account_check(),
            backup_check(),
            xprotect_check(),
        ]
    }

    fn installed_apps(&self) -> AppResult<Vec<InstalledApp>> {
        let mut apps = Vec::new();

        if let Some(output) = run_optional(
            "/usr/sbin/system_profiler",
            &["SPApplicationsDataType", "-json"],
            Duration::from_secs(30),
        ) {
            if !output.stdout.trim().is_empty() {
                apps.extend(parse_system_profiler(&output.stdout)?);
            }
        }

        for brew in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] {
            if let Some(output) =
                run_optional(brew, &["list", "--versions"], Duration::from_secs(12))
            {
                apps.extend(parse_brew(&output.stdout));
                break;
            }
        }

        apps.sort_by_key(|a| a.name.to_lowercase());
        apps.dedup_by(|a, b| {
            a.name.eq_ignore_ascii_case(&b.name) && a.version == b.version && a.source == b.source
        });
        apps.truncate(2000);
        Ok(apps)
    }

    fn connections(&self) -> AppResult<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        for args in [
            vec!["-nP", "-iTCP", "-sTCP:ESTABLISHED"],
            vec!["-nP", "-iTCP", "-sTCP:LISTEN"],
            vec!["-nP", "-iUDP"],
        ] {
            if let Some(output) = run_optional("lsof", &args, Duration::from_secs(8)) {
                connections.extend(parse_lsof(&output));
            }
        }
        connections.sort_by(|a, b| {
            a.process
                .as_deref()
                .unwrap_or("")
                .cmp(b.process.as_deref().unwrap_or(""))
                .then_with(|| a.local_address.cmp(&b.local_address))
        });
        connections.dedup();
        connections.truncate(500);
        Ok(connections)
    }
}

fn out(program: &str, args: &[&str]) -> Option<CommandOutput> {
    run_optional(program, args, TOOL_TIMEOUT)
}

#[allow(clippy::too_many_arguments)]
fn make(
    id: &str,
    title: &str,
    category: &str,
    status: CheckStatus,
    severity: Severity,
    weight: u32,
    evidence: impl Into<String>,
    explanation: impl Into<String>,
    remediation: impl Into<String>,
    verification: impl Into<String>,
) -> CheckResult {
    CheckResult {
        id: id.to_string(),
        title: title.to_string(),
        category: category.to_string(),
        status,
        severity,
        weight,
        evidence: evidence.into(),
        explanation: explanation.into(),
        remediation: remediation.into(),
        verification: verification.into(),
        source: SOURCE.to_string(),
        checked_at: now_rfc3339(),
    }
}

fn firewall_check() -> CheckResult {
    let output = out(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    );
    let text = output.as_ref().map(|o| o.combined()).unwrap_or_default();
    let lower = text.to_lowercase();
    let status = if lower.contains("enabled") {
        CheckStatus::Pass
    } else if lower.contains("disabled") {
        CheckStatus::Fail
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.firewall",
        "Application firewall",
        "firewall",
        status,
        Severity::High,
        20,
        if text.is_empty() {
            "No readable response from socketfilterfw".to_string()
        } else {
            text
        },
        "The macOS application firewall filters unsolicited inbound connections. Disabling it removes an important local network boundary.",
        "Open System Settings > Network > Firewall and turn the firewall on.",
        "Re-run the audit; this check should report 'enabled'.",
    )
}

fn stealth_mode_check() -> CheckResult {
    let text = out(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getstealthmode"],
    )
    .map(|o| o.combined())
    .unwrap_or_default();
    let status = if text.to_lowercase().contains("stealth mode is on") {
        CheckStatus::Pass
    } else if text.to_lowercase().contains("off") {
        CheckStatus::Warning
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.firewall_stealth",
        "Firewall stealth mode",
        "firewall",
        status,
        Severity::Low,
        3,
        text,
        "Stealth mode makes the device less responsive to unsolicited probes. It is optional hardening, not a substitute for the firewall.",
        "Enable stealth mode in System Settings > Network > Firewall > Options if it fits your network.",
        "Re-run the audit and confirm stealth mode reports on.",
    )
}

fn filevault_check() -> CheckResult {
    let text = out("fdesetup", &["status"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let lower = text.to_lowercase();
    let status = if lower.contains("filevault is on") {
        CheckStatus::Pass
    } else if lower.contains("filevault is off") {
        CheckStatus::Fail
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.filevault",
        "FileVault disk encryption",
        "encryption",
        status,
        Severity::High,
        20,
        text,
        "FileVault encrypts the startup disk, protecting data at rest if the device is lost or stolen.",
        "Open System Settings > Privacy & Security > FileVault and turn it on. Store the recovery key safely.",
        "Run 'fdesetup status' or re-run the audit; FileVault should report On.",
    )
}

fn sip_check() -> CheckResult {
    let text = out("csrutil", &["status"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let lower = text.to_lowercase();
    let status = if lower.contains("enabled") {
        CheckStatus::Pass
    } else if lower.contains("disabled") {
        CheckStatus::Fail
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.sip",
        "System Integrity Protection",
        "system",
        status,
        Severity::High,
        10,
        text,
        "System Integrity Protection restricts modifications to protected system locations and is a core macOS defense.",
        "Enable SIP from macOS Recovery using 'csrutil enable'. Only do this if you understand the implications.",
        "Run 'csrutil status'; it should report enabled.",
    )
}

fn gatekeeper_check() -> CheckResult {
    let text = out("spctl", &["--status"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let lower = text.to_lowercase();
    let status = if lower.contains("assessments enabled") {
        CheckStatus::Pass
    } else if lower.contains("disabled") {
        CheckStatus::Fail
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.gatekeeper",
        "Gatekeeper app verification",
        "system",
        status,
        Severity::High,
        10,
        text,
        "Gatekeeper verifies app signatures and notarization before allowing unknown software to run.",
        "Enable Gatekeeper in System Settings > Privacy & Security > Security ('Allow applications from: App Store and identified developers').",
        "Run 'spctl --status'; assessments should be enabled.",
    )
}

fn os_supported_check() -> CheckResult {
    let info = out("sw_vers", &["-productVersion"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let major = info
        .split('.')
        .next()
        .and_then(|v| v.trim().parse::<u32>().ok());
    let status = match major {
        Some(major) if major >= 13 => CheckStatus::Pass,
        Some(_) => CheckStatus::Fail,
        None => CheckStatus::Unavailable,
    };
    make(
        "macos.os_supported",
        "Supported operating system",
        "system",
        status,
        Severity::High,
        10,
        if info.is_empty() {
            "Could not determine macOS version".to_string()
        } else {
            format!("macOS {info}")
        },
        "CyberGates targets macOS 13 or newer. Older releases stop receiving security fixes.",
        "Upgrade to a supported macOS release through System Settings > General > Software Update.",
        "Re-run the audit and confirm the macOS version is 13 or newer.",
    )
}

fn screen_lock_check() -> CheckResult {
    let text = out("sysadminctl", &["-screenLock", "status"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let lower = text.to_lowercase();
    let status = if lower.contains("immediate") {
        CheckStatus::Pass
    } else if lower.contains("is off") || lower.contains("off") {
        CheckStatus::Fail
    } else if lower.contains("delay is") {
        let seconds = lower
            .split("delay is")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok());
        match seconds {
            Some(value) if value <= 300 => CheckStatus::Pass,
            Some(_) => CheckStatus::Warning,
            None => CheckStatus::Unavailable,
        }
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.screen_lock",
        "Screen lock requires authentication",
        "privacy",
        status,
        Severity::Medium,
        10,
        text,
        "A screen lock requires credentials after sleep or idle time, limiting physical access to an unlocked session.",
        "Set 'Require password after screen saver begins or display is turned off' to Immediately or a short delay in System Settings > Lock Screen.",
        "Re-run the audit or run 'sysadminctl -screenLock status'; the delay should be immediate or short.",
    )
}

fn auto_updates_check() -> CheckResult {
    let text = out("softwareupdate", &["--schedule"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let lower = text.to_lowercase();
    let status = if lower.contains("turned on") {
        CheckStatus::Pass
    } else if lower.contains("turned off") {
        CheckStatus::Warning
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.auto_updates",
        "Automatic security update checks",
        "updates",
        status,
        Severity::Medium,
        8,
        text,
        "Automatic update checks reduce the time a known vulnerability remains unpatched. This check only verifies the schedule, not whether every update is installed.",
        "Enable automatic updates in System Settings > General > Software Update.",
        "Run 'softwareupdate --schedule'; automatic checking should be turned on.",
    )
}

fn remote_login_check() -> CheckResult {
    let ssh_loaded = out("launchctl", &["print", "system/com.openssh.sshd"])
        .map(|o| o.success)
        .unwrap_or(false);
    let port_22 = out("lsof", &["-nP", "-iTCP:22", "-sTCP:LISTEN"])
        .map(|o| o.combined().lines().count() > 1)
        .unwrap_or(false);
    let enabled = ssh_loaded || port_22;
    make(
        "macos.remote_login",
        "Remote login (SSH) exposure",
        "network",
        if enabled { CheckStatus::Warning } else { CheckStatus::Pass },
        Severity::Medium,
        10,
        format!(
            "ssh service loaded: {}; TCP/22 listener: {}",
            ssh_loaded, port_22
        ),
        "Remote Login exposes an SSH server to the network. Keep it off unless you intentionally administer this Mac remotely.",
        "Turn off Remote Login in System Settings > General > Sharing if it is not needed.",
        "Re-run the audit; no TCP/22 listener should be reported.",
    )
}

fn screen_sharing_check() -> CheckResult {
    let text = out("lsof", &["-nP", "-iTCP:5900", "-sTCP:LISTEN"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let listening = text.lines().count() > 1;
    make(
        "macos.screen_sharing",
        "Screen sharing exposure",
        "network",
        if listening { CheckStatus::Warning } else { CheckStatus::Pass },
        Severity::Medium,
        5,
        if listening {
            "A TCP/5900 listener was detected".to_string()
        } else {
            "No TCP/5900 listener detected".to_string()
        },
        "Screen Sharing on port 5900 allows remote desktop access. Keep it disabled unless required and restrict who can connect.",
        "Disable Screen Sharing in System Settings > General > Sharing if unused.",
        "Re-run the audit; no TCP/5900 listener should be reported.",
    )
}

fn guest_account_check() -> CheckResult {
    let output = out(
        "defaults",
        &[
            "read",
            "/Library/Preferences/com.apple.loginwindow",
            "GuestEnabled",
        ],
    );
    let text = output.as_ref().map(|o| o.combined()).unwrap_or_default();
    let value = text.trim();
    let status = if value == "0" {
        CheckStatus::Pass
    } else if value == "1" {
        CheckStatus::Fail
    } else {
        CheckStatus::Unavailable
    };
    make(
        "macos.guest_account",
        "Guest account disabled",
        "privacy",
        status,
        Severity::Low,
        5,
        if text.is_empty() {
            "GuestEnabled could not be read".to_string()
        } else {
            format!("GuestEnabled = {value}")
        },
        "A guest account allows local sign-in without a personal credential and can expose a shared session.",
        "Disable the guest user in System Settings > Users & Groups.",
        "Re-run the audit; GuestEnabled should equal 0.",
    )
}

fn backup_check() -> CheckResult {
    let destinations = out("tmutil", &["destinationinfo"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let configured = destinations.to_lowercase().contains("name");
    if !configured {
        return make(
            "macos.backup",
            "Time Machine backup destination",
            "backup",
            CheckStatus::Warning,
            Severity::Medium,
            8,
            if destinations.is_empty() {
                "No Time Machine destination information available".to_string()
            } else {
                destinations
            },
            "No Time Machine destination was reported. Backups reduce data loss after ransomware, theft, or disk failure.",
            "Configure a backup destination in System Settings > General > Time Machine.",
            "Run 'tmutil destinationinfo'; at least one destination should be listed.",
        );
    }
    let latest = out("tmutil", &["latestbackup"])
        .map(|o| o.combined())
        .unwrap_or_default();
    let verified = !latest.is_empty() && !latest.to_lowercase().contains("no backups");
    make(
        "macos.backup",
        "Time Machine backup destination",
        "backup",
        if verified { CheckStatus::Pass } else { CheckStatus::Warning },
        Severity::Medium,
        8,
        if verified {
            format!("Destination configured; latest snapshot: {latest}")
        } else {
            "Destination configured, but backup recency could not be verified".to_string()
        },
        "A configured destination is not proof that a recent restore point exists. CyberGates only inspects backup metadata; it does not test a restore.",
        "Open Time Machine and confirm a recent successful backup, then test a restore when practical.",
        "Run 'tmutil latestbackup' and verify the returned snapshot is recent.",
    )
}

fn xprotect_check() -> CheckResult {
    let paths = [
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
        "/Library/Apple/System/Library/CoreServices/XProtect.app",
    ];
    let found: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|p| std::path::Path::new(p).exists())
        .collect();
    make(
        "macos.xprotect",
        "Apple XProtect signatures present",
        "threat_protection",
        if found.is_empty() { CheckStatus::Warning } else { CheckStatus::Pass },
        Severity::Medium,
        5,
        if found.is_empty() {
            "XProtect bundle/app was not found at the expected system paths".to_string()
        } else {
            format!("Found: {}", found.join(", "))
        },
        "XProtect is Apple's built-in malware signature mechanism. CyberGates does not replace or reconfigure it; it only verifies presence.",
        "Install current macOS security updates; XProtect is maintained by Apple. Do not remove system protection components.",
        "Re-run the audit; XProtect files should exist under /Library/Apple/System/Library/CoreServices.",
    )
}

fn parse_system_profiler(json: &str) -> AppResult<Vec<InstalledApp>> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|err| AppError::Internal(format!("invalid system_profiler JSON: {err}")))?;
    let entries = value
        .get("SPApplicationsDataType")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    Ok(entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("_name")?.as_str()?.trim().to_string();
            if name.is_empty() {
                return None;
            }
            let signed_by = entry
                .get("signed_by")
                .and_then(|value| value.as_array())
                .and_then(|array| array.first())
                .and_then(|value| value.as_str())
                .map(str::to_string);
            Some(InstalledApp {
                name,
                version: entry
                    .get("version")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                source: "Application".to_string(),
                path: entry
                    .get("path")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                signed_by,
                obtained_from: entry
                    .get("obtained_from")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
            })
        })
        .collect())
}

fn parse_brew(stdout: &str) -> Vec<InstalledApp> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?.to_string();
            let versions: Vec<&str> = fields.collect();
            Some(InstalledApp {
                name,
                version: if versions.is_empty() {
                    None
                } else {
                    Some(versions.join(" "))
                },
                source: "Homebrew".to_string(),
                path: None,
                signed_by: None,
                obtained_from: Some("homebrew".to_string()),
            })
        })
        .collect()
}

fn parse_lsof(output: &CommandOutput) -> Vec<NetworkConnection> {
    let mut connections = Vec::new();
    for line in output.stdout.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let process = fields[0].to_string();
        let pid = fields[1].parse::<u32>().ok();
        let protocol = fields[7].to_uppercase();
        let name = fields[8..].join(" ");
        let state = if let Some(start) = name.find('(') {
            name[start + 1..].trim_end_matches(')').to_string()
        } else {
            String::new()
        };
        let address = name.split_whitespace().next().unwrap_or("").to_string();
        let (local_address, remote_address) =
            if let Some((local, remote)) = address.split_once("->") {
                (local.to_string(), remote.to_string())
            } else {
                (address, String::new())
            };
        if protocol.is_empty() {
            continue;
        }
        connections.push(NetworkConnection {
            protocol,
            local_address,
            remote_address,
            state,
            pid,
            process: Some(process),
        });
    }
    connections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_profiler_json() {
        let json = r#"{
          "SPApplicationsDataType": [
            {"_name":"Example","version":"1.2.3","path":"/Applications/Example.app","obtained_from":"identified_developer","signed_by":["Developer ID Application: Example (ABC)"]},
            {"_name":"","version":"1.0"}
          ]
        }"#;
        let apps = parse_system_profiler(json).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "Example");
        assert_eq!(apps[0].version.as_deref(), Some("1.2.3"));
        assert_eq!(
            apps[0].signed_by.as_deref(),
            Some("Developer ID Application: Example (ABC)")
        );
    }

    #[test]
    fn parses_brew_versions() {
        let apps = parse_brew("jq 1.7.1\nopenssl@3 3.5.1\n");
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].source, "Homebrew");
        assert_eq!(apps[1].version.as_deref(), Some("3.5.1"));
    }

    #[test]
    #[ignore = "reads live system inventory; run explicitly on macOS"]
    fn live_inventory_smoke() {
        let apps = MacOsAdapter.installed_apps().expect("live inventory");
        assert!(!apps.is_empty(), "expected at least one installed item");
    }

    #[test]
    fn parses_lsof_lines() {
        let output = CommandOutput {
            success: true,
            stdout: "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nsafari 42 me 9u IPv4 0x1 0t0 TCP 192.168.1.2:5555->1.1.1.1:443 (ESTABLISHED)\nrapportd 7 me 14u IPv6 0x2 0t0 TCP *:49404 (LISTEN)\n".to_string(),
            stderr: String::new(),
        };
        let connections = parse_lsof(&output);
        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0].protocol, "TCP");
        assert_eq!(connections[0].remote_address, "1.1.1.1:443");
        assert_eq!(connections[0].state, "ESTABLISHED");
        assert_eq!(connections[1].local_address, "*:49404");
    }
}
