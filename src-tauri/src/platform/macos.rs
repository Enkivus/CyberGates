use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{AppError, AppResult};
use crate::models::{
    now_rfc3339, CheckResult, CheckStatus, FirewallRule, FirewallSnapshot, InstalledApp,
    NetworkConnection, NetworkInterface, NetworkSnapshot, Severity, StartupInventory, StartupItem,
};
use crate::platform::PlatformAudit;
use crate::security::process::{run_optional, run_optional_with_limit, CommandOutput};

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

    fn firewall_snapshot(&self) -> AppResult<Option<FirewallSnapshot>> {
        let tool = "/usr/libexec/ApplicationFirewall/socketfilterfw";
        let Some(list) = run_optional(tool, &["--listapps"], TOOL_TIMEOUT) else {
            return Err(AppError::Internal(
                "could not run the macOS Application Firewall tool".to_string(),
            ));
        };
        if !list.success {
            return Err(AppError::Internal(
                "macOS Application Firewall rules could not be read".to_string(),
            ));
        }

        let enabled = run_optional(tool, &["--getglobalstate"], TOOL_TIMEOUT)
            .filter(|output| output.success)
            .and_then(|output| parse_firewall_enabled(&output.stdout));
        let stealth_mode = run_optional(tool, &["--getstealthmode"], TOOL_TIMEOUT)
            .filter(|output| output.success)
            .and_then(|output| parse_stealth_mode(&output.stdout));
        let block_all = run_optional(tool, &["--getblockall"], TOOL_TIMEOUT)
            .filter(|output| output.success)
            .and_then(|output| parse_block_all(&output.stdout));
        let allow_signed = run_optional(tool, &["--getallowsigned"], TOOL_TIMEOUT)
            .filter(|output| output.success)
            .map(|output| parse_allow_signed(&output.stdout));
        let (allow_signed_builtin, allow_signed_downloaded) = allow_signed.unwrap_or((None, None));

        Ok(Some(FirewallSnapshot {
            enabled,
            stealth_mode,
            block_all,
            allow_signed_builtin,
            allow_signed_downloaded,
            rules: parse_firewall_rules(&list.stdout),
            fetched_at: now_rfc3339(),
            source: "macOS Application Firewall (socketfilterfw)".to_string(),
        }))
    }

    fn installed_apps(&self) -> AppResult<Vec<InstalledApp>> {
        let mut apps = Vec::new();

        if let Some(output) = run_optional_with_limit(
            "/usr/sbin/system_profiler",
            &["SPApplicationsDataType", "-json"],
            Duration::from_secs(30),
            8 * 1024 * 1024,
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

    fn startup_inventory(&self) -> AppResult<StartupInventory> {
        let mut directories = vec![
            (PathBuf::from("/Library/LaunchAgents"), "System"),
            (PathBuf::from("/Library/LaunchDaemons"), "System"),
        ];
        if let Some(home) = dirs::home_dir() {
            directories.push((home.join("Library/LaunchAgents"), "Current user"));
        }

        let mut items = Vec::new();
        let mut unreadable = 0;
        let mut examined = 0;
        let mut truncated = false;
        for (directory, scope) in &directories {
            match fs::read_dir(directory) {
                Ok(entries) => {
                    for entry in entries {
                        if examined >= 5000 {
                            truncated = true;
                            break;
                        }
                        examined += 1;
                        let Ok(entry) = entry else {
                            unreadable += 1;
                            continue;
                        };
                        if let Some(item) = startup_item(&entry.path(), scope) {
                            items.push(item);
                        }
                        if items.len() >= 1000 {
                            break;
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => unreadable += 1,
            }
            if items.len() >= 1000 {
                break;
            }
        }

        items.sort_by(|a, b| {
            a.scope
                .cmp(&b.scope)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        let warnings = if unreadable > 0 {
            vec![format!(
                "{unreadable} startup directory entries could not be read."
            )]
        } else {
            Vec::new()
        };
        let mut warnings = warnings;
        if truncated {
            warnings.push("Inventory stopped after examining 5,000 directory entries.".to_string());
        }

        Ok(StartupInventory {
            available: true,
            items,
            fetched_at: now_rfc3339(),
            source: "macOS launchd property-list directories".to_string(),
            scope_note: "Lists regular .plist files in /Library/LaunchAgents, /Library/LaunchDaemons, and the current user's ~/Library/LaunchAgents. This does not include every macOS Login Item, prove that a job is loaded, or assess the referenced program.".to_string(),
            warnings,
        })
    }

    fn connections(&self) -> AppResult<Vec<NetworkConnection>> {
        let mut connections = Vec::new();
        for args in [
            vec!["-nP", "-iTCP", "-sTCP:ESTABLISHED"],
            vec!["-nP", "-iTCP", "-sTCP:LISTEN"],
            vec!["-nP", "-iUDP"],
        ] {
            if let Some(output) = run_optional("/usr/sbin/lsof", &args, Duration::from_secs(8)) {
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

    fn network_snapshot(&self) -> AppResult<NetworkSnapshot> {
        let ifconfig = run_optional_with_limit(
            "/sbin/ifconfig",
            &["-a"],
            Duration::from_secs(8),
            2 * 1024 * 1024,
        );
        let dns = run_optional_with_limit(
            "/usr/sbin/scutil",
            &["--dns"],
            Duration::from_secs(8),
            2 * 1024 * 1024,
        );
        let mut warnings = Vec::new();
        let interfaces = match ifconfig.filter(|output| output.success) {
            Some(output) => parse_interfaces(&output.stdout),
            None => {
                warnings.push("Interface configuration could not be read.".to_string());
                Vec::new()
            }
        };
        let dns_servers = match dns.filter(|output| output.success) {
            Some(output) => parse_dns_servers(&output.stdout),
            None => {
                warnings.push("DNS resolver configuration could not be read.".to_string());
                Vec::new()
            }
        };
        let available = warnings.len() < 2;
        Ok(NetworkSnapshot {
            available,
            interfaces,
            dns_servers,
            fetched_at: now_rfc3339(),
            source: "macOS ifconfig and system resolver configuration".to_string(),
            scope_note: "Read-only local interface addresses and configured DNS resolver addresses. DNS servers are reported as configured; CyberGates does not assess their trustworthiness or intercept DNS traffic.".to_string(),
            warnings,
        })
    }
}

fn parse_interfaces(text: &str) -> Vec<NetworkInterface> {
    let mut interfaces: Vec<NetworkInterface> = Vec::new();
    for line in text.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':') {
            let name = line.split(':').next().unwrap_or_default().trim();
            if !name.is_empty() && name.len() <= 64 {
                let up = line
                    .split('<')
                    .nth(1)
                    .and_then(|flags| flags.split('>').next())
                    .is_some_and(|flags| flags.split(',').any(|flag| flag == "UP"));
                interfaces.push(NetworkInterface {
                    name: name.to_string(),
                    addresses: Vec::new(),
                    up,
                });
            }
            continue;
        }
        let Some(interface) = interfaces.last_mut() else {
            continue;
        };
        let trimmed = line.trim();
        let address = trimmed
            .strip_prefix("inet ")
            .and_then(|rest| rest.split_whitespace().next())
            .or_else(|| {
                trimmed
                    .strip_prefix("inet6 ")
                    .and_then(|rest| rest.split_whitespace().next())
            });
        if let Some(address) = address {
            if !interface
                .addresses
                .iter()
                .any(|existing| existing == address)
            {
                interface.addresses.push(address.to_string());
            }
        }
    }
    interfaces.retain(|interface| interface.up || !interface.addresses.is_empty());
    interfaces
}

fn parse_dns_servers(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().starts_with("nameserver[") {
            let server = value.trim();
            if !server.is_empty()
                && server.len() <= 128
                && !servers.iter().any(|item| item == server)
            {
                servers.push(server.to_string());
            }
        }
    }
    servers
}

fn startup_item(path: &Path, scope: &str) -> Option<StartupItem> {
    if path.extension()?.to_string_lossy().to_ascii_lowercase() != "plist" {
        return None;
    }
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let name = path.file_stem()?.to_string_lossy().trim().to_string();
    if name.is_empty() {
        return None;
    }
    let modified_at = metadata
        .modified()
        .ok()
        .map(chrono::DateTime::<chrono::Utc>::from)
        .map(|time| time.to_rfc3339());
    Some(StartupItem {
        name,
        path: path.to_string_lossy().to_string(),
        scope: scope.to_string(),
        modified_at,
    })
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
    let text = out("/usr/bin/fdesetup", &["status"])
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
    let text = out("/usr/bin/csrutil", &["status"])
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
    let text = out("/usr/sbin/spctl", &["--status"])
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
    let info = out("/usr/bin/sw_vers", &["-productVersion"])
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
    let text = out("/usr/sbin/sysadminctl", &["-screenLock", "status"])
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
    let text = out("/usr/sbin/softwareupdate", &["--schedule"])
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
    let ssh_loaded = out("/bin/launchctl", &["print", "system/com.openssh.sshd"])
        .map(|o| o.success)
        .unwrap_or(false);
    let port_22 = out("/usr/sbin/lsof", &["-nP", "-iTCP:22", "-sTCP:LISTEN"])
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
    let text = out("/usr/sbin/lsof", &["-nP", "-iTCP:5900", "-sTCP:LISTEN"])
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
        "/usr/bin/defaults",
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
    let destinations = out("/usr/bin/tmutil", &["destinationinfo"])
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
    let latest = out("/usr/bin/tmutil", &["latestbackup"])
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

fn parse_firewall_enabled(stdout: &str) -> Option<bool> {
    if stdout.contains("State = 1") {
        Some(true)
    } else if stdout.contains("State = 0") {
        Some(false)
    } else {
        None
    }
}

fn parse_stealth_mode(stdout: &str) -> Option<bool> {
    let lower = stdout.to_lowercase();
    if lower.contains("stealth mode is on") {
        Some(true)
    } else if lower.contains("stealth mode is off") {
        Some(false)
    } else {
        None
    }
}

fn parse_block_all(stdout: &str) -> Option<bool> {
    let lower = stdout.to_lowercase();
    if lower.contains("set to enabled") {
        Some(true)
    } else if lower.contains("set to disabled") {
        Some(false)
    } else {
        None
    }
}

fn parse_allow_signed(stdout: &str) -> (Option<bool>, Option<bool>) {
    let mut builtin = None;
    let mut downloaded = None;
    for line in stdout.lines() {
        let lower = line.to_lowercase();
        let value = if lower.contains("enabled") {
            Some(true)
        } else if lower.contains("disabled") {
            Some(false)
        } else {
            None
        };
        if lower.contains("built-in signed software") {
            builtin = value;
        } else if lower.contains("downloaded signed software") {
            downloaded = value;
        }
    }
    (builtin, downloaded)
}

fn parse_firewall_rules(stdout: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    let mut pending_path: Option<String> = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((index, rest)) = trimmed.split_once(':') {
            if index.trim().parse::<usize>().is_ok() {
                if let Some(path) = pending_path.take() {
                    rules.push(FirewallRule {
                        path,
                        action: "Unknown".to_string(),
                    });
                }
                pending_path = Some(rest.trim().to_string());
                continue;
            }
        }
        if let Some(path) = pending_path.take() {
            let action = trimmed.trim_matches(|c| c == '(' || c == ')').trim();
            let action = if action.is_empty() {
                "Unknown".to_string()
            } else {
                action.to_string()
            };
            rules.push(FirewallRule { path, action });
        }
    }

    if let Some(path) = pending_path {
        rules.push(FirewallRule {
            path,
            action: "Unknown".to_string(),
        });
    }
    rules
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
    fn parses_firewall_rules() {
        let output = "Total number of apps = 2 \n\n1 : /Applications/Example.app \n             (Allow incoming connections)\n2 : /usr/libexec/example\n             (Block incoming connections)\n";
        let rules = parse_firewall_rules(output);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].path, "/Applications/Example.app");
        assert_eq!(rules[0].action, "Allow incoming connections");
        assert_eq!(rules[1].action, "Block incoming connections");
    }

    #[test]
    fn parses_firewall_state_flags() {
        assert_eq!(
            parse_firewall_enabled("Firewall is enabled. (State = 1)"),
            Some(true)
        );
        assert_eq!(
            parse_firewall_enabled("Firewall is disabled. (State = 0)"),
            Some(false)
        );
        assert_eq!(
            parse_stealth_mode("Firewall stealth mode is on"),
            Some(true)
        );
        assert_eq!(
            parse_block_all("Firewall has block all state set to disabled."),
            Some(false)
        );
        assert_eq!(
            parse_allow_signed("Automatically allow built-in signed software ENABLED.\nAutomatically allow downloaded signed software DISABLED."),
            (Some(true), Some(false))
        );
    }

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
    fn startup_inventory_only_includes_regular_plist_files() {
        use std::os::unix::fs::symlink;

        let directory =
            std::env::temp_dir().join(format!("cybergates-startup-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let plist = directory.join("com.example.agent.plist");
        let other = directory.join("notes.txt");
        let link = directory.join("linked-agent.plist");
        fs::write(&plist, "fixture plist contents").unwrap();
        fs::write(&other, "not a startup file").unwrap();
        symlink(&plist, &link).unwrap();

        let item = startup_item(&plist, "Current user").unwrap();
        assert_eq!(item.name, "com.example.agent");
        assert_eq!(item.scope, "Current user");
        assert_eq!(item.path, plist.to_string_lossy());
        assert!(item.modified_at.is_some());
        assert!(startup_item(&other, "Current user").is_none());
        assert!(startup_item(&link, "Current user").is_none());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "reads live firewall state; run explicitly on macOS"]
    fn live_firewall_smoke() {
        let snapshot = MacOsAdapter
            .firewall_snapshot()
            .expect("live firewall read")
            .expect("macOS snapshot");
        assert!(snapshot.enabled.is_some());
        assert!(!snapshot.rules.is_empty(), "expected firewall app rules");
    }

    #[test]
    #[ignore = "reads live system inventory; run explicitly on macOS"]
    fn live_inventory_smoke() {
        let apps = MacOsAdapter.installed_apps().expect("live inventory");
        assert!(!apps.is_empty(), "expected at least one installed item");
    }

    #[test]
    #[ignore = "reads startup plist file names from standard macOS directories"]
    fn live_startup_inventory_smoke() {
        let inventory = MacOsAdapter
            .startup_inventory()
            .expect("live startup inventory");
        assert!(inventory.available);
        assert_eq!(inventory.source, "macOS launchd property-list directories");
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

    #[test]
    fn parses_interface_addresses_and_state() {
        let interfaces = parse_interfaces("en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX>\n\tinet 192.168.1.20 netmask 0xffffff00\n\tinet6 fe80::1%en0 prefixlen 64\nlo0: flags=8049<UP,LOOPBACK,RUNNING>\n\tinet 127.0.0.1 netmask 0xff000000\n");
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name, "en0");
        assert!(interfaces[0].up);
        assert_eq!(interfaces[0].addresses, ["192.168.1.20", "fe80::1%en0"]);
        assert_eq!(interfaces[1].name, "lo0");
        assert_eq!(interfaces[1].addresses, ["127.0.0.1"]);
    }

    #[test]
    fn parses_dns_resolvers_without_duplicates() {
        let servers = parse_dns_servers("resolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : 1.1.1.1\nresolver #2\n  nameserver[0] : 192.168.1.1\n");
        assert_eq!(servers, ["192.168.1.1", "1.1.1.1"]);
    }
}
