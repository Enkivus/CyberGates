use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::AppResult;
use crate::models::{
    now_rfc3339, CheckResult, CheckStatus, FirewallBackendStatus, FirewallSnapshot, InstalledApp,
    LoadedService, LoadedServiceInventory, NetworkInterface, NetworkSnapshot, Severity,
    StartupInventory, StartupItem,
};
use crate::platform::PlatformAudit;
use crate::security::process::run_optional_with_limit;
use crate::security::process::CommandOutput;

const SYSTEMCTL_PATHS: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];
const IP_PATHS: &[&str] = &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];
const DPKG_QUERY_PATHS: &[&str] = &["/usr/bin/dpkg-query", "/bin/dpkg-query"];
const RPM_PATHS: &[&str] = &["/usr/bin/rpm", "/bin/rpm"];
const PACMAN_PATHS: &[&str] = &["/usr/bin/pacman", "/bin/pacman"];
const UFW_PATHS: &[&str] = &["/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"];
const FIREWALL_CMD_PATHS: &[&str] = &["/usr/bin/firewall-cmd", "/bin/firewall-cmd"];
const NFT_PATHS: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"];
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(6);
const FIREWALL_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_COMMAND_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_FIREWALL_OUTPUT: usize = 64 * 1024;
const MAX_STARTUP_ITEMS: usize = 1000;
const MAX_EXAMINED_ENTRIES: usize = 5000;
const MAX_OS_RELEASE_BYTES: usize = 64 * 1024;

pub struct LinuxAdapter;

impl PlatformAudit for LinuxAdapter {
    fn platform_name(&self) -> &'static str {
        "Linux"
    }

    // Monitoring inventories exist, but posture checks have not been independently
    // implemented and verified on Linux. Keep scoring unavailable until then.
    fn supported(&self) -> bool {
        false
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "Linux startup configuration and current-user systemd inventories are available.".to_string(),
            "Read-only package names and versions are available through dpkg, RPM, or pacman when detected. Firewall tool observations are partial and separate from posture scoring. Verified Linux posture checks, network socket ownership, and Linux package advisory matching are not implemented; no security score is claimed.".to_string(),
        ]
    }

    fn audit(&self) -> Vec<CheckResult> {
        vec![CheckResult {
            id: "platform.unsupported".to_string(),
            title: "Linux posture audit unavailable".to_string(),
            category: "platform".to_string(),
            status: CheckStatus::Unavailable,
            severity: Severity::Info,
            weight: 0,
            evidence: "Operating system: Linux".to_string(),
            explanation: "CyberGates has partial Linux monitoring inventories but does not yet implement verified Linux security-posture checks. No protection status or score is claimed.".to_string(),
            remediation: "Use the available read-only inventories; re-run the audit after a verified Linux posture adapter is released.".to_string(),
            verification: "Check the platform capability matrix for Linux audit coverage.".to_string(),
            source: "CyberGates capability detection".to_string(),
            checked_at: now_rfc3339(),
        }]
    }

    fn firewall_snapshot(&self) -> AppResult<Option<FirewallSnapshot>> {
        let ufw_output = UFW_PATHS.iter().find_map(|path| {
            run_optional_with_limit(path, &["status"], FIREWALL_TIMEOUT, MAX_FIREWALL_OUTPUT)
        });
        let firewalld_output = FIREWALL_CMD_PATHS.iter().find_map(|path| {
            run_optional_with_limit(path, &["--state"], FIREWALL_TIMEOUT, MAX_FIREWALL_OUTPUT)
        });
        let nft_output = NFT_PATHS.iter().find_map(|path| {
            run_optional_with_limit(
                path,
                &["list", "ruleset"],
                FIREWALL_TIMEOUT,
                MAX_FIREWALL_OUTPUT,
            )
        });

        Ok(Some(FirewallSnapshot {
            enabled: None,
            stealth_mode: None,
            block_all: None,
            allow_signed_builtin: None,
            allow_signed_downloaded: None,
            rules: Vec::new(),
            backends: vec![
                parse_ufw_backend(ufw_output.as_ref()),
                parse_firewalld_backend(firewalld_output.as_ref()),
                parse_nft_backend(nft_output.as_ref()),
            ],
            scope_note: "Reports only the status exposed by UFW, firewalld, or nftables when available. These tools may coexist; no single global firewall state or complete ruleset is inferred, and no firewall configuration is changed.".to_string(),
            fetched_at: now_rfc3339(),
            source: "Linux firewall tools (read-only, partial coverage)".to_string(),
        }))
    }

    fn network_snapshot(&self) -> AppResult<NetworkSnapshot> {
        let mut warnings = Vec::new();
        let output = IP_PATHS.iter().find_map(|path| {
            run_optional_with_limit(
                path,
                &["-o", "address", "show"],
                SYSTEMCTL_TIMEOUT,
                MAX_COMMAND_OUTPUT,
            )
        });
        let (available, interfaces) = match output {
            Some(output) if output.success => (true, parse_ip_addresses(&output.stdout)),
            Some(_) => {
                warnings.push("The ip utility could not read interface addresses.".to_string());
                (false, Vec::new())
            }
            None => {
                warnings
                    .push("The ip utility was not available at known system paths.".to_string());
                (false, Vec::new())
            }
        };
        if interfaces.len() >= 256 {
            warnings.push("Interface inventory was capped at 256 interfaces.".to_string());
        }
        let dns_servers = read_resolver_config(&mut warnings);
        Ok(NetworkSnapshot {
            available,
            interfaces,
            dns_servers,
            fetched_at: now_rfc3339(),
            source: "Linux ip utility, sysfs, and /etc/resolv.conf".to_string(),
            scope_note: "Lists interface addresses visible to the current user and nameserver entries in /etc/resolv.conf. A local stub resolver may be shown instead of upstream DNS servers. This does not assess DNS trust, reputation, or reachability.".to_string(),
            warnings,
        })
    }

    fn installed_apps(&self) -> AppResult<Vec<InstalledApp>> {
        let dpkg_format = "${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\t${source:Package}\\t${source:Version}\\n";
        if let Some(output) = DPKG_QUERY_PATHS.iter().find_map(|path| {
            run_optional_with_limit(
                path,
                &["-W", &format!("--showformat={dpkg_format}")],
                SYSTEMCTL_TIMEOUT,
                MAX_COMMAND_OUTPUT,
            )
        }) {
            if output.success {
                let mut packages = parse_dpkg_packages(&output.stdout);
                if let Some(ecosystem) = read_debian_osv_ecosystem() {
                    for package in &mut packages {
                        package.advisory_ecosystem = Some(ecosystem.clone());
                    }
                }
                return Ok(packages);
            }
        }

        if let Some(output) = PACMAN_PATHS.iter().find_map(|path| {
            run_optional_with_limit(path, &["-Q"], SYSTEMCTL_TIMEOUT, MAX_COMMAND_OUTPUT)
        }) {
            if output.success {
                return Ok(parse_pacman_packages(&output.stdout));
            }
        }

        if let Some(output) = RPM_PATHS.iter().find_map(|path| {
            run_optional_with_limit(
                path,
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
                ],
                SYSTEMCTL_TIMEOUT,
                MAX_COMMAND_OUTPUT,
            )
        }) {
            if output.success {
                return Ok(parse_rpm_packages(&output.stdout));
            }
        }

        Ok(Vec::new())
    }

    fn startup_inventory(&self) -> AppResult<StartupInventory> {
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut examined = 0usize;
        let mut truncated = false;

        for (directory, scope) in autostart_directories() {
            match fs::read_dir(&directory) {
                Ok(entries) => {
                    for entry in entries {
                        if examined >= MAX_EXAMINED_ENTRIES || items.len() >= MAX_STARTUP_ITEMS {
                            truncated = true;
                            break;
                        }
                        examined += 1;
                        let Ok(entry) = entry else {
                            continue;
                        };
                        if let Some(item) = desktop_startup_item(&entry.path(), scope) {
                            items.push(item);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => warnings.push(format!(
                    "Could not read startup directory {}.",
                    directory.display()
                )),
            }
        }

        if let Some(output) = run_systemctl(&[
            "list-unit-files",
            "--type=service",
            "--state=enabled,enabled-runtime",
            "--no-legend",
            "--no-pager",
        ]) {
            if output.success {
                items.extend(parse_enabled_unit_files(&output.stdout, "System"));
            } else {
                warnings.push("System systemd enabled-unit state could not be read.".to_string());
            }
        } else {
            warnings.push(
                "systemctl was not available; enabled system units were not inspected.".to_string(),
            );
        }

        if let Some(output) = run_systemctl(&[
            "--user",
            "list-unit-files",
            "--type=service",
            "--state=enabled,enabled-runtime",
            "--no-legend",
            "--no-pager",
        ]) {
            if output.success {
                items.extend(parse_enabled_unit_files(&output.stdout, "Current user"));
            } else {
                warnings
                    .push("Current-user systemd enabled-unit state could not be read.".to_string());
            }
        } else {
            warnings.push(
                "systemctl was not available; enabled user units were not inspected.".to_string(),
            );
        }

        if items.len() > MAX_STARTUP_ITEMS {
            items.truncate(MAX_STARTUP_ITEMS);
            truncated = true;
        }
        if truncated {
            warnings.push(format!(
                "Startup inventory was capped at {MAX_STARTUP_ITEMS} items after examining at most {MAX_EXAMINED_ENTRIES} directory entries."
            ));
        }
        items.sort_by(|left, right| {
            left.scope
                .cmp(&right.scope)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        items.dedup_by(|left, right| left.scope == right.scope && left.name == right.name);

        Ok(StartupInventory {
            available: true,
            items,
            fetched_at: now_rfc3339(),
            source: "Linux XDG autostart directories and systemd unit files".to_string(),
            scope_note: "Lists regular .desktop files in system/current-user XDG autostart directories and systemd service units marked enabled. File presence does not prove a desktop entry is enabled or executed; enabled systemd units may be activated by their target rather than at boot. No referenced program is inspected.".to_string(),
            warnings,
        })
    }

    fn loaded_services(&self) -> AppResult<LoadedServiceInventory> {
        let output = SYSTEMCTL_PATHS.iter().find_map(|path| {
            run_optional_with_limit(
                path,
                &[
                    "--user",
                    "list-units",
                    "--type=service",
                    "--all",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                ],
                SYSTEMCTL_TIMEOUT,
                MAX_COMMAND_OUTPUT,
            )
        });

        let (available, services, warnings) = match output {
            Some(output) if output.success => {
                let (services, truncated) = parse_loaded_systemd_units(&output.stdout);
                let warnings = if truncated {
                    vec![
                        "Current-user loaded-service inventory was capped at 2,000 units."
                            .to_string(),
                    ]
                } else {
                    Vec::new()
                };
                (true, services, warnings)
            }
            Some(_) => (
                false,
                Vec::new(),
                vec!["systemd could not access the current user's service manager.".to_string()],
            ),
            None => (
                false,
                Vec::new(),
                vec!["systemctl was unavailable or timed out.".to_string()],
            ),
        };

        Ok(LoadedServiceInventory {
            available,
            services,
            fetched_at: now_rfc3339(),
            source: "systemd --user list-units".to_string(),
            scope_note: "Shows units currently loaded by the current user's systemd manager, including inactive loaded units. PID and last-exit status are not included by this provider. System services are excluded; no unit is started, stopped, or changed.".to_string(),
            warnings,
        })
    }
}

fn autostart_directories() -> Vec<(PathBuf, &'static str)> {
    let system_dirs: Vec<PathBuf> = std::env::var_os("XDG_CONFIG_DIRS")
        .map(|value| {
            let paths = PathBuf::from(value);
            std::env::split_paths(&paths)
                .filter(|path| path.is_absolute())
                .collect::<Vec<PathBuf>>()
        })
        .filter(|paths| !paths.is_empty())
        .unwrap_or_else(|| vec![PathBuf::from("/etc/xdg")]);
    let mut directories: Vec<_> = system_dirs
        .into_iter()
        .map(|directory| (directory.join("autostart"), "System"))
        .collect();
    let user_config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")));
    if let Some(user_config) = user_config {
        directories.push((user_config.join("autostart"), "Current user"));
    }
    directories.dedup_by(|left, right| left.0 == right.0);
    directories
}

fn desktop_startup_item(path: &Path, scope: &str) -> Option<StartupItem> {
    if path.extension()?.to_string_lossy().to_ascii_lowercase() != "desktop" {
        return None;
    }
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let file_name = path.file_name()?.to_string_lossy();
    if file_name.len() > 255 || file_name.chars().any(char::is_control) {
        return None;
    }
    Some(StartupItem {
        name: path.file_stem()?.to_string_lossy().to_string(),
        path: path.to_string_lossy().to_string(),
        scope: scope.to_string(),
        modified_at: metadata
            .modified()
            .ok()
            .map(|time| DateTime::<Utc>::from(time).to_rfc3339()),
    })
}

fn parse_ufw_backend(output: Option<&CommandOutput>) -> FirewallBackendStatus {
    let Some(output) = output else {
        return firewall_backend(
            "UFW",
            "Unavailable",
            "UFW was not found at a known system path or could not be started.",
        );
    };
    if !output.success {
        return firewall_backend("UFW", "Unknown", "UFW status could not be read.");
    }
    match output.stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Status:")
            .map(|status| status.trim())
    }) {
        Some("active") => firewall_backend(
            "UFW",
            "Reported active",
            "UFW reports that its firewall service is active.",
        ),
        Some("inactive") => firewall_backend(
            "UFW",
            "Reported inactive",
            "UFW reports that its firewall service is inactive.",
        ),
        _ => firewall_backend("UFW", "Unknown", "UFW returned an unrecognized status."),
    }
}

fn parse_firewalld_backend(output: Option<&CommandOutput>) -> FirewallBackendStatus {
    let Some(output) = output else {
        return firewall_backend(
            "firewalld",
            "Unavailable",
            "firewall-cmd was not found at a known system path or could not be started.",
        );
    };
    match output.combined().as_str() {
        "running" if output.success => firewall_backend(
            "firewalld",
            "Reported running",
            "firewall-cmd reports that the firewalld service is running.",
        ),
        "not running" => firewall_backend(
            "firewalld",
            "Reported stopped",
            "firewall-cmd reports that the firewalld service is not running.",
        ),
        _ => firewall_backend(
            "firewalld",
            "Unknown",
            "firewalld status could not be determined from firewall-cmd.",
        ),
    }
}

fn parse_nft_backend(output: Option<&CommandOutput>) -> FirewallBackendStatus {
    let Some(output) = output else {
        return firewall_backend(
            "nftables",
            "Unavailable",
            "The nft utility was not found at a known system path or could not be started.",
        );
    };
    if !output.success {
        return firewall_backend(
            "nftables",
            "Unknown",
            "The nftables ruleset could not be read; permission may be required.",
        );
    }
    if output.stdout.trim().is_empty() {
        firewall_backend(
            "nftables",
            "No rules returned",
            "nftables returned an empty ruleset view. This does not prove that host filtering is disabled.",
        )
    } else {
        firewall_backend(
            "nftables",
            "Ruleset visible",
            "nftables returned rules. CyberGates does not interpret them as a complete firewall policy.",
        )
    }
}

fn firewall_backend(name: &str, state: &str, detail: &str) -> FirewallBackendStatus {
    FirewallBackendStatus {
        name: name.to_string(),
        state: state.to_string(),
        detail: detail.to_string(),
    }
}

fn parse_enabled_unit_files(text: &str, scope: &str) -> Vec<StartupItem> {
    text.lines()
        .take(10_000)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().take(3).collect();
            let [unit, state, _preset] = fields.as_slice() else {
                return None;
            };
            if !unit.ends_with(".service")
                || !matches!(*state, "enabled" | "enabled-runtime")
                || unit.len() > 255
                || unit.chars().any(char::is_control)
            {
                return None;
            }
            Some(StartupItem {
                name: (*unit).to_string(),
                path: format!("systemd enabled unit: {unit}"),
                scope: scope.to_string(),
                modified_at: None,
            })
        })
        .collect()
}

fn parse_loaded_systemd_units(text: &str) -> (Vec<LoadedService>, bool) {
    let mut services = Vec::new();
    let mut truncated = false;
    for line in text.lines().take(10_000) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4
            || !fields[0].ends_with(".service")
            || fields[0].len() > 255
            || fields[0].chars().any(char::is_control)
        {
            continue;
        }
        if services.len() == 2000 {
            truncated = true;
            break;
        }
        services.push(LoadedService {
            label: fields[0].to_string(),
            state: systemd_state(fields[2], fields[3]),
            pid: None,
            last_exit_status: None,
        });
    }
    services.sort_by(|left, right| left.label.cmp(&right.label));
    (services, truncated)
}

fn systemd_state(active: &str, sub: &str) -> String {
    let active = match active {
        "active" => "Active",
        "inactive" => "Inactive",
        "failed" => "Failed",
        "activating" => "Starting",
        "deactivating" => "Stopping",
        other => other,
    };
    format!("{active} ({sub})")
}

fn valid_package_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.chars().any(char::is_control)
        && !value.contains(['/', '\\'])
}

fn read_debian_osv_ecosystem() -> Option<String> {
    let mut file = fs::File::open("/etc/os-release").ok()?;
    let mut contents = String::new();
    file.by_ref()
        .take(MAX_OS_RELEASE_BYTES as u64 + 1)
        .read_to_string(&mut contents)
        .ok()?;
    if contents.len() > MAX_OS_RELEASE_BYTES {
        return None;
    }
    debian_osv_ecosystem(&contents)
}

fn debian_osv_ecosystem(text: &str) -> Option<String> {
    let mut id = None;
    let mut version_id = None;
    for line in text.lines().take(512) {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = raw_value.trim();
        let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            &value[1..value.len() - 1]
        } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if value.is_empty() || value.chars().any(char::is_control) {
            continue;
        }
        match key {
            "ID" => id = Some(value),
            "VERSION_ID" => version_id = Some(value),
            _ => {}
        }
    }
    if id? != "debian" {
        return None;
    }
    let release = version_id?;
    if release.len() > 2 || !release.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(format!("Debian:{release}"))
}

fn parse_dpkg_packages(text: &str) -> Vec<InstalledApp> {
    text.lines()
        .take(20_000)
        .filter_map(|line| {
            let mut fields = line.splitn(6, '\t');
            let name = fields.next()?;
            let version = fields.next()?;
            let _architecture = fields.next()?;
            let status = fields.next()?;
            if status != "installed" || !valid_package_field(name) || !valid_package_field(version)
            {
                return None;
            }
            let advisory_name = fields
                .next()
                .filter(|value| valid_package_field(value))
                .unwrap_or_else(|| name.split(':').next().unwrap_or(name));
            let advisory_version = fields
                .next()
                .filter(|value| valid_package_field(value))
                .unwrap_or(version);
            Some(InstalledApp {
                name: name.to_string(),
                version: Some(version.to_string()),
                source: "Debian packages (dpkg)".to_string(),
                path: None,
                signed_by: None,
                obtained_from: Some("dpkg database".to_string()),
                advisory_name: Some(advisory_name.to_string()),
                advisory_version: Some(advisory_version.to_string()),
                advisory_ecosystem: None,
            })
        })
        .collect()
}

fn parse_rpm_packages(text: &str) -> Vec<InstalledApp> {
    text.lines()
        .take(20_000)
        .filter_map(|line| {
            let mut fields = line.splitn(3, '\t');
            let name = fields.next()?;
            let version = fields.next()?;
            let _architecture = fields.next()?;
            if !valid_package_field(name) || !valid_package_field(version) {
                return None;
            }
            Some(InstalledApp {
                name: name.to_string(),
                version: Some(version.to_string()),
                source: "RPM packages".to_string(),
                path: None,
                signed_by: None,
                obtained_from: Some("RPM database".to_string()),
                advisory_name: None,
                advisory_version: None,
                advisory_ecosystem: None,
            })
        })
        .collect()
}

fn parse_pacman_packages(text: &str) -> Vec<InstalledApp> {
    text.lines()
        .take(20_000)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            let version = fields.next()?;
            if fields.next().is_some()
                || !valid_package_field(name)
                || !valid_package_field(version)
            {
                return None;
            }
            Some(InstalledApp {
                name: name.to_string(),
                version: Some(version.to_string()),
                source: "Arch packages (pacman)".to_string(),
                path: None,
                signed_by: None,
                obtained_from: Some("pacman database".to_string()),
                advisory_name: None,
                advisory_version: None,
                advisory_ecosystem: None,
            })
        })
        .collect()
}

fn run_systemctl(args: &[&str]) -> Option<crate::security::process::CommandOutput> {
    SYSTEMCTL_PATHS
        .iter()
        .find_map(|path| run_optional_with_limit(path, args, SYSTEMCTL_TIMEOUT, MAX_COMMAND_OUTPUT))
}

fn parse_ip_addresses(text: &str) -> Vec<NetworkInterface> {
    let mut interfaces: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines().take(10_000) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 || !matches!(fields[2], "inet" | "inet6") {
            continue;
        }
        let name = fields[1].split('@').next().unwrap_or(fields[1]);
        if name.is_empty()
            || name.len() > 64
            || name.contains(['/', '\\'])
            || name.chars().any(char::is_control)
        {
            continue;
        }
        let address = fields[3].split('/').next().unwrap_or("");
        if address.parse::<IpAddr>().is_err() {
            continue;
        }
        let addresses = interfaces.entry(name.to_string()).or_default();
        if !addresses.iter().any(|item| item == address) {
            addresses.push(address.to_string());
        }
    }

    interfaces
        .into_iter()
        .take(256)
        .map(|(name, mut addresses)| {
            addresses.sort();
            let up = read_interface_state(&name).unwrap_or(false);
            NetworkInterface {
                name,
                addresses,
                up,
            }
        })
        .collect()
}

fn read_interface_state(name: &str) -> Option<bool> {
    if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
        return None;
    }
    let state =
        fs::read_to_string(Path::new("/sys/class/net").join(name).join("operstate")).ok()?;
    Some(matches!(state.trim(), "up" | "unknown"))
}

fn read_resolver_config(warnings: &mut Vec<String>) -> Vec<String> {
    let file = match fs::File::open("/etc/resolv.conf") {
        Ok(file) => file,
        Err(_) => {
            warnings.push("/etc/resolv.conf could not be read.".to_string());
            return Vec::new();
        }
    };
    let mut text = String::new();
    match file.take(256 * 1024 + 1).read_to_string(&mut text) {
        Ok(bytes_read) if bytes_read <= 256 * 1024 => {}
        Ok(_) => {
            warnings.push("/etc/resolv.conf exceeded the 256 KiB read limit.".to_string());
            return Vec::new();
        }
        Err(_) => {
            warnings.push("/etc/resolv.conf could not be read.".to_string());
            return Vec::new();
        }
    }
    parse_resolver_text(&text, warnings)
}

fn parse_resolver_text(text: &str, warnings: &mut Vec<String>) -> Vec<String> {
    let mut servers = Vec::new();
    for line in text.lines().take(4096) {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = fields.next() else {
            continue;
        };
        if address.parse::<IpAddr>().is_ok()
            && !servers.iter().any(|item| item == address)
            && servers.len() < 16
        {
            servers.push(address.to_string());
        }
    }
    if text.lines().count() > 4096 {
        warnings.push("Resolver configuration was capped at 4,096 lines.".to_string());
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_output(stdout: &str, success: bool) -> CommandOutput {
        CommandOutput {
            success,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn firewall_adapters_only_report_states_their_tools_expose() {
        assert_eq!(
            parse_ufw_backend(Some(&command_output("Status: active\n", true))).state,
            "Reported active"
        );
        assert_eq!(
            parse_ufw_backend(Some(&command_output("Status: inactive\n", true))).state,
            "Reported inactive"
        );
        assert_eq!(
            parse_ufw_backend(Some(&command_output("UFW status unavailable", false))).state,
            "Unknown"
        );
        assert_eq!(
            parse_firewalld_backend(Some(&command_output("running\n", true))).state,
            "Reported running"
        );
        assert_eq!(
            parse_firewalld_backend(Some(&command_output("not running\n", false))).state,
            "Reported stopped"
        );
        assert_eq!(
            parse_nft_backend(Some(&command_output("table inet filter {}\n", true))).state,
            "Ruleset visible"
        );
        assert_eq!(
            parse_nft_backend(Some(&command_output("", true))).state,
            "No rules returned"
        );
        assert_eq!(parse_nft_backend(None).state, "Unavailable");
    }

    #[test]
    fn parses_only_enabled_systemd_service_units() {
        let items = parse_enabled_unit_files(
            "alpha.service enabled enabled\nbeta.service disabled enabled\nhelper.socket enabled enabled\nworker.service enabled-runtime disabled\n",
            "Current user",
        );
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "alpha.service");
        assert_eq!(items[1].name, "worker.service");
        assert!(items.iter().all(|item| item.scope == "Current user"));
    }

    #[test]
    fn parses_loaded_unit_state_without_guessing_pid_or_exit_status() {
        let (services, truncated) = parse_loaded_systemd_units(
            "dbus.service loaded active running D-Bus System Message Bus\ncache.service loaded inactive dead Local cache\nfailed.service loaded failed failed Failed service\nnot-a-unit loaded active running ignored\n",
        );
        assert!(!truncated);
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].label, "cache.service");
        assert_eq!(services[0].state, "Inactive (dead)");
        assert_eq!(services[0].pid, None);
        assert_eq!(services[2].state, "Failed (failed)");
    }

    #[test]
    fn desktop_inventory_accepts_regular_desktop_files_only() {
        let root =
            std::env::temp_dir().join(format!("cybergates-linux-startup-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let desktop = root.join("example.desktop");
        fs::write(&desktop, "untrusted content is not parsed").unwrap();
        let item = desktop_startup_item(&desktop, "Current user").unwrap();
        assert_eq!(item.name, "example");
        assert_eq!(item.scope, "Current user");
        assert!(desktop_startup_item(&root.join("notes.txt"), "System").is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_linux_interface_addresses_and_deduplicates() {
        let interfaces = parse_ip_addresses(
            "2: enp0s1    inet 192.0.2.10/24 brd 192.0.2.255 scope global enp0s1\n2: enp0s1    inet 192.0.2.10/24 brd 192.0.2.255 scope global enp0s1\n2: enp0s1    inet6 2001:db8::10/64 scope global enp0s1\n",
        );
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "enp0s1");
        assert_eq!(interfaces[0].addresses, ["192.0.2.10", "2001:db8::10"]);
    }

    #[test]
    fn parses_resolver_config_without_directives_or_invalid_addresses() {
        let mut warnings = Vec::new();
        let servers = parse_resolver_text(
            "# generated\nnameserver 127.0.0.53\nnameserver 2001:db8::53 # v6\nsearch local\nnameserver invalid\n",
            &mut warnings,
        );
        assert_eq!(servers, ["127.0.0.53", "2001:db8::53"]);
    }

    #[test]
    fn parses_only_installed_dpkg_packages_with_bounded_fields() {
        let packages = parse_dpkg_packages(
            "openssl:amd64\t3.0.2-0ubuntu1\tamd64\tinstalled\topenssl\t3.0.2-0ubuntu1\nremoved\t1.0\tall\tconfig-files\nbad/name\t1.0\tall\tinstalled\nmalformed\t1.0\n",
        );
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "openssl:amd64");
        assert_eq!(packages[0].version.as_deref(), Some("3.0.2-0ubuntu1"));
        assert_eq!(packages[0].source, "Debian packages (dpkg)");
        assert_eq!(packages[0].advisory_name.as_deref(), Some("openssl"));
        assert_eq!(
            packages[0].advisory_version.as_deref(),
            Some("3.0.2-0ubuntu1")
        );
        assert!(packages[0].advisory_ecosystem.is_none());
    }

    #[test]
    fn maps_debian_release_only_for_exact_numeric_debian_identity() {
        assert_eq!(
            debian_osv_ecosystem("ID=debian\nVERSION_ID=13\n"),
            Some("Debian:13".to_string())
        );
        assert_eq!(debian_osv_ecosystem("ID=debian\nVERSION_ID=12.5\n"), None);
        assert_eq!(debian_osv_ecosystem("ID=ubuntu\nVERSION_ID=24.04\n"), None);
        assert_eq!(debian_osv_ecosystem("ID=debian\nVERSION_ID=sid\n"), None);
        assert_eq!(debian_osv_ecosystem("ID=debian\n"), None);
    }

    #[test]
    fn parses_rpm_and_pacman_package_rows_without_paths_or_controls() {
        let rpm = parse_rpm_packages("openssl\t3.2.1-4.fc42\tx86_64\ninvalid\\name\t1.0\tnoarch\n");
        assert_eq!(rpm.len(), 1);
        assert_eq!(rpm[0].source, "RPM packages");
        let pacman = parse_pacman_packages("linux 6.12.1-arch1-1\npackage with spaces\n");
        assert_eq!(pacman.len(), 1);
        assert_eq!(pacman[0].name, "linux");
        assert_eq!(pacman[0].source, "Arch packages (pacman)");
    }
}
