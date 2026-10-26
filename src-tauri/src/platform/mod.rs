use crate::error::AppResult;
use crate::models::{
    now_rfc3339, CheckResult, FirewallSnapshot, InstalledApp, LoadedServiceInventory,
    NetworkConnection, NetworkSnapshot, StartupInventory,
};

pub trait PlatformAudit: Send + Sync {
    fn platform_name(&self) -> &'static str;
    fn supported(&self) -> bool;
    fn notes(&self) -> Vec<String>;
    fn audit(&self) -> Vec<CheckResult>;
    fn connections(&self) -> AppResult<Vec<NetworkConnection>> {
        Ok(Vec::new())
    }

    fn network_snapshot(&self) -> AppResult<NetworkSnapshot> {
        Ok(NetworkSnapshot {
            available: false,
            interfaces: Vec::new(),
            dns_servers: Vec::new(),
            fetched_at: now_rfc3339(),
            source: "No native network configuration provider".to_string(),
            scope_note:
                "Interface and DNS configuration inspection is unavailable on this platform."
                    .to_string(),
            warnings: Vec::new(),
        })
    }

    fn installed_apps(&self) -> AppResult<Vec<InstalledApp>> {
        Ok(Vec::new())
    }

    fn firewall_snapshot(&self) -> AppResult<Option<FirewallSnapshot>> {
        Ok(None)
    }

    fn startup_inventory(&self) -> AppResult<StartupInventory> {
        Ok(StartupInventory {
            available: false,
            items: Vec::new(),
            fetched_at: now_rfc3339(),
            source: "No native startup-item provider".to_string(),
            scope_note: "Startup-item inspection is unavailable on this platform.".to_string(),
            warnings: Vec::new(),
        })
    }

    fn loaded_services(&self) -> AppResult<LoadedServiceInventory> {
        Ok(LoadedServiceInventory {
            available: false,
            services: Vec::new(),
            fetched_at: now_rfc3339(),
            source: "No native service-state provider".to_string(),
            scope_note: "Loaded service inspection is unavailable on this platform.".to_string(),
            warnings: Vec::new(),
        })
    }
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(
    not(target_os = "macos"),
    not(target_os = "linux"),
    not(target_os = "windows")
))]
mod unsupported;
#[cfg(any(target_os = "windows", test))]
mod windows;

pub fn adapter() -> Box<dyn PlatformAudit> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsAdapter)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxAdapter)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsAdapter)
    }
    #[cfg(all(
        not(target_os = "macos"),
        not(target_os = "linux"),
        not(target_os = "windows")
    ))]
    {
        Box::new(unsupported::UnsupportedAdapter)
    }
}
