use crate::error::AppResult;
use crate::models::{
    now_rfc3339, CheckResult, FirewallSnapshot, InstalledApp, NetworkConnection, StartupInventory,
};

pub trait PlatformAudit: Send + Sync {
    fn platform_name(&self) -> &'static str;
    fn supported(&self) -> bool;
    fn notes(&self) -> Vec<String>;
    fn audit(&self) -> Vec<CheckResult>;
    fn connections(&self) -> AppResult<Vec<NetworkConnection>> {
        Ok(Vec::new())
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
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod unsupported;

pub fn adapter() -> Box<dyn PlatformAudit> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsAdapter)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(unsupported::UnsupportedAdapter)
    }
}
