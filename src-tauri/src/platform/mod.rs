use crate::error::AppResult;
use crate::models::{CheckResult, NetworkConnection};

pub trait PlatformAudit: Send + Sync {
    fn platform_name(&self) -> &'static str;
    fn supported(&self) -> bool;
    fn notes(&self) -> Vec<String>;
    fn audit(&self) -> Vec<CheckResult>;
    fn connections(&self) -> AppResult<Vec<NetworkConnection>> {
        Ok(Vec::new())
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
