#[cfg(target_os = "windows")]
use crate::error::AppResult;
use crate::models::StartupItem;
#[cfg(target_os = "windows")]
use crate::models::{now_rfc3339, CheckResult, CheckStatus, Severity, StartupInventory};
#[cfg(target_os = "windows")]
use crate::platform::PlatformAudit;

#[cfg(target_os = "windows")]
const MAX_STARTUP_ITEMS: usize = 2000;
#[cfg(target_os = "windows")]
const MAX_VALUES_PER_KEY: u32 = 1000;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    KEY_READ,
};

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub struct WindowsAdapter;

#[cfg(target_os = "windows")]
impl PlatformAudit for WindowsAdapter {
    fn platform_name(&self) -> &'static str {
        "Windows"
    }

    fn supported(&self) -> bool {
        // A startup inventory is not a verified posture audit.
        false
    }

    fn notes(&self) -> Vec<String> {
        vec![
            "Read-only startup registry entries are available for current-user and local-machine Run/RunOnce keys.".to_string(),
            "Windows security-posture checks, startup folders, scheduled tasks, and loaded-service inventories are not implemented; no security score is claimed.".to_string(),
        ]
    }

    fn audit(&self) -> Vec<CheckResult> {
        vec![CheckResult {
            id: "platform.unsupported".to_string(),
            title: "Windows posture audit unavailable".to_string(),
            category: "platform".to_string(),
            status: CheckStatus::Unavailable,
            severity: Severity::Info,
            weight: 0,
            evidence: "Operating system: Windows".to_string(),
            explanation: "CyberGates provides a partial read-only startup registry inventory on Windows, but does not yet implement verified Windows security-posture checks. No protection status or score is claimed.".to_string(),
            remediation: "Use the available startup inventory; re-run the audit after a verified Windows posture adapter is released.".to_string(),
            verification: "Check the platform capability matrix for Windows audit coverage.".to_string(),
            source: "CyberGates capability detection".to_string(),
            checked_at: now_rfc3339(),
        }]
    }

    fn startup_inventory(&self) -> AppResult<StartupInventory> {
        let keys = [
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "Current user",
            ),
            (
                HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "Current user",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "Local machine",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "Local machine",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                "Local machine (32-bit registry view)",
            ),
            (
                HKEY_LOCAL_MACHINE,
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                "Local machine (32-bit registry view)",
            ),
        ];
        let mut items = Vec::new();
        let mut warnings = Vec::new();
        let mut truncated = false;

        for (root, key_path, scope) in keys {
            if items.len() >= MAX_STARTUP_ITEMS {
                truncated = true;
                break;
            }
            match read_registry_values(root, key_path, scope) {
                Ok((mut key_items, key_truncated)) => {
                    items.append(&mut key_items);
                    truncated |= key_truncated;
                }
                Err(RegistryReadError::Unavailable) => {}
                Err(RegistryReadError::AccessDenied) => warnings.push(format!(
                    "Access was denied while reading the {scope} startup registry key {key_path}."
                )),
                Err(RegistryReadError::Failed) => warnings.push(format!(
                    "The {scope} startup registry key {key_path} could not be read."
                )),
            }
        }

        if items.len() > MAX_STARTUP_ITEMS {
            items.truncate(MAX_STARTUP_ITEMS);
            truncated = true;
        }
        if truncated {
            warnings.push(
                "The startup inventory may be incomplete because a collection limit was reached."
                    .to_string(),
            );
        }
        items.sort_by(|left, right| {
            left.scope
                .cmp(&right.scope)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
                .then_with(|| left.path.cmp(&right.path))
        });
        items.dedup_by(|left, right| left.scope == right.scope && left.path == right.path);

        Ok(StartupInventory {
            available: true,
            items,
            fetched_at: now_rfc3339(),
            source: "Windows Run and RunOnce registry keys (read-only)".to_string(),
            scope_note: "Lists value names from current-user and local-machine Run/RunOnce registry keys, including the local-machine 32-bit registry view when present. Configured command data is not displayed or executed. Startup folders, scheduled tasks, services, policy-based startup, and whether a listed entry actually ran are not inspected.".to_string(),
            warnings,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(target_os = "windows")]
enum RegistryReadError {
    Unavailable,
    AccessDenied,
    Failed,
}

#[cfg(target_os = "windows")]
fn read_registry_values(
    root: HKEY,
    key_path: &str,
    scope: &str,
) -> Result<(Vec<StartupItem>, bool), RegistryReadError> {
    let wide_key: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_key` is NUL-terminated and remains alive for the call. The
    // requested access is read-only; `key` is a valid writable out pointer.
    let status = unsafe { RegOpenKeyExW(root, wide_key.as_ptr(), 0, KEY_READ, &mut key) };
    if status != ERROR_SUCCESS {
        return match status {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Err(RegistryReadError::Unavailable),
            ERROR_ACCESS_DENIED => Err(RegistryReadError::AccessDenied),
            _ => Err(RegistryReadError::Failed),
        };
    }

    let result = enumerate_registry_values(key, key_path, scope);
    // SAFETY: `key` was successfully returned by RegOpenKeyExW above.
    unsafe { RegCloseKey(key) };
    result
}

#[cfg(target_os = "windows")]
fn enumerate_registry_values(
    key: HKEY,
    key_path: &str,
    scope: &str,
) -> Result<(Vec<StartupItem>, bool), RegistryReadError> {
    let mut items = Vec::new();
    for index in 0..MAX_VALUES_PER_KEY {
        let mut name = vec![0u16; 1024];
        let mut name_length = name.len() as u32;
        // SAFETY: `name` is writable for `name_length` UTF-16 characters. We
        // intentionally pass null data pointers because only value names are
        // needed; configured command contents are neither read nor displayed.
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_length,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok((items, false));
        }
        if status == ERROR_MORE_DATA {
            // A long value name is skipped; its data is never read.
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(RegistryReadError::Failed);
        }
        let value_name = String::from_utf16_lossy(&name[..name_length as usize]);
        if let Some(item) = registry_startup_item(&value_name, key_path, scope) {
            items.push(item);
        }
    }
    Ok((items, true))
}

fn registry_startup_item(value_name: &str, key_path: &str, scope: &str) -> Option<StartupItem> {
    let name = value_name.trim();
    if name.is_empty() || name.chars().any(char::is_control) || name.chars().count() > 256 {
        return None;
    }
    let root = match scope {
        "Current user" => "HKCU",
        "Local machine" | "Local machine (32-bit registry view)" => "HKLM",
        _ => return None,
    };
    Some(StartupItem {
        name: name.to_string(),
        path: format!(r"{root}\{key_path}\{name}"),
        scope: scope.to_string(),
        modified_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_startup_item_reports_location_without_command_data() {
        let item = registry_startup_item(
            "Updater",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Current user",
        )
        .unwrap();
        assert_eq!(item.name, "Updater");
        assert_eq!(
            item.path,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
        );
        assert_eq!(item.scope, "Current user");
    }

    #[test]
    fn registry_startup_item_rejects_empty_or_control_names() {
        assert!(registry_startup_item(
            "  ",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Current user"
        )
        .is_none());
        assert!(registry_startup_item(
            "bad\nname",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "Current user"
        )
        .is_none());
    }
}
