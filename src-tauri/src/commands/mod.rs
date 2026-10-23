use serde::Serialize;
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::models::{
    AuditLogEntry, AuditRecord, Dashboard, Finding, ModuleStatus, NetworkConnection, ProcessInfo,
    SystemInfo,
};
use crate::platform;
use crate::security::validate;
use crate::services;
use crate::state::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageInfo {
    pub data_dir: String,
    pub reports_dir: String,
    pub log_dir: String,
    pub database_path: String,
    pub database_bytes: u64,
    pub retention_days: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingEntry {
    pub key: String,
    pub value: String,
}

#[tauri::command]
pub async fn get_dashboard(state: State<'_, AppState>) -> AppResult<Dashboard> {
    let db = state.db.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let adapter = platform::adapter();
        services::audit::build_dashboard(&db, adapter.as_ref())
    })
    .await
    .map_err(|err| AppError::Task(err.to_string()))?
}

struct AuditRunGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for AuditRunGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tauri::command]
pub async fn run_audit(state: State<'_, AppState>) -> AppResult<Dashboard> {
    use std::sync::atomic::Ordering;

    if state
        .audit_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(AppError::Validation(
            "a security audit is already running".to_string(),
        ));
    }

    let guard = AuditRunGuard(state.audit_running.clone());
    let db = state.db.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let adapter = platform::adapter();
        services::audit::execute(&db, adapter.as_ref())
    })
    .await
    .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn get_system_info(state: State<'_, AppState>) -> AppResult<SystemInfo> {
    let _ = state;
    tauri::async_runtime::spawn_blocking(|| {
        let adapter = platform::adapter();
        services::system::collect(adapter.as_ref())
    })
    .await
    .map_err(|err| AppError::Task(err.to_string()))
}

#[tauri::command]
pub async fn get_processes(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> AppResult<Vec<ProcessInfo>> {
    let _ = state;
    tauri::async_runtime::spawn_blocking(move || services::system::processes(limit.unwrap_or(250)))
        .await
        .map_err(|err| AppError::Task(err.to_string()))
}

#[tauri::command]
pub async fn get_network_connections(
    state: State<'_, AppState>,
) -> AppResult<Vec<NetworkConnection>> {
    let _ = state;
    tauri::async_runtime::spawn_blocking(services::network::default_connections)
        .await
        .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub fn get_module_statuses() -> AppResult<Vec<ModuleStatus>> {
    Ok(services::modules::list())
}

#[tauri::command]
pub fn get_open_findings(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> AppResult<Vec<Finding>> {
    state.db.list_open_findings(limit.unwrap_or(500))
}

#[tauri::command]
pub fn get_audit_history(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> AppResult<Vec<AuditRecord>> {
    services::audit::history(&state.db, limit.unwrap_or(50))
}

#[tauri::command]
pub fn get_audit_findings(state: State<'_, AppState>, audit_id: String) -> AppResult<Vec<Finding>> {
    let audit_id = validate::bounded_text(&audit_id, "audit id", 64)?;
    if !state.db.audit_exists(&audit_id)? {
        return Err(AppError::NotFound(format!("audit {audit_id}")));
    }
    state.db.findings_for_audit(&audit_id)
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> AppResult<Vec<SettingEntry>> {
    Ok(state
        .db
        .get_settings()?
        .into_iter()
        .map(|(key, value)| SettingEntry { key, value })
        .collect())
}

#[tauri::command]
pub fn update_setting(
    state: State<'_, AppState>,
    key: String,
    value: String,
) -> AppResult<SettingEntry> {
    let key = validate::setting_key(&key)?;
    if key == "lastAuditId" {
        return Err(AppError::Validation(
            "lastAuditId is managed internally".to_string(),
        ));
    }
    let value = validate::bounded_text(&value, "setting value", 128)?;

    match key {
        "theme" => {
            if !matches!(value.as_str(), "dark" | "light") {
                return Err(AppError::Validation(
                    "theme must be 'dark' or 'light'".to_string(),
                ));
            }
        }
        "telemetry" | "notifications" | "aiEnabled" => {
            if !matches!(value.as_str(), "true" | "false") {
                return Err(AppError::Validation(
                    "boolean settings must be 'true' or 'false'".to_string(),
                ));
            }
            if key == "telemetry" && value == "true" {
                return Err(AppError::Validation(
                    "CyberGates does not implement telemetry; this cannot be enabled.".to_string(),
                ));
            }
            if key == "aiEnabled" && value == "true" {
                return Err(AppError::Validation(
                    "No AI provider is implemented yet; the assistant cannot be enabled."
                        .to_string(),
                ));
            }
        }
        "retentionDays" => {
            let days: u32 = value
                .parse()
                .map_err(|_| AppError::Validation("retentionDays must be a number".to_string()))?;
            if !(1..=3650).contains(&days) {
                return Err(AppError::Validation(
                    "retentionDays must be between 1 and 3650".to_string(),
                ));
            }
            state.db.set_setting(key, &value)?;
            state.db.prune(days)?;
            state
                .db
                .log_action("settings.update", "retentionDays updated", "success")?;
            return Ok(SettingEntry {
                key: key.to_string(),
                value,
            });
        }
        "aiProvider" => {}
        _ => {}
    }

    if key == "aiProvider" && value != "none" {
        return Err(AppError::Validation(
            "Only the 'none' AI provider is available; no external provider is configured."
                .to_string(),
        ));
    }

    state.db.set_setting(key, &value)?;
    state
        .db
        .log_action("settings.update", &format!("{key} updated"), "success")?;
    Ok(SettingEntry {
        key: key.to_string(),
        value,
    })
}

#[tauri::command]
pub fn export_report(
    state: State<'_, AppState>,
    audit_id: String,
    format: String,
) -> AppResult<services::reports::ReportExport> {
    let audit_id = validate::bounded_text(&audit_id, "audit id", 64)?;
    services::reports::export(&state.db, &state.reports_dir, &audit_id, &format)
}

#[tauri::command]
pub fn get_audit_log(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> AppResult<Vec<AuditLogEntry>> {
    state.db.list_audit_log(limit.unwrap_or(100))
}

#[tauri::command]
pub fn get_storage_info(state: State<'_, AppState>) -> AppResult<StorageInfo> {
    let retention_days = state
        .db
        .get_setting("retentionDays")?
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(90);
    Ok(StorageInfo {
        data_dir: state.data_dir.to_string_lossy().to_string(),
        reports_dir: state.reports_dir.to_string_lossy().to_string(),
        log_dir: state.log_dir.to_string_lossy().to_string(),
        database_path: state.db.path().to_string_lossy().to_string(),
        database_bytes: state.db.db_size_bytes(),
        retention_days,
    })
}
