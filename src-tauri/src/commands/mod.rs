use serde::Serialize;
use tauri::State;

use crate::error::{AppError, AppResult};
use crate::models::{
    AdvisoryReport, AdvisoryUpdate, AuditLogEntry, AuditRecord, Dashboard, Finding,
    FirewallSnapshot, HostDiagnostic, IncidentDetail, IncidentRecord, InstalledApp,
    LoadedServiceInventory, ModuleStatus, NetworkConnection, NetworkSnapshot, ProcessInfo,
    StartupInventory, SystemInfo,
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
pub async fn get_network_snapshot(_state: State<'_, AppState>) -> AppResult<NetworkSnapshot> {
    tauri::async_runtime::spawn_blocking(|| platform::adapter().network_snapshot())
        .await
        .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn diagnose_host(state: State<'_, AppState>, host: String) -> AppResult<HostDiagnostic> {
    use std::sync::atomic::Ordering;

    if state
        .host_diagnostic_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(AppError::Validation(
            "a host diagnostic is already running".to_string(),
        ));
    }
    struct DiagnosticGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DiagnosticGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let guard = DiagnosticGuard(state.host_diagnostic_running.clone());
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        services::diagnostics::diagnose_host(&host)
    })
        .await
        .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn get_installed_apps(_state: State<'_, AppState>) -> AppResult<Vec<InstalledApp>> {
    tauri::async_runtime::spawn_blocking(|| {
        let adapter = platform::adapter();
        adapter.installed_apps()
    })
    .await
    .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn get_firewall_snapshot(
    _state: State<'_, AppState>,
) -> AppResult<Option<FirewallSnapshot>> {
    tauri::async_runtime::spawn_blocking(|| {
        let adapter = platform::adapter();
        adapter.firewall_snapshot()
    })
    .await
    .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn get_startup_inventory(_state: State<'_, AppState>) -> AppResult<StartupInventory> {
    tauri::async_runtime::spawn_blocking(|| platform::adapter().startup_inventory())
        .await
        .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn get_loaded_services(_state: State<'_, AppState>) -> AppResult<LoadedServiceInventory> {
    tauri::async_runtime::spawn_blocking(|| platform::adapter().loaded_services())
        .await
        .map_err(|err| AppError::Task(err.to_string()))?
}

struct AdvisoryUpdateGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for AdvisoryUpdateGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tauri::command]
pub async fn update_advisory_database(state: State<'_, AppState>) -> AppResult<AdvisoryUpdate> {
    use std::sync::atomic::Ordering;

    if state
        .advisory_update_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(AppError::Validation(
            "an advisory database update is already running".to_string(),
        ));
    }

    let guard = AdvisoryUpdateGuard(state.advisory_update_running.clone());
    let db = state.db.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let result = services::advisories::update(&db);
        match &result {
            Ok(update) => {
                let _ = db.log_action(
                    "advisory_update",
                    &format!(
                        "{} records, {} packages, {} bytes",
                        update.record_count, update.package_count, update.bytes
                    ),
                    "success",
                );
            }
            Err(err) => {
                let _ = db.log_action("advisory_update", &err.to_string(), "failed");
            }
        }
        result
    })
    .await
    .map_err(|err| AppError::Task(err.to_string()))?
}

#[tauri::command]
pub async fn get_advisory_report(state: State<'_, AppState>) -> AppResult<AdvisoryReport> {
    let db = state.db.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let adapter = platform::adapter();
        let apps = adapter.installed_apps()?;
        services::advisories::report(&db, &apps)
    })
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
pub fn get_incidents(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> AppResult<Vec<IncidentRecord>> {
    state.db.list_incidents(limit.unwrap_or(100))
}

#[tauri::command]
pub fn get_incident(state: State<'_, AppState>, incident_id: String) -> AppResult<IncidentDetail> {
    let incident_id = validate::bounded_text(&incident_id, "incident id", 64)?;
    state
        .db
        .incident_detail(&incident_id)?
        .ok_or_else(|| AppError::NotFound(format!("incident {incident_id}")))
}

#[tauri::command]
pub fn create_incident(
    state: State<'_, AppState>,
    finding_id: String,
) -> AppResult<IncidentRecord> {
    let finding_id = validate::bounded_text(&finding_id, "finding id", 64)?;
    let incident = state.db.create_incident_from_finding(&finding_id)?;
    state.db.log_action(
        "incident.create",
        "Incident created from an existing finding",
        "success",
    )?;
    Ok(incident)
}

#[tauri::command]
pub fn add_incident_note(
    state: State<'_, AppState>,
    incident_id: String,
    note: String,
) -> AppResult<()> {
    let incident_id = validate::bounded_text(&incident_id, "incident id", 64)?;
    let note = validate::bounded_text(&note, "incident note", 2000)?;
    if note.len() < 3 {
        return Err(AppError::Validation(
            "incident note must be at least 3 characters".to_string(),
        ));
    }
    state.db.add_incident_note(&incident_id, &note)?;
    state
        .db
        .log_action("incident.note", "Incident timeline note added", "success")?;
    Ok(())
}

#[tauri::command]
pub fn set_incident_status(
    state: State<'_, AppState>,
    incident_id: String,
    status: String,
    note: String,
) -> AppResult<()> {
    let incident_id = validate::bounded_text(&incident_id, "incident id", 64)?;
    let status = validate::bounded_text(&status, "incident status", 32)?;
    let note = validate::bounded_text(&note, "status update note", 2000)?;
    if note.len() < 10 {
        return Err(AppError::Validation(
            "status changes require an explanatory note of at least 10 characters".to_string(),
        ));
    }
    if !matches!(status.as_str(), "open" | "investigating" | "closed") {
        return Err(AppError::Validation("invalid incident status".to_string()));
    }
    state.db.set_incident_status(&incident_id, &status, &note)?;
    state.db.log_action(
        "incident.status",
        &format!("Incident status changed to {status}"),
        "success",
    )?;
    Ok(())
}

#[tauri::command]
pub fn export_incident_report(
    state: State<'_, AppState>,
    incident_id: String,
    format: String,
) -> AppResult<services::reports::IncidentExport> {
    let incident_id = validate::bounded_text(&incident_id, "incident id", 64)?;
    let format = validate::report_format(&format)?;
    services::reports::export_incident(&state.db, &state.reports_dir, &incident_id, format)
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

    match key.as_str() {
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
            state.db.set_setting(&key, &value)?;
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

    state.db.set_setting(&key, &value)?;
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
