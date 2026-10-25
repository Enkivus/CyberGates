mod commands;
mod core;
mod db;
mod error;
mod models;
mod platform;
mod security;
mod services;
mod state;

use std::path::Path;

use tauri::Manager;
use tracing_subscriber::EnvFilter;

use crate::db::Db;
use crate::security::filesystem::ensure_private_dir;
use crate::state::AppState;

fn init_logging(log_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    ensure_private_dir(log_dir)?;
    let file_appender = tracing_appender::rolling::daily(log_dir, "cybergates.log");
    let (writer, guard) = tracing_appender::non_blocking(file_appender);
    // Keep the writer guard alive for the entire process lifetime.
    Box::leak(Box::new(guard));
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("cybergates_lib=info,tauri=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(writer)
        .try_init();
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let log_dir = app.path().app_log_dir()?;
            init_logging(&log_dir)?;
            ensure_private_dir(&data_dir)?;

            let db = Db::open(&data_dir.join("cybergates.db"))?;
            let retention_days = db
                .get_setting("retentionDays")?
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(90);
            if let Ok(removed) = db.prune(retention_days) {
                tracing::info!(removed, "pruned expired audit records");
            }
            db.log_action("app.start", "CyberGates started", "success")?;

            tracing::info!(?data_dir, ?log_dir, "CyberGates storage initialized");
            app.manage(AppState::new(db, data_dir, log_dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard,
            commands::run_audit,
            commands::get_system_info,
            commands::get_processes,
            commands::get_network_connections,
            commands::get_installed_apps,
            commands::get_firewall_snapshot,
            commands::get_startup_inventory,
            commands::update_advisory_database,
            commands::get_advisory_report,
            commands::get_module_statuses,
            commands::get_open_findings,
            commands::get_audit_history,
            commands::get_audit_findings,
            commands::get_settings,
            commands::update_setting,
            commands::export_report,
            commands::get_audit_log,
            commands::get_storage_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running CyberGates");
}
